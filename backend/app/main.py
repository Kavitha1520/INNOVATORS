from __future__ import annotations

import asyncio
import json
import csv
import io
import logging
import os
import http.client
import importlib.util
import re
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import networkx as nx
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, aliased
from rapidfuzz import fuzz

from .config import BASE_DIR, DB_PATH, UPLOADS_DIR, APP_TITLE, PORT
from .database import Base, SessionLocal, engine
from .models import (
    AuditLog, Brand, Campaign, CampaignEvent, CustomerReport, DetectionResult,
    Entity, Evidence, Investigation, MonitoringSource, Organization, QRAnalysis,
    Relationship, ReportMatch, ReportMetadata, User,
)
from .services.auth import authenticate_request, create_access_token, hash_password, seed_demo_user, verify_password
from .services.detection import analyze_candidate, build_demo_scans, normalize_text, save_uploaded_logo
from .services.ingestion import (
    URL_PATTERN,
    assess_url_safety,
    decode_qr_image,
    extract_screenshot_text,
    get_tesseract_status,
    normalize_url,
    parse_findings_csv,
)
from .services.monitoring import (
    ThreatFeedError,
    phishtank_api_key,
    record_source_failure,
    run_phishtank_source,
)
from .schema import DatabaseIntegrityError, initialize_database

logger = logging.getLogger(__name__)

app = FastAPI(title=APP_TITLE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")


@app.exception_handler(IntegrityError)
async def handle_integrity_error(request: Request, error: IntegrityError) -> JSONResponse:
    logger.exception("Database constraint rejected %s %s.", request.method, request.url.path)
    return JSONResponse(
        status_code=409,
        content={"detail": "Database constraint prevented this change. No changes were saved."},
    )


@app.exception_handler(SQLAlchemyError)
async def handle_database_error(request: Request, error: SQLAlchemyError) -> JSONResponse:
    logger.exception("Database operation failed for %s %s.", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Database operation failed. No changes were saved."},
    )


@app.exception_handler(DatabaseIntegrityError)
async def handle_schema_integrity_error(request: Request, error: DatabaseIntegrityError) -> JSONResponse:
    logger.error("Database integrity validation failed: %s", error)
    return JSONResponse(status_code=503, content={"detail": str(error)})


@app.middleware("http")
async def require_local_session(request: Request, call_next):
    public_paths = {
        "/api/health",
        "/api/auth/login",
        "/api/customer/reports",
        "/api/customer/reports/screenshot",
    }
    if request.url.path in {"/api/customer/reports", "/api/customer/reports/screenshot"}:
        identity = authenticate_request(request)
        if identity:
            request.state.identity = identity
    if request.url.path.startswith("/api/") and request.url.path not in public_paths:
        identity = authenticate_request(request)
        if not identity:
            return JSONResponse(status_code=401, content={"detail": "Authentication required."})
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and identity.get("role") not in {"admin", "owner"}:
            return JSONResponse(status_code=403, content={"detail": "This account cannot modify platform data."})
        request.state.identity = identity
    return await call_next(request)


class LoginPayload(BaseModel):
    email: str
    password: str


class OrganizationUpdatePayload(BaseModel):
    name: str = Field(min_length=2, max_length=255)


class UserCreatePayload(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=256)


class UserUpdatePayload(BaseModel):
    email: Optional[str] = Field(default=None, min_length=3, max_length=255)
    password: Optional[str] = Field(default=None, min_length=12, max_length=256)


class CandidatePayload(BaseModel):
    brand_id: int
    name: str = Field(default="", max_length=500)
    entity_type: str = Field(default="social_profile", max_length=50)
    platform: str = Field(default="Unknown", max_length=80)
    url: str = Field(default="", max_length=2048)
    description: str = Field(default="", max_length=4000)
    package_id: str = Field(default="", max_length=255)
    developer_name: str = Field(default="", max_length=500)
    logo_perceptual_hash: str = Field(default="", max_length=64)


class MonitoringSourcePayload(BaseModel):
    brand_id: int
    source_type: str = Field(min_length=2, max_length=50)
    platform: str = Field(min_length=2, max_length=80)
    locator: str = Field(min_length=2, max_length=1000)
    interval_minutes: int = Field(default=360, ge=60, le=1440)


class MonitoringSourceUpdatePayload(BaseModel):
    platform: Optional[str] = Field(default=None, min_length=2, max_length=80)
    locator: Optional[str] = Field(default=None, min_length=2, max_length=1000)
    enabled: Optional[bool] = None
    interval_minutes: Optional[int] = Field(default=None, ge=60, le=1440)


class InvestigationPayload(BaseModel):
    brand_id: int
    title: str = Field(min_length=3, max_length=255)
    summary: str = Field(default="", max_length=4000)
    risk_level: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
    detection_id: Optional[int] = None


class InvestigationUpdatePayload(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=255)
    summary: Optional[str] = Field(default=None, max_length=4000)
    status: Optional[str] = Field(default=None, pattern="^(open|investigating|resolved|closed)$")
    risk_level: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low)$")
    detection_id: Optional[int] = None


class FindingUpdatePayload(BaseModel):
    status: str = Field(pattern="^(open|review|monitoring|resolved|closed)$")


class CustomerReportPayload(BaseModel):
    brand_id: Optional[int] = None
    reporter_contact: str = Field(default="", max_length=255)
    report_text: str = Field(min_length=5, max_length=4000)
    reported_url: str = Field(default="", max_length=2048)


class CommunityReviewPayload(BaseModel):
    status: str = Field(pattern="^(pending|reviewed|actioned|dismissed)$")
    analyst_verified: bool = False


class URLSafetyPayload(BaseModel):
    brand_id: Optional[int] = None
    url: str = Field(min_length=3, max_length=2048)


def parse_json_form_field(value: str, field_name: str, expected_type: type) -> Any:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=422, detail=f"'{field_name}' must contain valid JSON.") from error
    if not isinstance(parsed, expected_type):
        expected_name = "an array" if expected_type is list else "an object"
        raise HTTPException(status_code=422, detail=f"'{field_name}' must be {expected_name}.")
    if expected_type is list and any(not isinstance(item, str) for item in parsed):
        raise HTTPException(status_code=422, detail=f"Every value in '{field_name}' must be text.")
    if expected_type is dict and any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in parsed.items()
    ):
        raise HTTPException(status_code=422, detail=f"Every key and value in '{field_name}' must be text.")
    return parsed


# Seed sample data to make the demo functional.
def seed_demo_data(db: Session) -> None:
    seed_demo_user(db)
    organization = db.query(Organization).first()
    existing = db.query(Brand).count()
    if existing:
        return

    brand = Brand(
        organization_id=organization.id if organization else None,
        name="ApexSecure",
        company_description="Global digital payments and identity protection platform founded in 2014.",
        industry="Financial Technology",
        official_website="https://www.apexsecure.com",
        official_social_accounts=["https://instagram.com/apexsecure", "https://x.com/apexsecure", "https://facebook.com/apexsecure"],
        official_mobile_apps=["ApexSecure Wallet", "ApexSecure Pay"],
        official_package_ids=["com.apexsecure.wallet", "com.apexsecure.pay"],
        official_developer_names=["ApexSecure Ltd.", "ApexSecure Group"],
        brand_keywords=["payment", "wallet", "security", "identity", "fraud"],
        known_domains=["apexsecure.com", "wallet.apexsecure.com", "support.apexsecure.com"],
        logo_path="",
        additional_identifiers={"ticker": "APX", "hq": "London"},
        is_sample=1,
    )
    db.add(brand)
    db.flush()
    for source_type, platform, locator in [
        ("social_profile", "Instagram", "https://instagram.com/apexsecure"),
        ("social_profile", "X", "https://x.com/apexsecure"),
        ("application", "Android", "com.apexsecure.wallet"),
        ("application", "iOS", "ApexSecure Pay"),
    ]:
        db.add(MonitoringSource(brand_id=brand.id, source_type=source_type, platform=platform, locator=locator))

    for item in [
        {"title": "Impersonation cluster around support accounts", "summary": "Multiple suspicious social profiles used customer support branding to harvest credentials.", "status": "open", "risk_level": "critical"},
        {"title": "Fake mobile wallet app detection", "summary": "Similar app package metadata and naming characteristics match a likely impersonation threat.", "status": "investigating", "risk_level": "high"},
    ]:
        db.add(
            Investigation(
                brand_id=brand.id,
                title=item["title"],
                summary=item["summary"],
                status=item["status"],
                risk_level=item["risk_level"],
            )
        )

    demo_rows = build_demo_scans({**brand.__dict__, "id": brand.id})
    db.add_all(
        [
            DetectionResult(
                brand_id=brand.id,
                entity_name=row["entity_name"],
                entity_type=row["entity_type"],
                platform=row["platform"],
                similarity_score=row["similarity_score"],
                risk_score=row["risk_score"],
                risk_level=row["risk_level"],
                detection_reason=row["detection_reason"],
                status=row["status"],
                evidence=row["evidence"],
                detected_at=datetime.utcnow(),
            )
            for row in demo_rows
        ]
    )
    db.add(
        AuditLog(
            brand_id=brand.id,
            action="Seeded demo data",
            details="Loaded sample brand and detection history into the local SQLite environment.",
        )
    )
    db.flush()


def get_db():
    db = SessionLocal()
    try:
        yield db
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


@app.on_event("startup")
def startup_event():
    initialize_database(engine, Base.metadata)
    db = SessionLocal()
    try:
        seed_demo_user(db)
        seed_demo_data(db)
        organization = db.query(Organization).first()
        brands = db.query(Brand).all()
        for brand in brands:
            if organization and not brand.organization_id:
                brand.organization_id = organization.id
            if db.query(MonitoringSource).filter(MonitoringSource.brand_id == brand.id).count() == 0:
                for account in brand.official_social_accounts or []:
                    platform = account.split("/")[2].removeprefix("www.").split(".")[0].title() if "://" in account else "Social"
                    db.add(MonitoringSource(
                        brand_id=brand.id,
                        source_type="social_profile",
                        platform=platform,
                        locator=account,
                    ))
                for app_name in brand.official_mobile_apps or []:
                    db.add(MonitoringSource(
                        brand_id=brand.id,
                        source_type="application",
                        platform="Mobile app",
                        locator=app_name,
                    ))
        organization_by_brand = {brand.id: brand.organization_id for brand in brands}
        for report in db.query(CustomerReport).filter(
            CustomerReport.organization_id.is_(None),
            CustomerReport.brand_id.is_not(None),
        ).all():
            report.organization_id = organization_by_brand.get(report.brand_id)
        db.commit()
    except BaseException:
        db.rollback()
        logger.exception("Application startup database initialization failed.")
        raise
    finally:
        db.close()


@app.on_event("startup")
async def start_monitoring_scheduler():
    app.state.monitoring_scheduler = asyncio.create_task(_monitoring_scheduler())


@app.on_event("shutdown")
async def shutdown_event():
    scheduler = getattr(app.state, "monitoring_scheduler", None)
    if scheduler:
        scheduler.cancel()
        try:
            await scheduler
        except asyncio.CancelledError:
            pass


async def _monitoring_scheduler():
    while True:
        await asyncio.sleep(30)
        if not phishtank_api_key():
            continue
        await asyncio.to_thread(_run_due_monitoring_sources)


def _run_due_monitoring_sources():
    now = datetime.utcnow()
    with SessionLocal() as db:
        due_source_ids = [
            source_id
            for (source_id,) in db.query(MonitoringSource.id).filter(
                MonitoringSource.source_type == "threat_feed",
                MonitoringSource.platform == "PhishTank",
                MonitoringSource.enabled.is_(True),
                MonitoringSource.next_run_at <= now,
            ).all()
        ]

    for source_id in due_source_ids:
        with SessionLocal() as db:
            source = db.query(MonitoringSource).filter(MonitoringSource.id == source_id).first()
            if not source:
                continue
            brand = db.query(Brand).filter(Brand.id == source.brand_id).first()
            if not brand:
                continue
            try:
                run_phishtank_source(source, brand, db)
            except ThreatFeedError as error:
                record_source_failure(source, db, error)


@app.post("/api/auth/login")
def login(payload: LoginPayload, db: Session = Depends(get_db)) -> Dict[str, Any]:
    user = db.query(User).filter(User.email == payload.email.strip().lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    organization = db.query(Organization).filter(Organization.id == user.organization_id).first()
    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "expires_in": 43200,
        "user": {"id": user.id, "email": user.email, "role": user.role},
        "organization": {"id": organization.id, "name": organization.name} if organization else None,
    }


@app.get("/api/auth/me")
def current_session(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    identity = request.state.identity
    user = db.query(User).filter(User.id == identity["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="Session account no longer exists.")
    return {"id": user.id, "email": user.email, "role": user.role, "organization_id": user.organization_id}


@app.get("/api/organization")
def get_organization(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    organization = db.query(Organization).filter(
        Organization.id == request_organization_id(request)
    ).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found.")
    return {"id": organization.id, "name": organization.name, "created_at": organization.created_at.isoformat() if organization.created_at else None}


@app.patch("/api/organization")
def update_organization(
    payload: OrganizationUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    organization = db.query(Organization).filter(
        Organization.id == request_organization_id(request)
    ).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found.")
    organization.name = payload.name.strip()
    if len(organization.name) < 2:
        raise HTTPException(status_code=422, detail="Organization name must contain at least two characters.")
    db.commit()
    return {"id": organization.id, "name": organization.name}


@app.get("/api/users")
def list_users(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    users = db.query(User).filter(
        User.organization_id == request_organization_id(request)
    ).order_by(User.id.asc()).all()
    return [
        {"id": user.id, "email": user.email, "role": user.role, "created_at": user.created_at.isoformat() if user.created_at else None}
        for user in users
    ]


def normalize_user_email(email: str) -> str:
    normalized = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    return normalized


@app.post("/api/users", status_code=201)
def create_user(
    payload: UserCreatePayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    email = normalize_user_email(payload.email)
    user = User(
        organization_id=request_organization_id(request),
        email=email,
        password_hash=hash_password(payload.password),
        role="analyst",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "email": user.email, "role": user.role}


@app.put("/api/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    user = db.query(User).filter(
        User.id == user_id,
        User.organization_id == request_organization_id(request),
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    updates = payload.model_dump(exclude_unset=True)
    if "email" in updates:
        user.email = normalize_user_email(updates["email"])
    if updates.get("password"):
        user.password_hash = hash_password(updates["password"])
    if not updates:
        raise HTTPException(status_code=422, detail="Provide an email or password to update.")
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role}


@app.delete("/api/users/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    user = db.query(User).filter(
        User.id == user_id,
        User.organization_id == request_organization_id(request),
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    identity = request.state.identity
    if user.id == identity["sub"]:
        raise HTTPException(status_code=409, detail="You cannot delete your own account.")
    if user.role in {"admin", "owner"} and db.query(User).filter(
        User.organization_id == user.organization_id,
        User.role.in_(["admin", "owner"]),
    ).count() <= 1:
        raise HTTPException(status_code=409, detail="The organization must retain at least one administrator.")
    db.delete(user)
    db.commit()
    return {"message": "User deleted."}


def request_organization_id(request: Request) -> int:
    return int(request.state.identity["organization_id"])


def get_accessible_brand(db: Session, request: Request, brand_id: int) -> Brand:
    brand = db.query(Brand).filter(
        Brand.id == brand_id,
        Brand.organization_id == request_organization_id(request),
    ).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found.")
    return brand


def accessible_brand_ids(db: Session, request: Request) -> List[int]:
    return [
        row[0] for row in db.query(Brand.id).filter(
            Brand.organization_id == request_organization_id(request)
        ).all()
    ]


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "app": APP_TITLE,
        "database": str(DB_PATH),
        "demo_mode": True,
        "runtime": "local",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/api/settings")
def get_settings() -> Dict[str, Any]:
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_status = "disabled"
    if os.getenv("OLLAMA_ENABLED", "").lower() in {"1", "true", "yes"}:
        try:
            with urllib.request.urlopen(f"{ollama_url.rstrip('/')}/api/tags", timeout=0.4) as response:
                ollama_status = "available" if response.status == 200 else "unavailable"
        except (urllib.error.URLError, TimeoutError):
            ollama_status = "unavailable (rule-based fallback active)"
    qr_status = "available" if importlib.util.find_spec("cv2") else "unavailable"
    ocr_status = get_tesseract_status()
    return {
        "ai_runtime": "Local NLP + Fuzzy Matching Engine",
        "gpu_status": "Unavailable (CPU fallback active)",
        "ollama_status": ollama_status,
        "ocr_status": ocr_status,
        "qr_status": qr_status,
        "demo_mode": True,
        "monitoring_window": "Last 30 days",
        "platforms": ["Instagram", "Facebook", "X", "LinkedIn", "Android", "iOS"],
        "modules": [
            "Dashboard",
            "Brand Profiles",
            "Social Monitoring",
            "App Monitoring",
            "Scam DNA",
            "Investigations",
            "Reports",
            "Customer Reporting",
            "Trust Center",
            "Campaign Evolution",
            "Community Report Review",
            "QR Safety",
            "Investigation Copilot",
            "Settings",
        ],
    }


@app.get("/api/brands")
def list_brands(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    brands = db.query(Brand).filter(
        Brand.organization_id == request_organization_id(request)
    ).order_by(Brand.id.desc()).all()
    return [
        {
            "id": brand.id,
            "organization_id": brand.organization_id,
            "name": brand.name,
            "company_description": brand.company_description,
            "industry": brand.industry,
            "official_website": brand.official_website,
            "official_social_accounts": brand.official_social_accounts or [],
            "official_mobile_apps": brand.official_mobile_apps or [],
            "official_package_ids": brand.official_package_ids or [],
            "official_developer_names": brand.official_developer_names or [],
            "brand_keywords": brand.brand_keywords or [],
            "known_domains": brand.known_domains or [],
            "logo_path": brand.logo_path,
            "logo_perceptual_hash": brand.logo_perceptual_hash,
            "additional_identifiers": brand.additional_identifiers or {},
            "is_sample": bool(brand.is_sample),
            "created_at": brand.created_at.isoformat() if brand.created_at else None,
            "updated_at": brand.updated_at.isoformat() if brand.updated_at else None,
        }
        for brand in brands
    ]


@app.get("/api/brands/{brand_id}")
def get_brand(brand_id: int, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    brand = get_accessible_brand(db, request, brand_id)
    return {
        "id": brand.id,
        "organization_id": brand.organization_id,
        "name": brand.name,
        "company_description": brand.company_description,
        "industry": brand.industry,
        "official_website": brand.official_website,
        "official_social_accounts": brand.official_social_accounts or [],
        "official_mobile_apps": brand.official_mobile_apps or [],
        "official_package_ids": brand.official_package_ids or [],
        "official_developer_names": brand.official_developer_names or [],
        "brand_keywords": brand.brand_keywords or [],
        "known_domains": brand.known_domains or [],
        "logo_path": brand.logo_path,
        "logo_perceptual_hash": brand.logo_perceptual_hash,
        "additional_identifiers": brand.additional_identifiers or {},
        "is_sample": bool(brand.is_sample),
    }


@app.get("/api/brands/{brand_id}/trust")
def brand_trust_center(brand_id: int, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    brand = get_accessible_brand(db, request, brand_id)
    official_sources = (
        [{"type": "website", "value": brand.official_website, "owner_configured": True}]
        if brand.official_website else []
    )
    official_sources.extend(
        {"type": "trusted_domain", "value": domain, "owner_configured": True}
        for domain in brand.known_domains or []
    )
    official_sources.extend(
        {"type": "social_account", "value": account, "owner_configured": True}
        for account in brand.official_social_accounts or []
    )
    official_sources.extend(
        {"type": "mobile_app", "value": app_name, "owner_configured": True}
        for app_name in brand.official_mobile_apps or []
    )
    return {
        "brand_id": brand.id,
        "brand_name": brand.name,
        "status": "owner_configured",
        "verification_note": "These official assets are configured by the brand owner; no external ownership verification is performed.",
        "official_assets": official_sources,
        "logo_hash_configured": bool(brand.logo_perceptual_hash),
    }


@app.post("/api/brands")
async def create_brand(
    request: Request,
    name: str = Form(...),
    company_description: str = Form(""),
    industry: str = Form(""),
    official_website: str = Form(""),
    official_social_accounts: str = Form("[]"),
    official_mobile_apps: str = Form("[]"),
    official_package_ids: str = Form("[]"),
    official_developer_names: str = Form("[]"),
    brand_keywords: str = Form("[]"),
    known_domains: str = Form("[]"),
    additional_identifiers: str = Form("{}"),
    logo: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    payload = {
        "name": name,
        "company_description": company_description,
        "industry": industry,
        "official_website": official_website,
        "official_social_accounts": parse_json_form_field(official_social_accounts or "[]", "official_social_accounts", list),
        "official_mobile_apps": parse_json_form_field(official_mobile_apps or "[]", "official_mobile_apps", list),
        "official_package_ids": parse_json_form_field(official_package_ids or "[]", "official_package_ids", list),
        "official_developer_names": parse_json_form_field(official_developer_names or "[]", "official_developer_names", list),
        "brand_keywords": parse_json_form_field(brand_keywords or "[]", "brand_keywords", list),
        "known_domains": parse_json_form_field(known_domains or "[]", "known_domains", list),
        "additional_identifiers": parse_json_form_field(additional_identifiers or "{}", "additional_identifiers", dict),
    }
    payload["name"] = payload["name"].strip()
    if not payload["name"]:
        raise HTTPException(status_code=422, detail="Brand name is required.")

    brand = Brand(**payload, organization_id=request_organization_id(request))
    db.add(brand)
    db.flush()

    if logo and logo.filename:
        upload_info = save_uploaded_logo(logo)
        if not upload_info.get("valid"):
            raise HTTPException(status_code=422, detail=upload_info.get("error", "Invalid logo upload."))
        brand.logo_path = upload_info["path"]
        brand.logo_perceptual_hash = upload_info["hash"]
    db.commit()
    db.refresh(brand)

    return {"id": brand.id, "message": "Brand created successfully", "brand": brand.name}


@app.put("/api/brands/{brand_id}")
async def update_brand(
    brand_id: int,
    request: Request,
    name: str = Form(...),
    company_description: str = Form(""),
    industry: str = Form(""),
    official_website: str = Form(""),
    official_social_accounts: str = Form("[]"),
    official_mobile_apps: str = Form("[]"),
    official_package_ids: str = Form("[]"),
    official_developer_names: str = Form("[]"),
    brand_keywords: str = Form("[]"),
    known_domains: str = Form("[]"),
    additional_identifiers: str = Form("{}"),
    logo: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    brand = get_accessible_brand(db, request, brand_id)

    brand.name = name.strip()
    if not brand.name:
        raise HTTPException(status_code=422, detail="Brand name is required.")
    brand.company_description = company_description
    brand.industry = industry
    brand.official_website = official_website
    brand.official_social_accounts = parse_json_form_field(official_social_accounts or "[]", "official_social_accounts", list)
    brand.official_mobile_apps = parse_json_form_field(official_mobile_apps or "[]", "official_mobile_apps", list)
    brand.official_package_ids = parse_json_form_field(official_package_ids or "[]", "official_package_ids", list)
    brand.official_developer_names = parse_json_form_field(official_developer_names or "[]", "official_developer_names", list)
    brand.brand_keywords = parse_json_form_field(brand_keywords or "[]", "brand_keywords", list)
    brand.known_domains = parse_json_form_field(known_domains or "[]", "known_domains", list)
    brand.additional_identifiers = parse_json_form_field(additional_identifiers or "{}", "additional_identifiers", dict)

    if logo and logo.filename:
        upload_info = save_uploaded_logo(logo)
        if not upload_info.get("valid"):
            raise HTTPException(status_code=422, detail=upload_info.get("error", "Invalid logo upload."))
        brand.logo_path = upload_info["path"]
        brand.logo_perceptual_hash = upload_info["hash"]

    db.add(brand)
    db.commit()
    return {"id": brand.id, "message": "Brand updated successfully"}


@app.delete("/api/brands/{brand_id}")
def delete_brand(brand_id: int, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    brand = get_accessible_brand(db, request, brand_id)
    db.add(AuditLog(brand_id=brand_id, action="Brand deleted", details=f"Removed brand profile: {brand.name}"))
    campaign_ids = [row[0] for row in db.query(Campaign.id).filter(Campaign.brand_id == brand_id).all()]
    report_ids = [row[0] for row in db.query(CustomerReport.id).filter(CustomerReport.brand_id == brand_id).all()]
    entity_ids = [row[0] for row in db.query(Entity.id).filter(Entity.brand_id == brand_id).all()]
    detection_ids = [row[0] for row in db.query(DetectionResult.id).filter(DetectionResult.brand_id == brand_id).all()]
    evidence_ids = [row[0] for row in db.query(Evidence.id).filter(Evidence.detection_id.in_(detection_ids)).all()] if detection_ids else []
    if campaign_ids:
        db.query(CampaignEvent).filter(CampaignEvent.campaign_id.in_(campaign_ids)).delete(synchronize_session=False)
    if report_ids:
        db.query(ReportMatch).filter(ReportMatch.customer_report_id.in_(report_ids)).delete(synchronize_session=False)
    if detection_ids:
        db.query(ReportMatch).filter(ReportMatch.detection_id.in_(detection_ids)).delete(synchronize_session=False)
    if entity_ids:
        db.query(Relationship).filter(
            (Relationship.source_entity_id.in_(entity_ids))
            | (Relationship.target_entity_id.in_(entity_ids))
        ).delete(synchronize_session=False)
    if evidence_ids:
        db.query(Relationship).filter(Relationship.evidence_id.in_(evidence_ids)).delete(synchronize_session=False)
        db.query(Evidence).filter(Evidence.id.in_(evidence_ids)).delete(synchronize_session=False)
    if entity_ids:
        db.query(Entity).filter(Entity.id.in_(entity_ids)).delete(synchronize_session=False)
    db.query(MonitoringSource).filter(MonitoringSource.brand_id == brand_id).delete(synchronize_session=False)
    db.query(Investigation).filter(Investigation.brand_id == brand_id).delete(synchronize_session=False)
    db.query(ReportMetadata).filter(ReportMetadata.brand_id == brand_id).delete(synchronize_session=False)
    db.query(QRAnalysis).filter(QRAnalysis.brand_id == brand_id).delete(synchronize_session=False)
    db.query(DetectionResult).filter(DetectionResult.brand_id == brand_id).delete(synchronize_session=False)
    db.query(CustomerReport).filter(CustomerReport.brand_id == brand_id).delete(synchronize_session=False)
    if campaign_ids:
        db.query(Campaign).filter(Campaign.id.in_(campaign_ids)).delete(synchronize_session=False)
    db.delete(brand)
    db.commit()
    return {"message": "Brand deleted successfully"}


@app.get("/api/detections")
def list_detections(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    detections = db.query(DetectionResult).filter(
        DetectionResult.brand_id.in_(accessible_brand_ids(db, request))
    ).order_by(DetectionResult.id.desc()).all()
    return [
        {
            "id": item.id,
            "brand_id": item.brand_id,
            "entity_name": item.entity_name,
            "entity_type": item.entity_type,
            "platform": item.platform,
            "similarity_score": item.similarity_score,
            "risk_score": item.risk_score,
            "risk_level": item.risk_level,
            "detection_reason": item.detection_reason,
            "status": item.status,
            "evidence": item.evidence or {},
            "detected_at": item.detected_at.isoformat() if item.detected_at else None,
        }
        for item in detections
    ]


@app.get("/api/detections/{detection_id}")
def get_detection(detection_id: int, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    detection = db.query(DetectionResult).filter(
        DetectionResult.id == detection_id,
        DetectionResult.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not detection:
        raise HTTPException(status_code=404, detail="Finding not found.")
    evidence = db.query(Evidence).filter(Evidence.detection_id == detection.id).order_by(Evidence.id.asc()).all()
    return {
        "id": detection.id,
        "brand_id": detection.brand_id,
        "entity_name": detection.entity_name,
        "entity_type": detection.entity_type,
        "platform": detection.platform,
        "similarity_score": detection.similarity_score,
        "risk_score": detection.risk_score,
        "risk_level": detection.risk_level,
        "detection_reason": detection.detection_reason,
        "status": detection.status,
        "evidence": detection.evidence or {},
        "investigation_ids": [
            row[0] for row in db.query(Investigation.id).filter(
                Investigation.brand_id == detection.brand_id,
                Investigation.detection_id == detection.id,
            ).order_by(Investigation.id.asc()).all()
        ],
        "evidence_records": [
            {
                "id": item.id,
                "type": item.evidence_type,
                "value": item.value,
                "confidence": item.confidence,
                "details": item.details or {},
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in evidence
        ],
        "detected_at": detection.detected_at.isoformat() if detection.detected_at else None,
    }


@app.patch("/api/detections/{detection_id}")
def update_detection(
    detection_id: int,
    payload: FindingUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    detection = db.query(DetectionResult).filter(
        DetectionResult.id == detection_id,
        DetectionResult.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not detection:
        raise HTTPException(status_code=404, detail="Finding not found.")
    old_status = detection.status
    detection.status = payload.status
    db.add(AuditLog(
        brand_id=detection.brand_id,
        action="Finding status changed",
        details=f"{detection.entity_name}: {old_status} -> {payload.status}",
    ))
    db.commit()
    return {"id": detection.id, "status": detection.status}


@app.delete("/api/detections/{detection_id}")
def delete_detection(
    detection_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    detection = db.query(DetectionResult).filter(
        DetectionResult.id == detection_id,
        DetectionResult.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not detection:
        raise HTTPException(status_code=404, detail="Finding not found.")

    evidence_ids = [
        row[0] for row in db.query(Evidence.id).filter(Evidence.detection_id == detection.id).all()
    ]
    if evidence_ids:
        db.query(Relationship).filter(Relationship.evidence_id.in_(evidence_ids)).delete(synchronize_session=False)
        db.query(Evidence).filter(Evidence.id.in_(evidence_ids)).delete(synchronize_session=False)
    db.query(ReportMatch).filter(ReportMatch.detection_id == detection.id).delete(synchronize_session=False)
    db.query(CampaignEvent).filter(CampaignEvent.detection_id == detection.id).update(
        {CampaignEvent.detection_id: None},
        synchronize_session=False,
    )
    db.query(Investigation).filter(
        Investigation.brand_id == detection.brand_id,
        Investigation.detection_id == detection.id,
    ).update(
        {Investigation.detection_id: None},
        synchronize_session=False,
    )
    db.add(AuditLog(
        brand_id=detection.brand_id,
        action="Finding deleted",
        details=f"Removed finding {detection.id}: {detection.entity_name}",
    ))
    db.delete(detection)
    db.commit()
    return {"message": "Finding deleted; campaign history was retained without its finding link."}


@app.get("/api/sources")
def list_sources(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    sources = db.query(MonitoringSource).filter(
        MonitoringSource.brand_id.in_(accessible_brand_ids(db, request))
    ).order_by(MonitoringSource.id.desc()).all()
    return [
        {
            "id": source.id,
            "brand_id": source.brand_id,
            "source_type": source.source_type,
            "platform": source.platform,
            "locator": source.locator,
            "enabled": source.enabled,
            "interval_minutes": source.interval_minutes,
            "status": (
                "CONFIGURATION REQUIRED"
                if source.source_type == "threat_feed" and not phishtank_api_key()
                else "DISCONNECTED"
                if source.last_status == "CONFIGURATION REQUIRED" or not source.enabled
                else source.last_status
            ),
            "last_checked_at": source.last_checked_at.isoformat() if source.last_checked_at else None,
            "next_run_at": source.next_run_at.isoformat() if source.next_run_at else None,
            "last_error": source.last_error,
            "created_at": source.created_at.isoformat() if source.created_at else None,
        }
        for source in sources
    ]


@app.post("/api/sources")
def create_source(payload: MonitoringSourcePayload, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    get_accessible_brand(db, request, payload.brand_id)
    if payload.source_type not in {"social_profile", "application", "domain", "threat_feed"}:
        raise HTTPException(status_code=422, detail="Unsupported monitoring source type.")
    if payload.source_type == "threat_feed" and (
        payload.platform != "PhishTank" or payload.locator != "online-valid"
    ):
        raise HTTPException(status_code=422, detail="Threat-feed sources must use the supported PhishTank online-valid feed.")
    if payload.source_type == "threat_feed" and db.query(MonitoringSource.id).filter(
        MonitoringSource.brand_id == payload.brand_id,
        MonitoringSource.source_type == "threat_feed",
        MonitoringSource.platform == "PhishTank",
        MonitoringSource.locator == "online-valid",
    ).first():
        raise HTTPException(status_code=409, detail="PhishTank monitoring is already configured for this brand.")
    source_values = payload.model_dump()
    source_values["last_status"] = "DISCONNECTED" if phishtank_api_key() else "CONFIGURATION REQUIRED"
    source_values["next_run_at"] = datetime.utcnow()
    source = MonitoringSource(**source_values)
    db.add(source)
    db.add(AuditLog(brand_id=payload.brand_id, action="Monitoring source added", details=payload.locator))
    db.commit()
    db.refresh(source)
    return {"id": source.id, "message": "Monitoring source added."}


@app.get("/api/monitoring/status")
def get_monitoring_status(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    sources = db.query(MonitoringSource).filter(
        MonitoringSource.brand_id.in_(accessible_brand_ids(db, request)),
        MonitoringSource.source_type == "threat_feed",
    ).order_by(MonitoringSource.id.desc()).all()
    configured = bool(phishtank_api_key())
    scoped_statuses = [
        source.last_status if source.enabled else "DISCONNECTED"
        for source in sources
    ]
    provider_status = (
        "CONFIGURATION REQUIRED" if not configured
        else "LIVE" if "LIVE" in scoped_statuses
        else "ERROR" if "ERROR" in scoped_statuses
        else "DISCONNECTED"
    )
    return {
        "provider": "PhishTank",
        "status": provider_status,
        "credential_configured": configured,
        "sources": [
            {
                "id": source.id,
                "brand_id": source.brand_id,
                "enabled": source.enabled,
                "interval_minutes": source.interval_minutes,
                "status": (
                    "CONFIGURATION REQUIRED" if not configured
                    else "DISCONNECTED"
                    if source.last_status == "CONFIGURATION REQUIRED" or not source.enabled
                    else source.last_status
                ),
                "last_checked_at": source.last_checked_at.isoformat() if source.last_checked_at else None,
                "next_run_at": source.next_run_at.isoformat() if source.next_run_at else None,
                "last_error": source.last_error,
            }
            for source in sources
        ],
    }


@app.post("/api/monitoring/sources/{source_id}/run")
def run_monitoring_source(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    source = db.query(MonitoringSource).filter(
        MonitoringSource.id == source_id,
        MonitoringSource.brand_id.in_(accessible_brand_ids(db, request)),
        MonitoringSource.source_type == "threat_feed",
    ).first()
    if not source:
        raise HTTPException(status_code=404, detail="Threat-monitoring source not found.")
    if not source.enabled:
        raise HTTPException(status_code=409, detail="This monitoring source is disabled.")
    brand = db.query(Brand).filter(Brand.id == source.brand_id).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found.")
    try:
        return run_phishtank_source(source, brand, db)
    except ThreatFeedError as error:
        record_source_failure(source, db, error)
        status_code = 503 if error.status == "CONFIGURATION REQUIRED" else 502
        raise HTTPException(status_code=status_code, detail=str(error)) from error


@app.delete("/api/sources/{source_id}")
def delete_source(source_id: int, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    source = db.query(MonitoringSource).filter(
        MonitoringSource.id == source_id,
        MonitoringSource.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not source:
        raise HTTPException(status_code=404, detail="Monitoring source not found.")
    db.add(AuditLog(brand_id=source.brand_id, action="Monitoring source removed", details=source.locator))
    db.delete(source)
    db.commit()
    return {"message": "Monitoring source removed."}


@app.patch("/api/sources/{source_id}")
def update_source(
    source_id: int,
    payload: MonitoringSourceUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    source = db.query(MonitoringSource).filter(
        MonitoringSource.id == source_id,
        MonitoringSource.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not source:
        raise HTTPException(status_code=404, detail="Monitoring source not found.")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide a source field to update.")
    if "interval_minutes" in changes and source.source_type != "threat_feed":
        raise HTTPException(status_code=422, detail="Only threat-feed sources support a monitoring interval.")
    normalized_changes = {
        field: value.strip() if isinstance(value, str) else value
        for field, value in changes.items()
    }
    if source.source_type == "threat_feed" and "interval_minutes" in normalized_changes:
        source.next_run_at = datetime.utcnow()
    if len(normalized_changes.get("platform", source.platform)) < 2:
        raise HTTPException(status_code=422, detail="platform must contain at least two non-space characters.")
    if len(normalized_changes.get("locator", source.locator)) < 2:
        raise HTTPException(status_code=422, detail="locator must contain at least two non-space characters.")
    for field, value in normalized_changes.items():
        setattr(source, field, value)
    db.add(AuditLog(
        brand_id=source.brand_id,
        action="Monitoring source updated",
        details=f"Updated source {source.id}: {', '.join(sorted(normalized_changes))}",
    ))
    db.commit()
    return {
        "id": source.id,
        "brand_id": source.brand_id,
        "source_type": source.source_type,
        "platform": source.platform,
        "locator": source.locator,
        "enabled": source.enabled,
        "interval_minutes": source.interval_minutes,
    }


def persist_analysis(brand: Brand, result: Dict[str, Any], db: Session) -> DetectionResult:
    result["brand_id"] = brand.id
    result["status"] = "monitoring" if result["risk_score"] >= 70 else "review"
    detection = DetectionResult(
        brand_id=brand.id,
        entity_name=result["entity_name"],
        entity_type=result["entity_type"],
        platform=result["platform"],
        similarity_score=result["similarity_score"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        detection_reason=result["detection_reason"],
        status=result["status"],
        evidence={"signals": result["evidence"]},
    )
    db.add(detection)
    db.flush()

    canonical_key = result["entity_name"].strip().lower()
    entity = db.query(Entity).filter(
        Entity.brand_id == brand.id,
        Entity.canonical_key == canonical_key,
        Entity.entity_type == result["entity_type"],
    ).first()
    if not entity:
        entity = Entity(
            brand_id=brand.id,
            entity_type=result["entity_type"],
            canonical_key=canonical_key,
            display_name=result["entity_name"],
        )
        db.add(entity)
        db.flush()

    brand_entity = db.query(Entity).filter(
        Entity.brand_id == brand.id,
        Entity.canonical_key == f"brand:{brand.id}",
    ).first()
    if not brand_entity:
        brand_entity = Entity(
            brand_id=brand.id,
            entity_type="brand",
            canonical_key=f"brand:{brand.id}",
            display_name=brand.name,
        )
        db.add(brand_entity)
        db.flush()

    first_evidence_id = None
    for signal in result["evidence"]:
        evidence = Evidence(
            detection_id=detection.id,
            evidence_type=signal["type"],
            value=signal["value"],
            confidence=signal["confidence"],
            details=signal["details"],
        )
        db.add(evidence)
        db.flush()
        if first_evidence_id is None:
            first_evidence_id = evidence.id
    db.add(Relationship(
        source_entity_id=brand_entity.id,
        target_entity_id=entity.id,
        evidence_id=first_evidence_id,
        relation_type="suspected_impersonation",
        confidence=result["risk_score"] / 100,
    ))

    domain_signal = next(
        (signal for signal in result["evidence"] if signal["type"] == "domain_analysis"),
        None,
    )
    indicators: Dict[str, Any] = {
        "platform": result["platform"],
        "entity_name": result["entity_name"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
    }
    campaign_key = ""
    if (
        domain_signal
        and domain_signal.get("details", {}).get("domain")
        and domain_signal.get("details", {}).get("url_risk_category") == "suspicious"
    ):
        domain = domain_signal["details"]["domain"]
        campaign_key = f"domain:{domain}"
        indicators["domain"] = domain
        indicators["supporting_evidence"] = {
            "type": domain_signal["type"],
            "value": domain_signal["value"],
            "confidence": domain_signal["confidence"],
        }

    if campaign_key:
        campaign = db.query(Campaign).filter(
            Campaign.brand_id == brand.id,
            Campaign.campaign_key == campaign_key,
        ).first()
        event_type = "observation"
        if not campaign:
            campaign = Campaign(
                brand_id=brand.id,
                campaign_key=campaign_key,
                title=f"Suspicious-domain activity: {campaign_key.split(':', 1)[1]}",
            )
            db.add(campaign)
            db.flush()
            event_type = "campaign_opened"
        else:
            event_type = "indicator_update"
        db.add(CampaignEvent(
            campaign_id=campaign.id,
            detection_id=detection.id,
            event_type=event_type,
            summary=f"{result['entity_name']} observed on {result['platform']} at risk {result['risk_level']}.",
            indicators=indicators,
        ))

    db.add(AuditLog(brand_id=brand.id, action="Entity analyzed", details=result["entity_name"]))
    return detection


@app.post("/api/analysis/analyze")
def analyze_entity(payload: CandidatePayload, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    brand = get_accessible_brand(db, request, payload.brand_id)
    try:
        result = analyze_candidate(
            {
                "id": brand.id,
                "name": brand.name,
                "official_website": brand.official_website,
                "known_domains": brand.known_domains or [],
                "official_package_ids": brand.official_package_ids or [],
                "official_developer_names": brand.official_developer_names or [],
                "logo_perceptual_hash": brand.logo_perceptual_hash or "",
            },
            payload.model_dump(exclude={"brand_id"}),
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    detection = persist_analysis(brand, result, db)
    db.commit()
    db.refresh(detection)
    result.update({"id": detection.id, "detected_at": detection.detected_at.isoformat()})
    return result


def correlate_customer_report(report: CustomerReport, db: Session) -> List[Dict[str, Any]]:
    if report.brand_id is None:
        return []
    candidates = db.query(DetectionResult).filter(
        DetectionResult.brand_id == report.brand_id
    ).order_by(DetectionResult.id.desc()).all()
    report_text = f"{report.report_text} {report.reported_url}".strip()
    normalized_report_text = normalize_text(report_text)
    report_host = (urlparse(report.reported_url).hostname or "").lower().removeprefix("www.") if report.reported_url else ""
    matches = []
    for finding in candidates:
        signals = (finding.evidence or {}).get("signals", [])
        finding_domains = [
            str(signal.get("details", {}).get("domain", "")).lower().removeprefix("www.")
            for signal in signals
            if signal.get("type") == "domain_analysis"
        ]
        normalized_entity_name = normalize_text(finding.entity_name)
        if report_host and report_host in finding_domains:
            score = 100
            reason = "Reported URL domain matches a saved finding."
        elif normalized_entity_name and normalized_entity_name in normalized_report_text:
            score = 100
            reason = "Report text explicitly mentions the saved finding name."
        else:
            continue
        if score == 100:
            matches.append((finding, score, reason))

    results = []
    for finding, score, reason in matches:
        existing = db.query(ReportMatch).filter(
            ReportMatch.customer_report_id == report.id,
            ReportMatch.detection_id == finding.id,
        ).first()
        if not existing:
            existing = ReportMatch(
                customer_report_id=report.id,
                detection_id=finding.id,
                match_score=score,
                match_reason=reason,
            )
            db.add(existing)
            db.flush()
        results.append({
            "detection_id": finding.id,
            "entity_name": finding.entity_name,
            "match_score": score,
            "match_reason": reason,
        })
    return results


def store_customer_report(
    payload: CustomerReportPayload,
    db: Session,
    screenshot_ocr_status: str = "",
    reporting_organization_id: Optional[int] = None,
) -> Dict[str, Any]:
    normalized_report_text = payload.report_text.strip()
    if len(normalized_report_text) < 5:
        raise HTTPException(status_code=422, detail="Report text must contain at least five non-whitespace characters.")
    if len(normalized_report_text) > 4000:
        raise HTTPException(status_code=422, detail="Report text cannot exceed 4000 characters.")
    if len(payload.reporter_contact.strip()) > 255:
        raise HTTPException(status_code=422, detail="Contact cannot exceed 255 characters.")
    if payload.reported_url:
        try:
            normalized_url = normalize_url(payload.reported_url)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        if not normalized_url:
            raise HTTPException(status_code=422, detail="Reported URL is invalid.")
        payload.reported_url = normalized_url
    report_brand = None
    if payload.brand_id is not None:
        report_brand = db.query(Brand).filter(Brand.id == payload.brand_id).first()
        if not report_brand:
            raise HTTPException(status_code=404, detail="Brand was not found.")
    organization_id = report_brand.organization_id if report_brand else reporting_organization_id
    if organization_id is None:
        raise HTTPException(
            status_code=401,
            detail="Select a related brand or sign in to route this report to your organization.",
        )

    report = CustomerReport(
        brand_id=payload.brand_id,
        organization_id=organization_id,
        reporter_contact=payload.reporter_contact.strip(),
        report_text=payload.report_text.strip(),
        reported_url=payload.reported_url,
        status="pending",
    )
    db.add(report)
    db.flush()
    matches = correlate_customer_report(report, db)

    duplicate = None
    previous_query = db.query(CustomerReport).filter(CustomerReport.id != report.id)
    if payload.brand_id is not None:
        previous_query = previous_query.filter(CustomerReport.brand_id == payload.brand_id)
    else:
        previous_query = previous_query.filter(
            CustomerReport.brand_id.is_(None),
            CustomerReport.organization_id == organization_id,
        )
    previous_reports = previous_query.order_by(CustomerReport.id.desc()).all()
    for previous in previous_reports:
        previous_content = f"{previous.report_text} {previous.reported_url}".strip()
        similarity = fuzz.token_set_ratio(
            f"{report.report_text} {report.reported_url}".strip(),
            previous_content,
        )
        if report.reported_url and report.reported_url == previous.reported_url:
            similarity = 100
        if similarity >= 82:
            duplicate = {"report_id": previous.id, "similarity": similarity}
            break
    if duplicate:
        report.status = "duplicate"

    if report.brand_id and report.reported_url:
        report_host = report.reported_url.split("/")[2].split(":")[0]
        campaign_key = f"domain:{report_host}"
        campaign = db.query(Campaign).filter(
            Campaign.brand_id == report.brand_id,
            Campaign.campaign_key == campaign_key,
        ).first()
        if campaign:
            db.add(CampaignEvent(
                campaign_id=campaign.id,
                event_type="community_report",
                summary=f"Community report {report.id} submitted with a matching campaign domain.",
                indicators={"domain": report_host, "report_id": report.id, "matched_findings": len(matches)},
            ))

    db.commit()
    response = {
        "report_id": report.id,
        "status": report.status,
        "related_findings": matches,
        "duplicate_of": duplicate,
        "message": "Thank you. Your report was received for analyst review.",
    }
    if screenshot_ocr_status:
        response["ocr_status"] = screenshot_ocr_status
    return response


def customer_report_receipt(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: result[key]
        for key in ("report_id", "status", "message", "ocr_status", "ocr_message")
        if key in result
    }


def validate_customer_report_brand_access(
    brand_id: Optional[int],
    identity: Optional[Dict[str, Any]],
    db: Session,
) -> Optional[Brand]:
    if brand_id is None:
        return None
    brand = db.query(Brand).filter(Brand.id == brand_id).first()
    if not brand or (
        identity is not None and brand.organization_id != identity["organization_id"]
    ):
        raise HTTPException(status_code=404, detail="Brand not found.")
    return brand


@app.post("/api/customer/reports")
def submit_customer_report(
    payload: CustomerReportPayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    identity = getattr(request.state, "identity", None)
    validate_customer_report_brand_access(payload.brand_id, identity, db)
    organization_id = identity["organization_id"] if identity else None
    return customer_report_receipt(
        store_customer_report(payload, db, reporting_organization_id=organization_id)
    )


@app.post("/api/customer/reports/screenshot")
async def submit_customer_screenshot(
    request: Request,
    report_text: str = Form(""),
    reported_url: str = Form(""),
    reporter_contact: str = Form(""),
    brand_id: Optional[int] = Form(None),
    screenshot: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    if screenshot.size and screenshot.size > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Screenshot exceeds the 5MB upload limit.")
    if len(report_text) > 4000 or len(reported_url) > 2048 or len(reporter_contact) > 255:
        raise HTTPException(status_code=422, detail="Report text, URL, or contact exceeds the allowed length.")
    try:
        extracted = extract_screenshot_text(screenshot)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    combined_text = "\n".join(part for part in [report_text.strip(), extracted["text"]] if part)
    if len(combined_text) > 4000:
        raise HTTPException(status_code=422, detail="Combined report and extracted screenshot text cannot exceed 4000 characters.")
    extracted_urls = URL_PATTERN.findall(extracted["text"])
    valid_extracted_urls = [url for url in extracted_urls if normalize_url(url)]
    chosen_url = reported_url.strip() or (valid_extracted_urls[0] if valid_extracted_urls else "")
    if len(combined_text.strip()) < 5 and not chosen_url:
        raise HTTPException(status_code=422, detail=extracted["message"])
    payload = CustomerReportPayload(
        brand_id=brand_id,
        reporter_contact=reporter_contact,
        report_text=combined_text.strip() or "Screenshot submitted for analyst review.",
        reported_url=chosen_url,
    )
    identity = getattr(request.state, "identity", None)
    brand = validate_customer_report_brand_access(brand_id, identity, db)
    organization_id = identity["organization_id"] if identity else None
    result = store_customer_report(
        payload,
        db,
        extracted["ocr_status"],
        reporting_organization_id=organization_id,
    )
    # Public reporters may select a brand, but its private configuration is not
    # returned to anonymous callers.
    analysis_brand = brand if identity is not None else None
    analysis_url = normalize_url(chosen_url) if chosen_url else ""
    analysis = analyze_candidate(
        {
            "name": analysis_brand.name if analysis_brand else "",
            "known_domains": analysis_brand.known_domains or [] if analysis_brand else [],
            "official_website": analysis_brand.official_website or "" if analysis_brand else "",
            "official_package_ids": analysis_brand.official_package_ids or [] if analysis_brand else [],
            "official_developer_names": analysis_brand.official_developer_names or [] if analysis_brand else [],
            "logo_perceptual_hash": analysis_brand.logo_perceptual_hash or "" if analysis_brand else "",
        },
        {"name": "", "description": combined_text, "url": analysis_url},
    )
    return {
        **customer_report_receipt({**result, "ocr_message": extracted["message"]}),
        "extracted_text": extracted["text"],
        "extracted_urls": extracted_urls[:10],
        "analysis": analysis,
    }


@app.get("/api/community/reports")
def list_community_reports(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    organization_id = request_organization_id(request)
    reports = db.query(CustomerReport).filter(
        CustomerReport.organization_id == organization_id
    ).order_by(CustomerReport.id.desc()).all()
    result = []
    for report in reports:
        matches = db.query(ReportMatch).filter(ReportMatch.customer_report_id == report.id).all()
        result.append({
            "id": report.id,
            "brand_id": report.brand_id,
            "reporter_contact": report.reporter_contact,
            "report_text": report.report_text,
            "reported_url": report.reported_url,
            "status": report.status,
            "created_at": report.created_at.isoformat() if report.created_at else None,
            "matches": [
                {
                    "detection_id": match.detection_id,
                    "score": match.match_score,
                    "reason": match.match_reason,
                    "analyst_verified": match.analyst_verified,
                }
                for match in matches
            ],
        })
    return result


@app.patch("/api/community/reports/{report_id}")
def review_community_report(
    report_id: int,
    payload: CommunityReviewPayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    report = db.query(CustomerReport).filter(
        CustomerReport.id == report_id,
        CustomerReport.organization_id == request_organization_id(request),
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Community report not found.")
    report.status = payload.status
    for match in db.query(ReportMatch).filter(ReportMatch.customer_report_id == report.id).all():
        match.analyst_verified = payload.analyst_verified
    if report.brand_id:
        db.add(AuditLog(
            brand_id=report.brand_id,
            action="Community report reviewed",
            details=f"Report {report.id}: {payload.status}",
        ))
    db.commit()
    return {"message": "Community report review saved."}


@app.post("/api/ingestion/csv")
async def ingest_csv(
    request: Request,
    brand_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    brand = get_accessible_brand(db, request, brand_id)
    if file.size and file.size > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV exceeds the 2MB import limit.")
    if Path(file.filename or "").suffix.lower() != ".csv":
        raise HTTPException(status_code=415, detail="Upload a .csv file.")
    contents = await file.read()
    try:
        rows = parse_findings_csv(contents)
        results = []
        for row in rows:
            analysis = analyze_candidate(
                {
                    "id": brand.id,
                    "name": brand.name,
                    "official_website": brand.official_website,
                    "known_domains": brand.known_domains or [],
                    "official_package_ids": brand.official_package_ids or [],
                    "official_developer_names": brand.official_developer_names or [],
                    "logo_perceptual_hash": brand.logo_perceptual_hash or "",
                },
                row,
            )
            persist_analysis(brand, analysis, db)
            results.append({"name": row["name"], "risk_score": analysis["risk_score"], "risk_level": analysis["risk_level"]})
        db.add(AuditLog(brand_id=brand.id, action="CSV findings imported", details=f"Imported {len(results)} candidate records."))
        db.commit()
    except ValueError as error:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {"imported": len(results), "results": results}


@app.post("/api/ingestion/screenshot/analyze")
async def analyze_screenshot(
    request: Request,
    brand_id: int = Form(...),
    screenshot: UploadFile = File(...),
    notes: str = Form(""),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    brand = get_accessible_brand(db, request, brand_id)
    if screenshot.size and screenshot.size > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Screenshot exceeds the 5MB upload limit.")
    try:
        extracted = extract_screenshot_text(screenshot)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    extracted_text = extracted["text"]
    urls = URL_PATTERN.findall(extracted_text)
    text_for_report = "\n".join(part for part in [notes.strip(), extracted_text] if part)
    if len(text_for_report) < 5:
        raise HTTPException(status_code=422, detail=extracted["message"])
    report = store_customer_report(
        CustomerReportPayload(
            brand_id=brand.id,
            report_text=text_for_report[:4000],
            reported_url=urls[0] if urls else "",
        ),
        db,
        extracted["ocr_status"],
    )
    analysis = analyze_candidate(
        {
            "name": brand.name,
            "known_domains": brand.known_domains or [],
            "official_website": brand.official_website,
            "official_package_ids": brand.official_package_ids or [],
            "official_developer_names": brand.official_developer_names or [],
            "logo_perceptual_hash": brand.logo_perceptual_hash or "",
        },
        {
            "name": "",
            "description": text_for_report,
            "url": next((normalized for url in urls if (normalized := normalize_url(url))), ""),
        },
    )
    return {
        **report,
        "ocr_message": extracted["message"],
        "extracted_text": extracted_text[:2000],
        "extracted_urls": urls[:10],
        "analysis": analysis,
    }


@app.post("/api/qr/analyze")
async def analyze_qr(
    request: Request,
    image: UploadFile = File(...),
    brand_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    if image.size and image.size > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="QR image exceeds the 5MB upload limit.")
    brand = get_accessible_brand(db, request, brand_id) if brand_id is not None else None
    try:
        decoded = decode_qr_image(image)
        url = normalize_url(decoded["value"])
        if not url:
            looks_like_url = bool(re.match(r"^(?:https?://|www\.)", decoded["value"].strip(), re.IGNORECASE))
            category = "malformed_url" if looks_like_url else "non_url"
            explanation = (
                "The QR code contains URL-like content that is malformed. It was not opened or fetched."
                if looks_like_url else
                "The QR code contains non-URL text. No web safety assessment was performed and the content was not opened."
            )
            return {
                "id": None,
                "decoded_content": decoded["value"],
                "decoded_url": "",
                "content_type": category,
                "risk_score": 0,
                "risk_level": "low",
                "risk_category": "inconclusive",
                "indicators": [{
                    "code": category,
                    "severity": "low",
                    "message": explanation,
                }],
                "explanation": explanation,
                "opened": False,
                "stored": False,
                "safe_next_steps": [
                    "Do not open unexpected QR content.",
                    "If you expected a link, confirm it with the sender through a trusted channel.",
                ],
            }
        assessment = assess_url_safety(
            url,
            brand.name if brand else "",
            brand.known_domains or [] if brand else [],
        )
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    record = QRAnalysis(
        brand_id=brand.id if brand else None,
        source_name=(image.filename or "qr-upload")[:255],
        decoded_url=assessment["normalized_url"],
        risk_score=assessment["risk_score"],
        risk_level=assessment["risk_level"],
        indicators=assessment["indicators"],
    )
    db.add(record)
    if brand:
        db.add(AuditLog(brand_id=brand.id, action="QR code analyzed", details=assessment["host"]))
    db.commit()
    return {
        "id": record.id,
        "decoded_content": decoded["value"],
        "decoded_url": record.decoded_url,
        "content_type": "url",
        "host": assessment["host"],
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "risk_category": assessment["risk_category"],
        "indicators": record.indicators,
        "explanation": assessment["explanation"],
        "opened": False,
        "stored": True,
        "safe_next_steps": [
            "Do not open the link from the QR result.",
            "Verify the domain through the brand's official website or support channel.",
            "Report suspicious QR codes to the brand security team.",
        ],
    }


@app.get("/api/qr/history")
def list_qr_analyses(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    records = db.query(QRAnalysis).filter(
        QRAnalysis.brand_id.in_(accessible_brand_ids(db, request))
    ).order_by(QRAnalysis.id.desc()).limit(50).all()
    return [
        {
            "id": item.id,
            "source_name": item.source_name,
            "decoded_url": item.decoded_url,
            "risk_score": item.risk_score,
            "risk_level": item.risk_level,
            "risk_category": "suspicious" if item.risk_score >= 35 else "inconclusive" if item.risk_score >= 15 else "lower_risk",
            "indicators": item.indicators or [],
            "explanation": (
                "Heuristic indicators warrant caution: " + " ".join(
                    indicator.get("message", "")
                    for indicator in (item.indicators or [])
                    if indicator.get("message")
                )
                if item.risk_score >= 35 else
                "No meaningful URL risk indicators were found. This heuristic result does not guarantee the link is safe."
            ),
            "created_at": item.created_at.isoformat() if item.created_at else None,
        }
        for item in records
    ]


@app.get("/api/campaigns")
def list_campaigns(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    scoped_brand_ids = accessible_brand_ids(db, request)
    campaigns = db.query(Campaign).filter(
        Campaign.brand_id.in_(scoped_brand_ids),
        Campaign.campaign_key.like("domain:%"),
    ).order_by(Campaign.updated_at.desc(), Campaign.id.desc()).all()
    campaign_ids = [campaign.id for campaign in campaigns]
    events_by_campaign: Dict[int, List[CampaignEvent]] = {}
    if campaign_ids:
        events = db.query(CampaignEvent).filter(
            CampaignEvent.campaign_id.in_(campaign_ids)
        ).order_by(CampaignEvent.created_at.asc(), CampaignEvent.id.asc()).all()
        for event in events:
            events_by_campaign.setdefault(event.campaign_id, []).append(event)
    detection_ids = {
        event.detection_id
        for campaign_events in events_by_campaign.values()
        for event in campaign_events
        if event.detection_id is not None
    }
    detections_by_id = {}
    if detection_ids:
        detections_by_id = {
            detection.id: detection
            for detection in db.query(DetectionResult).filter(
                DetectionResult.id.in_(detection_ids),
                DetectionResult.brand_id.in_(scoped_brand_ids),
            ).all()
        }
    result = []
    for campaign in campaigns:
        events = events_by_campaign.get(campaign.id, [])
        linked_detections = []
        campaign_events = []
        for event in events:
            detection = detections_by_id.get(event.detection_id) if event.detection_id is not None else None
            if event.detection_id is not None and (
                detection is None or detection.brand_id != campaign.brand_id
            ):
                continue
            if detection:
                linked_detections.append(detection)
            campaign_events.append({
                "id": event.id,
                "detection_id": detection.id if detection else None,
                "event_type": event.event_type,
                "summary": event.summary,
                "indicators": event.indicators or {},
                "risk_level": detection.risk_level if detection else None,
                "risk_score": detection.risk_score if detection else None,
                "finding_status": detection.status if detection else None,
                "finding_available": detection is not None,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            })
        result.append({
            "id": campaign.id,
            "brand_id": campaign.brand_id,
            "title": campaign.title,
            "campaign_key": campaign.campaign_key,
            "status": campaign.status,
            "updated_at": campaign.updated_at.isoformat() if campaign.updated_at else None,
            "event_count": len(campaign_events),
            "linked_finding_count": len({detection.id for detection in linked_detections}),
            "risk_summary": {
                level: sum(1 for detection in linked_detections if detection.risk_level == level)
                for level in ("critical", "high", "medium", "low")
            },
            "events": campaign_events,
        })
    return result


@app.get("/api/investigations/{investigation_id}/copilot")
def investigation_copilot(
    investigation_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    findings = db.query(DetectionResult).filter(
        DetectionResult.brand_id == investigation.brand_id,
        DetectionResult.risk_level.in_(["critical", "high"]),
    ).order_by(DetectionResult.risk_score.desc()).limit(5).all()
    suggested_steps = [
        "Preserve the submitted URLs, account identifiers, timestamps, and screenshots as evidence.",
        "Verify suspected impersonation indicators against the brand's approved domains and official accounts.",
        "Escalate high-confidence cases through the relevant platform's official abuse-reporting process.",
        "Notify affected customers through verified brand channels; do not contact suspects using links in the report.",
        "Record analyst decisions and update the investigation status after evidence review.",
    ]
    if any("domain" in finding.detection_reason.lower() for finding in findings):
        suggested_steps.insert(1, "Compare registered and redirect domains using an approved internal or authorized source; this app will not open suspect URLs.")
    return {
        "investigation_id": investigation.id,
        "mode": "local_rules",
        "disclaimer": "Guidance is generated from local rules and stored evidence, not a remote LLM or legal conclusion.",
        "summary": investigation.summary,
        "related_findings": [
            {"id": finding.id, "entity_name": finding.entity_name, "risk_level": finding.risk_level, "risk_score": finding.risk_score}
            for finding in findings
        ],
        "suggested_steps": suggested_steps,
    }


@app.get("/api/scam-dna/graph")
def scam_dna_graph(request: Request, brand_id: Optional[int] = None, db: Session = Depends(get_db)) -> Dict[str, Any]:
    graph = nx.Graph()
    scoped_brand_ids = accessible_brand_ids(db, request)
    brands = db.query(Brand).filter(Brand.id.in_(scoped_brand_ids)).all()
    detections_query = db.query(DetectionResult).filter(DetectionResult.brand_id.in_(scoped_brand_ids))
    if brand_id is not None:
        if brand_id not in scoped_brand_ids:
            raise HTTPException(status_code=404, detail="Brand not found.")
        detections_query = detections_query.filter(DetectionResult.brand_id == brand_id)
        brands = [brand for brand in brands if brand.id == brand_id]
    detections = detections_query.order_by(DetectionResult.id.desc()).all()

    for brand in brands:
        graph.add_node(
            f"brand:{brand.id}",
            label=brand.name,
            kind="brand",
            risk="official",
            brand_id=brand.id,
            official_website=brand.official_website,
        )
    evidence_records: Dict[int, List[Evidence]] = {}
    if detections:
        for record in db.query(Evidence).filter(Evidence.detection_id.in_([item.id for item in detections])).all():
            evidence_records.setdefault(record.detection_id, []).append(record)
    entities = db.query(Entity).filter(Entity.brand_id.in_(scoped_brand_ids)).all()
    entities_by_key = {
        (entity.brand_id, entity.canonical_key, entity.entity_type): entity
        for entity in entities
    }
    detections_by_id = {item.id: item for item in detections}
    for item in detections:
        node_id = f"finding:{item.id}"
        graph.add_node(
            node_id,
            label=item.entity_name,
            kind=item.entity_type,
            risk=item.risk_level,
            risk_score=item.risk_score,
            platform=item.platform,
            status=item.status,
            detection_reason=item.detection_reason,
            detected_at=item.detected_at.isoformat() if item.detected_at else None,
            brand_id=item.brand_id,
        )
        brand_node = f"brand:{item.brand_id}"
        if brand_node in graph:
            graph.add_edge(brand_node, node_id, relation="candidate_for")
        linked_entity = entities_by_key.get(
            (item.brand_id, item.entity_name.strip().lower(), item.entity_type)
        )
        if linked_entity:
            entity_node = f"entity:{linked_entity.id}"
            graph.add_node(
                entity_node,
                label=linked_entity.display_name,
                kind=linked_entity.entity_type,
                canonical_key=linked_entity.canonical_key,
                brand_id=linked_entity.brand_id,
            )
            graph.add_edge(node_id, entity_node, relation="identifies")

        persisted_items = evidence_records.get(item.id, [])
        if persisted_items:
            for persisted in persisted_items:
                evidence_id = f"evidence:{persisted.id}"
                graph.add_node(
                    evidence_id,
                    label=persisted.evidence_type,
                    kind="evidence",
                    value=persisted.value,
                    confidence=persisted.confidence,
                    details=persisted.details or {},
                    brand_id=item.brand_id,
                )
                graph.add_edge(node_id, evidence_id, relation="supported_by", confidence=persisted.confidence / 100)
        else:
            legacy = item.evidence or {}
            token = legacy.get("shared_token") if isinstance(legacy, dict) else None
            if token:
                evidence_id = f"evidence:legacy:{item.id}"
                graph.add_node(evidence_id, label="shared_token", kind="evidence", value=token)
                graph.add_edge(node_id, evidence_id, relation="supported_by")

    # Entity-to-entity links are emitted only when persisted evidence identifies the relation.
    target_entity = aliased(Entity)
    relationships = db.query(Relationship, Entity, target_entity).join(
        Entity, Relationship.source_entity_id == Entity.id
    ).join(
        target_entity, Relationship.target_entity_id == target_entity.id
    ).filter(
        Entity.brand_id.in_(scoped_brand_ids),
        Entity.brand_id == target_entity.brand_id,
    )
    if brand_id is not None:
        relationships = relationships.filter(Entity.brand_id == brand_id)
    for relation, source, target in relationships.all():
        source_id = f"entity:{source.id}"
        target_id = f"entity:{target.id}"
        graph.add_node(
            source_id,
            label=source.display_name,
            kind=source.entity_type,
            canonical_key=source.canonical_key,
            brand_id=source.brand_id,
        )
        graph.add_node(
            target_id,
            label=target.display_name,
            kind=target.entity_type,
            canonical_key=target.canonical_key,
            brand_id=target.brand_id,
        )
        graph.add_edge(
            source_id,
            target_id,
            relation=relation.relation_type,
            confidence=relation.confidence,
            evidence_id=relation.evidence_id,
        )

    community_reports_query = db.query(CustomerReport).filter(
        CustomerReport.brand_id.in_(scoped_brand_ids)
    )
    if brand_id is not None:
        community_reports_query = community_reports_query.filter(CustomerReport.brand_id == brand_id)
    community_reports = community_reports_query.all()
    reports_by_id = {report.id: report for report in community_reports}
    report_matches = []
    if reports_by_id:
        report_matches = db.query(ReportMatch, DetectionResult).join(
            DetectionResult, ReportMatch.detection_id == DetectionResult.id
        ).filter(
            ReportMatch.customer_report_id.in_(reports_by_id),
            DetectionResult.brand_id.in_(scoped_brand_ids),
        ).all()
    for report in community_reports:
        report_node = f"community-report:{report.id}"
        graph.add_node(
            report_node,
            label=f"Community report #{report.id}",
            kind="community_report",
            status=report.status,
            reported_url=report.reported_url,
            report_text=report.report_text,
            brand_id=report.brand_id,
        )
    for match, finding in report_matches:
        report = reports_by_id[match.customer_report_id]
        if report.brand_id != finding.brand_id:
            continue
        graph.add_edge(
            f"community-report:{report.id}",
            f"finding:{finding.id}",
            relation="community_match",
            confidence=match.match_score / 100,
            analyst_verified=match.analyst_verified,
        )

    scoped_campaigns = db.query(Campaign).filter(Campaign.brand_id.in_(scoped_brand_ids))
    if brand_id is not None:
        scoped_campaigns = scoped_campaigns.filter(Campaign.brand_id == brand_id)
    campaigns = scoped_campaigns.all()
    campaign_ids = [campaign.id for campaign in campaigns]
    events_by_campaign: Dict[int, List[CampaignEvent]] = {}
    if campaign_ids:
        for event in db.query(CampaignEvent).filter(
            CampaignEvent.campaign_id.in_(campaign_ids)
        ).all():
            events_by_campaign.setdefault(event.campaign_id, []).append(event)
    for campaign in campaigns:
        campaign_node = f"campaign:{campaign.id}"
        graph.add_node(
            campaign_node,
            label=campaign.title,
            kind="campaign",
            status=campaign.status,
            campaign_key=campaign.campaign_key,
            brand_id=campaign.brand_id,
        )
        brand_node = f"brand:{campaign.brand_id}"
        if brand_node in graph:
            graph.add_edge(brand_node, campaign_node, relation="tracks_campaign")
        for event in events_by_campaign.get(campaign.id, []):
            event_finding = detections_by_id.get(event.detection_id)
            if event_finding and event_finding.brand_id == campaign.brand_id:
                graph.add_edge(
                    campaign_node,
                    f"finding:{event.detection_id}",
                    relation=event.event_type,
                    event_id=event.id,
                    summary=event.summary,
                )
            report_id = (event.indicators or {}).get("report_id")
            report_node = f"community-report:{report_id}" if report_id else ""
            report = reports_by_id.get(report_id) if isinstance(report_id, int) else None
            if report and report.brand_id == campaign.brand_id and report_node in graph:
                graph.add_edge(campaign_node, report_node, relation="reported_in_campaign")

    qr_records = db.query(QRAnalysis).filter(
        QRAnalysis.brand_id.in_(scoped_brand_ids)
    )
    if brand_id is not None:
        qr_records = qr_records.filter(QRAnalysis.brand_id == brand_id)
    for qr_record in qr_records.all():
        qr_node = f"qr-analysis:{qr_record.id}"
        graph.add_node(
            qr_node,
            label=f"QR check: {urlparse(qr_record.decoded_url).hostname or 'non-domain link'}",
            kind="qr_analysis",
            risk=qr_record.risk_level,
            risk_score=qr_record.risk_score,
            decoded_url=qr_record.decoded_url,
            indicators=qr_record.indicators or [],
            created_at=qr_record.created_at.isoformat() if qr_record.created_at else None,
            brand_id=qr_record.brand_id,
        )
        if qr_record.brand_id and f"brand:{qr_record.brand_id}" in graph:
            graph.add_edge(
                f"brand:{qr_record.brand_id}",
                qr_node,
                relation="qr_safety_check",
            )

    return {
        "nodes": [{"id": node_id, **attributes} for node_id, attributes in graph.nodes(data=True)],
        "edges": [{"source": source, "target": target, **attributes} for source, target, attributes in graph.edges(data=True)],
    }


@app.get("/api/investigations")
def list_investigations(request: Request, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    investigations = db.query(Investigation).filter(
        Investigation.brand_id.in_(accessible_brand_ids(db, request))
    ).order_by(Investigation.id.desc()).all()
    return [
        {
            "id": investigation.id,
            "brand_id": investigation.brand_id,
            "detection_id": investigation.detection_id,
            "title": investigation.title,
            "summary": investigation.summary,
            "status": investigation.status,
            "risk_level": investigation.risk_level,
            "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
        }
        for investigation in investigations
    ]


@app.get("/api/investigations/{investigation_id}")
def get_investigation(
    investigation_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {
        "id": investigation.id,
        "brand_id": investigation.brand_id,
        "detection_id": investigation.detection_id,
        "title": investigation.title,
        "summary": investigation.summary,
        "status": investigation.status,
        "risk_level": investigation.risk_level,
        "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
    }


@app.post("/api/investigations")
def create_investigation(payload: InvestigationPayload, request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    get_accessible_brand(db, request, payload.brand_id)
    title = payload.title.strip()
    if len(title) < 3:
        raise HTTPException(status_code=422, detail="Investigation title must contain at least three non-whitespace characters.")
    if payload.detection_id and not db.query(DetectionResult).filter(
        DetectionResult.id == payload.detection_id,
        DetectionResult.brand_id == payload.brand_id,
    ).first():
        raise HTTPException(status_code=404, detail="Finding not found for this brand.")
    investigation = Investigation(
        brand_id=payload.brand_id,
        detection_id=payload.detection_id,
        title=title,
        summary=payload.summary.strip(),
        risk_level=payload.risk_level,
        status="open",
    )
    db.add(investigation)
    db.add(AuditLog(brand_id=payload.brand_id, action="Investigation created", details=title))
    db.commit()
    db.refresh(investigation)
    return get_investigation(investigation.id, request, db)


@app.put("/api/investigations/{investigation_id}")
def replace_investigation(
    investigation_id: int,
    payload: InvestigationUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide at least one investigation field to update.")
    if "detection_id" in changes and changes["detection_id"] is not None and not db.query(DetectionResult).filter(
        DetectionResult.id == changes["detection_id"],
        DetectionResult.brand_id == investigation.brand_id,
    ).first():
        raise HTTPException(status_code=404, detail="Finding not found for this brand.")
    for field, value in changes.items():
        if field == "detection_id" or value is not None:
            setattr(investigation, field, value.strip() if isinstance(value, str) and field in {"title", "summary"} else value)
    if not investigation.title.strip():
        raise HTTPException(status_code=422, detail="Investigation title cannot be blank.")
    db.add(AuditLog(
        brand_id=investigation.brand_id,
        action="Investigation updated",
        details=f"Updated investigation {investigation.id}: {', '.join(sorted(changes))}",
    ))
    db.commit()
    return get_investigation(investigation.id, request, db)


@app.patch("/api/investigations/{investigation_id}")
def update_investigation(investigation_id: int, request: Request, status: str = Form(...), db: Session = Depends(get_db)) -> Dict[str, Any]:
    if status not in {"open", "investigating", "resolved", "closed"}:
        raise HTTPException(status_code=422, detail="Unsupported investigation status.")
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    investigation.status = status
    db.add(AuditLog(brand_id=investigation.brand_id, action="Investigation status changed", details=f"{investigation.title}: {status}"))
    db.commit()
    return get_investigation(investigation.id, request, db)


@app.delete("/api/investigations/{investigation_id}")
def delete_investigation(
    investigation_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.brand_id.in_(accessible_brand_ids(db, request)),
    ).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    db.add(AuditLog(
        brand_id=investigation.brand_id,
        action="Investigation deleted",
        details=f"Removed investigation {investigation.id}: {investigation.title}",
    ))
    db.delete(investigation)
    db.commit()
    return {"message": "Investigation deleted."}


@app.get("/api/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scoped_brand_ids = accessible_brand_ids(db, request)
    scoped_brands = db.query(Brand).filter(Brand.id.in_(scoped_brand_ids)).all()
    brands_count = len(scoped_brands)
    scoped_detections = db.query(DetectionResult).filter(DetectionResult.brand_id.in_(scoped_brand_ids))
    detection_count = scoped_detections.count()
    critical_count = scoped_detections.filter(DetectionResult.risk_level == "critical").count()
    social_count = scoped_detections.filter(DetectionResult.entity_type == "social_profile").count()
    app_count = scoped_detections.filter(DetectionResult.entity_type == "application").count()
    official_assets = sum(
        len(brand.official_mobile_apps or []) + len(brand.official_social_accounts or [])
        for brand in scoped_brands
    )

    detections = list_detections(request, db)
    month_keys = []
    now = datetime.utcnow()
    for offset in range(5, -1, -1):
        year = now.year
        month = now.month - offset
        while month <= 0:
            month += 12
            year -= 1
        month_keys.append((year, month))
    month_counts = {key: 0 for key in month_keys}
    by_platform = {}
    by_risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item, record in zip(
        detections,
        scoped_detections.order_by(DetectionResult.id.desc()).all(),
    ):
        by_platform[item["platform"]] = by_platform.get(item["platform"], 0) + 1
        by_risk[item["risk_level"]] = by_risk.get(item["risk_level"], 0) + 1
        if record.detected_at:
            key = (record.detected_at.year, record.detected_at.month)
            if key in month_counts:
                month_counts[key] += 1

    return {
        "summary": {
            "total_brands": brands_count,
            "social_profiles_analyzed": social_count,
            "applications_analyzed": app_count,
            "potential_impersonations": detection_count,
            "critical_risk_findings": critical_count,
            "official_assets_protected": official_assets,
        },
        "platform_distribution": by_platform,
        "risk_distribution": by_risk,
        "detections": detections[:8],
        "findings_by_month": [
            {"name": datetime(year, month, 1).strftime("%b"), "value": month_counts[(year, month)]}
            for year, month in month_keys
        ],
    }


@app.post("/api/run-demo-scan")
def run_demo_scan(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    brands = db.query(Brand).filter(Brand.id.in_(accessible_brand_ids(db, request))).all()
    if not brands:
        raise HTTPException(status_code=404, detail="No brands available in the demo database.")

    for brand in brands:
        rows = build_demo_scans({**brand.__dict__, "id": brand.id})
        prior_detection_ids = [
            row[0] for row in db.query(DetectionResult.id).filter(DetectionResult.brand_id == brand.id).all()
        ]
        prior_entity_ids = [
            row[0] for row in db.query(Entity.id).filter(Entity.brand_id == brand.id).all()
        ]
        if prior_entity_ids:
            db.query(Relationship).filter(
                (Relationship.source_entity_id.in_(prior_entity_ids))
                | (Relationship.target_entity_id.in_(prior_entity_ids))
            ).delete(synchronize_session=False)
        if prior_detection_ids:
            db.query(ReportMatch).filter(
                ReportMatch.detection_id.in_(prior_detection_ids)
            ).delete(synchronize_session=False)
            db.query(CampaignEvent).filter(
                CampaignEvent.detection_id.in_(prior_detection_ids)
            ).update(
                {CampaignEvent.detection_id: None},
                synchronize_session=False,
            )
            evidence_ids = [
                row[0] for row in db.query(Evidence.id).filter(Evidence.detection_id.in_(prior_detection_ids)).all()
            ]
            if evidence_ids:
                db.query(Relationship).filter(Relationship.evidence_id.in_(evidence_ids)).delete(synchronize_session=False)
                db.query(Evidence).filter(Evidence.id.in_(evidence_ids)).delete(synchronize_session=False)
        if prior_entity_ids:
            db.query(Entity).filter(Entity.id.in_(prior_entity_ids)).delete(synchronize_session=False)
        db.query(DetectionResult).filter(DetectionResult.brand_id == brand.id).delete()
        db.add_all(
            [
                DetectionResult(
                    brand_id=brand.id,
                    entity_name=row["entity_name"],
                    entity_type=row["entity_type"],
                    platform=row["platform"],
                    similarity_score=row["similarity_score"],
                    risk_score=row["risk_score"],
                    risk_level=row["risk_level"],
                    detection_reason=row["detection_reason"],
                    status=row["status"],
                    evidence=row["evidence"],
                    detected_at=datetime.utcnow(),
                )
                for row in rows
            ]
        )
        db.add(
            AuditLog(
                brand_id=brand.id,
                action="Run demo scan",
                details=f"Re-ran the local AI detection engine for {brand.name}.",
            )
        )
    db.commit()

    return {"message": "Demo scan completed successfully", "brand_count": len(brands)}


@app.get("/api/reports")
def reports(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    detections = db.query(DetectionResult).filter(
        DetectionResult.brand_id.in_(accessible_brand_ids(db, request))
    ).all()
    critical = [item for item in detections if item.risk_level == "critical"]
    high = [item for item in detections if item.risk_level == "high"]
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_findings": len(detections),
            "critical": len(critical),
            "high": len(high),
            "risk_score_avg": round(sum(item.risk_score for item in detections) / max(len(detections), 1), 2),
        },
        "findings": [
            {
                "entity_name": item.entity_name,
                "risk_level": item.risk_level,
                "platform": item.platform,
                "risk_score": item.risk_score,
            }
            for item in detections
        ],
    }


@app.get("/api/reports/export.csv")
def export_report(request: Request, db: Session = Depends(get_db)):
    detections = db.query(DetectionResult).filter(
        DetectionResult.brand_id.in_(accessible_brand_ids(db, request))
    ).order_by(DetectionResult.detected_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "finding_id", "brand_id", "entity_name", "entity_type", "platform",
        "similarity_score", "risk_score", "risk_level", "status", "reason", "detected_at",
    ])
    for item in detections:
        writer.writerow([
            item.id, item.brand_id, item.entity_name, item.entity_type, item.platform,
            item.similarity_score, item.risk_score, item.risk_level, item.status,
            item.detection_reason, item.detected_at.isoformat() if item.detected_at else "",
        ])
    brand_id = detections[0].brand_id if detections else None
    if brand_id is None:
        first_brand = db.query(Brand).filter(
            Brand.id.in_(accessible_brand_ids(db, request))
        ).first()
        brand_id = first_brand.id if first_brand else None
    if brand_id is not None:
        db.add(ReportMetadata(
            brand_id=brand_id,
            report_type="findings_csv",
            filename="brandshield-findings.csv",
            filters={"format": "csv", "rows": len(detections)},
        ))
        db.commit()
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=brandshield-findings.csv"},
    )

class NVIDIAChatPayload(BaseModel):
    message: str = Field(min_length=1, max_length=4000)

    @field_validator("message")
    @classmethod
    def require_non_whitespace_message(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Message cannot be empty.")
        return normalized


@app.post("/api/ai/chat")
def nvidia_ai_chat(payload: NVIDIAChatPayload):
    api_key = os.getenv("NVIDIA_API_KEY", "").strip()

    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="NVIDIA API key is not configured. Set NVIDIA_API_KEY in the backend .env file and restart the API."
        )

    request_data = {
        "model": "meta/llama-3.2-11b-vision-instruct",
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are BRANDSHIELD AI, a cybersecurity assistant. "
                    "Help analyze suspicious messages, URLs, and potential scams. "
                    "Do not claim a URL is malicious without sufficient evidence."
                ),
            },
            {"role": "user", "content": payload.message},
        ],
        "temperature": 0.2,
        "max_tokens": 500,
    }

    request = urllib.request.Request(
        "https://integrate.api.nvidia.com/v1/chat/completions",
        data=json.dumps(request_data).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            response_content = response.read(2 * 1024 * 1024 + 1)
        if len(response_content) > 2 * 1024 * 1024:
            raise HTTPException(status_code=502, detail="NVIDIA AI service response exceeded the size limit.")
        result = json.loads(response_content.decode("utf-8"))

        answer = result["choices"][0]["message"]["content"]
        if not isinstance(answer, str) or not answer.strip():
            raise ValueError("NVIDIA returned an empty answer.")
        return {
            "answer": answer,
            "model": "meta/llama-3.2-11b-vision-instruct",
        }

    except urllib.error.HTTPError as error:
        logger.error("NVIDIA API returned HTTP %s", error.code)

        if error.code in (401, 403):
            raise HTTPException(
                status_code=502,
                detail="NVIDIA API authentication or access failed.",
            ) from error

        if error.code == 429:
            raise HTTPException(
                status_code=503,
                detail="NVIDIA API rate limit or quota reached.",
            ) from error

        raise HTTPException(
            status_code=502,
            detail="NVIDIA AI service returned an error.",
        ) from error

    except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as error:
        raise HTTPException(
            status_code=504,
            detail="Could not connect to NVIDIA AI service.",
        ) from error

    except (KeyError, IndexError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        logger.exception("Unexpected NVIDIA API response format")
        raise HTTPException(
            status_code=502,
            detail="Unexpected response from NVIDIA AI service.",
        ) from error
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=PORT, reload=False)
