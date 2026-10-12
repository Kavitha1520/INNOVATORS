from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text

from .database import Base


class Brand(Base):
    __tablename__ = "brands"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    company_description = Column(Text, default="")
    industry = Column(String(255), default="")
    official_website = Column(String(500), default="")
    official_social_accounts = Column(JSON, default=list)
    official_mobile_apps = Column(JSON, default=list)
    official_package_ids = Column(JSON, default=list)
    official_developer_names = Column(JSON, default=list)
    brand_keywords = Column(JSON, default=list)
    known_domains = Column(JSON, default=list)
    logo_path = Column(String(500), default="")
    logo_perceptual_hash = Column(String(64), default="")
    additional_identifiers = Column(JSON, default=dict)
    is_sample = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False, index=True)
    entity_name = Column(String(255), nullable=False)
    entity_type = Column(String(50), nullable=False)
    platform = Column(String(50), nullable=False)
    similarity_score = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="low")
    detection_reason = Column(Text, default="")
    status = Column(String(20), default="open")
    evidence = Column(JSON, default=dict)
    detected_at = Column(DateTime, default=datetime.utcnow)


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False, index=True)
    detection_id = Column(Integer, ForeignKey("detection_results.id"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, default="")
    status = Column(String(20), default="open")
    risk_level = Column(String(20), default="medium")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, nullable=False)
    action = Column(String(255), nullable=False)
    details = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow)


class MonitoringSource(Base):
    __tablename__ = "monitoring_sources"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    source_type = Column(String(50), nullable=False)
    platform = Column(String(80), nullable=False)
    locator = Column(String(1000), nullable=False)
    enabled = Column(Boolean, default=True)
    interval_minutes = Column(Integer, nullable=False, default=360)
    last_status = Column(String(30), nullable=False, default="DISCONNECTED")
    last_checked_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detection_results.id"), nullable=False)
    evidence_type = Column(String(80), nullable=False)
    value = Column(Text, nullable=False)
    confidence = Column(Float, default=0.0)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    entity_type = Column(String(50), nullable=False)
    canonical_key = Column(String(1000), nullable=False)
    display_name = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_entity_id = Column(Integer, ForeignKey("entities.id"), nullable=False)
    target_entity_id = Column(Integer, ForeignKey("entities.id"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True)
    relation_type = Column(String(100), nullable=False)
    confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)


class ReportMetadata(Base):
    __tablename__ = "report_metadata"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    report_type = Column(String(50), nullable=False)
    filename = Column(String(255), nullable=False)
    filters = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class CustomerReport(Base):
    __tablename__ = "customer_reports"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    reporter_contact = Column(String(255), default="")
    report_text = Column(Text, nullable=False)
    reported_url = Column(String(2048), default="")
    status = Column(String(30), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)


class ReportMatch(Base):
    __tablename__ = "report_matches"

    id = Column(Integer, primary_key=True, index=True)
    customer_report_id = Column(Integer, ForeignKey("customer_reports.id"), nullable=False)
    detection_id = Column(Integer, ForeignKey("detection_results.id"), nullable=False)
    match_score = Column(Float, default=0.0)
    match_reason = Column(Text, default="")
    analyst_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False, index=True)
    campaign_key = Column(String(500), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    status = Column(String(30), default="tracking")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CampaignEvent(Base):
    __tablename__ = "campaign_events"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False, index=True)
    detection_id = Column(Integer, ForeignKey("detection_results.id"), nullable=True)
    event_type = Column(String(80), nullable=False)
    summary = Column(Text, nullable=False)
    indicators = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class QRAnalysis(Base):
    __tablename__ = "qr_analyses"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=True, index=True)
    source_name = Column(String(255), default="")
    decoded_url = Column(String(2048), default="")
    risk_score = Column(Float, default=0)
    risk_level = Column(String(20), default="low")
    indicators = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
