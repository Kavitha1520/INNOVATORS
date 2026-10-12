from __future__ import annotations

import json
import logging
import os
import http.client
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, List
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..models import Brand, DetectionResult, MonitoringSource
from .detection import analyze_candidate
from .ingestion import normalize_url


logger = logging.getLogger(__name__)

PHISHTANK_FEED_URL = "https://data.phishtank.com/data/{api_key}/online-valid.json"
PHISHTANK_API_KEY_ENV = "PHISHTANK_API_KEY"
PHISHTANK_USER_AGENT = "BRANDSHIELD-AI/1.0 (authorized threat-feed consumer)"
FEED_TIMEOUT_SECONDS = 20
MAX_FEED_BYTES = 20 * 1024 * 1024
MAX_FEED_RECORDS = 100_000


class ThreatFeedError(RuntimeError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def phishtank_api_key() -> str:
    return os.getenv(PHISHTANK_API_KEY_ENV, "").strip()


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _open_feed_request(request: urllib.request.Request):
    opener = urllib.request.build_opener(_RejectRedirectHandler())
    return opener.open(request, timeout=FEED_TIMEOUT_SECONDS)


def fetch_phishtank_feed(api_key: str) -> List[Dict[str, Any]]:
    if not api_key:
        raise ThreatFeedError("CONFIGURATION REQUIRED", "Configure PHISHTANK_API_KEY to enable PhishTank monitoring.")
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", api_key) is None:
        raise ThreatFeedError("CONFIGURATION REQUIRED", "PHISHTANK_API_KEY has an invalid format.")

    request = urllib.request.Request(
        PHISHTANK_FEED_URL.format(api_key=api_key),
        headers={"User-Agent": PHISHTANK_USER_AGENT, "Accept": "application/json"},
    )
    try:
        with _open_feed_request(request) as response:
            content = response.read(MAX_FEED_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = "ERROR"
        message = "PhishTank rate-limited the feed request." if error.code == 429 else "PhishTank feed request failed."
        logger.warning("PhishTank feed request returned HTTP %s.", error.code)
        raise ThreatFeedError(status, message) from None
    except (TimeoutError, urllib.error.URLError, OSError, http.client.HTTPException):
        logger.warning("PhishTank feed request could not be completed.")
        raise ThreatFeedError("ERROR", "PhishTank feed is temporarily unavailable.") from None

    if len(content) > MAX_FEED_BYTES:
        raise ThreatFeedError("ERROR", "PhishTank feed exceeded the configured response-size limit.")
    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ThreatFeedError("ERROR", "PhishTank returned an invalid JSON feed.") from None
    if not isinstance(payload, list) or len(payload) > MAX_FEED_RECORDS:
        raise ThreatFeedError("ERROR", "PhishTank returned an unsupported feed shape or record count.")
    return [record for record in payload if isinstance(record, dict)]


def _normalized_brand_target(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _is_trusted_brand_host(brand: Brand, host: str) -> bool:
    configured_domains = list(brand.known_domains or [])
    if brand.official_website:
        configured_domains.append(brand.official_website)
    for value in configured_domains:
        normalized = normalize_url(str(value))
        trusted_host = urlparse(normalized).hostname if normalized else None
        if trusted_host and (host == trusted_host.lower() or host.endswith("." + trusted_host.lower())):
            return True
    return False


def run_phishtank_source(source: MonitoringSource, brand: Brand, db: Session) -> Dict[str, Any]:
    api_key = phishtank_api_key()
    if not api_key:
        raise ThreatFeedError("CONFIGURATION REQUIRED", "Configure PHISHTANK_API_KEY to enable PhishTank monitoring.")

    records = fetch_phishtank_feed(api_key)
    now = datetime.utcnow()
    brand_target = _normalized_brand_target(brand.name)
    created = 0
    duplicates = 0
    ignored = 0

    for record in records:
        if str(record.get("verified", "")).casefold() != "yes":
            ignored += 1
            continue
        if str(record.get("online", "")).casefold() != "yes":
            ignored += 1
            continue
        target = str(record.get("target", "")).strip()
        if not target or _normalized_brand_target(target) != brand_target:
            ignored += 1
            continue

        raw_url = str(record.get("url", ""))
        url = normalize_url(raw_url)
        if not url or len(url) > 2048:
            ignored += 1
            continue
        host = (urlparse(url).hostname or "").lower()
        if not host or _is_trusted_brand_host(brand, host):
            ignored += 1
            continue

        duplicate = db.query(DetectionResult.id).filter(
            DetectionResult.brand_id == brand.id,
            DetectionResult.platform == "PhishTank",
            DetectionResult.entity_type == "domain",
            DetectionResult.entity_name == host,
        ).first()
        if duplicate:
            duplicates += 1
            continue

        analysis = analyze_candidate(
            {
                "id": brand.id,
                "name": brand.name,
                "official_website": brand.official_website,
                "known_domains": brand.known_domains or [],
                "official_package_ids": [],
                "official_developer_names": [],
                "logo_perceptual_hash": "",
            },
            {
                "name": host,
                "entity_type": "domain",
                "platform": "PhishTank",
                "url": url,
                "description": "Verified active PhishTank report; the feed's target field exactly matches this brand.",
            },
        )
        submission_time = str(record.get("submission_time", "")).strip()
        verification_time = str(record.get("verification_time", "")).strip()
        phish_detail_url = normalize_url(str(record.get("phish_detail_url", "")))
        source_evidence = {
            "type": "verified_threat_feed",
            "value": f"PhishTank reports this active phishing URL with target {target}.",
            "confidence": 100,
            "details": {
                "source": "PhishTank",
                "feed_url": url,
                "phish_detail_url": phish_detail_url,
                "discovered_at": submission_time,
                "verified_at": verification_time,
                "collected_at": now.isoformat(),
            },
        }
        analysis["evidence"].append(source_evidence)
        analysis["risk_score"] = max(analysis["risk_score"], 80)
        analysis["risk_level"] = "high" if analysis["risk_score"] < 85 else "critical"
        analysis["risk_category"] = "suspicious"
        analysis["explanation"] = (
            "PhishTank lists this URL as an active, verified phishing report and its target field "
            "exactly matches the protected brand. The URL was not opened."
        )
        analysis["indicators"].append({
            "code": "verified_phishing_feed",
            "severity": "high",
            "source": "PhishTank",
            "message": "Listed as an active, verified phishing URL with an exact protected-brand target match.",
        })
        analysis["detection_reason"] = analysis["explanation"]
        analysis["platform"] = "PhishTank"
        analysis["entity_type"] = "domain"

        from ..main import persist_analysis

        persist_analysis(brand, analysis, db)
        created += 1

    source.last_checked_at = now
    source.last_status = "LIVE"
    source.last_error = ""
    source.next_run_at = now + timedelta(minutes=source.interval_minutes)
    db.add(source)
    db.commit()
    return {
        "source_id": source.id,
        "status": "LIVE",
        "records_received": len(records),
        "findings_created": created,
        "duplicates_skipped": duplicates,
        "records_ignored": ignored,
        "last_checked_at": now.isoformat(),
        "next_run_at": source.next_run_at.isoformat(),
    }


def record_source_failure(source: MonitoringSource, db: Session, error: ThreatFeedError) -> None:
    source.last_status = error.status
    source.last_error = str(error)
    now = datetime.utcnow()
    source.last_checked_at = now
    source.next_run_at = now + timedelta(minutes=source.interval_minutes)
    db.add(source)
    db.commit()
