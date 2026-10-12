import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Any, Dict, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import Organization, User

logger = logging.getLogger(__name__)
_configured_secret = os.getenv("BRANDSHIELD_TOKEN_SECRET", "").strip()
if _configured_secret:
    if len(_configured_secret) < 32 or _configured_secret == "local-demo-secret-change-me":
        raise RuntimeError("BRANDSHIELD_TOKEN_SECRET must be a non-default secret of at least 32 characters.")
    _TOKEN_SECRET = _configured_secret.encode()
elif os.getenv("APP_ENV", "development").lower() in {"production", "prod", "staging"}:
    raise RuntimeError("BRANDSHIELD_TOKEN_SECRET must be configured outside local development.")
else:
    _TOKEN_SECRET = secrets.token_bytes(32)
    logger.warning(
        "BRANDSHIELD_TOKEN_SECRET is unset; using an ephemeral process secret. "
        "Configure a persistent random secret before a company pilot."
    )


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        candidate = hash_password(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
        return hmac.compare_digest(candidate, digest_hex)
    except (ValueError, TypeError):
        return False


def create_access_token(user: User) -> str:
    payload = {
        "sub": user.id,
        "organization_id": user.organization_id,
        "role": user.role,
        "exp": int(time.time()) + 60 * 60 * 12,
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(_TOKEN_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(_TOKEN_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def authenticate_request(request: Request) -> Optional[Dict[str, Any]]:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return decode_access_token(header[7:])


def seed_demo_user(db: Session) -> None:
    if db.query(User).filter(User.email == "analyst@brandshield.local").first():
        return
    organization = db.query(Organization).first()
    if not organization:
        organization = Organization(name="BrandShield Demo Organization")
        db.add(organization)
        db.flush()
    user = User(
        organization_id=organization.id,
        email="analyst@brandshield.local",
        password_hash=hash_password("brandshield-demo"),
        role="admin",
    )
    db.add(user)
    db.flush()
