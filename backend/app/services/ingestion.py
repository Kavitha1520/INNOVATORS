import csv
import io
import ipaddress
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from PIL import Image, UnidentifiedImageError


SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SUSPICIOUS_TERMS = {"login", "verify", "password", "wallet", "claim", "secure", "support", "gift", "recovery"}
WINDOWS_TESSERACT_PATH = Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")


def _load_pytesseract():
    try:
        import pytesseract
    except ImportError:
        return None

    executable = os.getenv("TESSERACT_CMD", "").strip()
    if executable:
        pytesseract.pytesseract.tesseract_cmd = executable
    elif (
        not shutil.which(pytesseract.pytesseract.tesseract_cmd)
        and WINDOWS_TESSERACT_PATH.is_file()
    ):
        pytesseract.pytesseract.tesseract_cmd = str(WINDOWS_TESSERACT_PATH)
    return pytesseract


def get_tesseract_status() -> str:
    pytesseract = _load_pytesseract()
    if pytesseract is None:
        return "unavailable (optional package missing)"
    try:
        pytesseract.get_tesseract_version()
    except (pytesseract.TesseractNotFoundError, OSError):
        return "unavailable (configure TESSERACT_CMD or PATH)"
    return "available"


def normalize_url(value: str) -> str:
    value = value.strip() if isinstance(value, str) else ""
    if not value or any(character.isspace() or ord(character) < 32 for character in value) or "\\" in value:
        return ""
    if re.match(r"^https?:[^/]", value, re.IGNORECASE):
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port
        if parsed.netloc.rsplit("@", 1)[-1].endswith(":"):
            return ""
    except (UnicodeError, ValueError):
        return ""
    if port is not None and not 1 <= port <= 65535:
        return ""

    try:
        ipaddress.ip_address(host)
        is_ip_address = True
    except ValueError:
        is_ip_address = False
    if not is_ip_address:
        labels = host.split(".")
        if (
            len(host) > 253
            or (len(labels) < 2 and host != "localhost")
            or (all(label.isdigit() for label in labels))
            or any(
                not label
                or len(label) > 63
                or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
                for label in labels
            )
        ):
            return ""

    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    normalized_host = f"[{host}]" if ":" in host else host
    normalized_netloc = userinfo + normalized_host + (f":{port}" if port is not None else "")
    return parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=normalized_netloc,
        fragment="",
    ).geturl().rstrip("/")


def assess_url_safety(value: str, brand_name: str = "", trusted_domains: List[str] | None = None) -> Dict[str, Any]:
    normalized = normalize_url(value)
    if not normalized:
        raise ValueError("Enter a valid HTTP or HTTPS URL or domain. The submitted address was not opened.")

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    indicators: List[Dict[str, str]] = []
    score = 0

    try:
        ipaddress.ip_address(host)
        indicators.append({"severity": "high", "code": "ip_host", "message": "Link uses a raw IP address instead of a recognizable domain."})
        score += 35
    except ValueError:
        pass

    if host in SHORTENER_HOSTS:
        indicators.append({"severity": "medium", "code": "url_shortener", "message": "Link uses a URL shortener, hiding its final destination."})
        score += 15
    if parsed.scheme != "https":
        indicators.append({"severity": "low", "code": "no_https", "message": "Link does not use HTTPS; this alone does not establish that it is malicious."})
        score += 8
    if "@" in parsed.netloc:
        indicators.append({"severity": "high", "code": "userinfo", "message": "URL contains user information before the host, a common deceptive-link pattern."})
        score += 40

    labels = host.split(".")
    if len(labels) >= 3 and any(len(label) >= 24 for label in labels):
        indicators.append({"severity": "medium", "code": "long_subdomain", "message": "Domain contains an unusually long subdomain."})
        score += 8
    if host.count("-") >= 3:
        indicators.append({"severity": "low", "code": "hyphenated_domain", "message": "Domain contains several hyphens, which is a weak signal by itself."})
        score += 5

    normalized_host = re.sub(r"[^a-z0-9]", "", host)
    normalized_brand = re.sub(r"[^a-z0-9]", "", brand_name.lower())
    trusted = [
        (urlparse(normalize_url(item) or f"https://{item}").hostname or "").lower().removeprefix("www.")
        for item in (trusted_domains or [])
    ]
    if normalized_brand and normalized_brand in normalized_host and not any(
        host == domain or host.endswith("." + domain) for domain in trusted
    ):
        indicators.append({"severity": "high", "code": "brand_lookalike_domain", "message": f"Domain includes '{brand_name}' but is not in the trusted domain list."})
        score += 24

    path_query = f"{parsed.path} {parsed.query}".lower()
    matched_terms = sorted(term for term in SUSPICIOUS_TERMS if term in path_query)
    if len(matched_terms) >= 2:
        indicators.append({"severity": "low", "code": "solicitation_path", "message": "URL path/query combines sensitive account or reward terms: " + ", ".join(matched_terms)})
        score += 10

    score = min(100, score)
    risk = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    category = "suspicious" if score >= 35 else "inconclusive" if score >= 15 else "lower_risk"
    messages = [indicator["message"] for indicator in indicators]
    explanation = (
        "Heuristic indicators warrant caution: " + " ".join(messages)
        if category == "suspicious" else
        "Some URL characteristics are uncertain and should be checked independently: " + " ".join(messages)
        if category == "inconclusive" else
        "No meaningful URL risk indicators were found. This heuristic result does not guarantee the link is safe."
    )
    return {
        "normalized_url": normalized,
        "host": host,
        "risk_score": score,
        "risk_level": risk,
        "risk_category": category,
        "verdict": category,
        "trusted_domains": trusted,
        "indicators": indicators,
        "explanation": explanation,
        "opened": False,
    }


def extract_screenshot_text(upload) -> Dict[str, Any]:
    try:
        upload.file.seek(0)
        with Image.open(upload.file) as image:
            if image.format not in {"PNG", "JPEG", "WEBP"}:
                raise ValueError("Upload a valid PNG, JPG, JPEG, or WEBP screenshot.")
            if image.width * image.height > 20_000_000:
                raise ValueError("Screenshot dimensions exceed the safe processing limit.")
            image.verify()
        upload.file.seek(0)
        with Image.open(upload.file) as image:
            image = image.convert("RGB")
    except ValueError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as error:
        raise ValueError("Upload a valid PNG, JPG, JPEG, or WEBP screenshot.") from error
    finally:
        upload.file.seek(0)

    pytesseract = _load_pytesseract()
    if pytesseract is None:
        return {
            "text": "",
            "ocr_status": "unavailable",
            "message": "The pytesseract package is not installed. Install backend requirements and submit screenshot text manually in the meantime.",
        }

    try:
        text = pytesseract.image_to_string(image, timeout=10).strip()
    except pytesseract.TesseractNotFoundError:
        return {
            "text": "",
            "ocr_status": "unavailable",
            "message": "Tesseract OCR executable was not found. On Windows, install it with 'winget install --id UB-Mannheim.TesseractOCR -e', then set TESSERACT_CMD to the full path of tesseract.exe or add its folder to PATH and restart the backend. You can also enter screenshot text manually.",
        }
    except pytesseract.TesseractError as error:
        return {
            "text": "",
            "ocr_status": "error",
            "message": f"Local Tesseract OCR failed: {error}. Enter screenshot text manually or check the Tesseract installation.",
        }
    except RuntimeError:
        return {
            "text": "",
            "ocr_status": "error",
            "message": "Local Tesseract OCR exceeded its 10-second processing limit. Try a smaller or clearer screenshot, or enter the text manually.",
        }
    if not text:
        return {
            "text": "",
            "ocr_status": "no_text",
            "message": "No readable text was found in this screenshot. Try a clearer image or enter the message manually.",
        }
    return {"text": text, "ocr_status": "available", "message": "Screenshot text extracted locally."}


def decode_qr_image(upload) -> Dict[str, Any]:
    try:
        import cv2
        import numpy as np
    except ImportError as error:
        raise RuntimeError("QR decoding requires the optional OpenCV package. Install backend requirements and retry.") from error

    upload.file.seek(0)
    raw = upload.file.read()
    upload.file.seek(0)
    try:
        with Image.open(io.BytesIO(raw)) as image:
            if image.format not in {"PNG", "JPEG", "WEBP"}:
                raise ValueError("Upload a valid PNG, JPG, JPEG, or WEBP QR image.")
            if image.width * image.height > 20_000_000:
                raise ValueError("Image dimensions exceed the safe QR processing limit.")
            image.verify()
    except ValueError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as error:
        raise ValueError("Upload a valid PNG, JPG, JPEG, or WEBP QR image.") from error

    image_array = np.frombuffer(raw, dtype=np.uint8)
    image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Upload a valid PNG, JPG, JPEG, or WEBP QR image.")
    detector = cv2.QRCodeDetector()
    value, _, _ = detector.detectAndDecode(image)
    if not value and min(image.shape[:2]) < 120 and max(image.shape[:2]) <= 2000:
        scale = min(4, (120 + min(image.shape[:2]) - 1) // min(image.shape[:2]))
        enlarged = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
        value, _, _ = detector.detectAndDecode(enlarged)
    if not value:
        raise ValueError("No decodable QR code was found in the uploaded image.")
    if len(value) > 2048:
        raise ValueError("Decoded QR content exceeds the supported size.")
    return {"value": value, "decoder": "OpenCV QRCodeDetector"}


def parse_findings_csv(contents: bytes, maximum_rows: int = 500) -> List[Dict[str, str]]:
    try:
        text = contents.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("CSV must be UTF-8 encoded.") from error
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV requires a header row.")
    fieldnames = {name.strip().lower() for name in reader.fieldnames if name}
    if "name" not in fieldnames and "entity_name" not in fieldnames:
        raise ValueError("CSV needs a 'name' or 'entity_name' column.")

    rows = []
    for row_number, row in enumerate(reader, start=2):
        if row_number > maximum_rows + 1:
            raise ValueError(f"CSV exceeds the {maximum_rows}-row import limit.")
        normalized = {(key or "").strip().lower(): (value or "").strip() for key, value in row.items()}
        name = normalized.get("name") or normalized.get("entity_name")
        if not name:
            continue
        rows.append({
            "name": name[:500],
            "entity_type": (normalized.get("entity_type") or "social_profile")[:50],
            "platform": (normalized.get("platform") or "CSV import")[:80],
            "url": (normalized.get("url") or "")[:2048],
            "description": (normalized.get("description") or normalized.get("text") or "")[:4000],
            "package_id": (normalized.get("package_id") or "")[:255],
            "developer_name": (normalized.get("developer_name") or "")[:500],
        })
    if not rows:
        raise ValueError("CSV did not contain any usable candidate rows.")
    return rows
