import hashlib
import json
import math
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.error import URLError
from urllib.request import Request, urlopen

from PIL import Image, UnidentifiedImageError
from imagehash import phash
from rapidfuzz import fuzz

from ..config import UPLOADS_DIR
from .ingestion import assess_url_safety


EXPLICIT_SCAM_PATTERNS = (
    (
        "credential_request",
        re.compile(
            r"\b(?:send|share|provide|give|reply with|enter)\s+"
            r"(?:(?:me|us)\s+)?(?:(?:your|my|the|a)\s+)?"
            r"(?:password|passcode|one time passcode|one time code|verification code|security code|otp)\b"
        ),
    ),
    (
        "coercive_account_recovery",
        re.compile(
            r"\bclick\b.{0,35}\b(?:link|url)\b.{0,25}\b(?:restore|unlock|recover)\b"
            r".{0,20}\b(?:account|access)\b"
        ),
    ),
    (
        "gift_card_payment_demand",
        re.compile(
            r"\bgift cards?\b.{0,25}\bcodes?\b.{0,40}"
            r"\b(?:release|unlock|restore|pay|payment)\b"
        ),
    ),
)
NEGATION_CUES = {"never", "not", "dont", "without"}


def local_embedding_similarity(text_a: str, text_b: str) -> Dict[str, Any]:
    if os.getenv("OLLAMA_ENABLED", "").lower() not in {"1", "true", "yes"}:
        return {"status": "disabled", "similarity": None}

    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
    model = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    request = Request(
        f"{base_url}/api/embed",
        data=json.dumps({"model": model, "input": [text_a, text_b]}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=1.5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        vectors = payload["embeddings"]
        vector_a, vector_b = vectors[0], vectors[1]
        if not vector_a or len(vector_a) != len(vector_b):
            raise ValueError("Ollama returned invalid embedding vectors.")
        dot = sum(a * b for a, b in zip(vector_a, vector_b))
        norm_a = math.sqrt(sum(a * a for a in vector_a))
        norm_b = math.sqrt(sum(b * b for b in vector_b))
        if norm_a == 0 or norm_b == 0:
            raise ValueError("Ollama returned a zero-length embedding.")
        cosine = max(-1.0, min(1.0, dot / (norm_a * norm_b)))
        return {"status": "available", "similarity": round((cosine + 1) * 50), "model": model}
    except (URLError, TimeoutError, OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
        return {"status": "unavailable", "similarity": None, "model": model}


def normalize_text(value: str) -> str:
    if not value:
        return ""
    text = value.lower().strip()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def score_similarity(name_a: str, name_b: str) -> int:
    if not name_a or not name_b:
        return 0
    direct = fuzz.ratio(normalize_text(name_a), normalize_text(name_b))
    token_set = fuzz.token_set_ratio(normalize_text(name_a), normalize_text(name_b))
    return max(direct, token_set)


def build_name_variants(name: str) -> List[str]:
    base = name.strip()
    variants = {base, normalize_text(base)}
    for suffix in ["official", "support", "global", "help", "customer", "team"]:
        variants.add(f"{base} {suffix}")
        variants.add(f"{base}{suffix}")
        variants.add(f"{base} {suffix.title()}")
    return [v for v in variants if v and len(v) > 2]


def determine_risk(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def analyze_candidate(brand: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    brand_name = str(brand.get("name", ""))
    candidate_name = str(candidate.get("name", "")).strip()
    candidate_url = str(candidate.get("url", "")).strip()
    description = str(candidate.get("description", "")).strip()
    package_id = str(candidate.get("package_id", "")).strip().lower()
    developer = str(candidate.get("developer_name", "")).strip()
    candidate_logo_hash = str(candidate.get("logo_perceptual_hash", "")).strip()
    entity_type = str(candidate.get("entity_type", "social_profile"))
    platform = str(candidate.get("platform", "Unknown"))
    if not any((candidate_name, candidate_url, description, package_id, developer, candidate_logo_hash)):
        raise ValueError("Enter a candidate name, suspicious text, URL, or application identifier to analyze.")
    if entity_type not in {"social_profile", "application", "domain"}:
        raise ValueError("entity_type must be social_profile, application, or domain.")

    evidence: List[Dict[str, Any]] = []
    indicators: List[Dict[str, str]] = []
    score = 0.0
    similarity = 0
    normalized_url = ""

    if candidate_name:
        fuzzy_similarity = score_similarity(candidate_name, brand_name)
        embedding = local_embedding_similarity(candidate_name, brand_name)
        similarity = fuzzy_similarity
        if embedding["similarity"] is not None:
            similarity = round(fuzzy_similarity * 0.7 + embedding["similarity"] * 0.3)
        name_points = 26 if similarity >= 95 else 20 if similarity >= 85 else 12 if similarity >= 70 else 6 if similarity >= 50 else 0
        score += name_points
        evidence.append({
            "type": "name_similarity",
            "value": f"Name similarity to {brand_name}: {similarity}% (fuzzy {fuzzy_similarity}%).",
            "confidence": similarity,
            "details": {"candidate_name": candidate_name, "brand_name": brand_name, "fuzzy_similarity": fuzzy_similarity},
        })
        if similarity >= 70:
            indicators.append({
                "code": "name_similarity",
                "severity": "medium" if similarity >= 85 else "low",
                "source": "name",
                "message": f"Candidate name resembles the protected brand ({similarity}% similarity).",
            })
        if embedding["status"] == "available":
            evidence.append({
                "type": "local_embedding_similarity",
                "value": f"Local {embedding['model']} embedding similarity: {embedding['similarity']}%.",
                "confidence": embedding["similarity"],
                "details": {"model": embedding["model"], "similarity": embedding["similarity"]},
            })
        elif embedding["status"] == "unavailable":
            evidence.append({
                "type": "local_embedding_fallback",
                "value": "Optional local embedding service unavailable; deterministic fuzzy/rule analysis used.",
                "confidence": 0,
                "details": {"model": embedding["model"], "fallback": "rapidfuzz_and_rules"},
            })

    trusted = list(brand.get("known_domains") or [])
    if not trusted and brand.get("official_website"):
        trusted = [str(brand["official_website"])]
    url_assessment = None
    if candidate_url:
        url_assessment = assess_url_safety(candidate_url, brand_name, trusted)
        normalized_url = url_assessment["normalized_url"]
        score += url_assessment["risk_score"] * 0.9
        domain = url_assessment["host"]
        is_trusted_domain = any(
            domain == trusted_domain or domain.endswith("." + trusted_domain)
            for trusted_domain in url_assessment["trusted_domains"]
        )
        evidence.append({
            "type": "domain_analysis",
            "value": f"URL was analyzed without opening it. Host: {domain}. " + (
                "It matches a configured trusted domain." if is_trusted_domain else
                "No configured trusted-domain match was found; this alone is not a risk finding."
            ),
            "confidence": url_assessment["risk_score"],
            "details": {
                "domain": domain,
                "trusted_domains": trusted,
                "trusted": is_trusted_domain,
                "url_risk_score": url_assessment["risk_score"],
                "url_risk_category": url_assessment["risk_category"],
                "normalized_url": normalized_url,
            },
        })
        indicators.extend(
            {**indicator, "source": "url"}
            for indicator in url_assessment["indicators"]
        )

    normalized_description = normalize_text(description)
    scam_terms = [
        "verify account",
        "claim reward",
        "send password",
        "urgent payment",
        "wallet recovery",
        "free gift",
        "login now",
    ]
    matched_terms = [term for term in scam_terms if normalize_text(term) in normalized_description]
    explicit_matches = []
    for pattern_code, pattern in EXPLICIT_SCAM_PATTERNS:
        for match in pattern.finditer(normalized_description):
            preceding_tokens = normalized_description[:match.start()].split()[-5:]
            if pattern_code == "credential_request" and NEGATION_CUES.intersection(preceding_tokens):
                continue
            explicit_matches.append(pattern_code)
            break
    if description:
        description_points = min(36, len(matched_terms) * 18)
        explicit_points = min(54, len(explicit_matches) * 36)
        score += description_points + explicit_points
        description_text = (
            "Description contains suspicious solicitation language: " + ", ".join(matched_terms) + "."
            if matched_terms else "No known high-risk solicitation phrases found in the description."
        )
        if explicit_matches:
            description_text += " Explicit high-risk behavior detected: " + ", ".join(explicit_matches) + "."
        evidence.append({
            "type": "description_analysis",
            "value": description_text,
            "confidence": min(100, description_points * 5 + explicit_points * 2),
            "details": {"matched_terms": matched_terms, "explicit_patterns": explicit_matches},
        })
        if matched_terms:
            indicators.append({
                "code": "solicitation_language",
                "severity": "high" if len(matched_terms) >= 2 else "medium",
                "source": "text",
                "message": description_text,
            })
        if explicit_matches:
            indicators.append({
                "code": "explicit_scam_behavior",
                "severity": "high",
                "source": "text",
                "message": "Message contains an explicit credential, coercive account-recovery, or gift-card payment demand: "
                + ", ".join(explicit_matches)
                + ".",
            })

    if entity_type == "application":
        known_packages = [str(item).lower() for item in brand.get("official_package_ids") or []]
        known_developers = [normalize_text(str(item)) for item in brand.get("official_developer_names") or []]
        package_match = package_id and package_id in known_packages
        developer_match = developer and normalize_text(developer) in known_developers
        if package_id:
            package_points = 0 if package_match else 10
            score += package_points
            package_text = "Package ID matches a configured official application." if package_match else "Package ID does not match the configured official registry; this is not proof of impersonation."
            evidence.append({
                "type": "package_id",
                "value": package_text,
                "confidence": 100 if package_match else 30,
                "details": {"package_id": package_id, "official_package_ids": known_packages},
            })
            if not package_match:
                indicators.append({"code": "unregistered_package", "severity": "low", "source": "application", "message": package_text})
        if developer:
            developer_points = 0 if developer_match else 6
            score += developer_points
            developer_text = "Developer matches a configured official publisher." if developer_match else "Developer does not match the configured publisher registry; this is not proof of impersonation."
            evidence.append({
                "type": "developer",
                "value": developer_text,
                "confidence": 100 if developer_match else 30,
                "details": {"developer": developer, "official_developers": brand.get("official_developer_names") or []},
            })
            if not developer_match:
                indicators.append({"code": "unverified_developer", "severity": "low", "source": "application", "message": developer_text})

    official_logo_hash = str(brand.get("logo_perceptual_hash", "")).strip()
    if official_logo_hash and candidate_logo_hash:
        distance = -1
        try:
            distance = (int(official_logo_hash, 16) ^ int(candidate_logo_hash, 16)).bit_count()
            logo_similarity = round(max(0, 100 - distance * 100 / max(len(official_logo_hash) * 4, 1)))
        except ValueError:
            logo_similarity = 0
        logo_points = 10 if logo_similarity >= 80 else 0
        score += logo_points
        logo_text = f"Perceptual logo similarity is {logo_similarity}%."
        evidence.append({
            "type": "logo_similarity",
            "value": logo_text,
            "confidence": logo_similarity,
            "details": {"similarity": logo_similarity, "hamming_distance": distance},
        })
        if logo_points:
            indicators.append({"code": "logo_similarity", "severity": "medium", "source": "image", "message": logo_text})

    final_score = int(round(min(100, max(0, score))))
    risk_category = "suspicious" if final_score >= 35 else "inconclusive" if final_score >= 15 else "lower_risk"
    if not candidate_name:
        entity_name = (
            url_assessment["host"] if url_assessment else
            description[:80].strip()
        )
    else:
        entity_name = candidate_name
    if indicators:
        indicator_summary = " ".join(indicator["message"] for indicator in indicators)
        explanation = (
            "Heuristic indicators warrant closer review: " + indicator_summary + " This is not confirmation of fraud."
            if risk_category == "suspicious" else
            "The available signal is weak or ambiguous: " + indicator_summary + " This does not confirm fraud."
        )
    elif risk_category == "inconclusive":
        explanation = "The available signals are limited or ambiguous. Verify the details independently; this result does not confirm fraud."
    else:
        explanation = "No meaningful risk indicators were found in the submitted details. A lower-risk result does not guarantee safety."
    return {
        "entity_name": entity_name,
        "entity_type": entity_type,
        "platform": platform,
        "similarity_score": similarity,
        "risk_score": final_score,
        "risk_level": determine_risk(final_score),
        "risk_category": risk_category,
        "verdict": risk_category,
        "detection_reason": explanation,
        "explanation": explanation,
        "url": normalized_url,
        "indicators": indicators,
        "evidence": evidence,
    }


def compute_perceptual_hash(image_path: str) -> str:
    with Image.open(image_path) as img:
        img = img.convert("RGB")
        img = img.resize((32, 32), Image.Resampling.LANCZOS)
        return str(phash(img))


def validate_image_upload(file, max_size_mb: int = 5) -> Dict[str, Any]:
    if not file:
        return {"valid": False, "error": "No file uploaded."}

    allowed_ext = {".png", ".jpg", ".jpeg", ".webp"}
    allowed_mime = {"image/png", "image/jpeg", "image/webp"}
    expected_mime = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}

    filename = file.filename or ""
    ext = Path(filename).suffix.lower()
    mime = getattr(file, "content_type", "") or ""

    if ext not in allowed_ext:
        return {"valid": False, "error": "Unsupported file type. Use PNG, JPG, JPEG, or WEBP."}
    if mime not in allowed_mime:
        return {"valid": False, "error": "Unsupported image MIME type."}
    if expected_mime.get(ext) != mime:
        return {"valid": False, "error": "Image MIME type does not match its file extension."}
    if file.size is not None and file.size > max_size_mb * 1024 * 1024:
        return {"valid": False, "error": f"Image size exceeds {max_size_mb}MB."}
    try:
        file.file.seek(0)
        with Image.open(file.file) as image:
            if image.format not in {"PNG", "JPEG", "WEBP"}:
                return {"valid": False, "error": "Image content does not match a supported format."}
            if image.width * image.height > 20_000_000:
                return {"valid": False, "error": "Image dimensions are too large to process safely."}
            image.verify()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return {"valid": False, "error": "Uploaded file is not a valid supported image."}
    finally:
        file.file.seek(0)

    return {"valid": True, "filename": filename, "extension": ext, "mime": mime}


def save_uploaded_logo(file) -> Dict[str, Any]:
    validation = validate_image_upload(file)
    if not validation["valid"]:
        return validation

    file.file.seek(0)
    contents = file.file.read()
    safe_name = hashlib.sha256(contents).hexdigest() + Path(file.filename).suffix.lower()
    upload_dir = UPLOADS_DIR / "logos"
    upload_dir.mkdir(parents=True, exist_ok=True)
    file_path = upload_dir / safe_name
    with open(file_path, "wb") as destination:
        destination.write(contents)
    hash_value = compute_perceptual_hash(str(file_path))
    return {"valid": True, "path": str(file_path), "hash": hash_value}


def correlate_entities(detection_rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = list(detection_rows)
    result = []
    for row in rows:
        evidence = row.get("evidence", {})
        if evidence.get("shared_token"):
            row["risk_score"] = min(100, row["risk_score"] + 8)
        row["risk_level"] = determine_risk(row["risk_score"])
        result.append(row)
    return result


def build_demo_scans(brand: Dict[str, Any]) -> List[Dict[str, Any]]:
    brand_name = brand.get("name", "")
    keywords = brand.get("brand_keywords") or []
    name_variants = build_name_variants(brand_name)
    candidates = [
        {"name": "Amaz0n Support Help", "entity_type": "social_profile", "platform": "Instagram", "reason": "Account branding mirrors official retailer naming and customer support language.", "shared_token": "amazon"},
        {"name": "PayPal Secure Center", "entity_type": "social_profile", "platform": "Facebook", "reason": "Similar brand lexicon and support wording used in scam profile creation.", "shared_token": "paypal"},
        {"name": "MetaPay Wallet", "entity_type": "social_profile", "platform": "X", "reason": "Impersonation pattern targeting a digital-wallet brand with suspicious login prompts.", "shared_token": "metapay"},
        {"name": "AstraBank Support", "entity_type": "social_profile", "platform": "LinkedIn", "reason": "Fake company verification page built around a nearly identical corporate brand.", "shared_token": "astrabank"},
        {"name": "SecurePay Mobile", "entity_type": "application", "platform": "Android", "reason": "App impersonates a payment platform using a nearly identical name and suspicious package ID.", "shared_token": "securepay"},
        {"name": "QuickPay Limited", "entity_type": "application", "platform": "iOS", "reason": "App icon and developer metadata resemble a high-value financial brand.", "shared_token": "quickpay"},
    ]

    rows = []
    for candidate in candidates:
        score = 0
        for variant in name_variants:
            if not variant:
                continue
            score = max(score, score_similarity(candidate["name"], variant))
        for keyword in keywords:
            if keyword and keyword.lower() in candidate["name"].lower():
                score = max(score, 82)
        if score < 20:
            score = 35
        risk_score = min(99, int(round(score * 0.9 + (30 if candidate["entity_type"] == "application" else 20))))
        rows.append({
            "brand_id": brand.get("id"),
            "entity_name": candidate["name"],
            "entity_type": candidate["entity_type"],
            "platform": candidate["platform"],
            "similarity_score": max(30, min(99, score)),
            "risk_score": risk_score,
            "risk_level": determine_risk(risk_score),
            "detection_reason": candidate["reason"],
            "status": "monitoring" if risk_score >= 70 else "review",
            "evidence": {
                "brand_name": brand_name,
                "keywords": keywords,
                "shared_token": candidate.get("shared_token"),
                "confidence": int(round((score + risk_score) / 2)),
            },
            "detected_at": datetime.utcnow().isoformat(),
        })

    return correlate_entities(rows)
