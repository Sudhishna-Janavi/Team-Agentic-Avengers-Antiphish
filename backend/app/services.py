from __future__ import annotations

import ipaddress
import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import ReportRequest, ThreatIntelItem, UrlFeatures

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "bank",
    "password",
    "wallet",
    "suspended",
    "confirm",
}

SPECIAL_CHARS = set("@-_?&=%+")


@dataclass
class ScanResult:
    risk_score: float
    verdict: str
    features: UrlFeatures
    reasons: list[str]


def _extract_domain_parts(url: str) -> tuple[str, list[str]]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = [p for p in hostname.split(".") if p]
    return hostname, parts


def _has_ip_domain(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_url_features(url: str) -> UrlFeatures:
    parsed = urlparse(url)
    hostname, parts = _extract_domain_parts(url)
    path_and_query = f"{parsed.path}{parsed.query}"

    keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k in path_and_query.lower())
    special_count = sum(1 for c in url if c in SPECIAL_CHARS)
    subdomain_count = max(0, len(parts) - 2)

    return UrlFeatures(
        url_length=len(url),
        subdomain_count=subdomain_count,
        has_ip_in_domain=_has_ip_domain(hostname),
        special_char_count=special_count,
        suspicious_keyword_hits=keyword_hits,
        uses_https=parsed.scheme.lower() == "https",
    )


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def score_url(url: str) -> ScanResult:
    features = extract_url_features(url)

    weighted_sum = -3.2
    weighted_sum += 0.02 * features.url_length
    weighted_sum += 0.45 * features.subdomain_count
    weighted_sum += 1.15 if features.has_ip_in_domain else 0.0
    weighted_sum += 0.18 * features.special_char_count
    weighted_sum += 0.50 * features.suspicious_keyword_hits
    weighted_sum += -0.25 if features.uses_https else 0.40

    risk_score = round(_sigmoid(weighted_sum), 4)

    reasons: list[str] = []
    if features.has_ip_in_domain:
        reasons.append("Domain uses raw IP address")
    if features.subdomain_count >= 2:
        reasons.append("Multiple subdomains detected")
    if features.suspicious_keyword_hits >= 2:
        reasons.append("Suspicious keywords present in URL")
    if features.special_char_count >= 5:
        reasons.append("High special character density")
    if not features.uses_https:
        reasons.append("Non-HTTPS scheme detected")
    if not reasons:
        reasons.append("No strong phishing signals detected")

    if risk_score >= 0.85:
        verdict = "likely_phishing"
    elif risk_score >= 0.50:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return ScanResult(
        risk_score=risk_score,
        verdict=verdict,
        features=features,
        reasons=reasons,
    )


class ThreatIntelStore:
    def __init__(self) -> None:
        self._reports: list[ThreatIntelItem] = []

    def add_report(self, payload: ReportRequest) -> str:
        report_id = f"rep_{uuid.uuid4().hex[:10]}"
        item = ThreatIntelItem(
            report_id=report_id,
            url=payload.url,
            created_at=datetime.now(timezone.utc),
            reason=re.sub(r"\s+", " ", payload.reason.strip()),
            reporter_type=payload.reporter_type,
        )
        self._reports.insert(0, item)
        return report_id

    def list_reports(self, limit: int = 20) -> list[ThreatIntelItem]:
        return self._reports[:limit]

    def count(self) -> int:
        return len(self._reports)
