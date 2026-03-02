from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import (
    AlertEvent,
    DashboardStatsResponse,
    DomainBreakdownItem,
    HourlyTrendPoint,
    ReportRequest,
    ReporterBreakdownItem,
    RiskContributor,
    ScanExplanation,
    ThreatIntelItem,
    UrlFeatures,
)
from .storage import SQLiteStore

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
TRUSTED_DOMAINS = {
    "nytimes.com",
    "straitstimes.com",
    "gov.sg",
    "google.com",
    "wikipedia.org",
}
SUSPICIOUS_TLDS = {".ru", ".tk", ".xyz", ".top", ".click", ".zip"}


@dataclass
class ScanResult:
    risk_score: float
    verdict: str
    features: UrlFeatures
    reasons: list[str]
    explanation: ScanExplanation


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
    is_ip = _has_ip_domain(hostname)

    keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k in path_and_query.lower())
    special_count = sum(1 for c in url if c in SPECIAL_CHARS)
    subdomain_count = 0 if is_ip else max(0, len(parts) - 2)

    return UrlFeatures(
        url_length=len(url),
        subdomain_count=subdomain_count,
        has_ip_in_domain=is_ip,
        special_char_count=special_count,
        suspicious_keyword_hits=keyword_hits,
        uses_https=parsed.scheme.lower() == "https",
    )


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def _is_trusted_domain(hostname: str) -> bool:
    host = (hostname or "").lower()
    if not host:
        return False
    return any(host == domain or host.endswith(f".{domain}") for domain in TRUSTED_DOMAINS)


def score_url(url: str) -> ScanResult:
    features = extract_url_features(url)
    hostname, _ = _extract_domain_parts(url)

    contributions: list[tuple[str, float, str]] = []

    def add_contribution(signal: str, weight: float, note: str) -> None:
        contributions.append((signal, weight, note))

    weighted_sum = -3.2
    add_contribution("base_prior", -3.2, "Model baseline for unknown URLs")

    length_weight = 0.02 * features.url_length
    weighted_sum += length_weight
    add_contribution("url_length", length_weight, "Long URLs can hide malicious paths")

    subdomain_weight = 0.45 * features.subdomain_count
    weighted_sum += subdomain_weight
    add_contribution(
        "subdomain_density",
        subdomain_weight,
        "Many subdomains can indicate brand impersonation",
    )

    ip_weight = 1.15 if features.has_ip_in_domain else 0.0
    weighted_sum += ip_weight
    add_contribution(
        "raw_ip_domain",
        ip_weight,
        "IP-based hostnames often bypass normal trust cues",
    )

    special_weight = 0.18 * features.special_char_count
    weighted_sum += special_weight
    add_contribution(
        "special_character_density",
        special_weight,
        "High symbol density can obfuscate destination",
    )

    keyword_weight = 0.50 * features.suspicious_keyword_hits
    weighted_sum += keyword_weight
    add_contribution(
        "suspicious_keywords",
        keyword_weight,
        "Urgent account/security terms are common phishing bait",
    )

    https_weight = -0.25 if features.uses_https else 0.40
    weighted_sum += https_weight
    add_contribution(
        "transport_security",
        https_weight,
        "Non-HTTPS URLs increase interception and scam risk",
    )

    trusted_weight = -1.35 if _is_trusted_domain(hostname) else 0.0
    weighted_sum += trusted_weight
    add_contribution(
        "trusted_domain_bonus",
        trusted_weight,
        "Known trusted/public domain receives lower baseline risk",
    )

    tld_weight = 0.0
    if any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
        tld_weight = 0.9
    weighted_sum += tld_weight
    add_contribution(
        "tld_risk",
        tld_weight,
        "Some TLDs are over-represented in abuse and phishing campaigns",
    )

    punycode_weight = 0.7 if "xn--" in hostname.lower() else 0.0
    weighted_sum += punycode_weight
    add_contribution(
        "punycode_risk",
        punycode_weight,
        "Punycode domains can be used for lookalike/homograph attacks",
    )

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
    if any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("Potentially risky top-level domain")
    if "xn--" in hostname.lower():
        reasons.append("Punycode domain detected")
    if not reasons:
        reasons.append("No strong phishing signals detected")

    if risk_score >= 0.85:
        verdict = "likely_phishing"
    elif risk_score >= 0.50:
        verdict = "suspicious"
    else:
        verdict = "safe"

    sorted_contributors = sorted(
        contributions,
        key=lambda item: abs(item[1]),
        reverse=True,
    )
    top = sorted_contributors[:4]

    contributor_items: list[RiskContributor] = []
    for signal, weight, note in top:
        abs_weight = abs(weight)
        impact = "low"
        if abs_weight >= 1.0:
            impact = "high"
        elif abs_weight >= 0.45:
            impact = "medium"
        contributor_items.append(
            RiskContributor(
                signal=signal,
                impact=impact,
                weight=round(weight, 4),
                note=note,
            )
        )

    summary = "No strong phishing pattern detected."
    if verdict == "likely_phishing":
        summary = "High-confidence phishing pattern detected. Block and report this URL."
    elif verdict == "suspicious":
        summary = "Risky signals detected. Verify carefully before interacting."

    explanation = ScanExplanation(
        summary=summary,
        confidence=round(max(risk_score, 1.0 - risk_score), 4),
        contributors=contributor_items,
    )

    return ScanResult(
        risk_score=risk_score,
        verdict=verdict,
        features=features,
        reasons=reasons,
        explanation=explanation,
    )


class ThreatIntelStore:
    def __init__(self, storage: SQLiteStore) -> None:
        self._storage = storage
        self._alert_queue: asyncio.Queue[AlertEvent] = asyncio.Queue()

    def add_report(self, payload: ReportRequest) -> str:
        report_id = f"rep_{uuid.uuid4().hex[:10]}"
        created_at = datetime.now(timezone.utc)
        reason = re.sub(r"\s+", " ", payload.reason.strip())
        reporter_user = (payload.reporter_name or "").strip() or "anonymous"
        self._storage.insert_report(
            report_id=report_id,
            url=str(payload.url),
            created_at=created_at,
            reason=reason,
            reporter_type=payload.reporter_type,
            reporter_user=reporter_user,
            evidence=payload.evidence,
        )
        item = ThreatIntelItem(
            report_id=report_id,
            url=payload.url,
            created_at=created_at,
            reason=reason,
            reporter_type=payload.reporter_type,
            reporter_user=reporter_user,
        )
        self._alert_queue.put_nowait(
            AlertEvent(
                report_id=item.report_id,
                created_at=item.created_at,
                url=str(item.url),
                reporter_type=item.reporter_type,
                reporter_user=item.reporter_user,
                reason=item.reason,
            )
        )
        return report_id

    def list_reports(self, limit: int = 20) -> list[ThreatIntelItem]:
        rows = self._storage.list_reports(limit=limit)
        return [
            ThreatIntelItem(
                report_id=row["report_id"],
                url=row["url"],
                created_at=row["created_at"],
                reason=row["reason"],
                reporter_type=row["reporter_type"],
                reporter_user=row["reporter_user"],
            )
            for row in rows
        ]

    def count(self) -> int:
        return self._storage.count_reports()

    def dashboard_stats(self) -> DashboardStatsResponse:
        reports = self._storage.list_all_reports()
        reporter_counter = Counter(item["reporter_type"] for item in reports)

        domain_counter: Counter[str] = Counter()
        hourly_counter: defaultdict[str, int] = defaultdict(int)

        for item in reports:
            parsed = urlparse(str(item["url"]))
            domain = (parsed.hostname or "unknown").lower()
            domain_counter[domain] += 1

            hour_bucket = item["created_at"].strftime("%Y-%m-%d %H:00")
            hourly_counter[hour_bucket] += 1

        reporters = [
            ReporterBreakdownItem(reporter_type=rtype, count=count)
            for rtype, count in reporter_counter.most_common()
        ]
        top_domains = [
            DomainBreakdownItem(domain=domain, count=count)
            for domain, count in domain_counter.most_common(6)
        ]
        hourly_points = [
            HourlyTrendPoint(hour_utc=hour, count=count)
            for hour, count in sorted(hourly_counter.items())
        ]

        return DashboardStatsResponse(
            reports_total=len(reports),
            reporters=reporters,
            top_domains=top_domains,
            hourly_trend=hourly_points,
        )

    async def next_alert(self) -> AlertEvent:
        return await self._alert_queue.get()
