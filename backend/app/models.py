from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl


class HealthResponse(BaseModel):
    status: str = "ok"
    timestamp: datetime
    version: str


class UrlScanRequest(BaseModel):
    url: HttpUrl
    source: str = Field(
        default="web",
        description="Client source that triggered the scan, e.g. extension, web, api.",
    )


class UrlFeatures(BaseModel):
    url_length: int
    subdomain_count: int
    has_ip_in_domain: bool
    special_char_count: int
    suspicious_keyword_hits: int
    uses_https: bool


class RiskContributor(BaseModel):
    signal: str
    impact: str = Field(..., description="low | medium | high")
    weight: float
    note: str


class ScanExplanation(BaseModel):
    summary: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    contributors: list[RiskContributor]


class UrlScanResponse(BaseModel):
    url: HttpUrl
    risk_score: float = Field(..., ge=0.0, le=1.0)
    verdict: str = Field(..., description="safe | suspicious | likely_phishing")
    threshold: float = Field(..., ge=0.0, le=1.0)
    features: UrlFeatures
    reasons: list[str]
    explanation: ScanExplanation


class ReportRequest(BaseModel):
    url: HttpUrl
    reason: str = Field(..., min_length=5, max_length=300)
    reporter_type: str = Field(
        default="user",
        description="Type of reporter: user, bank, gov, partner",
    )
    reporter_name: str | None = Field(default=None, max_length=80)
    evidence: str | None = Field(default=None, max_length=500)


class ReportResponse(BaseModel):
    report_id: str
    status: str
    message: str


class ThreatIntelItem(BaseModel):
    report_id: str
    url: HttpUrl
    created_at: datetime
    reason: str
    reporter_type: str
    reporter_user: str


class ReporterBreakdownItem(BaseModel):
    reporter_type: str
    count: int


class DomainBreakdownItem(BaseModel):
    domain: str
    count: int


class HourlyTrendPoint(BaseModel):
    hour_utc: str
    count: int


class DashboardStatsResponse(BaseModel):
    reports_total: int
    reporters: list[ReporterBreakdownItem]
    top_domains: list[DomainBreakdownItem]
    hourly_trend: list[HourlyTrendPoint]


class AlertEvent(BaseModel):
    report_id: str
    created_at: datetime
    url: str
    reporter_type: str
    reporter_user: str
    reason: str
