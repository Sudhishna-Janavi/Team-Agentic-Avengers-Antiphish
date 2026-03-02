from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=3, max_length=200)


class SignupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=3, max_length=200)


class LoginResponse(BaseModel):
    token: str
    role: str
    username: str
    expiresAt: datetime


class MeResponse(BaseModel):
    username: str
    role: str


class LogoutResponse(BaseModel):
    status: str


class Signal(BaseModel):
    id: str
    severity: str
    message: str


class RecommendedAction(BaseModel):
    id: str
    label: str


class AnalyzeResponse(BaseModel):
    url: str
    normalizedUrl: str
    timestamp: datetime
    riskScore: int = Field(ge=0, le=100)
    riskLabel: str
    signals: list[Signal]
    recommendedActions: list[RecommendedAction]


class ReportRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    reason: str = Field(min_length=3, max_length=100)
    whySuspicious: str = Field(min_length=5, max_length=1000)
    evidence: str | None = Field(default=None, max_length=1000)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"phishing_or_scam", "malware", "impersonation", "other"}
        if normalized not in allowed:
            raise ValueError(
                "reason must be one of: phishing_or_scam, malware, impersonation, other"
            )
        return normalized

    @field_validator("whySuspicious")
    @classmethod
    def validate_why_suspicious(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 5:
            raise ValueError("whySuspicious must be at least 5 characters.")
        return normalized

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class ReportResponse(BaseModel):
    status: str
    reportId: str
    timestamp: datetime
    deduped: bool
    message: str | None = None


class DeleteReportResponse(BaseModel):
    status: str
    reportId: str


class ReportListItem(BaseModel):
    reportId: str
    timestamp: datetime
    url: str
    normalizedUrl: str
    reason: str
    reporter: str
    user: str
    whySuspicious: str
    suspiciousPercent: int = Field(ge=0, le=100)
    frequency: int = Field(ge=1)


class ReportsListResponse(BaseModel):
    items: list[ReportListItem]
    page: int
    pageSize: int
    total: int
    availableUsers: list[str] = []


class ReportDetailResponse(BaseModel):
    reportId: str
    timestamp: datetime
    url: str
    normalizedUrl: str
    reason: str
    reporter: str
    user: str
    whySuspicious: str
    evidence: str | None = None
    suspiciousPercent: int = Field(ge=0, le=100)
    frequency: int = Field(ge=1)
