from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


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
    notes: str | None = Field(default=None, max_length=1000)

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


class ReportResponse(BaseModel):
    status: str
    reportId: str
    timestamp: datetime
    deduped: bool
    message: str | None = None


class ReportListItem(BaseModel):
    reportId: str
    timestamp: datetime
    url: str
    normalizedUrl: str
    reason: str
    reporter: str
    user: str


class ReportsListResponse(BaseModel):
    items: list[ReportListItem]
    page: int
    pageSize: int
    total: int


class ReportDetailResponse(BaseModel):
    reportId: str
    timestamp: datetime
    url: str
    normalizedUrl: str
    reason: str
    reporter: str
    user: str
    notes: str | None = None
