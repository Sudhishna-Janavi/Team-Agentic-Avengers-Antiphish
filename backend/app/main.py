from __future__ import annotations

import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    HealthResponse,
    ReportRequest,
    ReportResponse,
    ThreatIntelItem,
    UrlScanRequest,
    UrlScanResponse,
)
from .services import ThreatIntelStore, score_url

load_dotenv()

API_TITLE = os.getenv("API_TITLE", "Antiphish+ Backend API")
API_VERSION = os.getenv("API_VERSION", "0.1.0")
DEFAULT_RISK_THRESHOLD = float(os.getenv("DEFAULT_RISK_THRESHOLD", "0.70"))

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=(
        "Antiphish+ backend for phishing detection, community reports, "
        "and lightweight threat intelligence sharing."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

intel_store = ThreatIntelStore()


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc),
        version=API_VERSION,
    )


@app.post("/api/v1/scan-url", response_model=UrlScanResponse, tags=["Detection"])
def scan_url(
    payload: UrlScanRequest,
    threshold: float = Query(default=DEFAULT_RISK_THRESHOLD, ge=0.0, le=1.0),
) -> UrlScanResponse:
    scan = score_url(str(payload.url))
    verdict = scan.verdict if scan.risk_score >= threshold else "safe"
    return UrlScanResponse(
        url=payload.url,
        risk_score=scan.risk_score,
        verdict=verdict,
        threshold=threshold,
        features=scan.features,
        reasons=scan.reasons,
    )


@app.post("/api/v1/reports", response_model=ReportResponse, tags=["Community"])
def submit_report(payload: ReportRequest) -> ReportResponse:
    report_id = intel_store.add_report(payload)
    return ReportResponse(
        report_id=report_id,
        status="accepted",
        message=(
            "Report received. It can now be reviewed by bank/gov responders "
            "or used for threat intelligence."
        ),
    )


@app.get("/api/v1/intel-feed", response_model=list[ThreatIntelItem], tags=["Community"])
def intel_feed(limit: int = Query(default=20, ge=1, le=100)) -> list[ThreatIntelItem]:
    return intel_store.list_reports(limit=limit)


@app.get("/api/v1/stats", tags=["Community"])
def stats() -> dict[str, int]:
    return {"reports_total": intel_store.count()}
