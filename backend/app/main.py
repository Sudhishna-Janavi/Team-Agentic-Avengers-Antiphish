from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .models import (
    DashboardStatsResponse,
    HealthResponse,
    ReportRequest,
    ReportResponse,
    ThreatIntelItem,
    UrlScanRequest,
    UrlScanResponse,
)
from .services import ThreatIntelStore, score_url
from .storage import SQLiteStore

load_dotenv()

API_TITLE = os.getenv("API_TITLE", "Antiphish+ Backend API")
API_VERSION = os.getenv("API_VERSION", "0.1.0")
DEFAULT_RISK_THRESHOLD = float(os.getenv("DEFAULT_RISK_THRESHOLD", "0.70"))
DB_PATH = os.getenv("DB_PATH", "./data/antiphish.db")

db_dir = os.path.dirname(DB_PATH)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)
storage = SQLiteStore(DB_PATH)

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

intel_store = ThreatIntelStore(storage)


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
        explanation=scan.explanation,
    )


@app.post("/api/v1/reports", response_model=ReportResponse, tags=["Community"])
def submit_report(
    payload: ReportRequest,
) -> ReportResponse:
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
def intel_feed(
    limit: int = Query(default=20, ge=1, le=100),
) -> list[ThreatIntelItem]:
    return intel_store.list_reports(limit=limit)


@app.get("/api/v1/stats", tags=["Community"])
def stats() -> dict[str, int]:
    return {"reports_total": intel_store.count()}


@app.get("/api/v1/dashboard-stats", response_model=DashboardStatsResponse, tags=["Community"])
def dashboard_stats() -> DashboardStatsResponse:
    return intel_store.dashboard_stats()


@app.get("/api/v1/alerts/stream", tags=["Community"])
async def alerts_stream() -> StreamingResponse:
    async def event_generator():
        while True:
            try:
                alert = await asyncio.wait_for(intel_store.next_alert(), timeout=20.0)
                payload = json.dumps(alert.model_dump(), default=str)
                yield f"event: new_report\ndata: {payload}\n\n"
            except asyncio.TimeoutError:
                yield "event: ping\ndata: {}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
