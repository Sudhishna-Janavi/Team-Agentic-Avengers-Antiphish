from __future__ import annotations

from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import Settings, from_env
from .models import AnalyzeRequest, AnalyzeResponse, ReportRequest, ReportResponse
from .rate_limit import InMemoryRateLimiter
from .reporting import JsonlReportStore
from .scoring import analyze_url, normalize_url

load_dotenv()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def create_app(settings: Settings | None = None, now_provider=None) -> FastAPI:
    cfg = settings or from_env()

    app = FastAPI(
        title="PhishGuard Minimal API",
        version="1.0.0",
        description="Lightweight anti-phishing checker. No DB required.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    limiter = InMemoryRateLimiter(
        max_requests=cfg.rate_limit_requests,
        window_seconds=cfg.rate_limit_window_seconds,
    )
    report_store = JsonlReportStore(
        reports_dir=cfg.reports_dir,
        salt=cfg.report_ip_hash_salt,
        dedupe_seconds=cfg.report_dedupe_seconds,
        now_provider=now_provider,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "detail": "Invalid request body.",
                "errors": exc.errors(),
            },
        )

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        if request.url.path in {"/api/analyze", "/api/report"}:
            ip = _client_ip(request)
            if not limiter.allow(ip):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please try again shortly."},
                )
        return await call_next(request)

    @app.get("/api/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/api/analyze", response_model=AnalyzeResponse)
    def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
        try:
            result = analyze_url(payload.url, suspicious_tlds=cfg.suspicious_tlds)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err

        return AnalyzeResponse(
            url=result.original_url,
            normalizedUrl=result.normalized_url,
            timestamp=datetime.now(timezone.utc),
            riskScore=result.risk_score,
            riskLabel=result.risk_label,
            signals=result.signals,
            recommendedActions=result.recommended_actions,
        )

    @app.post("/api/report", response_model=ReportResponse)
    def report(payload: ReportRequest, request: Request) -> ReportResponse:
        try:
            normalized_url, _ = normalize_url(payload.url)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err

        result = report_store.write_report(
            payload=payload,
            normalized_url=normalized_url,
            client_ip=_client_ip(request),
        )
        return ReportResponse(
            status=result.status,
            reportId=result.report_id,
            timestamp=result.timestamp,
            deduped=result.deduped,
            message=result.message,
        )

    return app


app = create_app()
