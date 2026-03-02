# Antiphish+ API Plan

This file is the backend API planning document for team integration.

## API goals
- Give frontend/extension a single place to request phishing verdicts
- Collect user reports to support community intelligence
- Provide responder-friendly feed for triage and analysis

## Base URL
- Local: `http://127.0.0.1:8000`
- Version prefix: `/api/v1`

## Endpoint contracts

### 1) Health check
- Method: `GET`
- Path: `/health`
- Purpose: Monitoring / demo reliability check

Example response:
```json
{
  "status": "ok",
  "timestamp": "2026-03-02T07:31:00.000000+00:00",
  "version": "0.1.0"
}
```

### 2) URL scan
- Method: `POST`
- Path: `/api/v1/scan-url`
- Query params:
  - `threshold` (optional float 0-1, default from env)
- Purpose: Main detection endpoint for frontend + extension

Request:
```json
{
  "url": "https://secure-login-example.com/account/verify",
  "source": "extension"
}
```

Response:
```json
{
  "url": "https://secure-login-example.com/account/verify",
  "risk_score": 0.9132,
  "verdict": "likely_phishing",
  "threshold": 0.7,
  "features": {
    "url_length": 56,
    "subdomain_count": 1,
    "has_ip_in_domain": false,
    "special_char_count": 3,
    "suspicious_keyword_hits": 2,
    "uses_https": true
  },
  "reasons": [
    "Suspicious keywords present in URL"
  ]
}
```

### 3) Community report submission
- Method: `POST`
- Path: `/api/v1/reports`
- Purpose: Collect phishing reports for intel pipeline

Request:
```json
{
  "url": "http://example-scam.site/login",
  "reason": "Pretending to be DBS login page",
  "reporter_type": "user",
  "evidence": "Received via SMS"
}
```

Response:
```json
{
  "report_id": "rep_a1b2c3d4e5",
  "status": "accepted",
  "message": "Report received. It can now be reviewed by bank/gov responders or used for threat intelligence."
}
```

### 4) Intel feed
- Method: `GET`
- Path: `/api/v1/intel-feed`
- Query params:
  - `limit` (optional int 1-100, default 20)
- Purpose: Share latest reports with responder dashboard

### 5) Stats
- Method: `GET`
- Path: `/api/v1/stats`
- Purpose: Basic operational metric for demo/pitch

## Team integration notes

- Frontend should call `POST /api/v1/scan-url` when user pastes URL.
- AI/extension can use same route for real-time warning display.
- Report button should call `POST /api/v1/reports` after warning.
- Pitch angle: aggregated reports become actionable intelligence for first responders and financial institutions.

## Next improvements after MVP
- Persist reports in PostgreSQL
- Add auth + API keys for partner access
- Add async queue for model inference
- Replace heuristic scoring with trained RandomForest model endpoint
- Add URL reputation enrichment (VirusTotal / ScamShield integrations)
