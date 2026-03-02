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
  ],
  "explanation": {
    "summary": "High-confidence phishing pattern detected. Block and report this URL.",
    "confidence": 0.9132,
    "contributors": [
      {
        "signal": "suspicious_keywords",
        "impact": "high",
        "weight": 1.0,
        "note": "Urgent account/security terms are common phishing bait"
      }
    ]
  }
}
```

Explanation fields:
- `summary`: human-readable explanation for non-technical users
- `confidence`: confidence score for this verdict (0 to 1)
- `contributors`: top weighted signals for explainability panel

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
  "reporter_name": "Sudhishna",
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

### 6) Dashboard analytics
- Method: `GET`
- Path: `/api/v1/dashboard-stats`
- Purpose: Aggregated responder dashboard insights

Response:
```json
{
  "reports_total": 42,
  "reporters": [
    { "reporter_type": "user", "count": 35 },
    { "reporter_type": "bank", "count": 7 }
  ],
  "top_domains": [
    { "domain": "fake-login-verify.com", "count": 10 }
  ],
  "hourly_trend": [
    { "hour_utc": "2026-03-02 09:00", "count": 5 }
  ]
}
```

### 7) Real-time alert stream (SSE)
- Method: `GET`
- Path: `/api/v1/alerts/stream`
- Purpose: Push new report events to frontend instantly
- Content-Type: `text/event-stream`

## Team integration notes

- Frontend should call `POST /api/v1/scan-url` when user pastes URL.
- AI/extension can use same route for real-time warning display.
- Report button should call `POST /api/v1/reports` after warning.
- Pitch angle: aggregated reports become actionable intelligence for first responders and financial institutions.

## Next improvements after MVP
- Persist reports in PostgreSQL
- Add API keys for partner access
- Add async queue for model inference
- Replace heuristic scoring with trained RandomForest model endpoint
- Add URL reputation enrichment (VirusTotal / ScamShield integrations)
