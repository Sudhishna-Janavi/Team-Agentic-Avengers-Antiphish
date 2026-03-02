# PhishGuard Minimal API

Base URL (local): `http://127.0.0.1:8000`

## GET /api/health

Response:
```json
{ "ok": true }
```

## POST /api/analyze

Request:
```json
{ "url": "https://example.com/path?x=1" }
```

Response shape:
```json
{
  "url": "https://example.com/path?x=1",
  "normalizedUrl": "https://example.com/path?x=1",
  "timestamp": "2026-03-02T00:00:00+00:00",
  "riskScore": 18,
  "riskLabel": "low",
  "signals": [
    { "id": "https_present", "severity": "info", "message": "Uses HTTPS." }
  ],
  "recommendedActions": [
    { "id": "verify_sender", "label": "Verify the sender before sharing sensitive info." }
  ]
}
```

## POST /api/report

Request:
```json
{ "url": "https://example.com", "reason": "phishing_or_scam", "notes": "optional" }
```

Response:
```json
{ "status": "ok", "reportId": "uuid", "timestamp": "2026-03-02T00:00:00+00:00" }
```

Notes:
- Reports are saved as JSONL in `./reports/reports.jsonl`.
- Raw IP is not stored. Only salted SHA-256 hash (`clientIpHash`) is written.
- URL content is never fetched. Analysis is URL-string only.
