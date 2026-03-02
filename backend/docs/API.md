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

Case A: New report
```json
{
  "status": "ok",
  "reportId": "uuid",
  "timestamp": "2026-03-02T00:00:00+00:00",
  "deduped": false
}
```

Case B: Existing recent report (deduped)
```json
{
  "status": "exists",
  "reportId": "uuid_of_existing",
  "timestamp": "2026-03-02T00:00:00+00:00",
  "deduped": true,
  "message": "This URL was already reported recently."
}
```

Notes:
- Reports are saved as JSONL in `./reports/reports.jsonl`.
- Dedupe key is canonical `normalizedUrl`.
- Default dedupe window: `REPORT_DEDUPE_SECONDS=86400` (24h).
- Raw IP is not stored. Only salted SHA-256 hash (`clientIpHash`) is written.
- URL content is never fetched. Analysis is URL-string only.
