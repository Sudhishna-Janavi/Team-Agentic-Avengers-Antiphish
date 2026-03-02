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
{
  "url": "https://example.com",
  "reason": "phishing_or_scam",
  "whySuspicious": "Looks like fake login page with urgent wording",
  "evidence": "optional"
}
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

Case B: Repeated report on the same URL
```json
{
  "status": "ok",
  "reportId": "new_uuid",
  "timestamp": "2026-03-02T00:00:00+00:00",
  "deduped": false,
  "message": "Report submitted. Frequency updated."
}
```

Saved report fields include: `reason`, `whySuspicious`, `evidence`, and `suspiciousPercent` (derived from analyzer risk score).

## GET /api/reports

Query params:
- `query` (optional): substring match on `url` or `normalizedUrl`
- `reason` (optional): exact reason filter
- `since` (optional): `24h`, `7d`, `all`, or ISO timestamp
- `page` (default `1`)
- `pageSize` (default `25`, max `100`)

Response:
```json
{
  "items": [
    {
      "reportId": "uuid",
      "timestamp": "2026-03-02T00:00:00+00:00",
      "url": "http://secure-bank-login.ru/verify/account",
      "normalizedUrl": "http://secure-bank-login.ru/verify/account",
      "reason": "phishing_or_scam",
      "reporter": "user",
      "user": "private",
      "whySuspicious": "Looks like fake DBS login page with urgent wording",
      "suspiciousPercent": 92,
      "frequency": 5
    }
  ],
  "page": 1,
  "pageSize": 25,
  "total": 137,
  "availableUsers": []
}
```

## GET /api/reports/{reportId}

Response:
```json
{
  "reportId": "uuid",
  "timestamp": "2026-03-02T00:00:00+00:00",
  "url": "http://secure-bank-login.ru/verify/account",
  "normalizedUrl": "http://secure-bank-login.ru/verify/account",
  "reason": "phishing_or_scam",
  "reporter": "user",
  "user": "private",
  "whySuspicious": "Looks like fake DBS login page with urgent wording",
  "evidence": "Received from SMS claiming account suspension",
  "suspiciousPercent": 92,
  "frequency": 5
}
```

Notes:
- Reports are saved as JSONL in `./reports/reports.jsonl`.
- Repeated reports are accepted and increase URL frequency.
- Raw IP is not stored. Only salted SHA-256 hash (`clientIpHash`) is written.
- URL content is never fetched. Analysis is URL-string only.
