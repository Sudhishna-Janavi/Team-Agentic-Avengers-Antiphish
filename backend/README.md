# PhishGuard Backend (Minimal MVP)

This backend is intentionally simple and reliable for hackathon use.

## Principles
- No database
- No Docker required
- No URL content fetching (no SSRF risk)
- Stable API response shapes for frontend integration

## Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Run

```bash
uvicorn app.main:app --reload --port 8000
```

Open docs at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Endpoints
- `GET /api/health`
- `POST /api/analyze`
- `POST /api/report`

## Dedupe behavior for reports
- Reports are idempotent by canonical `normalizedUrl`.
- Default dedupe window is 24 hours (`REPORT_DEDUPE_SECONDS=86400`).
- If the same URL is reported again within the window, API returns `status="exists"` and does not create a new row.

## curl examples

Health:
```bash
curl http://127.0.0.1:8000/api/health
```

Analyze:
```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/path?x=1"}'
```

Report:
```bash
curl -X POST http://127.0.0.1:8000/api/report \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","reason":"phishing_or_scam","notes":"optional"}'
```

## How scoring works (deterministic heuristics)

The engine normalizes the URL and scores based on explainable signals:
- scheme (`http` vs `https`)
- IP address hostname
- suspicious TLD
- many subdomains
- very long URL
- deceptive keywords (`login`, `verify`, `secure`, etc.)
- `@` in URL
- punycode (`xn--`)
- unusual ports
- double encoding patterns
- simple lookalike checks against: `google.com`, `apple.com`, `microsoft.com`, `paypal.com`

Response always includes:
- `riskScore` (0-100)
- `riskLabel` (`low`/`medium`/`high`)
- `signals[]` with human-readable reasons
- `recommendedActions[]`

## Reports storage

Reports are appended to newline-delimited JSON at:
- `./reports/reports.jsonl`

If client IP is recorded, only salted hash is stored (`clientIpHash`), not raw IP.

## Tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```
