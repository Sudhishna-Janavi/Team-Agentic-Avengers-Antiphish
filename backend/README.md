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
- `GET /api/reports` (filter + pagination)
- `GET /api/reports/{reportId}`

## Dedupe behavior for reports
- Reports are idempotent by canonical `normalizedUrl`.
- Default dedupe window is 24 hours (`REPORT_DEDUPE_SECONDS=86400`).
- If the same URL is reported again within the window, API returns `status="exists"` and does not create a new row.

## Feed filtering and pagination
`GET /api/reports` supports:
- `query`: URL/domain substring search
- `reason`: exact reason filter
- `since`: `24h`, `7d`, `all`, or ISO timestamp
- `page` / `pageSize`

## Frontend pages
- Scanner page: `/`
- Community feed page: `/feed/`

## Tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```
