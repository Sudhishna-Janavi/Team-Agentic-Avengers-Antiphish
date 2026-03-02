# Antiphish+ Backend

Python 3.12 / FastAPI backend for the Antiphish+ platform.  
Deployed on **Render**: https://team-agentic-avengers-antiphish.onrender.com

## Principles
- No database — reports stored in JSONL files on disk
- No Docker required
- No URL content fetching (no SSRF risk)
- Stable API response shapes for frontend integration

## Dependencies
- `fastapi==0.115.8` — API framework
- `uvicorn[standard]==0.34.0` — ASGI server
- `pydantic==2.10.6` — request/response validation
- `python-dotenv==1.0.1` — environment variable handling
- `pytest==8.3.4` — testing

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Run Locally

```bash
uvicorn app.main:app --reload --port 8000
```

API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Production

- Deployed on Render at: https://team-agentic-avengers-antiphish.onrender.com
- API docs: https://team-agentic-avengers-antiphish.onrender.com/docs

## Endpoints
- `GET /api/health`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `POST /api/analyze`
- `POST /api/report`
- `GET /api/reports` (filter + pagination)
- `GET /api/reports/{reportId}`
- `DELETE /api/reports/{reportId}` (admin only)

## Community reporting fields
`POST /api/report` accepts:
- `url`
- `reason` (`phishing_or_scam | malware | impersonation | other`)
- `whySuspicious` (required, min length 5)
- `evidence` (optional)

Each report stores `suspiciousPercent` computed from analyzer risk score (`riskScore`).
Repeated reports on the same URL are accepted and contribute to URL `frequency` in the community feed.

## Login roles
- `user`: can add reports
- `admin`: can add reports and remove reports from feed

Configure credentials in `.env`:
- `USER_LOGIN_EMAIL`, `USER_LOGIN_PASSWORD` (default seeded user)
- `ADMIN_LOGIN_EMAIL`, `ADMIN_LOGIN_PASSWORD` (default seeded admin)
- `POST /api/auth/signup` also allows creating additional user accounts (role=`user`)

## Feed filtering and pagination
`GET /api/reports` supports:
- `query`: URL/domain substring search
- `reason`: exact reason filter
- `since`: `24h`, `7d`, `all`, or ISO timestamp
- `page` / `pageSize`

## Frontend pages
- Scanner page: `/`
- Community feed page: `/feed/`

## Data Storage
- Reports are stored in `reports.jsonl` inside the data directory
- Deleted reports tracked in `deleted_reports.jsonl`
- No external database required

## Tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```
