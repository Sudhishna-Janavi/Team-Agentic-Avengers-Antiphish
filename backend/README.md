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

## Tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```
