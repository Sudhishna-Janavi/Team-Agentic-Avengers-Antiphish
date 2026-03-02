# PhishGuard

Minimal anti-phishing checker for hackathon demos.

## Quick start

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Docs:
- [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

Core endpoints:
- `GET /api/health`
- `POST /api/analyze`
- `POST /api/report`

Detailed API and examples:
- [/Users/jamie/Documents/Hackaton/DLW/backend/docs/API.md](/Users/jamie/Documents/Hackaton/DLW/backend/docs/API.md)
