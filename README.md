# Antiphish+ (Team Agentic Avengers)

Antiphish+ is a digital safety platform that helps users detect suspicious URLs, submit phishing reports, and support responder intelligence through a shared threat feed.

## Who this app is for
- Residents and students who want safer browsing
- Bank fraud teams monitoring suspicious campaigns
- Government/first-responder teams triaging public reports
- Community partners supporting cyber awareness

## What users can do
1. Scan URLs for phishing risk and explanations
2. Submit suspicious URLs (optionally include reporter name)
3. View community intelligence feed and responder dashboard
4. See live report alerts in real time (SSE stream)

## Key features
- Explainable phishing scoring with reasons and confidence
- Community reporting with optional reporter attribution
- Real-time alert stream for new reports
- Responder analytics dashboard (top domains, reporter mix, hourly trend)
- Mobile-friendly frontend

## Run locally

### Backend
```bash
cd /Users/sudhishna/Desktop/DLW-Hackathon/Team-Agentic-Avengers-Antiphish/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd /Users/sudhishna/Desktop/DLW-Hackathon/Team-Agentic-Avengers-Antiphish/frontend
python3 -m http.server 5173
```

Open:
- Frontend: `http://127.0.0.1:5173`
- Backend docs: `http://127.0.0.1:8000/docs`

## User guide (quick)
- Paste a URL in scanner and click **Analyze**.
- If suspicious, click **Report This URL** to submit a community report.
- Add your name in report form if you want attribution; leave empty for anonymous.

## Data persistence
- Uses SQLite (`backend/data/antiphish.db`) so reports survive backend restarts.

## API overview
- `POST /api/v1/scan-url`
- `POST /api/v1/reports`
- `GET /api/v1/intel-feed`
- `GET /api/v1/dashboard-stats`
- `GET /api/v1/alerts/stream`
