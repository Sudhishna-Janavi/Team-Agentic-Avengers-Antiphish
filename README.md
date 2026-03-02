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

In a second terminal:

```bash
cd frontend
python -m http.server 5173
```

Pages:
- Scanner: [http://127.0.0.1:5173/](http://127.0.0.1:5173/)
- Community Feed: [http://127.0.0.1:5173/feed/](http://127.0.0.1:5173/feed/)
- API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

Core endpoints:
- `GET /api/health`
- `POST /api/analyze`
- `POST /api/report`
- `GET /api/reports`
- `GET /api/reports/{reportId}`

Detailed API and examples:
- [backend/docs/API.md](/Users/sudhishna/Desktop/DLW-Hackathon/Team-Agentic-Avengers-Antiphish-main/backend/docs/API.md)

## Deploy (Public URLs)

### 1) Deploy backend on Render
1. Push this repo to GitHub.
2. In Render, click **New +** -> **Blueprint** and select this repo.
3. Render will read `render.yaml` and create `antiphish-backend`.
4. After deploy, copy backend URL, e.g. `https://antiphish-backend.onrender.com`.
5. In Render service settings, update:
   - `CORS_ORIGINS=https://<your-frontend-domain>,http://127.0.0.1:5173`

### 2) Deploy frontend on Vercel
1. In Vercel, import the same GitHub repo.
2. Set **Root Directory** to `frontend`.
3. Deploy.
4. You will get URL like `https://your-project.vercel.app`.

### 3) Connect frontend to backend
1. Edit [frontend/config.js](/Users/sudhishna/Desktop/DLW-Hackathon/Team-Agentic-Avengers-Antiphish-main/frontend/config.js):
   - `API_BASE: "https://<your-render-backend>.onrender.com"`
2. Commit and push again so Vercel updates.
3. Confirm in browser:
   - `https://<your-vercel-domain>/`
   - `https://<your-vercel-domain>/feed/`
