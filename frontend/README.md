# Antiphish+ Frontend

Creative demo frontend for Antiphish+.

## Features
- Interactive URL scanner with visual risk gauge
- Community report modal flow
- Live intel feed table
- API health/status indicators
- Mobile-friendly responsive layout

## Run

1. Start backend first:

```bash
cd /Users/sudhishna/Desktop/DLW-Hackathon/Antiphish/backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

2. In another terminal, run frontend static server:

```bash
cd /Users/sudhishna/Desktop/DLW-Hackathon/Antiphish/frontend
python3 -m http.server 5173
```

3. Open:
- `http://127.0.0.1:5173`

The frontend calls backend at `http://127.0.0.1:8000`.
