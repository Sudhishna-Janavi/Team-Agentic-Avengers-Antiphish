# Antiphish+ Backend

Backend service for Antiphish+ hackathon project.

## What this backend does
- Scans URLs and returns phishing risk score + verdict
- Accepts community phishing reports
- Exposes a lightweight intel feed for responders (banks/government/partners)
- Provides auto-generated API docs via FastAPI Swagger

## Quick start

1. Create virtual environment and install dependencies:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Set environment variables:

```bash
cp .env.example .env
```

3. Run server:

```bash
uvicorn app.main:app --reload --port 8000
```

4. Open docs:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## Folder structure

```text
backend/
  app/
    __init__.py
    main.py
    models.py
    services.py
  docs/
    API.md
  requirements.txt
  .env.example
  README.md
```
