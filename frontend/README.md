# Antiphish+ Frontend

## Pages
- `/` scanner page + anonymous community report modal
- `/feed/` community feed with:
  - URL/domain search
  - reason filter
  - time filter
  - user filter
  - pagination
  - row detail modal

## Reporting UX
- Reports are anonymous.
- Report modal fields:
  - Reason/category (`phishing_or_scam`, `malware`, `impersonation`, `other`)
  - Why is this suspicious? (required)
  - Evidence (optional)

## Run

```bash
cd /Users/jamie/Documents/Hackaton/DLW/frontend
python -m http.server 5173
```

Open:
- `http://127.0.0.1:5173/`
- `http://127.0.0.1:5173/feed/`

Backend expected at `http://127.0.0.1:8000`.
