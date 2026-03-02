# Antiphish+ Frontend

Static HTML/CSS/JS frontend for the Antiphish+ platform.  
Deployed on **Netlify**.

## Pages
- `/` — scanner page + community report modal
- `/feed/` — community feed with search, filters, pagination, and detail modal

## Reporting UX
- Login is required to submit reports.
- Report modal fields:
  - Reason/category (`phishing_or_scam`, `malware`, `impersonation`, `other`)
  - Why is this suspicious? (required)
  - Evidence (optional)

## Login roles
- `user`: submit reports
- `admin`: submit reports + delete reports in `/feed/`

## Run Locally

```bash
cd frontend
python3 -m http.server 5173
```

Open:
- Scanner: [http://127.0.0.1:5173/](http://127.0.0.1:5173/)
- Community Feed: [http://127.0.0.1:5173/feed/](http://127.0.0.1:5173/feed/)

Backend expected at `http://127.0.0.1:8000` for local development.

## Deploy Config

The frontend API base URL is defined in [config.js](config.js):

```js
window.__ANTIPHISH_CONFIG__ = {
  API_BASE: "https://team-agentic-avengers-antiphish.onrender.com",
};
```

## Deployment (Netlify)
1. Import the GitHub repo in Netlify.
2. Set **Base directory** to `frontend`.
3. Set **Publish directory** to `frontend`.
4. Deploy.
5. Ensure `config.js` points to the Render backend URL above.
