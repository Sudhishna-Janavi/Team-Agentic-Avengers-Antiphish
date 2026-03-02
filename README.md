# How to Run the Project

From your project folder:

```sh
cd /Users/jamie/Documents/Hackaton/DLW
open index.html
```

If `open` doesn’t work on your machine, use:

```sh
cd /Users/jamie/Documents/Hackaton/DLW
python3 -m http.server 8080
```

Then open your browser and go to [http://localhost:8080](http://localhost:8080)
# PhishGuard UI Prototype

Lightweight phishing-detection web UI prototype.

## Run locally

1. Open `/Users/jamie/Documents/Hackaton/DLW/login.html` in a browser.
2. Log in with any email and a password that is at least 8 characters.
3. Paste a URL and click **Check Link Safety**.

## Files

- `login.html` - login page UI
- `login.js` - login validation and sign-in flow
- `auth.js` - shared client-side auth helpers and route guard
- `index.html` - app structure and content
- `styles.css` - visual design, layout, responsiveness, accessibility styles
- `script.js` - demo analysis flow, risk scoring presets, explainable reasons, report feedback
