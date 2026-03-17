# WebScanner v2

A security scanner web app that audits any URL for common vulnerabilities and misconfigurations.

## What it checks

| Category | Checks |
|---|---|
| TLS / HTTPS | HTTPS enforcement, TLS version, certificate expiry, self-signed cert |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORP, COOP |
| Cookie flags | Secure, HttpOnly, SameSite per cookie |
| Information disclosure | Server/X-Powered-By headers, exposed `.env`, `.git`, config files |
| Redirect chain | HTTPS→HTTP downgrade detection, redirect loops |

Every issue gets a **severity rating** (critical / high / medium / low / info), a plain-English description, and a specific fix.

## Quickstart

```bash
# 1. Create virtual environment
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python app.py

# 4. Open http://127.0.0.1:5000
```

## Docker

```bash
docker-compose up --build
```

## File structure

```
webscanner/
├── app.py                  # Flask routes
├── scanner.py              # Scanning engine
├── database.py             # SQLite helpers
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
└── app/
    ├── static/css/
    │   └── style.css       # Dark industrial theme
    └── templates/
        ├── base.html       # Shared layout
        ├── index.html      # Home / scan form
        ├── results.html    # Scan results page
        └── history.html    # Scan history table
```

## API

```
POST /api/scan        { "url": "https://example.com" }  → full scan result JSON
GET  /api/stats       → aggregate stats across all scans
GET  /api/history     → list of all scans
```

## Important

Only scan websites you own or have explicit permission to test.

## Notes

- SQLite is used for simplicity. For production, switch to PostgreSQL with SQLAlchemy.
- No rate limiting is included in this starter — add `flask-limiter` before deploying publicly.
