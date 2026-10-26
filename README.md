# SecureScan — Security Configuration Auditor

[Live read-only demo](https://securescan-demo.onrender.com/) · [Source code](https://github.com/eddy235/SecureScan)

SecureScan is a **local-first, passive website configuration auditor** built with Python, FastAPI, HTML, CSS, and JavaScript. It reviews HTTP response security headers, HTTPS configuration, and common cookie hardening controls. It is **not** a penetration test, a comprehensive vulnerability scanner, or proof that a website is secure.

## Features

- Security-header assessment (CSP, HSTS, MIME sniffing, referrer policy, frame protection, permissions policy)
- Cookie flag checks, evidence, severity, and remediation recommendations
- TLS inspection for authorized **loopback HTTPS endpoints only**, including certificate expiry classification
- Local SQLite scan history, trends, report comparison, JSON export, and PDF reports
- Bearer-token protection for private local scans, history, analytics, and reports
- Process-local scan throttling and loopback-only target validation
- Public **synthetic read-only** demonstration; visitors cannot submit live scans
- Responsive dashboard, keyboard-focus styles, and finding filters
- Automated Python tests via GitHub Actions

## Local setup (Windows PowerShell)

From the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
$env:SECURESCAN_PRIVATE_TOKEN = [BitConverter]::ToString($bytes).Replace('-', '').ToLower()
$rng.Dispose()
$env:SECURESCAN_DEMO_MODE = 'false'

.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --reload
```

Open http://127.0.0.1:8000 and paste the generated private token into the dashboard. Keep the token secret; do not commit it, put it in a URL, or publish it. Generate the token in the same shell that starts the server.

For local demonstration mode, stop the server, set `$env:SECURESCAN_DEMO_MODE = 'true'`, and restart. In this mode only synthetic reports are served.

## Public deployment

Render deployment is configured by `render.yaml` with:

- `SECURESCAN_DEMO_MODE=true`
- `ALLOW_PUBLIC_SCANS=false`

These settings **must not be changed** on the public demo. Verify `GET /api/config` reports `demo_mode: true` and `POST /api/scan` returns HTTP 403. Public history and PDF reports contain sample information only.

## API

| Route | Purpose | Private mode |
| --- | --- | --- |
| `GET /health` | Health status | Public |
| `GET /api/config` | Demo and scanning policy | Public |
| `POST /api/scan` | Authorized loopback assessment | Bearer token |
| `GET /api/history` | Saved scan list | Bearer token |
| `GET /api/history/{scan_id}` | Saved scan detail | Bearer token |
| `GET /api/analytics` | Recent scan analytics | Bearer token |
| `GET /api/history/{scan_id}/report.pdf` | Download PDF | Bearer token |

Private mode requires `Authorization: Bearer <token>`. A missing server token locks protected endpoints.

## Architecture

```text
Browser dashboard (HTML / CSS / JavaScript)
                |
           FastAPI API
          /     |     \
 Header analyzer |    PDF reporting
          |      |          |
      loopback   SQLite    ReportLab
      HTTP(S)    history
          |
   bounded TLS inspection
```

The public demo uses synthetic reports instead of scanning a remote target.

## Security boundaries and limitations

Only scan systems you own or have explicit permission to assess. This tool intentionally restricts scans to loopback destinations. External/domain scanning, unrestricted redirects, exploitation, and active vulnerability scanning are out of scope. The current process-local limiter does not provide a multi-instance quota. Authentication relies on a private bearer token rather than multi-user accounts. Production deployment with actual user data would require a separate security review, stronger isolation, secure hosting controls, and additional abuse prevention.

## Testing and roadmap

Run `python -m pytest -q`. GitHub Actions runs lint and tests on pull requests.

- v0.6: local authentication and initial TLS inspection
- v0.7: certificate-expiry classification, stronger CSP checks, and TLS PDF evidence
- v0.8: loopback target policy and private scan rate limiting
- v0.9: dashboard and documentation improvements
- v1.0: final validation, security review, and portfolio release

**Security scores measure only applicable configuration checks.**
