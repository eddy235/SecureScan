# SecureScan — Website Security Auditor (MVP)

A portfolio project implementing **passive** website configuration checks using FastAPI, httpx, and a responsive vanilla JavaScript dashboard.

## Features
- Human-readable security header checklist (HSTS, CSP, nosniff, Referrer Policy, Permissions Policy, frame protections)
- HTTPS presence, HTTP status, and a **heuristic** score (not a guarantee of safety)
- JSON report export from the web interface
- Authorization confirmation before scans
- Localhost-only scanning by default; no redirect following
- Swagger API at `/docs`, health check at `/health`

## Run locally (Windows PowerShell)
```powershell
cd securescan_mvp
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open **http://localhost:8000**, tick the permission box, and scan **http://localhost:8000**. Local HTTP intentionally gets a low score: it is a demo of missing hardening measures.

On macOS/Linux, activate using `source .venv/bin/activate`.

## Run tests
```bash
pytest -q
```

## Docker
```bash
docker build -t securescan .
docker run --rm -p 8000:8000 securescan
```
Note: from inside Docker, `localhost` refers to the container. Accessing the host or other containers requires intentional network setup.

## External websites (authorized targets only)
For a privately run local instance, start with `ALLOW_PUBLIC_SCANS=true` after confirming you own or have written authorization to assess the target. Do **not** expose this mode as a public unrestricted scanner. The current implementation checks DNS addresses but does not pin resolved IPs against DNS rebinding; it is not hardened for untrusted multi-user deployment.

## Scope and limitations
This is **not** a vulnerability scanner or a penetration-testing tool. It does not test for SQL injection, XSS, exploitable vulnerabilities, or CVEs. Security-header checks detect presence, not complete policy correctness. The rating is illustrative and not a formal risk assessment. There is no persistent database or user login in this first milestone.

## Next milestones
1. Validate header values and cookie attributes; handle redirects with per-hop address verification.
2. Add SSL certificate expiry checks and severity taxonomy.
3. Add SQLite scan history and export to PDF.
4. Add automated CI, dependency security scanning and deployment hardening.
5. Add cloud deployment behind authentication and rate limiting.

## Suggested GitHub repo
`securescan-web-auditor` — include screenshots and a brief write-up about architecture, security boundaries and lessons learned.

## Version 0.2 update

The v0.2 scanner validates *values* of CSP, HSTS, X-Frame-Options, X-Content-Type-Options and Referrer-Policy rather than just presence. It also evaluates Set-Cookie attributes individually and includes evidence, status and severity in the existing JSON report format. A local loopback HTTP development server has HTTPS marked **Not applicable**, avoiding a misleading production HTTPS failure. The displayed score is the percentage of applicable configuration checks passed, not a quantified measure of compromise or real-world vulnerability risk.

This checker remains passive, and HTTPS is verified by the HTTP client when used. **TLS certificate expiration reporting is not implemented yet.** Public-target support requires additional DNS rebinding / connection pinning defenses before safe exposure as a multiuser web service. For now, keep `ALLOW_PUBLIC_SCANS=false` and bind your development server to localhost only.

To upgrade: back up your v0.1 folder, then replace its source files with this release; use the same setup and startup commands. Run `python -m pytest -q` after installing requirements.


## v0.3 — Self-hardening and scan history

- Security headers added on all responses; CSP requires external stylesheet and JS (no inline code).
- Local SQLite history saved in `~/.securescan/history.sqlite3` by default. Override with `SECURESCAN_DB` environment variable before startup.
- `GET /api/history?limit=20` lists recent scan metadata; `GET /api/history/{id}` retrieves a full report.
- Dashboard shows recent scans and compares a prior scan to the current one for the same URL.
- The security score is a **configuration compliance score**, not a penetration-testing risk measure.
- History endpoints have **no authentication**; keep the service bound to localhost and don't deploy this edition publicly.
- `ALLOW_PUBLIC_SCANS=true` is not recommended: v0.3 does not pin DNS resolution to outbound connections or provide production-grade SSRF protection.

### Windows upgrade (from extracted project folder)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1
```

Run two scans of `http://127.0.0.1:8000`, then click **Compare** on an earlier scan. To compare against v0.2, import isn't yet provided; use the two existing JSON reports manually.
