# SecureScan v0.5 — Safe public demonstration

Public hosting uses **synthetic, read-only demonstration data**, never an unrestricted website scanner.

## Local testing on Windows

From the project root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
$env:SECURESCAN_DEMO_MODE = "true"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. Verify that the live scan form is replaced by a demo banner, sample assessments and PDF reports work, and `POST /api/scan` returns HTTP 403.

To return to local scanner mode, stop the server and run `Remove-Item Env:SECURESCAN_DEMO_MODE` before restarting it. Do not set `ALLOW_PUBLIC_SCANS=true` on any public deployment.

## Deploy using Render (manual account actions)

1. Push this project to a `feature/v0.5-public-demo` branch and open a pull request. Wait for CI to pass; merge to `main`.
2. Sign in at https://dashboard.render.com and connect your GitHub account.
3. Select **New → Blueprint**, select `eddy235/SecureScan`, and review the `render.yaml` configuration.
4. Confirm `SECURESCAN_DEMO_MODE=true`, `ALLOW_PUBLIC_SCANS=false`, Docker runtime, and health check `/health`.
5. Create the service. Render will provide a public `.onrender.com` address once the deployment succeeds; no URL can be known in advance.
6. Verify `/api/config` reports `demo_mode: true`; check that `/api/scan` returns 403 and PDF downloads work. Do not put production secrets into repository files.

The free hosting plan and availability are subject to Render's current terms. The demo has no user login, so all sample information must remain synthetic. In a future release, production scanning will require authentication, target allowlisting, SSRF protections, rate limiting, resource limits, and audit logs.
