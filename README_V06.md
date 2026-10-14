# SecureScan v0.6 - Private Access + TLS Foundations

Upgrade from v0.5, preserving the read-only Render demo. Changes:
- Private local API access via a bearer token; missing token fails closed (HTTP 503).
- Token passed in browser memory (not saved to local storage or cookies).
- TLS certificate inspection for loopback HTTPS endpoints only, with certificate validation.
- External scanning deliberately disabled, even if ALLOW_PUBLIC_SCANS is set, pending stronger SSRF protections.
- Existing demo endpoints stay synthetic and unauthenticated; POST /api/scan remains HTTP 403.

## Windows local installation

From the project root in PowerShell, generate a random token:

```powershell
$env:SECURESCAN_PRIVATE_TOKEN = ([Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))).ToLower()
$env:SECURESCAN_DEMO_MODE = 'false'
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1
```

In your browser at http://127.0.0.1:8000, paste the value of `$env:SECURESCAN_PRIVATE_TOKEN` (show it in another PowerShell terminal using that expression). Do not commit or share your token. Note that PowerShell environment variables exist only in the terminal session where they were set. Keep the server bound to 127.0.0.1.

## Deployment safeguards

Do not update Render to allow live scanning. Preserve `SECURESCAN_DEMO_MODE=true` and `ALLOW_PUBLIC_SCANS=false`. The demo can be visited without an access token, but its scan POST endpoint is blocked. For now v0.6 is a **local private beta**; public production-grade live scanning would require DNS pinning, per-user authentication, rate limits, network egress restrictions, and external penetration review.

## GitHub upgrade

Create `feature/v0.6-private-security` from main, copy changed files, run tests, push, and open a PR. Do not commit `.env`, local SQLite databases, tokens, or `.venv`.
