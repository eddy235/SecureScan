# SecureScan v0.4

Local-first, passive security configuration auditor built with FastAPI. **Use only for systems you own or are authorized to assess.**

## New in v0.4

- Security analytics: score trends, unique targets, mean score, severity counts (last 100 scans)
- Searchable and sortable history (up to 100 saved assessments)
- Downloadable PDF report for each saved scan, with evidence and remediation
- Preserves v0.3 database and API formats
- Automated test coverage and GitHub Actions integration

## Windows installation

Open this `securescan_mvp` folder in VS Code, then run in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1
```

Open http://127.0.0.1:8000 and scan your localhost application. Scans are saved to `~/.securescan/history.sqlite3`. The PDF action appears on each saved scan in history. Scan once, then refresh and compare.

## Git workflow

```powershell
git checkout -b feature/v0.4-analytics-pdf
# Copy updated application files from this package into your existing Git checkout
python -m pytest -q
git add .
git commit -m "Add analytics dashboard and PDF reporting"
git push -u origin feature/v0.4-analytics-pdf
```

Open a pull request against `main`. After GitHub Actions passes, merge it. **Do not overwrite your `.git` folder when copying the files.**

## Routes

- `GET /health` health check
- `POST /api/scan` perform authorized scan
- `GET /api/history?limit=100` recent saved scans
- `GET /api/history/{scan_id}` saved scan details
- `GET /api/analytics?limit=100` aggregate recent scan results
- `GET /api/history/{scan_id}/report.pdf` generate a PDF from saved scan

## Security limits

This is a developer-only local application. Saved scan reports and analytics are **not authenticated**. Keep it bound to `127.0.0.1` and do not deploy publicly until authentication, network protections, and scan authorization are implemented. External scanning is disabled by default. Scores represent a limited configuration checklist, not proof of application security. Local development HTTP and HSTS are not scored as production failures.
