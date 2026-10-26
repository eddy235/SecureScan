from __future__ import annotations
import os
import secrets
import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Depends
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .scanner import ScanInputError, scan
from .tls import inspect_tls_certificate
from .ratelimit import scan_limiter
from .history import save_scan, list_scans, get_scan, analytics
from .reports import build_pdf
from .demo import demo_history, demo_detail, demo_analytics, demo_scan

DEMO_MODE = os.getenv("SECURESCAN_DEMO_MODE", "false").lower() == "true"

app = FastAPI(title="SecureScan", version="0.8.0", description="Passive permission-based security configuration checks")
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

# Applied to the dashboard and API responses. CSP works because CSS/JS are separate same-origin files.
@app.middleware("http")
async def harden_response(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Frame-Options"] = "DENY"
    # HSTS only on HTTPS. Never set it unconditionally for local HTTP development.
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

def private_access(request: Request):
    """Restrict non-demo scan records to a configured bearer token."""
    if DEMO_MODE:
        return
    expected = os.getenv("SECURESCAN_PRIVATE_TOKEN", "")
    if len(expected) < 24:
        raise HTTPException(503, "Private API locked: configure SECURESCAN_PRIVATE_TOKEN (at least 24 characters).")
    supplied = request.headers.get("authorization", "")
    scheme, _, token = supplied.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token, expected):
        raise HTTPException(401, "Private access token required", headers={"WWW-Authenticate": "Bearer"})

class ScanRequest(BaseModel):
    url: str = Field(min_length=10, max_length=2048)
    authorized: bool = False

@app.get("/")
def home():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))

@app.get("/health")
def health():
    return {"status": "ok", "app": "SecureScan"}

@app.post("/api/scan")
async def check_website(payload: ScanRequest, _=Depends(private_access)):
    if DEMO_MODE:
        raise HTTPException(403, "Public demo: live scanning is disabled. Explore synthetic reports below.")
    if not payload.authorized:
        raise HTTPException(400, "Confirm you own the target or have permission to assess it.")
    if not scan_limiter.allow():
        raise HTTPException(429, "Scan request limit reached. Retry shortly.", headers={"Retry-After": "60"})
    try:
        # This version intentionally permits loopback targets only, including in local mode.
        # DNS rebinding-safe external scanning requires an independent security review.
        result = await scan(payload.url, allow_public=False)
        if result["url"].startswith("https://"):
            result["tls"] = inspect_tls_certificate(result["url"])
        return save_scan(result)
    except ScanInputError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (httpx.RequestError, ValueError):
        raise HTTPException(502, "Could not fetch the target. Confirm it is reachable and try again.")

@app.get('/api/history')
def history(limit: int = Query(default=20, ge=1, le=100), _=Depends(private_access)):
    return demo_history(limit) if DEMO_MODE else list_scans(limit)

@app.get('/api/history/{scan_id}')
def history_detail(scan_id: str, _=Depends(private_access)):
    result = demo_detail(scan_id) if DEMO_MODE else get_scan(scan_id)
    if result is None:
        raise HTTPException(404, 'Scan not found')
    return result


@app.get('/api/analytics')
def scan_analytics(limit: int = Query(default=100, ge=1, le=500), _=Depends(private_access)):
    return demo_analytics(limit) if DEMO_MODE else analytics(limit)

@app.get('/api/history/{scan_id}/report.pdf')
def report_pdf(scan_id: str, _=Depends(private_access)):
    result = demo_detail(scan_id) if DEMO_MODE else get_scan(scan_id)
    if result is None:
        raise HTTPException(404, 'Scan not found')
    return Response(content=build_pdf(result), media_type='application/pdf', headers={'Content-Disposition': f'attachment; filename="securescan-{scan_id}.pdf"', 'Cache-Control':'no-store'})

@app.get("/api/config")
def config():
    return {"demo_mode": DEMO_MODE, "live_scanning_enabled": not DEMO_MODE and len(os.getenv("SECURESCAN_PRIVATE_TOKEN", "")) >= 24, "private_access_required": not DEMO_MODE, "external_scanning_enabled": False}
