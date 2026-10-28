"""Dashboard smoke tests: static assets, no inline script, read-only demo."""
import httpx
import pytest
from app import main


@pytest.mark.asyncio
async def test_dashboard_assets_and_security_headers(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        page = await client.get("/")
        assert page.status_code == 200
        assert 'id="finding-filter"' in page.text
        assert '/static/filters.js' in page.text
        assert 'v1.5' in page.text
        assert "script-src 'self'" in page.headers["content-security-policy"]
        asset = await client.get("/static/filters.js")
        assert asset.status_code == 200
        assert "MutationObserver" in asset.text
        forbidden = await client.post("/api/scan", json={"url": "http://localhost:8000", "authorized": True})
        assert forbidden.status_code == 403
