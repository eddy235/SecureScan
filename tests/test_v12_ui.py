"""Verify the v1.3 intelligence dashboard remains data-driven and demo-safe."""
import httpx
import pytest
from app import main


@pytest.mark.asyncio
async def test_overview_ui_and_assets(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),
                                 base_url="http://testserver") as client:
        response = await client.get("/")
        assert response.status_code == 200
        for identifier in ("overview-score", "overview-gauge", "overview-total",
                           "overview-open", "overview-targets", "overview-tls-content"):
            assert 'id="' + identifier + '"' in response.text
        assert '/static/overview.js?v=1.3.1' in response.text
        script = await client.get("/static/overview.js?v=1.3.1")
        assert script.status_code == 200
        assert "getJSON('/api/analytics')" in script.text
        assert "getJSON('/api/history?limit=100')" in script.text
        assert "textContent" in script.text
        config = (await client.get("/api/config")).json()
        assert config["demo_mode"] is True
        assert config["external_scanning_enabled"] is False
        assert (await client.post("/api/scan", json={
            "url": "http://localhost:8000", "authorized": True
        })).status_code == 403
