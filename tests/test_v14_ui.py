"""Release smoke checks for real-data activity and severity filtering."""
import httpx
import pytest
from app import main


@pytest.mark.asyncio
async def test_v14_activity_filter_assets_and_demo_safety(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),
                                 base_url="http://testserver") as client:
        page = await client.get("/")
        assert page.status_code == 200
        assert 'id="recent-activity"' in page.text
        assert 'id="severity-filter"' in page.text
        assert "/static/overview.js?v=1.4.0" in page.text
        assert "/static/filters.js?v=1.4.0" in page.text
        overview = (await client.get("/static/overview.js")).text
        assert "renderActivity(history)" in overview
        assert "textContent" in overview
        filters = (await client.get("/static/filters.js")).text
        assert "check?.severity" in filters
        assert "check?.status" in filters
        assert "innerHTML" not in filters
        assert (await client.post("/api/scan", json={
            "url": "http://localhost:8000", "authorized": True
        })).status_code == 403
