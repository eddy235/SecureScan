"""v1.3 command center shell contracts."""
import httpx
import pytest

from app import main


@pytest.mark.asyncio
async def test_command_center_preserves_dashboard_hooks(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),base_url="http://testserver") as client:
        page = await client.get("/")
        assert page.status_code == 200
        for hook in ('id="form"', 'id="summary"', 'id="checks"', 'id="analytics-metrics"',
                     'id="history-list"', 'id="compare"', 'id="finding-filter"', 'id="download"'):
            assert hook in page.text
        for link in ('href="#overview"', 'href="#analytics"', 'href="#history"'):
            assert link in page.text
        assert "v1.5" in page.text
        assert '/static/app.js?v=1.5.0' in page.text
        assert (await client.get("/static/styles.css")).status_code == 200
        assert (await client.post("/api/scan", json={"url":"http://localhost:8000","authorized":True})).status_code == 403
