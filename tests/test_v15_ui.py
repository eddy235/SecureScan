"""Accessibility release smoke tests for the v1.5 interface."""
import httpx
import pytest

from app import main


@pytest.mark.asyncio
async def test_v15_accessibility_and_demo_contract(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
    ) as client:
        page = await client.get("/")
        assert page.status_code == 200
        assert 'class="skip-link" href="#main-content"' in page.text
        assert 'id="main-content" tabindex="-1"' in page.text
        assert 'aria-current="location"' in page.text
        assert '/static/styles.css?v=1.5.0' in page.text
        css = (await client.get("/static/styles.css")).text
        assert ".skip-link:focus" in css
        assert "prefers-reduced-motion" in css
        assert "prefers-contrast:more" in css
        cfg = (await client.get("/api/config")).json()
        assert cfg["demo_mode"] is True
        assert cfg["external_scanning_enabled"] is False
        denied = await client.post(
            "/api/scan", json={"url": "http://localhost:8000", "authorized": True}
        )
        assert denied.status_code == 403
