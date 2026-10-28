"""v1.3 progressive-enhancement and demo safety smoke checks."""
import httpx
import pytest
from app import main


@pytest.mark.asyncio
async def test_v13_ui_assets_and_readonly_demo(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),
                                 base_url="http://testserver") as client:
        page = await client.get("/")
        assert page.status_code == 200
        for asset in ("findings.js", "navigation.js", "styles.css", "app.js"):
            assert f"/static/{asset}?v=1.5.0" in page.text
            script = await client.get(f"/static/{asset}")
            assert script.status_code == 200
        findings = (await client.get("/static/findings.js")).text
        assert "aria-expanded" in findings
        assert "textContent" in findings
        assert "innerHTML" not in findings
        navigation = (await client.get("/static/navigation.js")).text
        assert "IntersectionObserver" in navigation
        assert "aria-current" in navigation
        assert "demo-assessment-button" in navigation
        assert "event.preventDefault()" in navigation
        demo_script = (await client.get("/static/demo.js")).text
        assert "button.id = 'demo-assessment-button'" in demo_script
        assert (await client.post("/api/scan", json={
            "url": "http://localhost:8000", "authorized": True
        })).status_code == 403
