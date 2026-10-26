"""Release gates: public demo, authentication and conservative target controls."""
import httpx
import pytest

from app import main
from app.scanner import ScanInputError, validate_target


@pytest.mark.asyncio
async def test_public_demo_release_contract(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        health = await client.get("/health")
        assert health.status_code == 200
        config = (await client.get("/api/config")).json()
        assert config["demo_mode"] is True
        assert config["external_scanning_enabled"] is False
        assert config["live_scanning_enabled"] is False
        response = await client.post(
            "/api/scan", json={"url": "http://localhost:8000", "authorized": True}
        )
        assert response.status_code == 403
        history = (await client.get("/api/history")).json()
        assert history and all(entry["id"].startswith("demo-") for entry in history)
        pdf = await client.get("/api/history/demo-003/report.pdf")
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF")
        assert pdf.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_private_release_contract(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", False)
    monkeypatch.setenv("SECURESCAN_PRIVATE_TOKEN", "release-test-token-with-more-than-24-chars")
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for route in ("/api/history", "/api/analytics", "/api/history/any-id/report.pdf"):
            assert (await client.get(route)).status_code == 401
        bad = await client.post(
            "/api/scan", json={"url": "http://localhost:8000", "authorized": True}
        )
        assert bad.status_code == 401
        info = (await client.get("/openapi.json")).json()
        assert info["info"]["version"] == "1.0.0"


@pytest.mark.parametrize("url", (
    "http://example.org",
    "http://169.254.169.254/",
    "http://192.168.0.1/",
    "http://localhost:22",
))
def test_release_rejects_unsafe_targets(url):
    with pytest.raises(ScanInputError):
        validate_target(url)
