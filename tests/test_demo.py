import httpx
import pytest
from app import main

@pytest.mark.asyncio
async def test_demo_is_read_only(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as client:
        cfg = (await client.get("/api/config")).json()
        assert cfg["demo_mode"] is True
        forbidden = await client.post("/api/scan", json={"url":"https://example.com","authorized":True})
        assert forbidden.status_code == 403
        hist = (await client.get("/api/history")).json()
        assert len(hist) == 3
        assert hist[0]["id"] == "demo-003"
        detail = (await client.get("/api/history/demo-003")).json()
        assert detail["score"] == 100
        assert "SYNTHETIC" in detail["note"]
        pdf = await client.get("/api/history/demo-003/report.pdf")
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF")
        analytics = (await client.get("/api/analytics")).json()
        assert analytics["total_scans"] == 3

@pytest.mark.asyncio
async def test_local_mode_is_default(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as client:
        assert (await client.get("/api/config")).json()["demo_mode"] is False
