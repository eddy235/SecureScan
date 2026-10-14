import httpx
import pytest
from app import main
from app.tls import inspect_tls_certificate

@pytest.mark.asyncio
async def test_private_api_fails_closed(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", False)
    monkeypatch.delenv("SECURESCAN_PRIVATE_TOKEN", raising=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as c:
        assert (await c.get('/api/history')).status_code == 503
        assert (await c.post('/api/scan', json={'url':'http://localhost:8000', 'authorized':True})).status_code == 503

@pytest.mark.asyncio
async def test_private_auth_and_read_only_demo(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", False)
    monkeypatch.setenv("SECURESCAN_PRIVATE_TOKEN", "test-token-with-at-least-24-chars")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver") as c:
        assert (await c.get('/api/history')).status_code == 401
        assert (await c.get('/api/history', headers={'Authorization':'Bearer wrong'})).status_code == 401
        assert (await c.get('/api/history', headers={'Authorization':'Bearer test-token-with-at-least-24-chars'})).status_code == 200
        assert (await c.get('/api/config')).json()['private_access_required']
        monkeypatch.setattr(main, "DEMO_MODE", True)
        assert (await c.get('/api/history')).status_code == 200
        assert (await c.post('/api/scan', json={'url':'http://localhost:8000','authorized':True},headers={'Authorization':'Bearer test-token-with-at-least-24-chars'})).status_code == 403

def test_tls_probe_never_connects_external():
    assert inspect_tls_certificate('https://example.com')['status'] == 'Not inspected'
    assert inspect_tls_certificate('http://localhost:8000')['status'] == 'Not applicable'
