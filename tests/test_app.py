import asyncio
from unittest.mock import AsyncMock, patch
import httpx
import pytest
from app import history
from app.main import app
from app.scanner import analyze_headers

@pytest.fixture
def configured_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURESCAN_PRIVATE_TOKEN", "a-very-long-local-test-token-123456789")
    monkeypatch.setattr(history, 'DB_PATH', tmp_path / 'history.sqlite3')

@pytest.mark.asyncio
async def test_security_headers_and_frontend(configured_db):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost:8000') as client:
        page=await client.get('/')
        assert page.status_code == 200
        assert "script-src 'self'" in page.headers['content-security-policy']
        assert page.headers['x-content-type-options']=='nosniff'
        assert 'src="/static/app.js?v=1.1.1"' in page.text
        assert '<style>' not in page.text
        assert 'style=' not in page.text
        asset=await client.get('/static/app.js')
        assert asset.status_code == 200

@pytest.mark.asyncio
async def test_scan_persisted_and_history(configured_db):
    result=analyze_headers('http://localhost:8000', {'content-security-policy':"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",'x-content-type-options':'nosniff','referrer-policy':'strict-origin-when-cross-origin','permissions-policy':'camera=()','x-frame-options':'DENY'},200)
    with patch('app.main.scan', new_callable=AsyncMock, return_value=result):
        async with httpx.AsyncClient(headers={"Authorization":"Bearer a-very-long-local-test-token-123456789"}, transport=httpx.ASGITransport(app=app),base_url='http://localhost:8000') as client:
            no_auth=await client.post('/api/scan',json={'url':'http://localhost:8000','authorized':False})
            assert no_auth.status_code==400
            resp=await client.post('/api/scan',json={'url':'http://localhost:8000','authorized':True})
            assert resp.status_code==200
            assert resp.json()['score']==100
            rows=(await client.get('/api/history')).json()
            assert len(rows)==1
            detail=await client.get('/api/history/'+rows[0]['id'])
            assert detail.json()['score']==100
            missing=await client.get('/api/history/not-real')
            assert missing.status_code==404
