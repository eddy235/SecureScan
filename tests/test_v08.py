"""Regression tests for private API request limits and scan-target safety."""
import socket

import httpx
import pytest

from app import main
from app.ratelimit import ScanRateLimiter
from app.scanner import ScanInputError, validate_target


def test_private_limiter_window():
    limiter = ScanRateLimiter(limit=2, window_seconds=60)
    assert limiter.allow(now=100)
    assert limiter.allow(now=100)
    assert not limiter.allow(now=101)
    assert limiter.allow(now=160)


@pytest.mark.parametrize("target", [
    "http://example.org",
    "http://10.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.1.1",
    "http://user:pass@localhost:8000",
    "http://localhost:22",
])
def test_forbidden_targets(target):
    with pytest.raises(ScanInputError):
        validate_target(target)


def test_localhost_cannot_resolve_to_external(monkeypatch):
    def fake_resolver(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8000))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver)
    with pytest.raises(ScanInputError):
        validate_target("http://localhost:8000")


def test_loopback_allowed():
    assert validate_target("http://127.0.0.1:8000") == "http://127.0.0.1:8000"


@pytest.mark.asyncio
async def test_private_scan_is_rate_limited(monkeypatch):
    monkeypatch.setattr(main, "DEMO_MODE", False)
    monkeypatch.setenv("SECURESCAN_PRIVATE_TOKEN", "test-token-with-at-least-24-chars")
    monkeypatch.setattr(main.scan_limiter, "allow", lambda: False)
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        data = {"url": "http://localhost:8000", "authorized": True}
        headers = {"Authorization": "Bearer test-token-with-at-least-24-chars"}
        assert (await client.post("/api/scan", json=data)).status_code == 401
        blocked = await client.post("/api/scan", json=data, headers=headers)
        assert blocked.status_code == 429
        assert blocked.headers.get("retry-after") == "60"
        monkeypatch.setattr(main, "DEMO_MODE", True)
        assert (await client.post("/api/scan", json=data, headers=headers)).status_code == 403
