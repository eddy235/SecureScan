"""Regression tests for v0.7 security analysis."""
from datetime import datetime, timedelta, timezone

from app.tls import certificate_expiry_status, inspect_tls_certificate
from app.scanner import analyze_headers


def test_valid_certificate_expiry():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = certificate_expiry_status(now + timedelta(days=60), now)
    assert result["status"] == "Valid"
    assert result["days_remaining"] == 60
    assert result["expiring_soon"] is False


def test_certificate_expiring_soon():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = certificate_expiry_status(now + timedelta(days=10), now)
    assert result["status"] == "Expiring soon"
    assert result["expiring_soon"] is True


def test_certificate_expired():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = certificate_expiry_status(now - timedelta(days=1), now)
    assert result["status"] == "Expired"
    assert result["days_remaining"] == 0


def test_tls_inspector_blocks_external_hosts_and_bad_ports():
    assert inspect_tls_certificate("https://example.com")["status"] == "Not inspected"
    assert inspect_tls_certificate("https://localhost:22")["status"] == "Not inspected"
    assert inspect_tls_certificate("https://localhost:invalid")["status"] == "Not inspected"


def test_csp_unsafe_inline_is_rejected():
    headers = {
        "content-security-policy": "default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
    }
    result = analyze_headers("https://example.org", headers, 200)
    csp = next(c for c in result["checks"] if c["name"] == "Content Security Policy")
    assert csp["status"] == "Needs attention"


def test_csp_unsafe_eval_is_rejected():
    headers = {
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'"
    }
    result = analyze_headers("https://example.org", headers, 200)
    csp = next(c for c in result["checks"] if c["name"] == "Content Security Policy")
    assert csp["passed"] is False
