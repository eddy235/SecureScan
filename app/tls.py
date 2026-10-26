"""Bounded local TLS certificate inspection; avoids remote network access."""
from datetime import datetime, timezone
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


def inspect_tls_certificate(url: str) -> dict:
    parsed = urlsplit(url)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        return {"status": "Not applicable", "reason": "Not an HTTPS URL"}
    # TLS probes are restricted to loopback; do not let this method become an SSRF path.
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                return {"status": "Not inspected", "reason": "Only loopback TLS probes supported"}
        except ValueError:
            return {"status": "Not inspected", "reason": "Only loopback TLS probes supported"}
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
                expires = cert.get("notAfter")
                expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc) if expires else None
                remaining = (expires_at - datetime.now(timezone.utc)).days if expires_at else None
                return {"status": "Valid" if remaining is not None and remaining >= 0 else "Unknown", "tls_version": secure.version(), "expires_at": expires_at.isoformat() if expires_at else None, "days_remaining": remaining, "expiring_soon": remaining is not None and remaining < 30}
    except (ssl.SSLError, OSError, ValueError) as exc:
        # No sensitive network configuration or certificate contents in public reports.
        return {"status": "Verification failed", "reason": type(exc).__name__}
