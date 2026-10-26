"""Bounded, validated TLS inspection for local loopback HTTPS endpoints."""
from datetime import datetime, timezone
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


def certificate_expiry_status(expires_at: datetime, now: datetime | None = None) -> dict:
    """Classify a verified certificate's expiry without performing network access."""
    now = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    remaining_seconds = (expires_at - now).total_seconds()
    days_remaining = max(0, int(remaining_seconds // 86400))
    if remaining_seconds <= 0:
        status = "Expired"
    elif remaining_seconds <= 30 * 86400:
        status = "Expiring soon"
    else:
        status = "Valid"
    return {
        "status": status,
        "expires_at": expires_at.isoformat(),
        "days_remaining": days_remaining,
        "expiring_soon": status == "Expiring soon",
    }


def inspect_tls_certificate(url: str) -> dict:
    """Inspect only loopback HTTPS; never open a socket to an external host."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError:
        return {"status": "Not inspected", "reason": "Invalid HTTPS target"}
    if parsed.scheme != "https" or not host:
        return {"status": "Not applicable", "reason": "Not an HTTPS URL"}
    if parsed.username or parsed.password or parsed.fragment:
        return {"status": "Not inspected", "reason": "Unsupported URL format"}
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                return {"status": "Not inspected", "reason": "Only loopback TLS probes supported"}
        except ValueError:
            return {"status": "Not inspected", "reason": "Only loopback TLS probes supported"}
    if port not in (443, 8000, 8080, 8888):
        return {"status": "Not inspected", "reason": "Port not allowed"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
                expires = cert.get("notAfter")
                tls_version = secure.version()
                if not expires:
                    return {"status": "Unknown", "reason": "Verified certificate has no expiration field"}
                expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc)
                result = certificate_expiry_status(expires_at)
                result["tls_version"] = tls_version
                return result
    except (ssl.SSLError, OSError, ValueError) as exc:
        return {"status": "Verification failed", "reason": type(exc).__name__}
