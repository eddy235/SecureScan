"""Passive response configuration assessment. Permission required; local targets by default."""
from __future__ import annotations
import ipaddress
import os
import re
import socket
from urllib.parse import urlsplit
import httpx

class ScanInputError(ValueError):
    pass

def validate_target(target: str, allow_public: bool = False) -> str:
    parsed = urlsplit(target)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ScanInputError('Provide an http(s) URL without credentials or fragments.')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ScanInputError('Invalid port.') from exc
    if port not in (None, 80, 443, 8000, 8080, 8888):
        raise ScanInputError('Port not allowed.')
    host = parsed.hostname.lower().rstrip('.')
    if host == 'localhost':
        return target
    try:
        results = socket.getaddrinfo(host, port or (443 if parsed.scheme == 'https' else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanInputError('Hostname could not be resolved.') from exc
    if not results:
        raise ScanInputError('Hostname could not be resolved.')
    ips = [ipaddress.ip_address(r[4][0]) for r in results]
    if all(ip.is_loopback for ip in ips):
        return target
    if not allow_public:
        raise ScanInputError('External scans disabled. Use a controlled localhost target.')
    if any(not ip.is_global for ip in ips):
        raise ScanInputError('Private and non-public targets are blocked.')
    return target

def _check(name, passed, severity, evidence, recommendation=None, applicable=True):
    return {'name': name, 'passed': passed if applicable else None, 'severity': severity if applicable and not passed else 'Informational',
            'evidence': evidence, 'recommendation': recommendation if applicable and not passed else None,
            'status': 'Not applicable' if not applicable else ('Passed' if passed else 'Needs attention')}

def _directives(csp):
    return {part.strip().split(None, 1)[0].lower(): part.strip().split(None, 1)[1] if len(part.strip().split(None, 1)) > 1 else ''
            for part in csp.split(';') if part.strip()}

def analyze_headers(url: str, headers: dict[str, str], status_code: int, cookies: list[str] | None = None) -> dict:
    h = {k.lower(): v for k, v in headers.items()}
    parsed = urlsplit(url)
    https = parsed.scheme == 'https'
    local = parsed.hostname in ('localhost', '127.0.0.1', '::1')
    checks = []
    def add(name, passed, severity, evidence, remedy=None, applicable=True):
        checks.append(_check(name, passed, severity, evidence, remedy, applicable))
    csp = h.get('content-security-policy', '')
    directives = _directives(csp)
    csp_good = bool(csp) and 'object-src' in directives and 'base-uri' in directives and ('default-src' in directives or 'script-src' in directives)
    add('Content Security Policy', csp_good, 'High', csp or 'Header absent', 'Define restrictive default-src/script-src, object-src and base-uri directives; validate against your application.')
    nosniff = h.get('x-content-type-options', '').strip().lower() == 'nosniff'
    add('MIME Sniffing Protection', nosniff, 'Medium', h.get('x-content-type-options', 'Header absent'), 'Set X-Content-Type-Options: nosniff.')
    ref = h.get('referrer-policy', '').strip().lower()
    good_ref = any(p.strip() in ('no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin') for p in ref.split(','))
    add('Referrer Policy', good_ref, 'Low', ref or 'Header absent', 'Use Referrer-Policy: strict-origin-when-cross-origin or a more restrictive policy.')
    perms = h.get('permissions-policy', '')
    add('Permissions Policy', bool(perms.strip()), 'Low', perms or 'Header absent', 'Set Permissions-Policy to disable browser capabilities the app does not use.')
    xframe = h.get('x-frame-options', '').strip().upper()
    ancestors = directives.get('frame-ancestors', '')
    protected = xframe in ('DENY', 'SAMEORIGIN') or (bool(ancestors) and ('\'none\'' in ancestors or '\'self\'' in ancestors))
    add('Frame Protection', protected, 'Medium', xframe or (f'CSP frame-ancestors {ancestors}' if ancestors else 'No framing restriction'), 'Use X-Frame-Options: DENY/SAMEORIGIN or restrictive CSP frame-ancestors.')
    hsts = h.get('strict-transport-security', '')
    match = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)', hsts, re.I)
    hsts_ok = bool(match and int(match.group(1)) >= 15552000)
    add('HSTS', hsts_ok, 'Medium', hsts or ('HTTP response (not applicable)' if not https else 'Header absent'), 'Set Strict-Transport-Security with max-age >= 15552000 on HTTPS.', applicable=https)
    add('HTTPS Encryption', https, 'High', 'HTTPS URL' if https else ('Local HTTP development endpoint' if local else 'Plain HTTP'), 'Use HTTPS with a valid certificate for production.', applicable=not local)
    # Set-Cookie is a repeating header: callers should pass each separately.
    cookie_list = cookies if cookies is not None else ([h['set-cookie']] if 'set-cookie' in h else [])
    for i, cookie in enumerate(cookie_list, 1):
        name = cookie.split('=', 1)[0].strip()[:80] or f'Cookie {i}'
        tokens = {p.strip().split('=', 1)[0].lower() for p in cookie.split(';')[1:]}
        add(f'Cookie {name}: HttpOnly', 'httponly' in tokens, 'Medium', 'HttpOnly present' if 'httponly' in tokens else 'HttpOnly absent', 'Set HttpOnly on cookies not accessed by JavaScript.')
        add(f'Cookie {name}: Secure', 'secure' in tokens, 'Medium', 'Secure present' if 'secure' in tokens else 'Secure absent', 'Set Secure on cookies served over HTTPS.', applicable=not local)
        same_site = next((p.split('=', 1)[1].strip().lower() for p in cookie.split(';')[1:] if p.strip().lower().startswith('samesite=')), None)
        add(f'Cookie {name}: SameSite', same_site in ('lax', 'strict', 'none'), 'Low', f'SameSite={same_site}' if same_site else 'SameSite absent', 'Set SameSite=Lax or Strict where suitable.')
    scored = [c for c in checks if c['status'] != 'Not applicable']
    score = round(100 * sum(c['passed'] for c in scored) / len(scored)) if scored else 100
    failures = [c for c in scored if not c['passed']]
    risk = 'High' if any(c['severity'] == 'High' for c in failures) else 'Moderate' if failures else 'Low'
    note = 'Passive response configuration review only; not a penetration test or proof of overall security.'
    if local:
        note += ' Loopback HTTP is treated as development context and is not scored as a production TLS failure.'
    return {'url': url, 'status_code': status_code, 'score': score, 'risk': risk, 'checks': checks, 'note': note,
            'summary': {'passed': sum(c['status'] == 'Passed' for c in checks), 'failed': len(failures),
                        'not_applicable': sum(c['status'] == 'Not applicable' for c in checks)}, 'score_method': 'Percentage of applicable configuration checks passed; not a vulnerability risk score.'}

async def scan(url: str, allow_public: bool = False) -> dict:
    validate_target(url, allow_public)
    async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=8.0, headers={'User-Agent': 'SecureScan-Portfolio/0.2'}) as client:
        response = await client.get(url)
    output = analyze_headers(str(response.url), dict(response.headers), response.status_code, response.headers.get_list('set-cookie'))
    if 300 <= response.status_code < 400:
        output['note'] += ' Redirect detected; destination not inspected.'
    return output
