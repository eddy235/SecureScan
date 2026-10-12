import pytest
from app.scanner import analyze_headers, validate_target, ScanInputError

GOOD = {'strict-transport-security':'max-age=31536000', 'content-security-policy':"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",'x-content-type-options':'nosniff','referrer-policy':'strict-origin-when-cross-origin','permissions-policy':'camera=()','x-frame-options':'DENY'}

def test_strong_https_headers():
    r=analyze_headers('https://example.org', GOOD, 200)
    assert r['score']==100 and r['risk']=='Low'

def test_local_http_is_not_tls_failure():
    r=analyze_headers('http://127.0.0.1:8000', {}, 200)
    assert next(c for c in r['checks'] if c['name']=='HTTPS Encryption')['status']=='Not applicable'
    assert r['score']==0

def test_header_values_are_validated():
    r=analyze_headers('https://example.org', {'x-content-type-options':'enabled','x-frame-options':'ALLOWALL','strict-transport-security':'max-age=0'}, 200)
    assert not next(c for c in r['checks'] if c['name']=='MIME Sniffing Protection')['passed']
    assert not next(c for c in r['checks'] if c['name']=='HSTS')['passed']

def test_cookie_checks():
    r=analyze_headers('https://example.org', GOOD, 200, ['session=abc; HttpOnly; Secure; SameSite=Lax'])
    assert all(c['passed'] for c in r['checks'] if c['name'].startswith('Cookie'))

def test_weak_cookie():
    r=analyze_headers('https://example.org', GOOD, 200, ['session=abc'])
    assert sum(not c['passed'] for c in r['checks'] if c['name'].startswith('Cookie'))==3

def test_localhost_allowed():
    assert validate_target('http://localhost:8000')=='http://localhost:8000'

def test_credentials_rejected():
    with pytest.raises(ScanInputError): validate_target('http://user:pass@localhost:8000')

def test_prohibited_port():
    with pytest.raises(ScanInputError): validate_target('http://localhost:22')
