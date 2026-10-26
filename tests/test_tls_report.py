"""PDF reporting tests for verified and unavailable TLS inspections."""
from app.reports import build_pdf


def test_pdf_includes_tls_section(monkeypatch):
    from reportlab.platypus import Paragraph
    original = Paragraph.__init__
    seen = []

    def record(self, text, style, *args, **kwargs):
        seen.append(text)
        return original(self, text, style, *args, **kwargs)

    monkeypatch.setattr(Paragraph, "__init__", record)
    document = build_pdf({
        "url": "https://localhost:8000",
        "score": 100,
        "risk": "Low",
        "checks": [],
        "summary": {"passed": 0, "failed": 0, "not_applicable": 0},
        "tls": {
            "status": "Expiring soon",
            "tls_version": "TLSv1.3",
            "days_remaining": 12,
            "expires_at": "2026-11-07T12:00:00+00:00",
            "expiring_soon": True,
        },
    })
    assert document.startswith(b"%PDF")
    assert any("TLS certificate inspection" in item for item in seen)
    assert any("Expiring soon" in item for item in seen)
    assert any("TLSv1.3" in item for item in seen)


def test_pdf_without_tls_is_still_valid():
    document = build_pdf({
        "url": "http://localhost:8000",
        "score": 80,
        "checks": [],
        "summary": {"passed": 0, "failed": 0, "not_applicable": 0},
    })
    assert document.startswith(b"%PDF")
