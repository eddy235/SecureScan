"""Synthetic, read-only demonstration data. Never generated from real websites."""
from .scanner import analyze_headers

DEMO_TARGET = "https://example.com"

def _sample(scan_id, stamp, headers):
    report = analyze_headers(DEMO_TARGET, headers, 200)
    return {**report, "id": scan_id, "scanned_at": stamp, "note": "SYNTHETIC DEMO DATA. " + report["note"]}

HEADERS_FIXED = {
 "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
 "x-content-type-options": "nosniff",
 "referrer-policy": "strict-origin-when-cross-origin",
 "permissions-policy": "camera=(), microphone=(), geolocation=()",
 "x-frame-options": "DENY",
 "strict-transport-security": "max-age=31536000"
}
REPORTS = [
 _sample("demo-001", "2026-10-01T10:00:00+00:00", {}),
 _sample("demo-002", "2026-10-05T10:00:00+00:00", {"x-content-type-options":"nosniff", "referrer-policy":"strict-origin-when-cross-origin"}),
 _sample("demo-003", "2026-10-10T10:00:00+00:00", HEADERS_FIXED),
]

def demo_history(limit=20):
    return [{"id":r["id"],"scanned_at":r["scanned_at"],"url":r["url"],"score":r["score"],"summary":r["summary"]} for r in reversed(REPORTS)][0:limit]

def demo_detail(scan_id):
    return next((r for r in REPORTS if r["id"] == scan_id), None)

def demo_scan():
    return REPORTS[-1]

def demo_analytics(limit=100):
    reports = REPORTS[-limit:]
    severity = {"Critical":0,"High":0,"Medium":0,"Low":0,"Informational":0}
    for r in reports:
        for c in r["checks"]:
            if c["status"] == "Needs attention":
                severity[c["severity"]] += 1
    return {"total_scans":len(reports),"unique_targets":1,"average_score":round(sum(r["score"] for r in reports)/len(reports),1), "severity":severity,"trend":[{"id":r["id"],"scanned_at":r["scanned_at"],"url":r["url"],"score":r["score"]} for r in reports], "sample_limit":limit}
