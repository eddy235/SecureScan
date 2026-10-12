"""Minimal local scan-history storage. No authentication: intended for one developer on localhost."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

DB_PATH = Path(os.environ.get('SECURESCAN_DB', str(Path.home() / '.securescan' / 'history.sqlite3')))

def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, scanned_at TEXT NOT NULL, url TEXT NOT NULL, score INTEGER NOT NULL, payload TEXT NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scanned_at DESC)')
    return conn

def save_scan(report):
    scan_id = str(uuid4())
    captured = datetime.now(timezone.utc).isoformat(timespec='seconds')
    saved = {**report, 'id': scan_id, 'scanned_at': captured}
    with _connect() as conn:
        conn.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?)', (scan_id, captured, report['url'], report['score'], json.dumps(saved)))
    return saved

def list_scans(limit=20):
    with _connect() as conn:
        rows = conn.execute('SELECT id, scanned_at, url, score, payload FROM scans ORDER BY scanned_at DESC, rowid DESC LIMIT ?', (min(max(limit, 1), 100),)).fetchall()
    return [{'id': r[0], 'scanned_at': r[1], 'url': r[2], 'score': r[3], 'summary':json.loads(r[4])['summary']} for r in rows]

def get_scan(scan_id):
    with _connect() as conn:
        row = conn.execute('SELECT payload FROM scans WHERE id=?', (scan_id,)).fetchone()
    return json.loads(row[0]) if row else None
