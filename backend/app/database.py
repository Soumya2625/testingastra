from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("ASTRA_DB_PATH", Path(__file__).resolve().parents[2] / "data" / "astra.sqlite3"))
_lock = threading.RLock()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def managed_connection():
    conn = connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize() -> None:
    with _lock, managed_connection() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, repository TEXT NOT NULL,
                branch TEXT NOT NULL, commit_sha TEXT, status TEXT NOT NULL,
                scanner_status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
                duration_seconds REAL, scanned_files INTEGER NOT NULL DEFAULT 0,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT NOT NULL, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                scanner TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL,
                cwe TEXT, file_path TEXT NOT NULL, line INTEGER, end_line INTEGER, resource TEXT,
                evidence TEXT, description TEXT NOT NULL, remediation TEXT NOT NULL,
                confidence TEXT NOT NULL, verification_status TEXT NOT NULL, status TEXT NOT NULL,
                PRIMARY KEY(scan_id, finding_id)
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                messages TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scans_tenant_started ON scans(tenant, started_at DESC);
            CREATE INDEX IF NOT EXISTS findings_scan_severity ON findings(scan_id, severity);
            CREATE INDEX IF NOT EXISTS conversations_tenant_scan ON conversations(tenant, scan_id);
        """)


def execute(sql: str, args: tuple[Any, ...] = ()) -> None:
    with _lock, managed_connection() as db:
        db.execute(sql, args)


def rows(sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with _lock, managed_connection() as db:
        return [dict(row) for row in db.execute(sql, args).fetchall()]


def row(sql: str, args: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    found = rows(sql, args)
    return found[0] if found else None


def save_finding(scan_id: str, finding: dict[str, Any]) -> None:
    fields = (
        "finding_id", "scanner", "rule_id", "severity", "cwe", "file_path", "line", "end_line",
        "resource", "evidence", "description", "remediation", "confidence",
        "verification_status", "status",
    )
    values = tuple(finding.get(key) for key in fields)
    with _lock, managed_connection() as db:
        db.execute(
            f"INSERT OR IGNORE INTO findings ({','.join(fields)}, scan_id) VALUES ({','.join('?' for _ in fields)}, ?)",
            values + (scan_id,),
        )
