"""SQLite storage layer for AlertDeck.

Every call opens a fresh connection (cheap for SQLite), which keeps the
CLI, the API server and tests interchangeable: point them at the same
database via ``ALERTDECK_DB`` or pass an explicit path.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .models import SEVERITIES, STATUSES, utcnow_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    source      TEXT NOT NULL,
    rule_name   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new',
    assignee    TEXT,
    description TEXT NOT NULL DEFAULT '',
    src_ip      TEXT,
    dst_ip      TEXT,
    username    TEXT,
    host        TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_detected ON alerts(detected_at);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    author     TEXT NOT NULL DEFAULT 'analyst',
    text       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_alert ON notes(alert_id);
"""

_ORDER = {
    "newest": "detected_at DESC, id DESC",
    "oldest": "detected_at ASC, id ASC",
    "severity": (
        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END ASC, "
        "detected_at DESC"
    ),
}


def default_db_path() -> Path:
    """Database location: ``ALERTDECK_DB`` env var, else ``~/.alertdeck/alertdeck.db``."""
    env = os.environ.get("ALERTDECK_DB")
    if env:
        return Path(env)
    return Path.home() / ".alertdeck" / "alertdeck.db"


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


# --------------------------------------------------------------------------
# alerts
# --------------------------------------------------------------------------

def insert_alert(conn: sqlite3.Connection, data: dict[str, Any]) -> int:
    """Insert one alert dict and return its id."""
    cur = conn.execute(
        """INSERT INTO alerts
           (created_at, detected_at, source, rule_name, severity, status,
            assignee, description, src_ip, dst_ip, username, host, raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data.get("created_at") or utcnow_iso(),
            data.get("detected_at") or utcnow_iso(),
            data["source"],
            data["rule_name"],
            data.get("severity", "medium"),
            data.get("status", "new"),
            data.get("assignee"),
            data.get("description", ""),
            data.get("src_ip"),
            data.get("dst_ip"),
            data.get("username"),
            data.get("host"),
            data.get("raw"),
        ),
    )
    conn.commit()
    return cur.lastrowid


def list_alerts(
    conn: sqlite3.Connection,
    *,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    assignee: Optional[str] = None,
    q: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    sort: str = "newest",
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Query alerts with triage-style filters. ``q`` matches rule name,
    description, source IP, username and host."""
    where: list[str] = []
    params: list[Any] = []

    if severity:
        where.append("severity = ?")
        params.append(severity)
    if status:
        where.append("status = ?")
        params.append(status)
    if source:
        where.append("source = ?")
        params.append(source)
    if assignee:
        where.append("assignee = ?")
        params.append(assignee)
    if since:
        where.append("substr(detected_at, 1, 10) >= ?")
        params.append(since)
    if until:
        where.append("substr(detected_at, 1, 10) <= ?")
        params.append(until)
    if q:
        like = f"%{q}%"
        where.append(
            "(rule_name LIKE ? OR description LIKE ? OR src_ip LIKE ? "
            "OR username LIKE ? OR host LIKE ?)"
        )
        params.extend([like, like, like, like, like])

    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {_ORDER.get(sort, _ORDER['newest'])} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    return [dict(row) for row in conn.execute(sql, params)]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


UPDATABLE = {"severity", "status", "assignee", "description"}


def update_alert(conn: sqlite3.Connection, alert_id: int, fields: dict[str, Any]) -> bool:
    """Update whitelisted fields (assignee=None clears the assignment)."""
    sets: list[str] = []
    params: list[Any] = []
    for key in UPDATABLE & fields.keys():
        sets.append(f"{key} = ?")
        params.append(fields[key])
    if not sets:
        return get_alert(conn, alert_id) is not None
    params.append(alert_id)
    cur = conn.execute(
        f"UPDATE alerts SET {', '.join(sets)} WHERE id = ?", params
    )
    conn.commit()
    return cur.rowcount > 0


# --------------------------------------------------------------------------
# notes
# --------------------------------------------------------------------------

def add_note(
    conn: sqlite3.Connection, alert_id: int, author: str, text: str
) -> int:
    cur = conn.execute(
        "INSERT INTO notes (alert_id, created_at, author, text) VALUES (?, ?, ?, ?)",
        (alert_id, utcnow_iso(), author, text),
    )
    conn.commit()
    return cur.lastrowid


def list_notes(conn: sqlite3.Connection, alert_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM notes WHERE alert_id = ? ORDER BY created_at ASC, id ASC",
        (alert_id,),
    )
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# statistics
# --------------------------------------------------------------------------

def stats(conn: sqlite3.Connection, days: int = 14) -> dict[str, Any]:
    by_severity = dict.fromkeys(SEVERITIES, 0)
    by_status = dict.fromkeys(STATUSES, 0)
    for row in conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"):
        by_severity[row["severity"]] = row["c"]
    for row in conn.execute("SELECT status, COUNT(*) c FROM alerts GROUP BY status"):
        by_status[row["status"]] = row["c"]

    today = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    since = (today - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    counts = {
        row["d"]: row["c"]
        for row in conn.execute(
            "SELECT substr(detected_at, 1, 10) d, COUNT(*) c FROM alerts "
            "WHERE substr(detected_at, 1, 10) >= ? GROUP BY d",
            (since,),
        )
    }
    timeline = [
        {"date": (today - timedelta(days=i)).strftime("%Y-%m-%d"),
         "count": counts.get((today - timedelta(days=i)).strftime("%Y-%m-%d"), 0)}
        for i in range(days - 1, -1, -1)
    ]

    def top(column: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            f"SELECT {column} v, COUNT(*) c FROM alerts WHERE {column} IS NOT NULL "
            f"GROUP BY {column} ORDER BY c DESC LIMIT 5"
        )
        return [{"value": row["v"], "count": row["c"]} for row in rows]

    sources = [
        row["v"]
        for row in conn.execute("SELECT DISTINCT source v FROM alerts ORDER BY v")
    ]
    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
        "by_status": by_status,
        "timeline": timeline,
        "top_sources": top("source"),
        "top_src_ips": top("src_ip"),
        "sources": sources,
    }
