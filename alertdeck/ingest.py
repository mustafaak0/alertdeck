"""Flexible alert ingestion: aliases, timestamp handling, file loading."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import SEVERITIES, STATUSES

# Common field names seen in SIEM/webhook exports mapped to AlertDeck fields.
ALIASES = {
    "title": "rule_name",
    "name": "rule_name",
    "rule": "rule_name",
    "alert": "rule_name",
    "event_type": "rule_name",
    "signature": "rule_name",
    "sensor": "source",
    "product": "source",
    "tool": "source",
    "ip": "src_ip",
    "attacker_ip": "src_ip",
    "client_ip": "src_ip",
    "src": "src_ip",
    "dest_ip": "dst_ip",
    "dst": "dst_ip",
    "target_ip": "dst_ip",
    "user": "username",
    "user_name": "username",
    "account": "username",
    "hostname": "host",
    "device": "host",
    "endpoint": "host",
    "timestamp": "detected_at",
    "time": "detected_at",
    "date": "detected_at",
    "dt": "detected_at",
    "msg": "description",
    "message": "description",
}


def normalize_timestamp(value: Any) -> str:
    """Coerce ISO strings, datetimes or epoch seconds into compact ISO-8601 UTC."""
    if value is None:
        from .models import utcnow_iso

        return utcnow_iso()
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.isdigit():  # epoch seconds
            dt = datetime.fromtimestamp(int(text), tz=timezone.utc)
        else:
            try:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(
                    f"unrecognized timestamp {value!r}; use ISO-8601 or epoch seconds"
                ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_alert(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a single alert dict (keys lowercased + aliases applied)."""
    d: dict[str, Any] = {}
    for key, value in data.items():
        key = ALIASES.get(str(key).strip().lower(), str(key).strip().lower())
        if value is not None and value != "":
            d[key] = value

    if not d.get("source") or not d.get("rule_name"):
        raise ValueError("alert requires at least 'source' and 'rule_name'")

    severity = str(d.get("severity", "medium")).strip().lower()
    if severity not in SEVERITIES:
        raise ValueError(
            f"invalid severity {severity!r} (expected one of: {', '.join(SEVERITIES)})"
        )
    d["severity"] = severity

    status = str(d.get("status", "new")).strip().lower()
    if status not in STATUSES:
        raise ValueError(
            f"invalid status {status!r} (expected one of: {', '.join(STATUSES)})"
        )
    d["status"] = status

    d["detected_at"] = normalize_timestamp(d.get("detected_at"))

    raw = d.get("raw")
    if isinstance(raw, (dict, list)):
        d["raw"] = json.dumps(raw, default=str)
    return d


def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Read raw alert dicts from .json, .jsonl or .csv files."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("alerts", "items", "data", "events"):
                if isinstance(payload.get(key), list):
                    return payload[key]
            return [payload]
        raise ValueError("JSON root must be an object or an array")
    if suffix == ".jsonl":
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    if suffix == ".csv":
        with path.open(encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))
    raise ValueError(f"unsupported file type {suffix!r} (use .json, .jsonl or .csv)")


def ingest_file(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load + normalize every record. Returns (alerts, errors)."""
    alerts: list[dict[str, Any]] = []
    errors: list[str] = []
    for i, record in enumerate(load_records(path), start=1):
        try:
            alerts.append(normalize_alert(record))
        except ValueError as exc:
            errors.append(f"record #{i}: {exc}")
    return alerts, errors
