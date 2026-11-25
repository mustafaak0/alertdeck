"""Shared domain types for AlertDeck."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["new", "in_progress", "resolved", "false_positive"]

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
STATUSES: tuple[str, ...] = ("new", "in_progress", "resolved", "false_positive")


def utcnow_iso() -> str:
    """Current UTC time as a compact ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
