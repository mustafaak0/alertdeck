"""FastAPI application: REST API + web dashboard."""

from __future__ import annotations

import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from . import __version__
from .db import (
    add_note,
    connect,
    get_alert,
    insert_alert,
    list_alerts,
    list_notes,
    stats as db_stats,
    update_alert,
)
from .ingest import ALIASES, normalize_alert
from .models import SEVERITIES, STATUSES

app = FastAPI(
    title="AlertDeck",
    version=__version__,
    summary="Lightweight alert triage workbench for SOC analysts",
)

WEB_DIR = Path(__file__).resolve().parent / "web"


# --------------------------------------------------------------------------
# auth (optional): set ALERTDECK_TOKEN to require it on write endpoints
# --------------------------------------------------------------------------

def require_token(
    x_alertdeck_token: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> None:
    expected = os.environ.get("ALERTDECK_TOKEN")
    if not expected:
        return
    supplied = x_alertdeck_token
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:]
    if not supplied or not secrets.compare_digest(supplied.strip(), expected):
        raise HTTPException(status_code=401, detail="invalid or missing ingest token")


# --------------------------------------------------------------------------
# schemas
# --------------------------------------------------------------------------

class AlertIn(BaseModel):
    source: str = Field(min_length=1, examples=["wazuh"])
    rule_name: str = Field(min_length=1, examples=["SSH brute force"])
    severity: str = "medium"
    status: str = "new"
    detected_at: Optional[datetime] = None
    assignee: Optional[str] = None
    description: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    username: Optional[str] = None
    host: Optional[str] = None
    raw: Optional[Union[dict, str]] = None

    @model_validator(mode="before")
    @classmethod
    def _apply_aliases(cls, data):
        """Accept common SIEM field names (title, ip, user, timestamp, ...)."""
        if isinstance(data, dict):
            return {
                ALIASES.get(str(key).strip().lower(), str(key).strip().lower()): value
                for key, value in data.items()
            }
        return data


class AlertPatch(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    assignee: Optional[str] = None
    description: Optional[str] = None


class NoteIn(BaseModel):
    author: str = "analyst"
    text: str = Field(min_length=1)


def _validate_enum(value: str, allowed: tuple[str, ...], label: str) -> str:
    if value and value not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"invalid {label} {value!r} (expected one of: {', '.join(allowed)})",
        )
    return value


# --------------------------------------------------------------------------
# alert endpoints
# --------------------------------------------------------------------------

@app.get("/api/alerts", tags=["alerts"])
def read_alerts(
    q: str = "",
    severity: str = "",
    status: str = "",
    source: str = "",
    assignee: str = "",
    sort: str = "newest",
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    _validate_enum(severity, SEVERITIES, "severity")
    _validate_enum(status, STATUSES, "status")
    if sort not in ("newest", "oldest", "severity"):
        raise HTTPException(status_code=422, detail="sort must be newest|oldest|severity")
    return list_alerts(
        connect(),
        severity=severity or None,
        status=status or None,
        source=source or None,
        assignee=assignee or None,
        q=q or None,
        sort=sort,
        limit=limit,
        offset=offset,
    )


@app.post("/api/alerts", status_code=201, tags=["alerts"],
          dependencies=[Depends(require_token)])
def create_alerts(alerts: Union[AlertIn, list[AlertIn]]) -> list[dict]:
    """Ingest one alert or a batch - point your SIEM webhook/export here."""
    items = alerts if isinstance(alerts, list) else [alerts]
    conn = connect()
    created = []
    for item in items:
        data = item.model_dump(mode="json")
        try:
            alert_id = insert_alert(conn, normalize_alert(data))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        created.append(get_alert(conn, alert_id))
    return created


@app.get("/api/alerts/{alert_id}", tags=["alerts"])
def read_alert(alert_id: int) -> dict:
    conn = connect()
    alert = get_alert(conn, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")
    alert["notes"] = list_notes(conn, alert_id)
    return alert


@app.patch("/api/alerts/{alert_id}", tags=["alerts"],
           dependencies=[Depends(require_token)])
def patch_alert(alert_id: int, patch: AlertPatch) -> dict:
    fields = patch.model_dump(exclude_unset=True)
    for label, allowed in (("severity", SEVERITIES), ("status", STATUSES)):
        if fields.get(label) and fields[label] not in allowed:
            raise HTTPException(
                status_code=422,
                detail=f"invalid {label} {fields[label]!r} "
                       f"(expected one of: {', '.join(allowed)})",
            )
    if fields.get("assignee") == "":
        fields["assignee"] = None  # empty string clears the assignment

    conn = connect()
    if not get_alert(conn, alert_id):
        raise HTTPException(status_code=404, detail="alert not found")
    update_alert(conn, alert_id, fields)
    return get_alert(conn, alert_id)


@app.post("/api/alerts/{alert_id}/notes", status_code=201, tags=["alerts"],
          dependencies=[Depends(require_token)])
def create_note(alert_id: int, note: NoteIn) -> dict:
    conn = connect()
    if not get_alert(conn, alert_id):
        raise HTTPException(status_code=404, detail="alert not found")
    add_note(conn, alert_id, note.author, note.text)
    return get_alert(conn, alert_id) | {"notes": list_notes(conn, alert_id)}


@app.get("/api/stats", tags=["stats"])
def read_stats(days: int = Query(default=14, ge=1, le=90)) -> dict:
    return db_stats(connect(), days=days)


@app.get("/api/meta", tags=["stats"])
def read_meta() -> dict:
    return {
        "severities": list(SEVERITIES),
        "statuses": list(STATUSES),
        "sources": db_stats(connect())["sources"],
    }


# --------------------------------------------------------------------------
# dashboard
# --------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
