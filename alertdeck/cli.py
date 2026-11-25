"""AlertDeck command line interface (Typer + Rich)."""

from __future__ import annotations

import json
from enum import Enum
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .db import (
    add_note,
    connect,
    default_db_path,
    get_alert,
    insert_alert,
    list_alerts as db_list_alerts,
    list_notes,
    stats as db_stats,
    update_alert,
)
from .ingest import ingest_file
from .models import SEVERITIES, STATUSES

app = typer.Typer(
    help="AlertDeck - lightweight SOC alert triage workbench.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
STATUS_STYLE = {
    "new": "bold cyan",
    "in_progress": "bold yellow",
    "resolved": "bold green",
    "false_positive": "dim",
}


class SeverityOpt(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class StatusOpt(str, Enum):
    new = "new"
    in_progress = "in_progress"
    resolved = "resolved"
    false_positive = "false_positive"


class SortOpt(str, Enum):
    newest = "newest"
    oldest = "oldest"
    severity = "severity"


def _fail(message: str) -> None:
    console.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code=1)


def _get_or_fail(conn, alert_id: int) -> dict:
    alert = get_alert(conn, alert_id)
    if not alert:
        _fail(f"alert #{alert_id} not found")
    return alert


def _fmt(value: Optional[str], dash: str = "-") -> str:
    return value if value else dash


def _badge(value: str, styles: dict) -> str:
    return f"[{styles.get(value, '')}]{value.replace('_', ' ')}[/{styles.get(value, '')}]".replace(
        "[]", ""
    )


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

@app.command()
def demo(
    count: int = typer.Option(40, "--count", "-n", min=1, max=1000, help="How many alerts to generate."),
    seed: Optional[int] = typer.Option(None, "--seed", help="Random seed for reproducible data."),
) -> None:
    """Seed the database with realistic sample alerts."""
    from .demo import seed as seed_demo

    ids = seed_demo(count, seed)
    console.print(
        f"[green]Inserted {len(ids)} demo alerts (ids {ids[0]}..{ids[-1]}).[/green]"
    )
    console.print(f"Try: [bold]alertdeck list[/bold] or [bold]alertdeck serve[/bold]")


@app.command(name="list")
def list_alerts(
    severity: Optional[SeverityOpt] = typer.Option(None, "--severity", "-s", help="Filter by severity."),
    status: Optional[StatusOpt] = typer.Option(None, "--status", help="Filter by status."),
    source: Optional[str] = typer.Option(None, help="Filter by source (e.g. wazuh)."),
    assignee: Optional[str] = typer.Option(None, help="Filter by assignee."),
    q: Optional[str] = typer.Option(None, "--query", "-q", help="Search rule/IP/user/host."),
    sort: SortOpt = typer.Option(SortOpt.newest, "--sort", help="Sort order."),
    limit: int = typer.Option(50, "--limit", "-l", min=1, max=1000),
    as_json: bool = typer.Option(False, "--json", help="Print raw JSON instead of a table."),
) -> None:
    """List alerts with triage filters."""
    rows = db_list_alerts(
        connect(),
        severity=severity.value if severity else None,
        status=status.value if status else None,
        source=source,
        assignee=assignee,
        q=q,
        sort=sort.value,
        limit=limit,
    )
    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return

    table = Table(title=f"Alerts ({len(rows)} shown)", box=None, header_style="bold")
    for column in ("ID", "Detected", "Sev", "Status", "Source", "Rule", "Src IP", "User", "Assignee"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            str(row["id"]),
            row["detected_at"].replace("T", " ").replace("Z", ""),
            _badge(row["severity"], SEVERITY_STYLE),
            _badge(row["status"], STATUS_STYLE),
            row["source"],
            row["rule_name"],
            _fmt(row["src_ip"]),
            _fmt(row["username"]),
            _fmt(row["assignee"]),
        )
    console.print(table)


@app.command()
def show(alert_id: int = typer.Argument(..., help="Alert id.")) -> None:
    """Show one alert in detail, including its note history."""
    conn = connect()
    alert = _get_or_fail(conn, alert_id)

    body = Table(box=None, show_header=False)
    body.add_column(style="dim")
    body.add_column()
    body.add_row("Detected", alert["detected_at"])
    body.add_row("Ingested", alert["created_at"])
    body.add_row("Severity", _badge(alert["severity"], SEVERITY_STYLE))
    body.add_row("Status", _badge(alert["status"], STATUS_STYLE))
    body.add_row("Source", alert["source"])
    body.add_row("Assignee", _fmt(alert["assignee"]))
    body.add_row("Src / Dst IP", f"{_fmt(alert['src_ip'])} -> {_fmt(alert['dst_ip'])}")
    body.add_row("User / Host", f"{_fmt(alert['username'])} @ {_fmt(alert['host'])}")
    body.add_row("Description", alert["description"] or "-")
    if alert["raw"]:
        body.add_row("Raw", alert["raw"])
    console.print(
        Panel(body, title=f"[bold]#{alert_id} - {alert['rule_name']}[/bold]",
              subtitle=f"{alert['source']}")
    )

    notes = list_notes(conn, alert_id)
    if not notes:
        console.print("[dim]No notes yet. Add one with: alertdeck note "
                      f"{alert_id} -m '...'[/dim]")
        return
    note_table = Table(title="Notes", box=None, header_style="bold")
    for column in ("When", "Author", "Text"):
        note_table.add_column(column)
    for note in notes:
        note_table.add_row(
            note["created_at"].replace("T", " ").replace("Z", ""),
            note["author"],
            note["text"],
        )
    console.print(note_table)


@app.command()
def add(
    source: str = typer.Option(..., "--source", help="Detection source, e.g. wazuh."),
    rule_name: str = typer.Option(..., "--rule", help="Rule / alert name."),
    severity: SeverityOpt = typer.Option(SeverityOpt.medium, "--severity", "-s"),
    description: str = typer.Option("", "--description", "-d"),
    src_ip: Optional[str] = typer.Option(None, help="Source IP."),
    dst_ip: Optional[str] = typer.Option(None, help="Destination IP."),
    username: Optional[str] = typer.Option(None, help="Involved account."),
    host: Optional[str] = typer.Option(None, help="Involved host."),
) -> None:
    """Add a single alert manually."""
    alert_id = insert_alert(connect(), {
        "source": source,
        "rule_name": rule_name,
        "severity": severity.value,
        "description": description,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": username,
        "host": host,
    })
    console.print(f"[green]Created alert #{alert_id}.[/green]")


@app.command()
def update(
    alert_id: int = typer.Argument(..., help="Alert id."),
    status: Optional[StatusOpt] = typer.Option(None, "--status", help="New status."),
    severity: Optional[SeverityOpt] = typer.Option(None, "--severity", "-s", help="New severity."),
    assignee: Optional[str] = typer.Option(
        None, "--assignee", "-a", help="New assignee (empty string to clear)."
    ),
    note: Optional[str] = typer.Option(None, "--note", "-m", help="Append a note."),
) -> None:
    """Triage an alert: change status, severity, assignee and optionally note it."""
    conn = connect()
    _get_or_fail(conn, alert_id)
    fields: dict = {}
    if status:
        fields["status"] = status.value
    if severity:
        fields["severity"] = severity.value
    if assignee is not None:
        fields["assignee"] = assignee or None
    if fields:
        update_alert(conn, alert_id, fields)
        console.print(f"[green]Updated alert #{alert_id}: "
                      f"{', '.join(fields.keys())}[/green]")
    if note:
        add_note(conn, alert_id, "analyst", note)
        console.print(f"[green]Note added to alert #{alert_id}.[/green]")
    if not fields and not note:
        console.print("[yellow]Nothing to update - pass --status, --severity, "
                      "--assignee and/or --note.[/yellow]")


@app.command()
def note(
    alert_id: int = typer.Argument(..., help="Alert id."),
    text: str = typer.Option(..., "--text", "-m", help="Note text."),
    author: str = typer.Option("analyst", "--author", help="Note author."),
) -> None:
    """Append an investigation note to an alert."""
    conn = connect()
    _get_or_fail(conn, alert_id)
    add_note(conn, alert_id, author, text)
    console.print(f"[green]Note added to alert #{alert_id}.[/green]")


@app.command(name="import")
def import_cmd(
    file: str = typer.Argument(..., help=".json / .jsonl / .csv file with alerts."),
) -> None:
    """Import alerts from a file (flexible field names, see README)."""
    try:
        alerts, errors = ingest_file(file)
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        return
    if not alerts and errors:
        _fail(f"no valid records - first error: {errors[0]}")
        return
    conn = connect()
    for alert in alerts:
        insert_alert(conn, alert)
    console.print(f"[green]Imported {len(alerts)} alerts from {file}.[/green]")
    for error in errors[:10]:
        console.print(f"[yellow]skipped[/yellow] {error}")
    if len(errors) > 10:
        console.print(f"[yellow]...and {len(errors) - 10} more skipped records.[/yellow]")


@app.command()
def stats() -> None:
    """Show severity/status distribution and top talkers."""
    data = db_stats(connect())

    table = Table(title="Severity distribution", box=None, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    table.add_column("")
    max_count = max([1] + list(data["by_severity"].values()))
    for severity in SEVERITIES:
        count = data["by_severity"][severity]
        bar = "#" * round(count / max_count * 30)
        table.add_row(_badge(severity, SEVERITY_STYLE), str(count), f"[dim]{bar}[/dim]")
    console.print(table)

    table = Table(title="Status distribution", box=None, header_style="bold")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    for status in STATUSES:
        table.add_row(_badge(status, STATUS_STYLE), str(data["by_status"][status]))
    console.print(table)

    for title, key in (("Top sources", "top_sources"), ("Top source IPs", "top_src_ips")):
        table = Table(title=title, box=None, header_style="bold")
        table.add_column("Value")
        table.add_column("Count", justify="right")
        for item in data[key]:
            table.add_row(item["value"], str(item["count"]))
        console.print(table)
    console.print(f"[dim]Total alerts: {data['total']} | db: {default_db_path()}[/dim]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address (keep local by default)."),
    port: int = typer.Option(8000, help="Port."),
) -> None:
    """Start the web dashboard (http://127.0.0.1:8000 by default)."""
    import uvicorn

    from .api import app as api_app

    console.print(f"[bold]AlertDeck v{__version__}[/bold] - dashboard on "
                  f"[cyan]http://{host}:{port}[/cyan]")
    console.print(f"[dim]database: {default_db_path()}[/dim]")
    uvicorn.run(api_app, host=host, port=port, log_level="warning")


@app.command(name="db-path")
def db_path() -> None:
    """Print the database path in use."""
    typer.echo(default_db_path())


if __name__ == "__main__":
    app()
