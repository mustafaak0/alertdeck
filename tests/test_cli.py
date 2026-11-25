"""Tests for the Typer CLI."""

import json

import pytest
from typer.testing import CliRunner

from alertdeck.cli import app

runner = CliRunner()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERTDECK_DB", str(tmp_path / "cli-test.db"))
    return monkeypatch


def test_demo_list_show(env):
    result = runner.invoke(app, ["demo", "--count", "15", "--seed", "7"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["list", "--json"])
    assert result.exit_code == 0
    alerts = json.loads(result.output)
    assert len(alerts) == 15
    assert alerts[0]["source"]

    result = runner.invoke(app, ["show", "1"])
    assert result.exit_code == 0
    assert "rule_name" not in result.output  # show() renders, not dumps

    result = runner.invoke(app, ["show", "9999"])
    assert result.exit_code == 1


def test_list_filters(env):
    runner.invoke(app, ["demo", "--count", "30", "--seed", "3"])
    result = runner.invoke(app, ["list", "--severity", "critical", "--json"])
    assert result.exit_code == 0
    assert all(a["severity"] == "critical" for a in json.loads(result.output))


def test_add_update_note_flow(env):
    result = runner.invoke(app, [
        "add", "--source", "manual", "--rule", "Analyst hunch",
        "--severity", "medium", "--src-ip", "203.0.113.5",
    ])
    assert result.exit_code == 0

    result = runner.invoke(app, [
        "update", "1", "--status", "in_progress", "--assignee", "ayla",
        "--note", "investigating",
    ])
    assert result.exit_code == 0

    result = runner.invoke(app, ["show", "1"])
    assert "investigating" in result.output
    assert "ayla" in result.output


def test_import_json(env, tmp_path):
    file = tmp_path / "alerts.json"
    file.write_text(json.dumps([
        {"sensor": "zeek", "title": "DNS tunneling", "severity": "high"},
        {"source": "x", "rule_name": "bad severity", "severity": "nope"},
        {"source": "y", "rule_name": "ok alert"},
    ]), encoding="utf-8")
    result = runner.invoke(app, ["import", str(file)])
    assert result.exit_code == 0

    result = runner.invoke(app, ["list", "--json"])
    alerts = json.loads(result.output)
    assert len(alerts) == 2  # the invalid one was skipped
    assert {a["source"] for a in alerts} == {"zeek", "y"}


def test_stats_and_db_path(env):
    runner.invoke(app, ["demo", "--count", "5", "--seed", "1"])
    assert runner.invoke(app, ["stats"]).exit_code == 0
    assert runner.invoke(app, ["db-path"]).exit_code == 0
