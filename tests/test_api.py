"""Tests for the FastAPI layer."""

import pytest
from fastapi.testclient import TestClient

from alertdeck.api import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERTDECK_DB", str(tmp_path / "api-test.db"))
    monkeypatch.delenv("ALERTDECK_TOKEN", raising=False)
    return TestClient(app)


def test_ingest_and_read(client):
    payload = {
        "source": "wazuh",
        "rule_name": "SSH brute force",
        "severity": "high",
        "src_ip": "203.0.113.7",
        "raw": {"event": "auth_failure", "count": 31},
    }
    res = client.post("/api/alerts", json=payload)
    assert res.status_code == 201
    alert = res.json()[0]
    assert alert["id"] == 1
    assert alert["severity"] == "high"
    assert '"count": 31' in alert["raw"]

    assert len(client.get("/api/alerts").json()) == 1
    detail = client.get("/api/alerts/1").json()
    assert detail["rule_name"] == "SSH brute force"
    assert detail["notes"] == []


def test_batch_ingest_with_aliases(client):
    res = client.post("/api/alerts", json=[
        {"sensor": "suricata", "title": "Web shell upload", "severity": "high"},
        {"source": "okta", "rule_name": "Impossible travel", "ip": "198.51.100.9"},
    ])
    assert res.status_code == 201
    alerts = {a["rule_name"]: a for a in res.json()}
    assert alerts["Web shell upload"]["source"] == "suricata"
    assert alerts["Impossible travel"]["src_ip"] == "198.51.100.9"
    assert alerts["Impossible travel"]["severity"] == "medium"  # default


def test_filters_and_sort(client):
    for i in range(4):
        client.post("/api/alerts", json={
            "source": "wazuh",
            "rule_name": f"alert-{i}",
            "severity": ["critical", "high", "medium", "low"][i],
        })
    assert len(client.get("/api/alerts", params={"severity": "critical"}).json()) == 1
    rows = client.get("/api/alerts", params={"sort": "severity"}).json()
    assert [r["severity"] for r in rows] == ["critical", "high", "medium", "low"]
    assert client.get(
        "/api/alerts", params={"severity": "bogus"}
    ).status_code == 422


def test_patch_and_notes(client):
    client.post("/api/alerts", json={"source": "x", "rule_name": "y"})
    res = client.patch("/api/alerts/1", json={"status": "in_progress", "assignee": "ayla"})
    assert res.json()["status"] == "in_progress"
    assert res.json()["assignee"] == "ayla"

    res = client.patch("/api/alerts/1", json={"assignee": ""})
    assert res.json()["assignee"] is None

    res = client.post("/api/alerts/1/notes", json={"author": "ayla", "text": "contained"})
    assert res.status_code == 201
    assert res.json()["notes"][0]["text"] == "contained"
    assert client.get("/api/alerts/999").status_code == 404


def test_stats_and_meta(client):
    client.post("/api/alerts", json={"source": "wazuh", "rule_name": "a"})
    client.post("/api/alerts", json={"source": "suricata", "rule_name": "b",
                                     "severity": "critical"})
    stats = client.get("/api/stats").json()
    assert stats["total"] == 2
    assert stats["by_severity"]["critical"] == 1

    meta = client.get("/api/meta").json()
    assert set(meta["sources"]) == {"wazuh", "suricata"}
    assert "false_positive" in meta["statuses"]


def test_token_protection(tmp_path, monkeypatch):
    monkeypatch.setenv("ALERTDECK_DB", str(tmp_path / "token.db"))
    monkeypatch.setenv("ALERTDECK_TOKEN", "s3cret")
    client = TestClient(app)

    denied = client.post("/api/alerts", json={"source": "x", "rule_name": "y"})
    assert denied.status_code == 401

    ok = client.post(
        "/api/alerts",
        json={"source": "x", "rule_name": "y"},
        headers={"X-Alertdeck-Token": "s3cret"},
    )
    assert ok.status_code == 201

    # reads stay open
    assert client.get("/api/alerts").status_code == 200


def test_dashboard_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "AlertDeck" in res.text
    assert client.get("/static/app.js").status_code == 200
