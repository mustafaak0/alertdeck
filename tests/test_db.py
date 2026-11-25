"""Tests for the SQLite storage layer."""

import pytest

from alertdeck import db


@pytest.fixture()
def conn(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    yield connection
    connection.close()


def base_alert(**overrides):
    data = {
        "source": "wazuh",
        "rule_name": "SSH brute force",
        "severity": "high",
        "src_ip": "203.0.113.7",
        "username": "root",
        "host": "srv-dc-01",
    }
    data.update(overrides)
    return data


def test_insert_and_get(conn):
    alert_id = db.insert_alert(conn, base_alert())
    alert = db.get_alert(conn, alert_id)
    assert alert["source"] == "wazuh"
    assert alert["status"] == "new"
    assert alert["severity"] == "high"
    assert db.get_alert(conn, 999) is None


def test_list_filters(conn):
    db.insert_alert(conn, base_alert(severity="critical", src_ip="1.1.1.1"))
    db.insert_alert(conn, base_alert(rule_name="Phishing", severity="low"))
    db.insert_alert(conn, base_alert(source="suricata", src_ip="9.9.9.9"))

    assert len(db.list_alerts(conn)) == 3
    assert len(db.list_alerts(conn, severity="critical")) == 1
    assert len(db.list_alerts(conn, source="suricata")) == 1
    assert len(db.list_alerts(conn, q="phishing")) == 1
    assert len(db.list_alerts(conn, q="9.9.9.9")) == 1
    assert len(db.list_alerts(conn, q="nope")) == 0


def test_list_sort_severity(conn):
    db.insert_alert(conn, base_alert(severity="low"))
    db.insert_alert(conn, base_alert(severity="critical"))
    rows = db.list_alerts(conn, sort="severity")
    assert [r["severity"] for r in rows] == ["critical", "low"]


def test_update_and_clear_assignee(conn):
    alert_id = db.insert_alert(conn, base_alert())
    assert db.update_alert(conn, alert_id, {"status": "in_progress", "assignee": "ayla"})
    alert = db.get_alert(conn, alert_id)
    assert alert["status"] == "in_progress"
    assert alert["assignee"] == "ayla"

    # empty assignee clears the assignment
    db.update_alert(conn, alert_id, {"assignee": None})
    assert db.get_alert(conn, alert_id)["assignee"] is None


def test_notes(conn):
    alert_id = db.insert_alert(conn, base_alert())
    db.add_note(conn, alert_id, "ayla", "contained")
    db.add_note(conn, alert_id, "kerem", "escalated")
    notes = db.list_notes(conn, alert_id)
    assert [n["text"] for n in notes] == ["contained", "escalated"]
    assert notes[0]["author"] == "ayla"


def test_stats(conn):
    db.insert_alert(conn, base_alert(severity="critical"))
    db.insert_alert(conn, base_alert(severity="critical", status="resolved"))
    s = db.stats(conn)
    assert s["total"] == 2
    assert s["by_severity"]["critical"] == 2
    assert s["by_status"]["resolved"] == 1
    assert len(s["timeline"]) == 14
    assert sum(d["count"] for d in s["timeline"]) == 2
    assert s["top_src_ips"][0]["value"] in {"203.0.113.7"}
