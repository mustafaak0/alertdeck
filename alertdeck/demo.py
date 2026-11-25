"""Realistic sample data generator for demos and first-run experience."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .db import add_note, connect, insert_alert

TEMPLATES: list[dict[str, Any]] = [
    {"source": "wazuh", "rule_name": "Multiple authentication failures (SSH brute force)",
     "severities": ["high", "critical"],
     "description": "More than 25 failed SSH logins from a single source within 5 minutes."},
    {"source": "ms-defender", "rule_name": "Malware detected (Trojan:Win32/Emotet.PX)",
     "severities": ["critical"],
     "description": "Real-time protection blocked a malicious payload dropped via an email attachment."},
    {"source": "okta", "rule_name": "Impossible travel sign-in",
     "severities": ["high", "medium"],
     "description": "Successful sign-in from two geographically distant locations within 40 minutes."},
    {"source": "suricata", "rule_name": "ET WEB_SERVER Possible web shell upload",
     "severities": ["high"],
     "description": "POST to /upload delivering a .php file matched a known web shell signature."},
    {"source": "sysmon", "rule_name": "Credential dumping (LSASS access)",
     "severities": ["critical"],
     "description": "Process accessed lsass.exe with dump privileges; matches Mimikatz behaviour."},
    {"source": "proofpoint", "rule_name": "Phishing email quarantined",
     "severities": ["medium", "low"],
     "description": "Credential harvesting link detected in a message titled 'Urgent: payroll update'."},
    {"source": "fortigate", "rule_name": "Anomalous outbound data volume",
     "severities": ["critical", "high"],
     "description": "Host transferred 4.2 GB to an unclassified external IP over 443 outside business hours."},
    {"source": "zeek", "rule_name": "DNS tunneling beacon pattern",
     "severities": ["medium"],
     "description": "Long TXT query sequences to a single dynamic-DNS domain at a 60 second interval."},
    {"source": "velociraptor", "rule_name": "Encoded PowerShell execution",
     "severities": ["high"],
     "description": "powershell.exe launched with -enc flag from a user-writable path."},
    {"source": "wazuh", "rule_name": "Sudoers file modified outside change window",
     "severities": ["high", "critical"],
     "description": "Unexpected write to /etc/sudoers detected by file integrity monitoring."},
    {"source": "crowdstrike", "rule_name": "MFA push fatigue (repeated denials)",
     "severities": ["medium", "low"],
     "description": "Eight MFA push requests denied by the user within 10 minutes."},
    {"source": "apache", "rule_name": "SQL injection attempts in query string",
     "severities": ["high", "medium"],
     "description": "Repeated UNION SELECT patterns against /search.php from the same source."},
]

USERS = ["j.doe", "a.smith", "svc_backup", "admin", "root", "m.kaya", "sysadmin", "devops"]
HOSTS = ["ws-fin-014", "srv-dc-01", "srv-sql-02", "ws-hr-021", "k8s-node-3", "ws-eng-007", "srv-web-05"]
ANALYSTS = ["ayla", "kerem", "deniz"]
RESOLUTION_NOTES = [
    "Confirmed malicious. Host isolated, IR case #2214 opened.",
    "Benign - activity traced to an approved vulnerability scan (ticket CHG-1187).",
    "User verified the login via service desk. Closing as false positive.",
    "Containment done. Credentials reset, EDR sweep came back clean.",
    "Escalated to IR team, awaiting forensic image.",
]

_FIRST_OCTETS = [23, 45, 51, 77, 89, 103, 141, 154, 167, 176, 185, 190, 196, 201, 212]


def _ip(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST_OCTETS)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def generate(count: int = 40, seed: Optional[int] = None) -> list[dict[str, Any]]:
    """Generate ``count`` normalized alert dicts biased towards recent timestamps."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    alerts: list[dict[str, Any]] = []
    for _ in range(count):
        template = rng.choice(TEMPLATES)
        age_hours = rng.triangular(0, 24 * 14, 2)  # skewed towards the last few hours
        detected = now - timedelta(hours=age_hours)

        status, assignee = "new", None
        if age_hours > 48 and rng.random() < 0.75:
            status = rng.choices(
                ["resolved", "false_positive", "in_progress"], weights=[5, 3, 2]
            )[0]
            if rng.random() < 0.8:
                assignee = rng.choice(ANALYSTS)

        alerts.append({
            "detected_at": detected.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": template["source"],
            "rule_name": template["rule_name"],
            "severity": rng.choice(template["severities"]),
            "status": status,
            "assignee": assignee,
            "description": template["description"],
            "src_ip": _ip(rng),
            "dst_ip": _ip(rng) if rng.random() < 0.5 else None,
            "username": rng.choice(USERS),
            "host": rng.choice(HOSTS),
        })
    return alerts


def seed(count: int = 40, seed: Optional[int] = None, db_path=None) -> list[int]:
    """Insert demo alerts (plus occasional analyst notes) into the database."""
    rng = random.Random(seed)
    conn = connect(db_path)
    ids: list[int] = []
    for alert in generate(count, seed):
        alert_id = insert_alert(conn, alert)
        ids.append(alert_id)
        if alert["status"] != "new" and rng.random() < 0.5:
            add_note(conn, alert_id, rng.choice(ANALYSTS), rng.choice(RESOLUTION_NOTES))
    return ids
