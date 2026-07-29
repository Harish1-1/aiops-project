from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATABASE_PATH = Path(__file__).resolve().parents[1] / "data" / "incidents.db"


def _connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initialize_database() -> None:
    with _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                alert TEXT NOT NULL,
                namespace TEXT NOT NULL,
                pod TEXT NOT NULL,
                status TEXT NOT NULL,
                approval_status TEXT NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                incident_json TEXT NOT NULL,
                result_json TEXT,
                error TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS approval_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                decision TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                comment TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                downstream_json TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_approval_incident ON approval_history(incident_id, id)")


def create_incident(incident: dict[str, Any]) -> int:
    now = _now()
    with _connect() as connection:
        cursor = connection.execute("""
            INSERT INTO incidents (
                created_at, updated_at, alert, namespace, pod, status,
                approval_status, retry_count, incident_json, result_json, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now, now, str(incident.get("alert", "Unknown")),
            str(incident.get("namespace", "default")),
            str(incident.get("pod", "unknown")), "QUEUED", "PENDING", 0,
            json.dumps(incident), None, None,
        ))
        return int(cursor.lastrowid)


def mark_running(incident_id: int) -> None:
    with _connect() as connection:
        connection.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", ("RUNNING", _now(), incident_id))


def mark_completed(incident_id: int, result: dict[str, Any]) -> None:
    workflow_approval = str(result.get("approval_status", "NOT APPROVED"))
    human_status = "PENDING HUMAN APPROVAL" if workflow_approval == "APPROVED FOR HUMAN REVIEW" else "NOT APPROVED"
    with _connect() as connection:
        connection.execute("""
            UPDATE incidents SET status=?, updated_at=?, approval_status=?,
            retry_count=?, result_json=?, error=NULL WHERE id=?
        """, ("COMPLETED", _now(), human_status, int(result.get("retry_count", 0)), json.dumps(result), incident_id))


def mark_failed(incident_id: int, error: str, result: dict[str, Any] | None = None) -> None:
    with _connect() as connection:
        connection.execute("""
            UPDATE incidents SET status=?, updated_at=?, approval_status=?,
            result_json=?, error=? WHERE id=?
        """, ("FAILED", _now(), "NOT APPROVED", json.dumps(result) if result else None, error, incident_id))


def list_incidents(limit: int = 50) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute("""
            SELECT id, created_at, updated_at, alert, namespace, pod,
            status, approval_status, retry_count, error
            FROM incidents ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def list_pending_approval(limit: int = 100) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute("""
            SELECT id, created_at, updated_at, alert, namespace, pod,
            status, approval_status, retry_count, error
            FROM incidents
            WHERE status='COMPLETED' AND approval_status='PENDING HUMAN APPROVAL'
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_incident(incident_id: int) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["incident"] = json.loads(record.pop("incident_json"))
    result_json = record.pop("result_json")
    record["result"] = json.loads(result_json) if result_json else None
    return record


def update_incident_data(incident_id: int, incident: dict[str, Any]) -> None:
    with _connect() as connection:
        connection.execute("""
            UPDATE incidents SET updated_at=?, alert=?, namespace=?, pod=?, incident_json=? WHERE id=?
        """, (_now(), str(incident.get("alert", "Unknown")), str(incident.get("namespace", "default")), str(incident.get("pod", "unknown")), json.dumps(incident), incident_id))


def record_approval_decision(
    incident_id: int,
    decision: str,
    reviewer: str,
    comment: str,
    downstream: dict[str, Any],
) -> dict[str, Any]:
    decision = decision.upper()
    if decision not in {"APPROVED", "REJECTED"}:
        raise ValueError("Decision must be APPROVED or REJECTED.")
    approval_status = "HUMAN APPROVED" if decision == "APPROVED" else "HUMAN REJECTED"
    now = _now()
    with _connect() as connection:
        row = connection.execute("SELECT status, approval_status FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise LookupError("Incident not found.")
        if row["status"] != "COMPLETED":
            raise ValueError("Only completed incidents can be reviewed.")
        if row["approval_status"] not in {"PENDING HUMAN APPROVAL", "HUMAN APPROVED", "HUMAN REJECTED"}:
            raise ValueError("This incident is not eligible for human approval.")
        connection.execute("UPDATE incidents SET approval_status=?, updated_at=? WHERE id=?", (approval_status, now, incident_id))
        cursor = connection.execute("""
            INSERT INTO approval_history (
                incident_id, decision, reviewer, comment, created_at, downstream_json
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (incident_id, decision, reviewer, comment, now, json.dumps(downstream)))
    return {
        "id": int(cursor.lastrowid), "incident_id": incident_id,
        "decision": decision, "approval_status": approval_status,
        "reviewer": reviewer, "comment": comment, "created_at": now,
        "downstream": downstream,
    }


def list_approval_history(incident_id: int) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute("""
            SELECT id, incident_id, decision, reviewer, comment, created_at, downstream_json
            FROM approval_history WHERE incident_id=? ORDER BY id DESC
        """, (incident_id,)).fetchall()
    result=[]
    for row in rows:
        item=dict(row)
        raw=item.pop("downstream_json")
        item["downstream"] = json.loads(raw) if raw else {}
        result.append(item)
    return result
