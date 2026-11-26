"""Device enrollment, revocation, and multi-node enforcement timing."""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from fastapi import HTTPException

from .audit import record_audit_event, utc_now_iso
from .nodes import propagate_device_revocation_to_nodes


def list_devices(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT d.device_id, d.owner_id, u.username AS owner_username, u.full_name AS owner_name,
               d.device_name, d.device_type, d.status, d.registered_at, d.last_activity,
               d.revoked_at, d.revoked_by, d.revocation_reason, d.replaces_device_id
        FROM devices d
        JOIN users u ON u.user_id = d.owner_id
        ORDER BY d.registered_at DESC
        """
    ).fetchall()

    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        node_rows = conn.execute(
            """
            SELECT nr.node_id, sn.name AS node_name, nr.enforced, nr.enforcement_ms,
                   nr.enforced_at, nr.status
            FROM node_revocations nr
            JOIN service_nodes sn ON sn.node_id = nr.node_id
            WHERE nr.device_id = ?
            ORDER BY nr.node_id ASC
            """,
            (row["device_id"],),
        ).fetchall()
        item["node_enforcement"] = [dict(nr) for nr in node_rows]
        result.append(item)
    return result


def register_device(
    conn: sqlite3.Connection,
    *,
    owner_id: str,
    device_name: str,
    device_type: str,
    actor_id: str,
    replaces_device_id: str | None = None,
) -> dict[str, Any]:
    owner = conn.execute("SELECT user_id, username FROM users WHERE user_id = ?", (owner_id,)).fetchone()
    if not owner:
        raise HTTPException(status_code=404, detail="Device owner user not found.")

    if replaces_device_id:
        old_dev = conn.execute(
            "SELECT * FROM devices WHERE device_id = ?", (replaces_device_id,)
        ).fetchone()
        if not old_dev:
            raise HTTPException(status_code=404, detail="Device to replace not found.")
        if old_dev["owner_id"] != owner_id:
            raise HTTPException(
                status_code=403, detail="Replacement device must belong to the same owner."
            )

    now_iso = utc_now_iso()
    device_id = f"dev-{owner['username'].split('.')[0]}-{uuid.uuid4().hex[:6]}"
    conn.execute(
        """
        INSERT INTO devices (
            device_id, owner_id, device_name, device_type, status,
            registered_at, last_activity, replaces_device_id
        ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
        """,
        (device_id, owner_id, device_name.strip(), device_type.strip(), now_iso, now_iso, replaces_device_id),
    )
    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="DEVICE_REPLACEMENT_ENROLLED" if replaces_device_id else "DEVICE_REGISTERED",
        resource=device_id,
        result="SUCCESS",
        metadata={
            "owner_id": owner_id,
            "device_name": device_name,
            "replaces_device_id": replaces_device_id or "none",
        },
        timestamp=now_iso,
    )

    row = conn.execute(
        """
        SELECT d.*, u.username AS owner_username, u.full_name AS owner_name
        FROM devices d JOIN users u ON u.user_id = d.owner_id
        WHERE d.device_id = ?
        """,
        (device_id,),
    ).fetchone()
    return {**dict(row), "node_enforcement": []}


def revoke_device(
    conn: sqlite3.Connection,
    *,
    device_id: str,
    actor_id: str,
    reason: str = "Reported lost or compromised",
) -> dict[str, Any]:
    dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if not dev:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")

    now_iso = utc_now_iso()
    if dev["status"] != "REVOKED":
        conn.execute(
            """
            UPDATE devices
            SET status = 'REVOKED', revoked_at = ?, revoked_by = ?, revocation_reason = ?
            WHERE device_id = ?
            """,
            (now_iso, actor_id, reason, device_id),
        )
        conn.commit()

    propagation = propagate_device_revocation_to_nodes(conn, device_id=device_id)

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="DEVICE_REVOKED",
        resource=device_id,
        result="SUCCESS",
        metadata={
            "owner_id": dev["owner_id"],
            "reason": reason,
            "nodes_enforced": sum(1 for p in propagation if p["status"] == "ENFORCED"),
            "nodes_pending": sum(1 for p in propagation if p["status"] == "PENDING_SYNC"),
        },
        timestamp=now_iso,
    )

    updated = conn.execute(
        """
        SELECT d.*, u.username AS owner_username, u.full_name AS owner_name
        FROM devices d JOIN users u ON u.user_id = d.owner_id
        WHERE d.device_id = ?
        """,
        (device_id,),
    ).fetchone()
    return {
        "device": {**dict(updated), "node_enforcement": propagation},
        "node_propagation": propagation,
    }
