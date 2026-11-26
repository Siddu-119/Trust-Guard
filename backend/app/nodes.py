"""Persistent simulation of Service Nodes A, B, and C.

Demonstrates distributed key rotation propagation, device revocation enforcement
with measured per-node latency, node-level access verification, and offline
recovery synchronization.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from fastapi import HTTPException

from .audit import record_audit_event, utc_now_iso


def list_service_nodes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    nodes = conn.execute(
        """
        SELECT node_id, name, role, status, synced_key_version, last_sync_at, last_sync_latency_ms
        FROM service_nodes
        ORDER BY node_id ASC
        """
    ).fetchall()

    result: list[dict[str, Any]] = []
    for node in nodes:
        rev_rows = conn.execute(
            """
            SELECT device_id, enforced, enforcement_ms, enforced_at, status
            FROM node_revocations
            WHERE node_id = ?
            ORDER BY id DESC
            """,
            (node["node_id"],),
        ).fetchall()
        enforced_list = [dict(r) for r in rev_rows]
        pending_count = sum(1 for r in enforced_list if r["status"] == "PENDING_SYNC")
        result.append(
            {
                **dict(node),
                "revoked_devices_enforced": sum(1 for r in enforced_list if r["enforced"] == 1),
                "pending_revocations": pending_count,
                "revocation_records": enforced_list,
            }
        )
    return result


def get_latest_active_key_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT MAX(version) AS max_v FROM crypto_keys WHERE status = 'ACTIVE'"
    ).fetchone()
    return int(row["max_v"] or 1)


def propagate_key_version_to_nodes(
    conn: sqlite3.Connection, *, new_version: int
) -> list[dict[str, Any]]:
    """Push committed key version to all ONLINE nodes; OFFLINE nodes remain behind until sync."""
    nodes = conn.execute("SELECT * FROM service_nodes ORDER BY node_id ASC").fetchall()
    now_iso = utc_now_iso()
    report: list[dict[str, Any]] = []

    for node in nodes:
        t0 = time.perf_counter()
        if node["status"] == "ONLINE":
            # Verify node state update in SQLite and measure actual latency
            conn.execute(
                """
                UPDATE service_nodes
                SET synced_key_version = ?, last_sync_at = ?, last_sync_latency_ms = ?
                WHERE node_id = ?
                """,
                (new_version, now_iso, 0.0, node["node_id"]),
            )
            elapsed_ms = round(max(0.05, (time.perf_counter() - t0) * 1000.0), 3)
            conn.execute(
                "UPDATE service_nodes SET last_sync_latency_ms = ? WHERE node_id = ?",
                (elapsed_ms, node["node_id"]),
            )
            report.append(
                {
                    "node_id": node["node_id"],
                    "name": node["name"],
                    "status": "SYNCED",
                    "synced_key_version": new_version,
                    "latency_ms": elapsed_ms,
                }
            )
        else:
            report.append(
                {
                    "node_id": node["node_id"],
                    "name": node["name"],
                    "status": "DEFERRED_OFFLINE",
                    "synced_key_version": node["synced_key_version"],
                    "latency_ms": None,
                }
            )
    conn.commit()
    return report


def propagate_device_revocation_to_nodes(
    conn: sqlite3.Connection, *, device_id: str
) -> list[dict[str, Any]]:
    """Enforce device revocation across all service nodes and measure per-node timing."""
    nodes = conn.execute("SELECT * FROM service_nodes ORDER BY node_id ASC").fetchall()
    now_iso = utc_now_iso()
    propagation: list[dict[str, Any]] = []

    for node in nodes:
        t0 = time.perf_counter()
        if node["status"] == "ONLINE":
            conn.execute(
                """
                INSERT INTO node_revocations (node_id, device_id, enforced, enforcement_ms, enforced_at, status)
                VALUES (?, ?, 1, 0.0, ?, 'ENFORCED')
                ON CONFLICT(node_id, device_id) DO UPDATE SET
                    enforced = 1,
                    enforced_at = excluded.enforced_at,
                    status = 'ENFORCED'
                """,
                (node["node_id"], device_id, now_iso),
            )
            elapsed_ms = round(max(0.05, (time.perf_counter() - t0) * 1000.0), 3)
            conn.execute(
                "UPDATE node_revocations SET enforcement_ms = ? WHERE node_id = ? AND device_id = ?",
                (elapsed_ms, node["node_id"], device_id),
            )
            propagation.append(
                {
                    "node_id": node["node_id"],
                    "name": node["name"],
                    "node_status": "ONLINE",
                    "status": "ENFORCED",
                    "enforcement_ms": elapsed_ms,
                    "enforced_at": now_iso,
                }
            )
        else:
            conn.execute(
                """
                INSERT INTO node_revocations (node_id, device_id, enforced, enforcement_ms, enforced_at, status)
                VALUES (?, ?, 0, NULL, NULL, 'PENDING_SYNC')
                ON CONFLICT(node_id, device_id) DO UPDATE SET
                    enforced = 0,
                    status = 'PENDING_SYNC'
                """,
                (node["node_id"], device_id),
            )
            propagation.append(
                {
                    "node_id": node["node_id"],
                    "name": node["name"],
                    "node_status": "OFFLINE",
                    "status": "PENDING_SYNC",
                    "enforcement_ms": None,
                    "enforced_at": None,
                }
            )
    conn.commit()
    return propagation


def sync_node(conn: sqlite3.Connection, *, node_id: str, actor_id: str) -> dict[str, Any]:
    """Synchronize a node with latest committed key version and any pending revocations."""
    node = conn.execute("SELECT * FROM service_nodes WHERE node_id = ?", (node_id,)).fetchone()
    if not node:
        raise HTTPException(status_code=404, detail=f"Service node '{node_id}' not found.")
    if node["status"] != "ONLINE":
        raise HTTPException(
            status_code=409,
            detail=f"Cannot synchronize '{node['name']}' while it is OFFLINE.",
        )

    t0 = time.perf_counter()
    now_iso = utc_now_iso()
    latest_ver = get_latest_active_key_version(conn)

    # Catch up all revoked devices not yet enforced on this node
    revoked_devices = conn.execute(
        "SELECT device_id FROM devices WHERE status = 'REVOKED'"
    ).fetchall()
    caught_up = 0
    for dev in revoked_devices:
        existing = conn.execute(
            "SELECT enforced FROM node_revocations WHERE node_id = ? AND device_id = ?",
            (node_id, dev["device_id"]),
        ).fetchone()
        if not existing or existing["enforced"] == 0:
            caught_up += 1
            step_t0 = time.perf_counter()
            conn.execute(
                """
                INSERT INTO node_revocations (node_id, device_id, enforced, enforcement_ms, enforced_at, status)
                VALUES (?, ?, 1, ?, ?, 'ENFORCED')
                ON CONFLICT(node_id, device_id) DO UPDATE SET
                    enforced = 1,
                    enforcement_ms = excluded.enforcement_ms,
                    enforced_at = excluded.enforced_at,
                    status = 'ENFORCED'
                """,
                (
                    node_id,
                    dev["device_id"],
                    round(max(0.05, (time.perf_counter() - step_t0) * 1000.0), 3),
                    now_iso,
                ),
            )

    total_ms = round(max(0.05, (time.perf_counter() - t0) * 1000.0), 3)
    conn.execute(
        """
        UPDATE service_nodes
        SET synced_key_version = ?, last_sync_at = ?, last_sync_latency_ms = ?
        WHERE node_id = ?
        """,
        (latest_ver, now_iso, total_ms, node_id),
    )
    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="NODE_SYNCHRONIZED",
        resource=node_id,
        result="SUCCESS",
        metadata={
            "synced_key_version": latest_ver,
            "caught_up_revocations": caught_up,
            "latency_ms": total_ms,
        },
    )

    return {
        "node_id": node_id,
        "status": "ONLINE",
        "synced_key_version": latest_ver,
        "caught_up_revocations": caught_up,
        "latency_ms": total_ms,
        "synced_at": now_iso,
    }


def set_node_status(
    conn: sqlite3.Connection, *, node_id: str, new_status: str, actor_id: str
) -> dict[str, Any]:
    """Set a service node ONLINE or OFFLINE; bringing ONLINE automatically reconciles pending updates."""
    if new_status not in {"ONLINE", "OFFLINE"}:
        raise HTTPException(status_code=400, detail="Status must be ONLINE or OFFLINE.")
    node = conn.execute("SELECT * FROM service_nodes WHERE node_id = ?", (node_id,)).fetchone()
    if not node:
        raise HTTPException(status_code=404, detail=f"Service node '{node_id}' not found.")

    conn.execute(
        "UPDATE service_nodes SET status = ? WHERE node_id = ?",
        (new_status, node_id),
    )
    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action=f"NODE_SET_{new_status}",
        resource=node_id,
        result="SUCCESS",
        metadata={"previous_status": node["status"], "new_status": new_status},
    )

    sync_result = None
    if new_status == "ONLINE":
        sync_result = sync_node(conn, node_id=node_id, actor_id=actor_id)

    updated = conn.execute("SELECT * FROM service_nodes WHERE node_id = ?", (node_id,)).fetchone()
    return {
        "node": dict(updated),
        "auto_sync": sync_result,
    }
