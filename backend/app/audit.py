"""Tamper-evident hash-chained audit logging for TrustGuard.

Each audit event links cryptographically to the previous event's SHA-256 hash
using canonical JSON serialization. User-supplied text is serialized strictly
inside typed JSON fields and never concatenated into raw log strings, preventing
log injection or actor spoofing. Sensitive fields (passwords, private keys,
plaintext messages, tokens) are rejected/redacted before persistence.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from .crypto import canonical_json, sha256_hex

_AUDIT_LOCK = threading.Lock()

FORBIDDEN_METADATA_KEYS = {
    "password",
    "password_hash",
    "private_key",
    "secret_key",
    "encrypted_private_key",
    "plaintext",
    "message_body",
    "shared_secret",
    "token",
    "master_key",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Strip any forbidden sensitive fields and ensure JSON-safe scalar values."""
    if not metadata:
        return {}
    clean: dict[str, Any] = {}
    for k, v in metadata.items():
        key_str = str(k)
        if key_str.lower() in FORBIDDEN_METADATA_KEYS:
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            clean[key_str] = str(v)[:300] if isinstance(v, str) else v
        else:
            clean[key_str] = str(v)[:300]
    return clean


def _compute_event_hash(
    *,
    event_id: str,
    actor_id: str,
    action: str,
    resource: str,
    timestamp: str,
    result: str,
    metadata_json: str,
    previous_hash: str,
) -> str:
    payload = {
        "event_id": event_id,
        "actor_id": actor_id,
        "action": action,
        "resource": resource,
        "timestamp": timestamp,
        "result": result,
        "metadata_json": metadata_json,
        "previous_hash": previous_hash,
    }
    canonical = canonical_json(payload)
    return sha256_hex(canonical)


def record_audit_event(
    conn: sqlite3.Connection,
    *,
    actor_id: str,
    action: str,
    resource: str,
    result: str,
    metadata: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Append a tamper-evident event to the hash-chained audit_logs table."""
    safe_actor = str(actor_id).strip() or "system"
    safe_action = str(action).strip()[:120]
    safe_resource = str(resource).strip()[:160]
    safe_result = str(result).strip()[:64]
    ts = timestamp or utc_now_iso()
    event_id = f"evt-{uuid.uuid4().hex[:16]}"
    sanitized_meta = _sanitize_metadata(metadata)
    metadata_json = canonical_json(sanitized_meta).decode("utf-8")

    with _AUDIT_LOCK:
        row = conn.execute(
            "SELECT current_hash FROM audit_logs ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = row["current_hash"] if row else "GENESIS"

        current_hash = _compute_event_hash(
            event_id=event_id,
            actor_id=safe_actor,
            action=safe_action,
            resource=safe_resource,
            timestamp=ts,
            result=safe_result,
            metadata_json=metadata_json,
            previous_hash=previous_hash,
        )

        conn.execute(
            """
            INSERT INTO audit_logs (
                event_id, actor_id, action, resource, timestamp,
                result, metadata_json, previous_hash, current_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                safe_actor,
                safe_action,
                safe_resource,
                ts,
                safe_result,
                metadata_json,
                previous_hash,
                current_hash,
            ),
        )
        conn.commit()

    return {
        "event_id": event_id,
        "actor_id": safe_actor,
        "action": safe_action,
        "resource": safe_resource,
        "timestamp": ts,
        "result": safe_result,
        "metadata_json": metadata_json,
        "previous_hash": previous_hash,
        "current_hash": current_hash,
    }


def verify_audit_chain(conn: sqlite3.Connection) -> dict[str, Any]:
    """Verify the entire audit_logs hash chain from GENESIS to the latest event."""
    rows = conn.execute(
        """
        SELECT seq, event_id, actor_id, action, resource, timestamp,
               result, metadata_json, previous_hash, current_hash
        FROM audit_logs
        ORDER BY seq ASC
        """
    ).fetchall()

    expected_prev = "GENESIS"
    checked = 0
    for row in rows:
        checked += 1
        if row["previous_hash"] != expected_prev:
            return {
                "valid": False,
                "tampered": True,
                "checked_events": checked,
                "broken_event_id": row["event_id"],
                "broken_seq": row["seq"],
                "reason": (
                    f"Chain link mismatch at {row['event_id']}: "
                    f"expected previous_hash {expected_prev[:12]}..., "
                    f"got {row['previous_hash'][:12]}..."
                ),
            }

        recomputed = _compute_event_hash(
            event_id=row["event_id"],
            actor_id=row["actor_id"],
            action=row["action"],
            resource=row["resource"],
            timestamp=row["timestamp"],
            result=row["result"],
            metadata_json=row["metadata_json"],
            previous_hash=row["previous_hash"],
        )
        if recomputed != row["current_hash"]:
            return {
                "valid": False,
                "tampered": True,
                "checked_events": checked,
                "broken_event_id": row["event_id"],
                "broken_seq": row["seq"],
                "reason": (
                    f"Content hash mismatch at {row['event_id']}: "
                    "record fields were altered after logging."
                ),
            }
        expected_prev = row["current_hash"]

    return {
        "valid": True,
        "tampered": False,
        "checked_events": checked,
        "broken_event_id": None,
        "broken_seq": None,
        "latest_hash": expected_prev,
        "reason": f"All {checked} audit events verified cleanly from GENESIS.",
    }


def list_audit_events(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT seq, event_id, actor_id, action, resource, timestamp,
               result, metadata_json, previous_hash, current_hash
        FROM audit_logs
        ORDER BY seq DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]
