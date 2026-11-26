"""Post-Quantum Key Management, Recoverable Rotation (PENDING -> COMMITTED), and Cutoff Policy."""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from fastapi import HTTPException

from .audit import record_audit_event, utc_now_iso
from .config import Settings
from .crypto import (
    KEM_ALGORITHM,
    SIGN_ALGORITHM,
    b64e,
    generate_kem_keypair,
    generate_signing_keypair,
    unwrap_private_key,
    wrap_private_key,
)
from .nodes import propagate_key_revocation_to_nodes, propagate_key_version_to_nodes
from .threat_detection import SecurityEventInput, process_and_store_event

PUBLIC_KEY_COLUMNS = """
    key_id, purpose, owner_id, algorithm, version, status,
    public_key_b64, created_at, activated_at, retired_at, cutoff_at, revoked_at
"""


def get_grace_versions(conn: sqlite3.Connection, settings: Settings) -> int:
    row = conn.execute(
        "SELECT value FROM app_settings WHERE key = 'key_grace_versions'"
    ).fetchone()
    if row is not None:
        try:
            return max(0, int(row["value"]))
        except ValueError:
            pass
    return settings.key_grace_versions


def list_keys(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return key metadata only. Private key material is NEVER exposed."""
    rows = conn.execute(
        f"""
        SELECT {PUBLIC_KEY_COLUMNS}
        FROM crypto_keys
        ORDER BY owner_id ASC, purpose ASC, version DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def list_rotations(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT rotation_id, purpose, owner_id, old_key_id, new_key_id,
               old_version, new_version, state, initiated_by,
               started_at, committed_at, recovered, notes
        FROM key_rotations
        ORDER BY started_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def generate_keypair_entry(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    purpose: str,
    owner_id: str,
    algorithm: str,
    actor_id: str,
) -> dict[str, Any]:
    """Generate a new PQC keypair, encrypt private key at rest, and persist."""
    if algorithm == KEM_ALGORITHM:
        pk, sk = generate_kem_keypair()
    elif algorithm == SIGN_ALGORITHM:
        pk, sk = generate_signing_keypair()
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported algorithm '{algorithm}'. Use '{KEM_ALGORITHM}' or '{SIGN_ALGORITHM}'.",
        )

    max_row = conn.execute(
        "SELECT MAX(version) AS max_v FROM crypto_keys WHERE purpose = ? AND owner_id = ?",
        (purpose, owner_id),
    ).fetchone()
    next_ver = int(max_row["max_v"] or 0) + 1
    key_id = f"key-{purpose.lower()[:6]}-{uuid.uuid4().hex[:8]}-v{next_ver}"
    now_iso = utc_now_iso()

    # Retire previous active key for same (purpose, owner_id) if any
    conn.execute(
        """
        UPDATE crypto_keys
        SET status = 'RETIRED', retired_at = ?
        WHERE purpose = ? AND owner_id = ? AND status = 'ACTIVE'
        """,
        (now_iso, purpose, owner_id),
    )

    wrapped_sk = wrap_private_key(settings.master_key_bytes, key_id, sk)
    conn.execute(
        """
        INSERT INTO crypto_keys (
            key_id, purpose, owner_id, algorithm, version, status,
            public_key_b64, encrypted_private_key, created_at, activated_at
        ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)
        """,
        (key_id, purpose, owner_id, algorithm, next_ver, b64e(pk), wrapped_sk, now_iso, now_iso),
    )
    _apply_cutoff_policy_locked(conn, settings, purpose=purpose, owner_id=owner_id, active_version=next_ver, now_iso=now_iso)
    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="KEY_GENERATED",
        resource=key_id,
        result="SUCCESS",
        metadata={"purpose": purpose, "owner_id": owner_id, "algorithm": algorithm, "version": next_ver},
    )

    row = conn.execute(
        f"SELECT {PUBLIC_KEY_COLUMNS} FROM crypto_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    return dict(row)


def _apply_cutoff_policy_locked(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    purpose: str,
    owner_id: str,
    active_version: int,
    now_iso: str,
) -> list[str]:
    """Expire keys older than (active_version - grace_versions) per cutoff policy."""
    grace = get_grace_versions(conn, settings)
    cutoff_threshold = active_version - grace
    stale_rows = conn.execute(
        """
        SELECT key_id FROM crypto_keys
        WHERE purpose = ? AND owner_id = ?
          AND status IN ('RETIRED', 'ACTIVE')
          AND version < ?
        """,
        (purpose, owner_id, cutoff_threshold),
    ).fetchall()
    expired_ids = [r["key_id"] for r in stale_rows]
    if expired_ids:
        conn.execute(
            """
            UPDATE crypto_keys
            SET status = 'EXPIRED_CUTOFF', cutoff_at = ?
            WHERE purpose = ? AND owner_id = ?
              AND status IN ('RETIRED', 'ACTIVE')
              AND version < ?
            """,
            (now_iso, purpose, owner_id, cutoff_threshold),
        )
    return expired_ids


def _commit_pending_rotation(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    rotation_id: str,
    actor_id: str,
    recovered: bool = False,
) -> dict[str, Any]:
    """Atomically verify and commit a PENDING rotation to COMMITTED."""
    rot = conn.execute(
        "SELECT * FROM key_rotations WHERE rotation_id = ?", (rotation_id,)
    ).fetchone()
    if not rot:
        raise HTTPException(status_code=404, detail="Rotation record not found.")
    if rot["state"] == "COMMITTED":
        return dict(rot)
    if rot["state"] != "PENDING":
        raise HTTPException(
            status_code=409, detail=f"Rotation '{rotation_id}' is in state '{rot['state']}'."
        )

    new_key = conn.execute(
        "SELECT * FROM crypto_keys WHERE key_id = ?", (rot["new_key_id"],)
    ).fetchone()
    now_iso = utc_now_iso()

    # Never use unverified or revoked key material during recovery
    if not new_key or new_key["status"] == "REVOKED":
        conn.execute(
            """
            UPDATE key_rotations
            SET state = 'ROLLED_BACK', committed_at = ?, recovered = ?, notes = ?
            WHERE rotation_id = ?
            """,
            (now_iso, 1 if recovered else 0, "Rolled back: pending key missing or revoked", rotation_id),
        )
        conn.commit()
        raise HTTPException(status_code=409, detail="Pending key missing or revoked; rolled back.")

    try:
        unwrapped = unwrap_private_key(
            settings.master_key_bytes, new_key["key_id"], new_key["encrypted_private_key"]
        )
        if not unwrapped:
            raise ValueError("Empty unwrapped private key")
    except Exception as exc:
        conn.execute(
            "UPDATE crypto_keys SET status = 'REVOKED', revoked_at = ? WHERE key_id = ?",
            (now_iso, new_key["key_id"]),
        )
        conn.execute(
            """
            UPDATE key_rotations
            SET state = 'ROLLED_BACK', committed_at = ?, recovered = ?, notes = ?
            WHERE rotation_id = ?
            """,
            (now_iso, 1 if recovered else 0, f"Rolled back: integrity check failed ({exc})", rotation_id),
        )
        conn.commit()
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="KEY_ROTATION_ROLLED_BACK",
            resource=rotation_id,
            result="FAIL",
            metadata={"new_key_id": new_key["key_id"], "reason": "integrity_check_failed"},
        )
        raise HTTPException(status_code=500, detail="Pending key integrity failed; rotation rolled back.")

    # Promote new key to ACTIVE and retire old key (while strictly preserving any REVOKED status)
    if rot["old_key_id"]:
        conn.execute(
            """
            UPDATE crypto_keys
            SET status = CASE WHEN status = 'REVOKED' THEN 'REVOKED' ELSE 'RETIRED' END,
                retired_at = COALESCE(retired_at, ?)
            WHERE key_id = ?
            """,
            (now_iso, rot["old_key_id"]),
        )

    conn.execute(
        """
        UPDATE crypto_keys
        SET status = 'ACTIVE', activated_at = ?
        WHERE key_id = ?
        """,
        (now_iso, new_key["key_id"]),
    )

    expired_ids = _apply_cutoff_policy_locked(
        conn,
        settings,
        purpose=rot["purpose"],
        owner_id=rot["owner_id"],
        active_version=int(rot["new_version"]),
        now_iso=now_iso,
    )

    note = (
        f"Recovered interrupted PENDING rotation to v{rot['new_version']}; expired cutoff keys: {len(expired_ids)}"
        if recovered
        else f"Committed rotation to v{rot['new_version']}; expired cutoff keys: {len(expired_ids)}"
    )
    conn.execute(
        """
        UPDATE key_rotations
        SET state = 'COMMITTED', committed_at = ?, recovered = ?, notes = ?
        WHERE rotation_id = ?
        """,
        (now_iso, 1 if recovered else 0, note, rotation_id),
    )
    conn.commit()

    node_sync = propagate_key_version_to_nodes(conn, new_version=int(rot["new_version"]))

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="KEY_ROTATION_RECOVERED" if recovered else "KEY_ROTATION_COMMITTED",
        resource=new_key["key_id"],
        result="SUCCESS",
        metadata={
            "rotation_id": rotation_id,
            "old_key_id": rot["old_key_id"] or "none",
            "new_version": rot["new_version"],
            "expired_cutoff_count": len(expired_ids),
            "recovered": recovered,
        },
    )

    committed_rot = conn.execute(
        "SELECT * FROM key_rotations WHERE rotation_id = ?", (rotation_id,)
    ).fetchone()
    new_key_pub = conn.execute(
        f"SELECT {PUBLIC_KEY_COLUMNS} FROM crypto_keys WHERE key_id = ?",
        (new_key["key_id"],),
    ).fetchone()

    return {
        "rotation": dict(committed_rot),
        "new_key": dict(new_key_pub),
        "expired_cutoff_keys": expired_ids,
        "node_propagation": node_sync,
    }


def rotate_key(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    purpose: str,
    owner_id: str,
    actor_id: str,
    actor_role: str,
    simulate_crash: bool = False,
) -> dict[str, Any]:
    """Rotate a key using a two-phase recoverable state machine: PENDING -> COMMITTED."""
    # Prevent starting another rotation while one is already PENDING for the same target
    pending = conn.execute(
        """
        SELECT rotation_id FROM key_rotations
        WHERE purpose = ? AND owner_id = ? AND state = 'PENDING'
        """,
        (purpose, owner_id),
    ).fetchone()
    if pending:
        raise HTTPException(
            status_code=409,
            detail=f"Interrupted rotation '{pending['rotation_id']}' is still PENDING. Recover it first.",
        )

    current = conn.execute(
        """
        SELECT * FROM crypto_keys
        WHERE purpose = ? AND owner_id = ? AND status = 'ACTIVE'
        ORDER BY version DESC LIMIT 1
        """,
        (purpose, owner_id),
    ).fetchone()

    if not current:
        # Determine algorithm from latest key or purpose default
        latest_any = conn.execute(
            """
            SELECT algorithm, MAX(version) AS max_v FROM crypto_keys
            WHERE purpose = ? AND owner_id = ?
            """,
            (purpose, owner_id),
        ).fetchone()
        algorithm = (
            latest_any["algorithm"]
            if latest_any and latest_any["algorithm"]
            else (KEM_ALGORITHM if "KEM" in purpose or "TRANSPORT" in purpose else SIGN_ALGORITHM)
        )
        old_key_id = None
        old_version = int(latest_any["max_v"] or 0) if latest_any else 0
    else:
        algorithm = current["algorithm"]
        old_key_id = current["key_id"]
        old_version = int(current["version"])

    new_version = old_version + 1
    if algorithm == KEM_ALGORITHM:
        pk, sk = generate_kem_keypair()
    else:
        pk, sk = generate_signing_keypair()

    new_key_id = f"key-{purpose.lower()[:6]}-{uuid.uuid4().hex[:8]}-v{new_version}"
    rotation_id = f"rot-{uuid.uuid4().hex[:12]}"
    now_iso = utc_now_iso()

    # Phase 1: Write PENDING key and PENDING rotation state durably
    wrapped_sk = wrap_private_key(settings.master_key_bytes, new_key_id, sk)
    conn.execute(
        """
        INSERT INTO crypto_keys (
            key_id, purpose, owner_id, algorithm, version, status,
            public_key_b64, encrypted_private_key, created_at
        ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
        """,
        (new_key_id, purpose, owner_id, algorithm, new_version, b64e(pk), wrapped_sk, now_iso),
    )
    conn.execute(
        """
        INSERT INTO key_rotations (
            rotation_id, purpose, owner_id, old_key_id, new_key_id,
            old_version, new_version, state, initiated_by, started_at, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
        """,
        (
            rotation_id,
            purpose,
            owner_id,
            old_key_id,
            new_key_id,
            old_version,
            new_version,
            actor_id,
            now_iso,
            "Interrupted during PENDING phase (simulated crash)" if simulate_crash else "Rotation started",
        ),
    )
    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="KEY_ROTATION_PENDING",
        resource=new_key_id,
        result="INTERRUPTED" if simulate_crash else "PENDING",
        metadata={
            "rotation_id": rotation_id,
            "purpose": purpose,
            "owner_id": owner_id,
            "new_version": new_version,
            "simulate_crash": simulate_crash,
        },
        timestamp=now_iso,
    )

    # Emit threat telemetry for rapid consecutive key rotations check
    process_and_store_event(
        conn,
        SecurityEventInput(
            user_identity=actor_id,
            role=actor_role,
            device_id=None,
            device_status="ACTIVE",
            source_service="node-a",
            destination_service="key-vault",
            resource="keys",
            action="rotate",
            decision="ALLOW",
            event_time=now_iso,
        ),
    )

    if simulate_crash:
        rot_row = conn.execute(
            "SELECT * FROM key_rotations WHERE rotation_id = ?", (rotation_id,)
        ).fetchone()
        pending_pub = conn.execute(
            f"SELECT {PUBLIC_KEY_COLUMNS} FROM crypto_keys WHERE key_id = ?", (new_key_id,)
        ).fetchone()
        return {
            "interrupted": True,
            "rotation": dict(rot_row),
            "new_key": dict(pending_pub),
            "message": "Simulated application crash during rotation: state remains PENDING.",
        }

    # Phase 2: Commit transition PENDING -> COMMITTED
    result = _commit_pending_rotation(
        conn, settings, rotation_id=rotation_id, actor_id=actor_id, recovered=False
    )
    return {"interrupted": False, **result}


def recover_pending_rotations(
    conn: sqlite3.Connection, settings: Settings, *, actor_id: str = "system"
) -> list[dict[str, Any]]:
    """Recover any interrupted PENDING rotations safely (called at startup and on demand)."""
    pending_rows = conn.execute(
        "SELECT rotation_id FROM key_rotations WHERE state = 'PENDING' ORDER BY started_at ASC"
    ).fetchall()
    recovered_results: list[dict[str, Any]] = []
    for row in pending_rows:
        try:
            res = _commit_pending_rotation(
                conn,
                settings,
                rotation_id=row["rotation_id"],
                actor_id=actor_id,
                recovered=True,
            )
            recovered_results.append({"rotation_id": row["rotation_id"], "status": "RECOVERED_COMMITTED", **res})
        except HTTPException as exc:
            recovered_results.append(
                {"rotation_id": row["rotation_id"], "status": "ROLLED_BACK", "detail": exc.detail}
            )
    return recovered_results


def verify_key_usage(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    key_id: str,
    actor_id: str,
    actor_role: str,
    node_id: str | None = None,
) -> dict[str, Any]:
    """Verify whether a key version is allowed under the current cutoff and node revocation policy."""
    key_row = conn.execute(
        f"SELECT {PUBLIC_KEY_COLUMNS} FROM crypto_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    if not key_row:
        raise HTTPException(status_code=404, detail=f"Key '{key_id}' not found.")

    if node_id:
        node_row = conn.execute(
            "SELECT name, status FROM service_nodes WHERE node_id = ?", (node_id,)
        ).fetchone()
        if not node_row:
            raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found.")
        if node_row["status"] == "OFFLINE":
            return {
                "key_id": key_id,
                "node_id": node_id,
                "version": key_row["version"],
                "status": "NODE_OFFLINE",
                "accepted": False,
                "reason": f"Node '{node_row['name']}' is OFFLINE.",
            }

    grace = get_grace_versions(conn, settings)
    active_row = conn.execute(
        """
        SELECT MAX(version) AS max_v FROM crypto_keys
        WHERE purpose = ? AND owner_id = ? AND status = 'ACTIVE'
        """,
        (key_row["purpose"], key_row["owner_id"]),
    ).fetchone()
    active_v = int(active_row["max_v"] or key_row["version"])
    now_iso = utc_now_iso()

    status_val = key_row["status"]
    if status_val == "REVOKED":
        accepted = False
        reason = f"Key '{key_id}' (v{key_row['version']}) is REVOKED and permanently rejected."
        reason_code = "REVOKED_KEY_USAGE"
    elif status_val == "EXPIRED_CUTOFF":
        accepted = False
        reason = (
            f"Key '{key_id}' (v{key_row['version']}) is past cutoff policy "
            f"(active v{active_v}, grace={grace} version(s))."
        )
        reason_code = "EXPIRED_KEY_USAGE"
    elif status_val == "PENDING":
        accepted = False
        reason = f"Key '{key_id}' is still PENDING commit and cannot be used yet."
        reason_code = "UNAUTHORIZED_KEY_OP"
    elif status_val == "RETIRED":
        if int(key_row["version"]) < (active_v - grace):
            conn.execute(
                "UPDATE crypto_keys SET status = 'EXPIRED_CUTOFF', cutoff_at = ? WHERE key_id = ?",
                (now_iso, key_id),
            )
            conn.commit()
            accepted = False
            reason = (
                f"Key '{key_id}' (v{key_row['version']}) exceeded cutoff window "
                f"(active v{active_v}, grace={grace})."
            )
            reason_code = "EXPIRED_KEY_USAGE"
            status_val = "EXPIRED_CUTOFF"
        else:
            accepted = True
            reason = (
                f"Key '{key_id}' (v{key_row['version']}) is RETIRED but still within "
                f"grace window (active v{active_v}, grace={grace})."
            )
            reason_code = ""
    else:
        accepted = True
        reason = f"Key '{key_id}' (v{key_row['version']}) is ACTIVE and valid."
        reason_code = ""

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="KEY_USAGE_CHECK",
        resource=key_id,
        result="ALLOW" if accepted else "DENY",
        metadata={"key_status": status_val, "version": key_row["version"], "reason": reason},
        timestamp=now_iso,
    )

    if not accepted:
        process_and_store_event(
            conn,
            SecurityEventInput(
                user_identity=actor_id,
                role=actor_role,
                device_id=None,
                device_status="ACTIVE",
                source_service="node-a",
                destination_service="key-vault",
                resource="keys",
                action="verify",
                decision="DENY",
                event_time=now_iso,
                key_status=status_val,
                reason_code=reason_code,
            ),
        )

    return {
        "key_id": key_id,
        "node_id": node_id,
        "version": key_row["version"],
        "status": status_val,
        "accepted": accepted,
        "active_version": active_v,
        "grace_versions": grace,
        "reason": reason,
    }


def revoke_key_entry(
    conn: sqlite3.Connection, *, key_id: str, actor_id: str, reason: str = "Compromised or administrative revocation"
) -> dict[str, Any]:
    key_row = conn.execute(
        f"SELECT {PUBLIC_KEY_COLUMNS} FROM crypto_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    if not key_row:
        raise HTTPException(status_code=404, detail=f"Key '{key_id}' not found.")

    now_iso = utc_now_iso()
    conn.execute(
        "UPDATE crypto_keys SET status = 'REVOKED', revoked_at = ? WHERE key_id = ?",
        (now_iso, key_id),
    )
    conn.commit()

    propagation = propagate_key_revocation_to_nodes(conn, key_id=key_id)

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="KEY_REVOKED",
        resource=key_id,
        result="SUCCESS",
        metadata={
            "purpose": key_row["purpose"],
            "version": key_row["version"],
            "reason": reason,
            "nodes_enforced": sum(1 for p in propagation if p["status"] == "ENFORCED"),
        },
        timestamp=now_iso,
    )

    updated = conn.execute(
        f"SELECT {PUBLIC_KEY_COLUMNS} FROM crypto_keys WHERE key_id = ?", (key_id,)
    ).fetchone()
    return {**dict(updated), "node_propagation": propagation}
