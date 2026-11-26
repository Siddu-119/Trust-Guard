"""Encrypted Post-Quantum Key Backup, Corruption Detection, and Safe Recovery."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from typing import Any

from fastapi import HTTPException

from .audit import record_audit_event, utc_now_iso
from .config import Settings
from .crypto import (
    InvalidTag,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64d,
    b64e,
    canonical_json,
    derive_aes_key,
    sha256_hex,
    sign_data,
    unwrap_private_key,
    verify_signature,
)


def list_backups(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """List backup summaries without exposing encrypted key blobs."""
    rows = conn.execute(
        """
        SELECT backup_id, created_by, created_at, key_count, revoked_count, payload_sha256, status
        FROM key_backups
        ORDER BY created_at DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def create_encrypted_backup(
    conn: sqlite3.Connection, settings: Settings, *, actor_id: str
) -> dict[str, Any]:
    """Create an AES-256-GCM encrypted and ML-DSA-65 signed key backup."""
    # Export only non-PENDING keys (never back up unverified pending key material)
    key_rows = conn.execute(
        """
        SELECT key_id, purpose, owner_id, algorithm, version, status,
               public_key_b64, encrypted_private_key, created_at,
               activated_at, retired_at, cutoff_at, revoked_at
        FROM crypto_keys
        WHERE status != 'PENDING'
        ORDER BY version ASC, key_id ASC
        """
    ).fetchall()

    keys_payload = []
    revoked_count = 0
    for row in key_rows:
        # Verify each key unwraps cleanly before backing it up
        unwrap_private_key(
            settings.master_key_bytes, row["key_id"], row["encrypted_private_key"]
        )
        if row["status"] == "REVOKED":
            revoked_count += 1
        keys_payload.append(dict(row))

    backup_id = f"bkp-{uuid.uuid4().hex[:12]}"
    created_at = utc_now_iso()
    plaintext_bytes = canonical_json({"backup_id": backup_id, "keys": keys_payload})
    payload_sha256 = sha256_hex(plaintext_bytes)

    salt = os.urandom(16)
    backup_key = derive_aes_key(
        settings.master_key_bytes,
        salt=salt,
        info=f"trustguard:backup:{backup_id}".encode("utf-8"),
    )
    nonce, ciphertext = aes_gcm_encrypt(
        backup_key,
        plaintext_bytes,
        aad=f"{backup_id}|{payload_sha256}".encode("utf-8"),
    )

    # Sign backup manifest with active system BACKUP_SIGNING ML-DSA-65 key
    sig_key = conn.execute(
        """
        SELECT key_id, public_key_b64, encrypted_private_key
        FROM crypto_keys
        WHERE purpose = 'BACKUP_SIGNING' AND owner_id = 'system' AND status = 'ACTIVE'
        ORDER BY version DESC LIMIT 1
        """
    ).fetchone()
    if not sig_key:
        raise HTTPException(
            status_code=500, detail="System BACKUP_SIGNING ML-DSA-65 key unavailable."
        )

    sys_sk = unwrap_private_key(
        settings.master_key_bytes, sig_key["key_id"], sig_key["encrypted_private_key"]
    )
    manifest_bytes = canonical_json(
        {
            "backup_id": backup_id,
            "created_at": created_at,
            "payload_sha256": payload_sha256,
            "salt": b64e(salt),
            "nonce": b64e(nonce),
            "ct": b64e(ciphertext),
        }
    )
    signature = sign_data(sys_sk, manifest_bytes)

    blob = {
        "v": 1,
        "backup_id": backup_id,
        "created_at": created_at,
        "payload_sha256": payload_sha256,
        "signing_key_id": sig_key["key_id"],
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ct": b64e(ciphertext),
        "signature_b64": b64e(signature),
    }

    conn.execute(
        """
        INSERT INTO key_backups (
            backup_id, created_by, created_at, key_count, revoked_count,
            payload_sha256, backup_blob_json, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'VALID')
        """,
        (
            backup_id,
            actor_id,
            created_at,
            len(keys_payload),
            revoked_count,
            payload_sha256,
            json.dumps(blob, separators=(",", ":")),
        ),
    )
    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="BACKUP_CREATED",
        resource=backup_id,
        result="SUCCESS",
        metadata={
            "key_count": len(keys_payload),
            "revoked_count": revoked_count,
            "payload_sha256": payload_sha256,
        },
        timestamp=created_at,
    )

    return {
        "backup_id": backup_id,
        "created_by": actor_id,
        "created_at": created_at,
        "key_count": len(keys_payload),
        "revoked_count": revoked_count,
        "payload_sha256": payload_sha256,
        "status": "VALID",
    }


def _verify_and_decrypt_backup(
    conn: sqlite3.Connection, settings: Settings, *, backup_id: str
) -> tuple[bool, str, dict[str, Any] | None]:
    row = conn.execute(
        "SELECT * FROM key_backups WHERE backup_id = ?", (backup_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Backup '{backup_id}' not found.")

    try:
        blob = json.loads(row["backup_blob_json"])
        salt = b64d(blob["salt"])
        nonce = b64d(blob["nonce"])
        ct = b64d(blob["ct"])
        sig = b64d(blob["signature_b64"])
        expected_sha = row["payload_sha256"]
        if blob.get("payload_sha256") != expected_sha:
            return False, "Backup manifest SHA-256 does not match stored header.", None
    except Exception as exc:
        return False, f"Backup envelope structure corrupted: {exc}", None

    # 1. Verify ML-DSA-65 signature
    sig_key = conn.execute(
        "SELECT public_key_b64 FROM crypto_keys WHERE key_id = ?",
        (blob.get("signing_key_id"),),
    ).fetchone()
    if not sig_key:
        return False, "Backup signing key missing; refusing unverified backup.", None

    manifest_bytes = canonical_json(
        {
            "backup_id": blob["backup_id"],
            "created_at": blob["created_at"],
            "payload_sha256": expected_sha,
            "salt": blob["salt"],
            "nonce": blob["nonce"],
            "ct": blob["ct"],
        }
    )
    if not verify_signature(b64d(sig_key["public_key_b64"]), manifest_bytes, sig):
        return False, "ML-DSA-65 backup signature verification failed (tampered or corrupted).", None

    # 2. Decrypt AES-256-GCM backup ciphertext
    backup_key = derive_aes_key(
        settings.master_key_bytes,
        salt=salt,
        info=f"trustguard:backup:{backup_id}".encode("utf-8"),
    )
    try:
        pt_bytes = aes_gcm_decrypt(
            backup_key,
            nonce,
            ct,
            aad=f"{backup_id}|{expected_sha}".encode("utf-8"),
        )
    except InvalidTag:
        return False, "AES-256-GCM authentication tag failed (ciphertext corrupted).", None

    # 3. Verify payload SHA-256 digest
    actual_sha = sha256_hex(pt_bytes)
    if actual_sha != expected_sha:
        return False, "Decrypted payload SHA-256 mismatch.", None

    payload = json.loads(pt_bytes.decode("utf-8"))
    return True, "Backup integrity, ML-DSA-65 signature, and AES-GCM tag verified.", payload


def verify_backup_integrity(
    conn: sqlite3.Connection, settings: Settings, *, backup_id: str, actor_id: str
) -> dict[str, Any]:
    valid, reason, payload = _verify_and_decrypt_backup(conn, settings, backup_id=backup_id)
    new_status = "VALID" if valid else "CORRUPTED"
    conn.execute(
        "UPDATE key_backups SET status = ? WHERE backup_id = ?", (new_status, backup_id)
    )
    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="BACKUP_VERIFIED",
        resource=backup_id,
        result="VALID" if valid else "CORRUPTED",
        metadata={"reason": reason},
    )

    return {
        "backup_id": backup_id,
        "valid": valid,
        "corrupted": not valid,
        "status": new_status,
        "reason": reason,
        "verified_keys": len(payload["keys"]) if payload else 0,
    }


def restore_from_backup(
    conn: sqlite3.Connection, settings: Settings, *, backup_id: str, actor_id: str
) -> dict[str, Any]:
    """Verify and restore keys safely while preserving committed versions and revocations."""
    valid, reason, payload = _verify_and_decrypt_backup(conn, settings, backup_id=backup_id)
    if not valid or payload is None:
        conn.execute(
            "UPDATE key_backups SET status = 'CORRUPTED' WHERE backup_id = ?", (backup_id,)
        )
        conn.commit()
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="BACKUP_RESTORE",
            resource=backup_id,
            result="DENY_CORRUPTED",
            metadata={"reason": reason},
        )
        raise HTTPException(
            status_code=400,
            detail=f"Refusing restore from unverified/corrupted backup: {reason}",
        )

    restored_count = 0
    revoked_preserved = 0
    committed_preserved = 0

    for k in payload["keys"]:
        # Verify individual wrapped private key before restoring
        unwrap_private_key(
            settings.master_key_bytes, k["key_id"], k["encrypted_private_key"]
        )
        existing = conn.execute(
            "SELECT key_id, status, version FROM crypto_keys WHERE key_id = ?",
            (k["key_id"],),
        ).fetchone()

        if existing:
            # Never resurrect a key that was revoked either live or in the backup
            if existing["status"] == "REVOKED" or k["status"] == "REVOKED":
                conn.execute(
                    "UPDATE crypto_keys SET status = 'REVOKED', revoked_at = COALESCE(revoked_at, ?) WHERE key_id = ?",
                    (k.get("revoked_at") or utc_now_iso(), k["key_id"]),
                )
                revoked_preserved += 1
            else:
                committed_preserved += 1
            continue

        # Check if a newer committed ACTIVE key already exists for this (purpose, owner_id)
        newer_active = conn.execute(
            """
            SELECT MAX(version) AS max_v FROM crypto_keys
            WHERE purpose = ? AND owner_id = ? AND status = 'ACTIVE'
            """,
            (k["purpose"], k["owner_id"]),
        ).fetchone()
        max_live_v = int(newer_active["max_v"] or 0)

        target_status = k["status"]
        if target_status == "ACTIVE" and max_live_v > int(k["version"]):
            # Preserve newer committed version in DB; restore older key as RETIRED
            target_status = "RETIRED"
            committed_preserved += 1

        if target_status == "REVOKED":
            revoked_preserved += 1

        conn.execute(
            """
            INSERT INTO crypto_keys (
                key_id, purpose, owner_id, algorithm, version, status,
                public_key_b64, encrypted_private_key, created_at,
                activated_at, retired_at, cutoff_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                k["key_id"],
                k["purpose"],
                k["owner_id"],
                k["algorithm"],
                int(k["version"]),
                target_status,
                k["public_key_b64"],
                k["encrypted_private_key"],
                k["created_at"],
                k.get("activated_at"),
                k.get("retired_at"),
                k.get("cutoff_at"),
                k.get("revoked_at"),
            ),
        )
        restored_count += 1

    conn.commit()

    record_audit_event(
        conn,
        actor_id=actor_id,
        action="BACKUP_RESTORED",
        resource=backup_id,
        result="SUCCESS",
        metadata={
            "restored_count": restored_count,
            "revoked_preserved": revoked_preserved,
            "committed_preserved": committed_preserved,
        },
    )

    return {
        "backup_id": backup_id,
        "restored_keys": restored_count,
        "revoked_preserved": revoked_preserved,
        "committed_preserved": committed_preserved,
        "status": "RESTORED_SAFELY",
    }
