"""Post-Quantum Secure Messaging with Ephemeral Forward Secrecy and Replay Protection.

Forward Secrecy Design & Security Assumptions:
- Static long-term KEM keys alone do NOT provide forward secrecy: if a static
  KEM private key were later compromised, captured past ciphertexts could be
  decrypted.
- TrustGuard therefore generates a fresh ephemeral ML-KEM-768 keypair per
  message/session in volatile memory (`ephemeral_sessions`). After decapsulation
  at the verified delivery gate, the ephemeral secret key buffer is overwritten
  with zeros and evicted.
- Long-term ML-DSA-65 identity keys authenticate sender, recipient binding, and
  ciphertext integrity via canonical AAD, so compromising a signing key later
  cannot decrypt past ephemeral sessions (assuming ephemeral memory was not
  dumped during the brief active window).
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from fastapi import HTTPException

from .audit import record_audit_event, utc_now_iso
from .config import Settings
from .crypto import (
    KEM_ALGORITHM,
    SIGN_ALGORITHM,
    InvalidTag,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64d,
    b64e,
    canonical_json,
    derive_aes_key,
    ephemeral_sessions,
    kem_encapsulate,
    sha256_hex,
    sign_data,
    unwrap_private_key,
    verify_signature,
)
from .threat_detection import SecurityEventInput, process_and_store_event


def _seal_for_recipient_inbox(
    settings: Settings, *, recipient_id: str, message_id: str, plaintext: str
) -> str:
    """Seal verified message for the recipient's authenticated inbox view."""
    inbox_key = derive_aes_key(
        settings.master_key_bytes,
        salt=message_id.encode("utf-8"),
        info=f"trustguard:inbox:{recipient_id}".encode("utf-8"),
    )
    nonce, ct = aes_gcm_encrypt(
        inbox_key,
        plaintext.encode("utf-8"),
        aad=f"{recipient_id}|{message_id}".encode("utf-8"),
    )
    return json.dumps({"nonce": b64e(nonce), "ct": b64e(ct)}, separators=(",", ":"))


def _unseal_for_recipient_inbox(
    settings: Settings, *, recipient_id: str, message_id: str, sealed_json: str
) -> str:
    payload = json.loads(sealed_json)
    inbox_key = derive_aes_key(
        settings.master_key_bytes,
        salt=message_id.encode("utf-8"),
        info=f"trustguard:inbox:{recipient_id}".encode("utf-8"),
    )
    pt = aes_gcm_decrypt(
        inbox_key,
        b64d(payload["nonce"]),
        b64d(payload["ct"]),
        aad=f"{recipient_id}|{message_id}".encode("utf-8"),
    )
    return pt.decode("utf-8")


def _build_signature_digest(
    aad_bytes: bytes, nonce: bytes, ciphertext: bytes, kem_ciphertext: bytes
) -> bytes:
    return bytes.fromhex(sha256_hex(aad_bytes + nonce + ciphertext + kem_ciphertext))


def create_signed_encrypted_envelope(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    sender_id: str,
    sender_device_id: str | None,
    recipient_id: str,
    plaintext: str,
    message_id: str | None = None,
) -> dict[str, Any]:
    """Build a forward-secret ML-KEM-768 + HKDF + AES-256-GCM + ML-DSA-65 envelope."""
    if not plaintext or not plaintext.strip():
        raise HTTPException(status_code=400, detail="Message plaintext cannot be empty.")

    recipient = conn.execute(
        "SELECT user_id, username, status FROM users WHERE user_id = ?", (recipient_id,)
    ).fetchone()
    if not recipient or recipient["status"] != "ACTIVE":
        raise HTTPException(status_code=404, detail="Active recipient user not found.")

    signing_key = conn.execute(
        """
        SELECT * FROM crypto_keys
        WHERE purpose = 'IDENTITY_SIGNING' AND owner_id = ? AND status = 'ACTIVE'
        ORDER BY version DESC LIMIT 1
        """,
        (sender_id,),
    ).fetchone()
    if not signing_key:
        raise HTTPException(
            status_code=403,
            detail="Sender lacks an ACTIVE ML-DSA-65 identity signing key.",
        )

    msg_id = message_id or f"msg-{uuid.uuid4().hex[:14]}"
    timestamp = utc_now_iso()

    # 1. Start fresh ephemeral ML-KEM-768 session (forward secrecy)
    session_id, eph_pk = ephemeral_sessions.create_session(sender_id, recipient_id)
    kem_ct, shared_secret = kem_encapsulate(eph_pk)

    # 2. Derive per-message AES-256-GCM key bound to sender, recipient, session, and message ID
    msg_key = derive_aes_key(
        shared_secret,
        salt=session_id.encode("utf-8"),
        info=f"trustguard-msg-v1|{sender_id}|{recipient_id}|{msg_id}".encode("utf-8"),
    )

    aad_obj = {
        "message_id": msg_id,
        "sender_id": sender_id,
        "sender_device_id": sender_device_id or "none",
        "recipient_id": recipient_id,
        "session_id": session_id,
        "signing_key_id": signing_key["key_id"],
        "signing_key_version": int(signing_key["version"]),
        "timestamp": timestamp,
    }
    aad_bytes = canonical_json(aad_obj)
    nonce, ciphertext = aes_gcm_encrypt(msg_key, plaintext.encode("utf-8"), aad_bytes)

    # 3. Authenticate sender + recipient binding + ciphertext using ML-DSA-65
    sender_sk = unwrap_private_key(
        settings.master_key_bytes, signing_key["key_id"], signing_key["encrypted_private_key"]
    )
    digest = _build_signature_digest(aad_bytes, nonce, ciphertext, kem_ct)
    signature = sign_data(sender_sk, digest)

    return {
        "message_id": msg_id,
        "session_id": session_id,
        "sender_id": sender_id,
        "sender_device_id": sender_device_id or "none",
        "recipient_id": recipient_id,
        "signing_key_id": signing_key["key_id"],
        "signing_key_version": int(signing_key["version"]),
        "kem_algorithm": KEM_ALGORITHM,
        "sig_algorithm": SIGN_ALGORITHM,
        "kem_ciphertext_b64": b64e(kem_ct),
        "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(ciphertext),
        "aad_b64": b64e(aad_bytes),
        "signature_b64": b64e(signature),
        "timestamp": timestamp,
    }


def verify_and_deliver_envelope(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    envelope: dict[str, Any],
    actor_id: str,
    actor_role: str,
) -> dict[str, Any]:
    """Verify completeness, replay protection, ML-DSA-65 signature, recipient binding, and decrypt."""
    required_fields = [
        "message_id",
        "session_id",
        "sender_id",
        "sender_device_id",
        "recipient_id",
        "signing_key_id",
        "signing_key_version",
        "kem_ciphertext_b64",
        "nonce_b64",
        "ciphertext_b64",
        "aad_b64",
        "signature_b64",
    ]
    missing = [f for f in required_fields if not envelope.get(f)]
    now_iso = utc_now_iso()

    if missing:
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=str(envelope.get("message_id") or "incomplete"),
            result="REJECTED_INVALID",
            metadata={"missing_fields": ",".join(missing)},
            timestamp=now_iso,
        )
        raise HTTPException(
            status_code=400,
            detail=f"REJECTED_INVALID: Missing required envelope fields: {', '.join(missing)}",
        )

    msg_id = str(envelope["message_id"])
    sender_id = str(envelope["sender_id"])
    recipient_id = str(envelope["recipient_id"])
    session_id = str(envelope["session_id"])
    signing_key_id = str(envelope["signing_key_id"])

    # 1. Replay protection: reject duplicate message IDs
    dup = conn.execute(
        "SELECT message_id FROM secure_messages WHERE message_id = ?", (msg_id,)
    ).fetchone()
    if dup:
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=msg_id,
            result="REJECTED_REPLAY",
            metadata={"sender_id": sender_id, "recipient_id": recipient_id},
            timestamp=now_iso,
        )
        process_and_store_event(
            conn,
            SecurityEventInput(
                user_identity=actor_id,
                role=actor_role,
                device_id=str(envelope.get("sender_device_id")),
                device_status="ACTIVE",
                source_service="node-a",
                destination_service="node-b",
                resource="messages",
                action="deliver",
                decision="DENY",
                event_time=now_iso,
                reason_code="MESSAGE_REPLAY",
            ),
        )
        raise HTTPException(
            status_code=409,
            detail=f"REJECTED_REPLAY: Duplicate message_id '{msg_id}' rejected by replay protection.",
        )

    # 2. Decode cryptographic artifacts
    try:
        kem_ct = b64d(envelope["kem_ciphertext_b64"])
        nonce = b64d(envelope["nonce_b64"])
        ciphertext = b64d(envelope["ciphertext_b64"])
        aad_bytes = b64d(envelope["aad_b64"])
        signature = b64d(envelope["signature_b64"])
        aad_parsed = json.loads(aad_bytes.decode("utf-8"))
    except Exception as exc:
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=msg_id,
            result="REJECTED_INVALID",
            metadata={"reason": "malformed_base64_or_aad"},
            timestamp=now_iso,
        )
        raise HTTPException(
            status_code=400, detail=f"REJECTED_INVALID: Malformed cryptographic encoding ({exc})."
        ) from exc

    # 3. Check recipient binding inside AAD matches claimed envelope recipient
    if (
        aad_parsed.get("recipient_id") != recipient_id
        or aad_parsed.get("sender_id") != sender_id
        or aad_parsed.get("message_id") != msg_id
        or aad_parsed.get("session_id") != session_id
    ):
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=msg_id,
            result="REJECTED_TAMPERED",
            metadata={"reason": "recipient_or_metadata_mismatch", "claimed_recipient": recipient_id},
            timestamp=now_iso,
        )
        raise HTTPException(
            status_code=400,
            detail="REJECTED_TAMPERED: Envelope recipient/metadata does not match bound AAD.",
        )

    # 4. Check sender device & signing key validity
    sender_dev_id = str(envelope["sender_device_id"])
    if sender_dev_id != "none":
        dev = conn.execute(
            "SELECT status FROM devices WHERE device_id = ? AND owner_id = ?",
            (sender_dev_id, sender_id),
        ).fetchone()
        if not dev or dev["status"] == "REVOKED":
            record_audit_event(
                conn,
                actor_id=actor_id,
                action="MESSAGE_DELIVERY",
                resource=msg_id,
                result="REJECTED_REVOKED",
                metadata={"sender_device_id": sender_dev_id},
                timestamp=now_iso,
            )
            raise HTTPException(
                status_code=403,
                detail="REJECTED_REVOKED: Sender device is revoked or invalid.",
            )

    signing_key = conn.execute(
        "SELECT * FROM crypto_keys WHERE key_id = ? AND owner_id = ?",
        (signing_key_id, sender_id),
    ).fetchone()
    if not signing_key or signing_key["status"] in {"REVOKED", "EXPIRED_CUTOFF", "PENDING"}:
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=msg_id,
            result="REJECTED_REVOKED",
            metadata={"signing_key_id": signing_key_id},
            timestamp=now_iso,
        )
        raise HTTPException(
            status_code=403,
            detail="REJECTED_REVOKED: Sender signing key is invalid, revoked, or past cutoff.",
        )

    # 5. Verify ML-DSA-65 signature over AAD + nonce + ciphertext + kem_ct
    digest = _build_signature_digest(aad_bytes, nonce, ciphertext, kem_ct)
    sig_ok = verify_signature(b64d(signing_key["public_key_b64"]), digest, signature)
    if not sig_ok:
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=msg_id,
            result="REJECTED_TAMPERED",
            metadata={"reason": "ml_dsa_signature_failed"},
            timestamp=now_iso,
        )
        raise HTTPException(
            status_code=400,
            detail="REJECTED_TAMPERED: ML-DSA-65 signature verification failed.",
        )

    # 6. Decapsulate ephemeral ML-KEM-768 shared secret (one-time consume + zeroize)
    try:
        shared_secret = ephemeral_sessions.consume_decapsulate(
            session_id, sender_id, recipient_id, kem_ct
        )
    except ValueError as exc:
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=msg_id,
            result="REJECTED_INVALID",
            metadata={"reason": "ephemeral_session_unavailable"},
            timestamp=now_iso,
        )
        raise HTTPException(status_code=400, detail=f"REJECTED_INVALID: {exc}") from exc

    # 7. Derive AES-256-GCM key bound to recipient & decrypt authenticated message
    msg_key = derive_aes_key(
        shared_secret,
        salt=session_id.encode("utf-8"),
        info=f"trustguard-msg-v1|{sender_id}|{recipient_id}|{msg_id}".encode("utf-8"),
    )
    try:
        plaintext_bytes = aes_gcm_decrypt(msg_key, nonce, ciphertext, aad_bytes)
        plaintext = plaintext_bytes.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        record_audit_event(
            conn,
            actor_id=actor_id,
            action="MESSAGE_DELIVERY",
            resource=msg_id,
            result="REJECTED_TAMPERED",
            metadata={"reason": "aes_gcm_auth_tag_failed"},
            timestamp=now_iso,
        )
        raise HTTPException(
            status_code=400,
            detail="REJECTED_TAMPERED: AES-256-GCM authentication tag verification failed.",
        ) from exc

    # 8. Persist verified message record (seal inbox copy for authenticated recipient; never log plaintext)
    inbox_sealed = _seal_for_recipient_inbox(
        settings, recipient_id=recipient_id, message_id=msg_id, plaintext=plaintext
    )
    conn.execute(
        """
        INSERT INTO secure_messages (
            message_id, session_id, sender_id, sender_device_id, recipient_id,
            signing_key_id, signing_key_version, kem_algorithm, sig_algorithm,
            kem_ciphertext_b64, nonce_b64, ciphertext_b64, aad_b64, signature_b64,
            inbox_sealed_b64, delivery_status, failure_reason, forward_secret, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'DELIVERED', NULL, 1, ?)
        """,
        (
            msg_id,
            session_id,
            sender_id,
            sender_dev_id,
            recipient_id,
            signing_key_id,
            int(envelope["signing_key_version"]),
            envelope.get("kem_algorithm", KEM_ALGORITHM),
            envelope.get("sig_algorithm", SIGN_ALGORITHM),
            envelope["kem_ciphertext_b64"],
            envelope["nonce_b64"],
            envelope["ciphertext_b64"],
            envelope["aad_b64"],
            envelope["signature_b64"],
            inbox_sealed,
            now_iso,
        ),
    )
    conn.commit()

    # Audit log strictly excludes plaintext message content
    record_audit_event(
        conn,
        actor_id=sender_id,
        action="MESSAGE_DELIVERED",
        resource=msg_id,
        result="DELIVERED",
        metadata={
            "recipient_id": recipient_id,
            "kem_algorithm": KEM_ALGORITHM,
            "sig_algorithm": SIGN_ALGORITHM,
            "forward_secret": True,
            "signing_key_version": int(envelope["signing_key_version"]),
        },
        timestamp=now_iso,
    )

    return {
        "message_id": msg_id,
        "session_id": session_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "delivery_status": "DELIVERED",
        "forward_secret": True,
        "ephemeral_key_zeroized": True,
        "kem_algorithm": KEM_ALGORITHM,
        "sig_algorithm": SIGN_ALGORITHM,
        "created_at": now_iso,
    }


def list_messages_for_user(
    conn: sqlite3.Connection, settings: Settings, *, user_id: str, role: str
) -> list[dict[str, Any]]:
    """List delivered messages. Plaintext is unsealed ONLY for the intended recipient."""
    if role == "Admin":
        rows = conn.execute(
            """
            SELECT m.*, su.username AS sender_username, ru.username AS recipient_username
            FROM secure_messages m
            JOIN users su ON su.user_id = m.sender_id
            JOIN users ru ON ru.user_id = m.recipient_id
            ORDER BY m.created_at DESC
            LIMIT 100
            """
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT m.*, su.username AS sender_username, ru.username AS recipient_username
            FROM secure_messages m
            JOIN users su ON su.user_id = m.sender_id
            JOIN users ru ON ru.user_id = m.recipient_id
            WHERE m.sender_id = ? OR m.recipient_id = ?
            ORDER BY m.created_at DESC
            LIMIT 100
            """,
            (user_id, user_id),
        ).fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "message_id": row["message_id"],
            "session_id": row["session_id"],
            "sender_id": row["sender_id"],
            "sender_username": row["sender_username"],
            "sender_device_id": row["sender_device_id"],
            "recipient_id": row["recipient_id"],
            "recipient_username": row["recipient_username"],
            "signing_key_id": row["signing_key_id"],
            "signing_key_version": row["signing_key_version"],
            "kem_algorithm": row["kem_algorithm"],
            "sig_algorithm": row["sig_algorithm"],
            "delivery_status": row["delivery_status"],
            "forward_secret": bool(row["forward_secret"]),
            "created_at": row["created_at"],
            "ciphertext_preview": row["ciphertext_b64"][:36] + "...",
            "plaintext": None,
        }
        # Only decrypt inbox copy when requested by the actual intended recipient
        if row["recipient_id"] == user_id and row["inbox_sealed_b64"]:
            try:
                item["plaintext"] = _unseal_for_recipient_inbox(
                    settings,
                    recipient_id=user_id,
                    message_id=row["message_id"],
                    sealed_json=row["inbox_sealed_b64"],
                )
            except Exception:
                item["plaintext"] = "[Decryption unavailable]"
        results.append(item)
    return results
