"""SQLite database initialization and synthetic seed data for TrustGuard."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .audit import record_audit_event
from .config import Settings
from .crypto import (
    KEM_ALGORITHM,
    SIGN_ALGORITHM,
    generate_kem_keypair,
    generate_signing_keypair,
    hash_password,
    wrap_private_key,
    b64e,
)

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Admin', 'Employee', 'Viewer')),
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'DISABLED')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_permissions (
    perm_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    allowed INTEGER NOT NULL CHECK(allowed IN (0, 1)),
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, resource, action)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REVOKED')),
    registered_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT,
    revocation_reason TEXT,
    replaces_device_id TEXT
);

CREATE TABLE IF NOT EXISTS service_nodes (
    node_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ONLINE', 'OFFLINE')),
    synced_key_version INTEGER NOT NULL DEFAULT 1,
    last_sync_at TEXT NOT NULL,
    last_sync_latency_ms REAL NOT NULL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS node_revocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL REFERENCES service_nodes(node_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    enforced INTEGER NOT NULL CHECK(enforced IN (0, 1)),
    enforcement_ms REAL,
    enforced_at TEXT,
    status TEXT NOT NULL CHECK(status IN ('ENFORCED', 'PENDING_SYNC')),
    UNIQUE(node_id, device_id)
);

CREATE TABLE IF NOT EXISTS crypto_keys (
    key_id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'ACTIVE', 'RETIRED', 'EXPIRED_CUTOFF', 'REVOKED')),
    public_key_b64 TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    activated_at TEXT,
    retired_at TEXT,
    cutoff_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS key_rotations (
    rotation_id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    old_key_id TEXT,
    new_key_id TEXT NOT NULL,
    old_version INTEGER,
    new_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PENDING', 'COMMITTED', 'ROLLED_BACK')),
    initiated_by TEXT NOT NULL,
    started_at TEXT NOT NULL,
    committed_at TEXT,
    recovered INTEGER NOT NULL DEFAULT 0,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS secure_messages (
    message_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signing_key_version INTEGER NOT NULL,
    kem_algorithm TEXT NOT NULL,
    sig_algorithm TEXT NOT NULL,
    kem_ciphertext_b64 TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    aad_b64 TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    inbox_sealed_b64 TEXT,
    delivery_status TEXT NOT NULL,
    failure_reason TEXT,
    forward_secret INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_decisions (
    decision_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    device_id TEXT,
    source_service TEXT NOT NULL,
    destination_service TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY')),
    reason TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_alerts (
    alert_id TEXT PRIMARY KEY,
    user_identity TEXT NOT NULL,
    source_service TEXT NOT NULL,
    destination_service TEXT NOT NULL,
    event_time TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    reason TEXT NOT NULL,
    rule_triggered TEXT NOT NULL,
    detection_latency_ms REAL NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    result TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_backups (
    backup_id TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    key_count INTEGER NOT NULL,
    revoked_count INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    backup_blob_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'VALID'
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open a SQLite connection configured with Row factory and foreign keys."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_database(conn: sqlite3.Connection, settings: Settings) -> None:
    """Create schema if needed and seed initial synthetic hackathon data once."""
    conn.executescript(SCHEMA_SQL)
    conn.commit()

    existing = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]
    if existing > 0:
        return

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # 1. Seed synthetic test users
    synthetic_users = [
        ("usr-alice", "alice.admin", "Alice Vance (Security Admin)", "Admin", "AdminPass#2026!"),
        ("usr-bob", "bob.eng", "Bob Mercer (Systems Engineer)", "Employee", "EmpPass#2026!"),
        ("usr-carol", "carol.viewer", "Carol Lin (Compliance Auditor)", "Viewer", "ViewPass#2026!"),
    ]
    for uid, uname, fname, role, pwd in synthetic_users:
        conn.execute(
            """
            INSERT INTO users (user_id, username, full_name, role, password_hash, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
            """,
            (uid, uname, fname, role, hash_password(pwd), now_iso),
        )

    # 2. Seed initial synthetic devices
    devices = [
        ("dev-alice-01", "usr-alice", "Alice ThinkPad X1 (TPM2)", "Workstation", "ACTIVE", (now - timedelta(days=14)).isoformat(), now_iso),
        ("dev-bob-01", "usr-bob", "Bob MacBook Pro (Secure Enclave)", "Workstation", "ACTIVE", (now - timedelta(days=10)).isoformat(), now_iso),
        ("dev-carol-01", "usr-carol", "Carol Audit Tablet", "Tablet", "ACTIVE", (now - timedelta(days=7)).isoformat(), now_iso),
    ]
    for did, oid, dname, dtype, status, reg_at, last_act in devices:
        conn.execute(
            """
            INSERT INTO devices (device_id, owner_id, device_name, device_type, status, registered_at, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (did, oid, dname, dtype, status, reg_at, last_act),
        )

    # 3. Seed 3 simulated service nodes
    nodes = [
        ("node-a", "Service Node A", "Identity & Zero-Trust Gateway", "ONLINE", 1, now_iso, 1.2),
        ("node-b", "Service Node B", "Post-Quantum Messaging Broker", "ONLINE", 1, now_iso, 1.5),
        ("node-c", "Service Node C", "Confidential Vault & Archive", "ONLINE", 1, now_iso, 1.8),
    ]
    for nid, name, role, status, ver, sync_at, lat in nodes:
        conn.execute(
            """
            INSERT INTO service_nodes (node_id, name, role, status, synced_key_version, last_sync_at, last_sync_latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (nid, name, role, status, ver, sync_at, lat),
        )

    # 4. Seed initial PQC keys (ML-DSA-65 signing keys per user + system KEM/signing keys)
    # System root KEM key (ML-KEM-768)
    sys_kem_pk, sys_kem_sk = generate_kem_keypair()
    sys_kem_id = "key-sys-kem-v1"
    conn.execute(
        """
        INSERT INTO crypto_keys (
            key_id, purpose, owner_id, algorithm, version, status,
            public_key_b64, encrypted_private_key, created_at, activated_at
        ) VALUES (?, 'NODE_TRANSPORT', 'system', ?, 1, 'ACTIVE', ?, ?, ?, ?)
        """,
        (
            sys_kem_id,
            KEM_ALGORITHM,
            b64e(sys_kem_pk),
            wrap_private_key(settings.master_key_bytes, sys_kem_id, sys_kem_sk),
            now_iso,
            now_iso,
        ),
    )

    # System backup signing key (ML-DSA-65)
    sys_sig_pk, sys_sig_sk = generate_signing_keypair()
    sys_sig_id = "key-sys-sig-v1"
    conn.execute(
        """
        INSERT INTO crypto_keys (
            key_id, purpose, owner_id, algorithm, version, status,
            public_key_b64, encrypted_private_key, created_at, activated_at
        ) VALUES (?, 'BACKUP_SIGNING', 'system', ?, 1, 'ACTIVE', ?, ?, ?, ?)
        """,
        (
            sys_sig_id,
            SIGN_ALGORITHM,
            b64e(sys_sig_pk),
            wrap_private_key(settings.master_key_bytes, sys_sig_id, sys_sig_sk),
            now_iso,
            now_iso,
        ),
    )

    # User ML-DSA-65 identity signing keys
    for uid, _, _, _, _ in synthetic_users:
        spk, ssk = generate_signing_keypair()
        kid = f"key-sig-{uid}-v1"
        conn.execute(
            """
            INSERT INTO crypto_keys (
                key_id, purpose, owner_id, algorithm, version, status,
                public_key_b64, encrypted_private_key, created_at, activated_at
            ) VALUES (?, 'IDENTITY_SIGNING', ?, ?, 1, 'ACTIVE', ?, ?, ?, ?)
            """,
            (
                kid,
                uid,
                SIGN_ALGORITHM,
                b64e(spk),
                wrap_private_key(settings.master_key_bytes, kid, ssk),
                now_iso,
                now_iso,
            ),
        )

    # 5. Seed baseline app settings
    app_settings = [
        ("key_grace_versions", str(settings.key_grace_versions)),
        ("zero_trust_strict_device_check", "true"),
        ("require_ephemeral_forward_secrecy", "true"),
        ("auto_sync_nodes_on_recover", "true"),
    ]
    for k, v in app_settings:
        conn.execute(
            "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)",
            (k, v, now_iso),
        )

    # 6. Seed initial benign access decisions so Dashboard charts show real DB history
    baseline_decisions = [
        ("dec-init-1", "usr-alice", "alice.admin", "Admin", "dev-alice-01", "client", "node-a", "users", "read", "ALLOW", "Role Admin permitted for users:read", (now - timedelta(minutes=30)).isoformat()),
        ("dec-init-2", "usr-bob", "bob.eng", "Employee", "dev-bob-01", "node-a", "node-b", "messages", "write", "ALLOW", "Role Employee permitted for messages:write", (now - timedelta(minutes=20)).isoformat()),
        ("dec-init-3", "usr-carol", "carol.viewer", "Viewer", "dev-carol-01", "node-a", "node-b", "audit", "read", "ALLOW", "Role Viewer permitted for audit:read", (now - timedelta(minutes=10)).isoformat()),
    ]
    for row in baseline_decisions:
        conn.execute(
            """
            INSERT INTO access_decisions (
                decision_id, user_id, username, role, device_id,
                source_service, destination_service, resource, action,
                decision, reason, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )

    conn.commit()

    # 7. Seed GENESIS audit event
    record_audit_event(
        conn,
        actor_id="system",
        action="PLATFORM_INITIALIZED",
        resource="trustguard-core",
        result="SUCCESS",
        metadata={
            "kem_algorithm": KEM_ALGORITHM,
            "sign_algorithm": SIGN_ALGORITHM,
            "nodes": "node-a,node-b,node-c",
        },
        timestamp=now_iso,
    )
