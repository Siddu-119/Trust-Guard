"""FastAPI entry point for TrustGuard – Post-Quantum Zero Trust Security Platform."""

import json
import sqlite3
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .audit import list_audit_events, record_audit_event, utc_now_iso, verify_audit_chain
from .auth import (
    VALID_ROLES,
    AuthContext,
    authenticate_user,
    enforce_server_permission,
    evaluate_zero_trust_access,
    get_auth_context,
)
from .backup import (
    create_encrypted_backup,
    list_backups,
    restore_from_backup,
    verify_backup_integrity,
)
from .config import Settings, load_settings
from .crypto import (
    KEM_ALGORITHM,
    PQC_AVAILABLE,
    PQC_IMPORT_ERROR,
    SIGN_ALGORITHM,
    SYMMETRIC_ALGORITHM,
    b64e,
    generate_signing_keypair,
    hash_password,
    wrap_private_key,
)
from .database import get_connection, init_database
from .devices import list_devices, register_device, revoke_device
from .keys import (
    generate_keypair_entry,
    get_grace_versions,
    list_keys,
    list_rotations,
    recover_pending_rotations,
    revoke_key_entry,
    rotate_key,
    verify_key_usage,
)
from .messaging import (
    create_signed_encrypted_envelope,
    list_delivery_attempts,
    list_messages_for_user,
    list_sessions_for_user,
    resume_resumable_session,
    start_resumable_session,
    verify_and_deliver_envelope,
)
from .nodes import list_service_nodes, set_node_status, sync_node
from .threat_detection import (
    SecurityEventInput,
    build_service_graph_summary,
    evaluate_synthetic_dataset,
    get_timing_policy,
    list_threat_alerts,
    process_and_store_event,
)


# ------------------------------------------------------------------
# Request Schemas
# ------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: str | None = None


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    full_name: str = Field(min_length=2, max_length=120)
    role: str
    password: str = Field(min_length=8, max_length=128)
    initial_device_name: str | None = None


class UpdateRoleRequest(BaseModel):
    role: str


class SetPermissionRequest(BaseModel):
    resource: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    allowed: bool


class AccessCheckRequest(BaseModel):
    user_id: str
    device_id: str | None = None
    source_service: str = "client"
    destination_service: str = "node-a"
    resource: str
    action: str


class GenerateKeyRequest(BaseModel):
    purpose: str
    owner_id: str = "system"
    algorithm: str = KEM_ALGORITHM


class RotateKeyRequest(BaseModel):
    purpose: str = "NODE_TRANSPORT"
    owner_id: str = "system"
    simulate_crash: bool = False


class VerifyKeyUsageRequest(BaseModel):
    key_id: str
    node_id: str | None = None


class RevokeKeyRequest(BaseModel):
    reason: str = "Administrative revocation"


class RegisterDeviceRequest(BaseModel):
    owner_id: str
    device_name: str = Field(min_length=2, max_length=120)
    device_type: str = "Workstation"


class ReplaceDeviceRequest(BaseModel):
    revoked_device_id: str
    new_device_name: str = Field(min_length=2, max_length=120)
    device_type: str = "Workstation"


class RevokeDeviceRequest(BaseModel):
    reason: str = "Reported lost / compromised"


class StartSessionRequest(BaseModel):
    recipient_id: str


class SendMessageRequest(BaseModel):
    recipient_id: str
    plaintext: str
    message_id: str | None = None
    session_id: str | None = None


class DeliverEnvelopeRequest(BaseModel):
    envelope: dict[str, Any]


class SimulateThreatRequest(BaseModel):
    user_identity: str
    role: str = "Employee"
    device_id: str | None = None
    device_status: str = "ACTIVE"
    source_service: str = "node-a"
    destination_service: str = "node-b"
    resource: str = "keys"
    action: str = "rotate"
    decision: str = "DENY"
    key_status: str = "ACTIVE"
    reason_code: str = ""
    event_time: str | None = None
    clock_offset_seconds: float = 0.0


class NodeStatusRequest(BaseModel):
    status: str


class UpdateSettingsRequest(BaseModel):
    key_grace_versions: int = Field(ge=0, le=10)
    zero_trust_strict_device_check: bool = True
    require_ephemeral_forward_secrecy: bool = True


def create_app(custom_settings: Settings | None = None) -> FastAPI:
    """Create and configure the TrustGuard FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings = custom_settings or load_settings()
        conn = get_connection(settings.db_path)
        init_database(conn, settings)
        app.state.settings = settings
        app.state.conn = conn
        # Automatically recover any interrupted PENDING key rotations on startup
        recover_pending_rotations(conn, settings, actor_id="system-startup")
        try:
            yield
        finally:
            conn.close()

    settings_for_cors = custom_settings or load_settings()
    app = FastAPI(
        title="TrustGuard – Post-Quantum Zero Trust Security Platform",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings_for_cors.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_db(request: Request) -> sqlite3.Connection:
        return request.app.state.conn

    def get_cfg(request: Request) -> Settings:
        return request.app.state.settings

    # ------------------------------------------------------------------
    # Health & Public Discovery
    # ------------------------------------------------------------------

    @app.get("/api/health")
    def health(conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        return {
            "status": "ok" if PQC_AVAILABLE else "degraded",
            "pqc_available": PQC_AVAILABLE,
            "pqc_error": PQC_IMPORT_ERROR or None,
            "algorithms": {
                "kem": KEM_ALGORITHM,
                "signature": SIGN_ALGORITHM,
                "symmetric": SYMMETRIC_ALGORITHM,
            },
            "users_initialized": user_count,
        }

    @app.get("/api/auth/demo-accounts")
    def demo_accounts(conn: sqlite3.Connection = Depends(get_db)) -> list[dict[str, Any]]:
        """List synthetic test identities and their devices for hackathon login selection."""
        users = conn.execute(
            "SELECT user_id, username, full_name, role, status FROM users ORDER BY role ASC, username ASC"
        ).fetchall()
        out = []
        for u in users:
            devs = conn.execute(
                "SELECT device_id, device_name, status FROM devices WHERE owner_id = ?",
                (u["user_id"],),
            ).fetchall()
            out.append({**dict(u), "devices": [dict(d) for d in devs]})
        return out

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    @app.post("/api/auth/login")
    def login(
        body: LoginRequest,
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        return authenticate_user(
            conn,
            settings,
            username=body.username,
            password=body.password,
            device_id=body.device_id,
        )

    @app.get("/api/auth/me")
    def me(ctx: AuthContext = Depends(get_auth_context)) -> dict[str, Any]:
        return {
            "user_id": ctx.user_id,
            "username": ctx.username,
            "full_name": ctx.full_name,
            "role": ctx.role,
            "device_id": ctx.device_id,
        }

    # ------------------------------------------------------------------
    # Dashboard Overview (100% live DB metrics)
    # ------------------------------------------------------------------

    @app.get("/api/dashboard/overview")
    def dashboard_overview(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        total_users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        active_devices = conn.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE status = 'ACTIVE'"
        ).fetchone()["c"]
        revoked_devices = conn.execute(
            "SELECT COUNT(*) AS c FROM devices WHERE status = 'REVOKED'"
        ).fetchone()["c"]
        active_keys = conn.execute(
            "SELECT COUNT(*) AS c FROM crypto_keys WHERE status = 'ACTIVE'"
        ).fetchone()["c"]
        suspicious_activities = conn.execute(
            "SELECT COUNT(*) AS c FROM threat_alerts"
        ).fetchone()["c"]
        delivered_messages = conn.execute(
            "SELECT COUNT(*) AS c FROM secure_messages WHERE delivery_status = 'DELIVERED'"
        ).fetchone()["c"]

        latest_rotation = conn.execute(
            "SELECT * FROM key_rotations ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        pending_rotations = conn.execute(
            "SELECT COUNT(*) AS c FROM key_rotations WHERE state = 'PENDING'"
        ).fetchone()["c"]

        recent_audit = list_audit_events(conn, limit=8)
        recent_alerts = list_threat_alerts(conn, limit=6)
        nodes = list_service_nodes(conn)

        # Real access activity breakdown grouped by destination & decision
        access_chart_rows = conn.execute(
            """
            SELECT destination_service AS service,
                   SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) AS allow_count,
                   SUM(CASE WHEN decision = 'DENY' THEN 1 ELSE 0 END) AS deny_count
            FROM access_decisions
            GROUP BY destination_service
            ORDER BY destination_service ASC
            """
        ).fetchall()

        # Real security events by severity / category
        severity_rows = conn.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM threat_alerts
            GROUP BY severity
            """
        ).fetchall()
        sev_map = {r["severity"]: r["count"] for r in severity_rows}
        security_events_chart = [
            {"category": "CRITICAL", "count": sev_map.get("CRITICAL", 0)},
            {"category": "HIGH", "count": sev_map.get("HIGH", 0)},
            {"category": "MEDIUM", "count": sev_map.get("MEDIUM", 0)},
            {"category": "LOW", "count": sev_map.get("LOW", 0)},
        ]

        # Key status breakdown
        key_status_rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM crypto_keys GROUP BY status"
        ).fetchall()

        return {
            "metrics": {
                "total_users": total_users,
                "active_devices": active_devices,
                "revoked_devices": revoked_devices,
                "active_keys": active_keys,
                "suspicious_activities": suspicious_activities,
                "delivered_messages": delivered_messages,
                "pending_rotations": pending_rotations,
            },
            "key_rotation_status": {
                "state": "PENDING_RECOVERY"
                if pending_rotations > 0
                else (latest_rotation["state"] if latest_rotation else "STEADY"),
                "latest_rotation": dict(latest_rotation) if latest_rotation else None,
                "pending_count": pending_rotations,
                "key_breakdown": [dict(r) for r in key_status_rows],
            },
            "charts": {
                "access_activity": [dict(r) for r in access_chart_rows],
                "security_events": security_events_chart,
            },
            "recent_security_events": recent_alerts,
            "recent_audit_events": recent_audit,
            "service_nodes": nodes,
            "pqc_suite": {
                "pqc_available": PQC_AVAILABLE,
                "kem": KEM_ALGORITHM,
                "signature": SIGN_ALGORITHM,
                "symmetric": SYMMETRIC_ALGORITHM,
            },
        }

    # ------------------------------------------------------------------
    # Users, Identity & Zero-Trust Access Control
    # ------------------------------------------------------------------

    @app.get("/api/users")
    def get_users(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="users", action="read")
        users = conn.execute(
            "SELECT user_id, username, full_name, role, status, created_at FROM users ORDER BY created_at ASC"
        ).fetchall()
        out = []
        for u in users:
            perms = conn.execute(
                """
                SELECT perm_id, resource, action, allowed, granted_by, created_at
                FROM resource_permissions
                WHERE user_id = ?
                """,
                (u["user_id"],),
            ).fetchall()
            out.append({**dict(u), "permissions": [dict(p) for p in perms]})
        return out

    @app.post("/api/users")
    def create_user(
        body: CreateUserRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="users", action="write")
        if body.role not in VALID_ROLES:
            raise HTTPException(status_code=400, detail=f"Role must be one of {sorted(VALID_ROLES)}.")

        existing = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (body.username.strip(),)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists.")

        uid = f"usr-{uuid.uuid4().hex[:8]}"
        now_iso = utc_now_iso()
        conn.execute(
            """
            INSERT INTO users (user_id, username, full_name, role, password_hash, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
            """,
            (uid, body.username.strip(), body.full_name.strip(), body.role, hash_password(body.password), now_iso),
        )

        # Provision ML-DSA-65 identity signing keypair for the new user
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
        conn.commit()

        device = None
        if body.initial_device_name:
            device = register_device(
                conn,
                owner_id=uid,
                device_name=body.initial_device_name,
                device_type="Workstation",
                actor_id=ctx.user_id,
            )

        record_audit_event(
            conn,
            actor_id=ctx.user_id,
            action="USER_REGISTERED",
            resource=uid,
            result="SUCCESS",
            metadata={"username": body.username, "role": body.role, "signing_key": kid},
            timestamp=now_iso,
        )

        return {
            "user_id": uid,
            "username": body.username.strip(),
            "full_name": body.full_name.strip(),
            "role": body.role,
            "status": "ACTIVE",
            "signing_key_id": kid,
            "device": device,
        }

    @app.patch("/api/users/{user_id}/role")
    def update_role(
        user_id: str,
        body: UpdateRoleRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="users", action="admin")
        if body.role not in VALID_ROLES:
            raise HTTPException(status_code=400, detail=f"Role must be one of {sorted(VALID_ROLES)}.")
        user = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        conn.execute("UPDATE users SET role = ? WHERE user_id = ?", (body.role, user_id))
        conn.commit()
        record_audit_event(
            conn,
            actor_id=ctx.user_id,
            action="USER_ROLE_UPDATED",
            resource=user_id,
            result="SUCCESS",
            metadata={"old_role": user["role"], "new_role": body.role},
        )
        return {"user_id": user_id, "role": body.role}

    @app.post("/api/users/{user_id}/permissions")
    def set_user_permission(
        user_id: str,
        body: SetPermissionRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="users", action="admin")
        user = conn.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        perm_id = f"prm-{uuid.uuid4().hex[:10]}"
        now_iso = utc_now_iso()
        conn.execute(
            """
            INSERT INTO resource_permissions (perm_id, user_id, resource, action, allowed, granted_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, resource, action) DO UPDATE SET
                allowed = excluded.allowed,
                granted_by = excluded.granted_by,
                created_at = excluded.created_at
            """,
            (perm_id, user_id, body.resource, body.action, 1 if body.allowed else 0, ctx.user_id, now_iso),
        )
        conn.commit()

        record_audit_event(
            conn,
            actor_id=ctx.user_id,
            action="PERMISSION_UPDATED",
            resource=f"{user_id}:{body.resource}:{body.action}",
            result="ALLOW" if body.allowed else "DENY",
            metadata={"allowed": body.allowed},
            timestamp=now_iso,
        )
        return {
            "user_id": user_id,
            "resource": body.resource,
            "action": body.action,
            "allowed": body.allowed,
        }

    @app.post("/api/access/check")
    def check_access(
        body: AccessCheckRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        # Users can check their own access or Admin can simulate/evaluate any user
        if body.user_id != ctx.user_id and ctx.role != "Admin":
            raise HTTPException(
                status_code=403, detail="Only Admins may simulate access checks for other users."
            )
        return evaluate_zero_trust_access(
            conn,
            user_id=body.user_id,
            resource=body.resource,
            action=body.action,
            device_id=body.device_id,
            source_service=body.source_service,
            destination_service=body.destination_service,
        )

    @app.get("/api/access/decisions")
    def get_access_decisions(
        limit: int = 50,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT decision_id, user_id, username, role, device_id,
                   source_service, destination_service, resource, action,
                   decision, reason, timestamp
            FROM access_decisions
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Key Management & Recoverable Rotation
    # ------------------------------------------------------------------

    @app.get("/api/keys")
    def get_keys(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="keys", action="read")
        return {
            "keys": list_keys(conn),
            "rotations": list_rotations(conn),
            "grace_versions": get_grace_versions(conn, settings),
        }

    @app.post("/api/keys/generate")
    def create_key(
        body: GenerateKeyRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="keys", action="write")
        return generate_keypair_entry(
            conn,
            settings,
            purpose=body.purpose,
            owner_id=body.owner_id,
            algorithm=body.algorithm,
            actor_id=ctx.user_id,
        )

    @app.post("/api/keys/rotate")
    def rotate_key_endpoint(
        body: RotateKeyRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="keys", action="rotate")
        return rotate_key(
            conn,
            settings,
            purpose=body.purpose,
            owner_id=body.owner_id,
            actor_id=ctx.user_id,
            actor_role=ctx.role,
            simulate_crash=body.simulate_crash,
        )

    @app.post("/api/keys/recover-rotation")
    def recover_rotation_endpoint(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="keys", action="rotate")
        recovered = recover_pending_rotations(conn, settings, actor_id=ctx.user_id)
        return {"recovered_count": len(recovered), "results": recovered}

    @app.post("/api/keys/verify-usage")
    def verify_key_endpoint(
        body: VerifyKeyUsageRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        return verify_key_usage(
            conn,
            settings,
            key_id=body.key_id,
            actor_id=ctx.user_id,
            actor_role=ctx.role,
            node_id=body.node_id,
        )

    @app.post("/api/keys/{key_id}/revoke")
    def revoke_key_endpoint(
        key_id: str,
        body: RevokeKeyRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="keys", action="revoke")
        return revoke_key_entry(conn, key_id=key_id, actor_id=ctx.user_id, reason=body.reason)

    # ------------------------------------------------------------------
    # Device Management
    # ------------------------------------------------------------------

    @app.get("/api/devices")
    def get_devices(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="devices", action="read")
        return list_devices(conn)

    @app.post("/api/devices")
    def create_device(
        body: RegisterDeviceRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        if body.owner_id != ctx.user_id:
            enforce_server_permission(conn, ctx, resource="devices", action="admin")
        else:
            enforce_server_permission(conn, ctx, resource="devices", action="replace")
        return register_device(
            conn,
            owner_id=body.owner_id,
            device_name=body.device_name,
            device_type=body.device_type,
            actor_id=ctx.user_id,
        )

    @app.post("/api/devices/{device_id}/revoke")
    def revoke_device_endpoint(
        device_id: str,
        body: RevokeDeviceRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        dev = conn.execute("SELECT owner_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found.")
        # Admins can revoke any device; owners can report their own device lost
        if dev["owner_id"] != ctx.user_id:
            enforce_server_permission(conn, ctx, resource="devices", action="revoke")
        return revoke_device(conn, device_id=device_id, actor_id=ctx.user_id, reason=body.reason)

    @app.post("/api/devices/replace")
    def replace_device_endpoint(
        body: ReplaceDeviceRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        old_dev = conn.execute(
            "SELECT owner_id FROM devices WHERE device_id = ?", (body.revoked_device_id,)
        ).fetchone()
        if not old_dev:
            raise HTTPException(status_code=404, detail="Original device not found.")
        if old_dev["owner_id"] != ctx.user_id:
            enforce_server_permission(conn, ctx, resource="devices", action="admin")
        else:
            enforce_server_permission(conn, ctx, resource="devices", action="replace")
        return register_device(
            conn,
            owner_id=old_dev["owner_id"],
            device_name=body.new_device_name,
            device_type=body.device_type,
            actor_id=ctx.user_id,
            replaces_device_id=body.revoked_device_id,
        )

    # ------------------------------------------------------------------
    # Secure Messaging (Ephemeral Forward Secrecy + Replay + Recipient Binding)
    # ------------------------------------------------------------------

    @app.get("/api/messages")
    def get_messages(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="messages", action="read")
        return list_messages_for_user(conn, settings, user_id=ctx.user_id, role=ctx.role)

    @app.get("/api/messages/sessions")
    def get_sessions(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="messages", action="read")
        return list_sessions_for_user(conn, user_id=ctx.user_id, role=ctx.role)

    @app.post("/api/messages/sessions")
    def create_session_endpoint(
        body: StartSessionRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="messages", action="write", destination_service="node-b")
        return start_resumable_session(
            conn,
            initiator_id=ctx.user_id,
            initiator_device_id=ctx.device_id,
            recipient_id=body.recipient_id,
        )

    @app.post("/api/messages/sessions/{session_id}/resume")
    def resume_session_endpoint(
        session_id: str,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="messages", action="read")
        return resume_resumable_session(
            conn,
            session_id=session_id,
            actor_id=ctx.user_id,
            actor_role=ctx.role,
            actor_device_id=ctx.device_id,
        )

    @app.get("/api/messages/delivery-attempts")
    def get_delivery_attempts(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="messages", action="read")
        return list_delivery_attempts(conn, user_id=ctx.user_id, role=ctx.role)

    @app.post("/api/messages/create-envelope")
    def create_envelope_endpoint(
        body: SendMessageRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="messages", action="write", destination_service="node-b")
        return create_signed_encrypted_envelope(
            conn,
            settings,
            sender_id=ctx.user_id,
            sender_role=ctx.role,
            sender_device_id=ctx.device_id,
            recipient_id=body.recipient_id,
            plaintext=body.plaintext,
            message_id=body.message_id,
            session_id=body.session_id,
        )

    @app.post("/api/messages/deliver-envelope")
    def deliver_envelope_endpoint(
        body: DeliverEnvelopeRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="messages", action="send", destination_service="node-b")
        return verify_and_deliver_envelope(
            conn,
            settings,
            envelope=body.envelope,
            actor_id=ctx.user_id,
            actor_role=ctx.role,
        )

    @app.post("/api/messages/send")
    def send_message_endpoint(
        body: SendMessageRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="messages", action="send", destination_service="node-b")
        envelope = create_signed_encrypted_envelope(
            conn,
            settings,
            sender_id=ctx.user_id,
            sender_role=ctx.role,
            sender_device_id=ctx.device_id,
            recipient_id=body.recipient_id,
            plaintext=body.plaintext,
            message_id=body.message_id,
            session_id=body.session_id,
        )
        delivery = verify_and_deliver_envelope(
            conn,
            settings,
            envelope=envelope,
            actor_id=ctx.user_id,
            actor_role=ctx.role,
        )
        return {"delivery": delivery, "envelope": envelope}

    # ------------------------------------------------------------------
    # Threat Detection (Deterministic Rules + Graph Analysis)
    # ------------------------------------------------------------------

    @app.get("/api/threats/timing-policy")
    def get_threat_timing_policy(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="threat", action="read")
        return get_timing_policy()

    @app.get("/api/threats/alerts")
    def get_threat_alerts(
        limit: int = 100,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="threat", action="read")
        return list_threat_alerts(conn, limit=limit)

    @app.get("/api/threats/graph")
    def get_threat_graph(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="threat", action="read")
        return build_service_graph_summary(conn)

    @app.post("/api/threats/simulate")
    def simulate_threat_event(
        body: SimulateThreatRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="threat", action="write")
        ts = body.event_time or utc_now_iso()
        alerts = process_and_store_event(
            conn,
            SecurityEventInput(
                user_identity=body.user_identity,
                role=body.role,
                device_id=body.device_id,
                device_status=body.device_status,
                source_service=body.source_service,
                destination_service=body.destination_service,
                resource=body.resource,
                action=body.action,
                decision=body.decision,
                event_time=ts,
                key_status=body.key_status,
                reason_code=body.reason_code,
                clock_offset_seconds=body.clock_offset_seconds,
            ),
        )
        record_audit_event(
            conn,
            actor_id=ctx.user_id,
            action="THREAT_EVENT_EVALUATED",
            resource=f"{body.source_service}->{body.destination_service}",
            result="ALERT" if alerts else "BENIGN",
            metadata={"alerts_triggered": len(alerts)},
            timestamp=ts,
        )
        return {"alerts_triggered": alerts}

    @app.post("/api/threats/evaluate-dataset")
    def evaluate_dataset_endpoint(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="threat", action="read")
        return evaluate_synthetic_dataset()

    # ------------------------------------------------------------------
    # Audit Logs (Tamper-Evident Hash Chain)
    # ------------------------------------------------------------------

    @app.get("/api/audit/logs")
    def get_audit_logs(
        limit: int = 100,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="audit", action="read")
        return list_audit_events(conn, limit=limit)

    @app.get("/api/audit/verify")
    def verify_audit_endpoint(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="audit", action="verify")
        return verify_audit_chain(conn)

    # ------------------------------------------------------------------
    # Recovery & Backups
    # ------------------------------------------------------------------

    @app.get("/api/backups")
    def get_backups(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="backups", action="read")
        return list_backups(conn)

    @app.post("/api/backups")
    def create_backup_endpoint(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="backups", action="backup")
        return create_encrypted_backup(conn, settings, actor_id=ctx.user_id)

    @app.post("/api/backups/{backup_id}/verify")
    def verify_backup_endpoint(
        backup_id: str,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="backups", action="read")
        return verify_backup_integrity(conn, settings, backup_id=backup_id, actor_id=ctx.user_id)

    @app.post("/api/backups/{backup_id}/restore")
    def restore_backup_endpoint(
        backup_id: str,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
        settings: Settings = Depends(get_cfg),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="backups", action="restore")
        return restore_from_backup(conn, settings, backup_id=backup_id, actor_id=ctx.user_id)

    @app.post("/api/backups/{backup_id}/simulate-corruption")
    def simulate_backup_corruption(
        backup_id: str,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        """Demo-only endpoint to inject ciphertext corruption into a backup for verification testing."""
        enforce_server_permission(conn, ctx, resource="backups", action="admin")
        row = conn.execute(
            "SELECT backup_blob_json FROM key_backups WHERE backup_id = ?", (backup_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Backup not found.")
        blob = json.loads(row["backup_blob_json"])
        ct = blob["ct"]
        flipped = ("A" if ct[0] != "A" else "B") + ct[1:]
        blob["ct"] = flipped
        conn.execute(
            "UPDATE key_backups SET backup_blob_json = ? WHERE backup_id = ?",
            (json.dumps(blob, separators=(",", ":")), backup_id),
        )
        conn.commit()
        record_audit_event(
            conn,
            actor_id=ctx.user_id,
            action="BACKUP_CORRUPTION_SIMULATED",
            resource=backup_id,
            result="DEMO_TEST",
            metadata={"note": "Injected 1-byte ciphertext flip for integrity verification demo"},
        )
        return {"backup_id": backup_id, "corrupted_injected": True}

    # ------------------------------------------------------------------
    # Service Nodes & Platform Settings
    # ------------------------------------------------------------------

    @app.get("/api/nodes")
    def get_nodes(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> list[dict[str, Any]]:
        enforce_server_permission(conn, ctx, resource="nodes", action="read")
        return list_service_nodes(conn)

    @app.post("/api/nodes/{node_id}/status")
    def update_node_status_endpoint(
        node_id: str,
        body: NodeStatusRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="nodes", action="manage-nodes")
        return set_node_status(conn, node_id=node_id, new_status=body.status, actor_id=ctx.user_id)

    @app.post("/api/nodes/{node_id}/sync")
    def sync_node_endpoint(
        node_id: str,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="nodes", action="manage-nodes")
        return sync_node(conn, node_id=node_id, actor_id=ctx.user_id)

    @app.get("/api/settings")
    def get_settings(
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="settings", action="read")
        rows = conn.execute("SELECT key, value, updated_at FROM app_settings").fetchall()
        cfg_map = {r["key"]: r["value"] for r in rows}
        return {
            "settings": cfg_map,
            "pqc_algorithms": {
                "kem": KEM_ALGORITHM,
                "signature": SIGN_ALGORITHM,
                "symmetric": SYMMETRIC_ALGORITHM,
                "pqc_available": PQC_AVAILABLE,
            },
            "security_assumptions": [
                "Forward secrecy uses per-message ephemeral ML-KEM-768 keys stored only in volatile memory and zeroized immediately upon decapsulation.",
                "Private keys at rest are wrapped with AES-256-GCM under HKDF keys derived from TRUSTGUARD_MASTER_KEY.",
                "Threat detection uses strictly deterministic rules and directed service-graph analysis without AI/ML.",
                "Key rotation follows a two-phase PENDING -> COMMITTED state machine persisted in SQLite WAL.",
            ],
        }

    @app.put("/api/settings")
    def update_settings(
        body: UpdateSettingsRequest,
        ctx: AuthContext = Depends(get_auth_context),
        conn: sqlite3.Connection = Depends(get_db),
    ) -> dict[str, Any]:
        enforce_server_permission(conn, ctx, resource="settings", action="write")
        now_iso = utc_now_iso()
        updates = {
            "key_grace_versions": str(body.key_grace_versions),
            "zero_trust_strict_device_check": "true" if body.zero_trust_strict_device_check else "false",
            "require_ephemeral_forward_secrecy": "true" if body.require_ephemeral_forward_secrecy else "false",
        }
        for k, v in updates.items():
            conn.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (k, v, now_iso),
            )
        conn.commit()
        record_audit_event(
            conn,
            actor_id=ctx.user_id,
            action="SETTINGS_UPDATED",
            resource="app_settings",
            result="SUCCESS",
            metadata=updates,
            timestamp=now_iso,
        )
        return {"updated": updates}

    return app


app = create_app()
