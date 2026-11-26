"""Zero-Trust Authentication, RBAC, and Resource Permission Enforcement."""

from __future__ import annotations

import base64
import hmac
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from .audit import record_audit_event, utc_now_iso
from .config import Settings
from .crypto import verify_password
from .database import get_db_session
from .threat_detection import SecurityEventInput, process_and_store_event

VALID_ROLES = {"Admin", "Employee", "Viewer"}

ROLE_DEFAULT_PERMISSIONS: dict[str, dict[str, set[str]]] = {
    "Admin": {
        "users": {"read", "write", "admin"},
        "keys": {"read", "write", "rotate", "revoke", "admin"},
        "devices": {"read", "write", "revoke", "replace", "admin"},
        "messages": {"read", "write", "send", "admin"},
        "nodes": {"read", "write", "manage-nodes", "admin"},
        "audit": {"read", "verify", "tamper-test", "admin"},
        "threat": {"read", "write", "evaluate", "admin"},
        "backups": {"read", "write", "backup", "restore", "admin"},
        "settings": {"read", "write", "admin"},
        "vault-docs": {"read", "write", "admin"},
    },
    "Employee": {
        "users": {"read"},
        "keys": {"read"},
        "devices": {"read", "replace"},
        "messages": {"read", "write", "send"},
        "nodes": {"read"},
        "audit": {"read", "verify"},
        "threat": {"read"},
        "backups": set(),
        "settings": {"read"},
        "vault-docs": {"read", "write"},
    },
    "Viewer": {
        "users": {"read"},
        "keys": {"read"},
        "devices": {"read"},
        "messages": {"read"},
        "nodes": {"read"},
        "audit": {"read", "verify"},
        "threat": {"read"},
        "backups": set(),
        "settings": {"read"},
        "vault-docs": {"read"},
    },
}


@dataclass
class AuthContext:
    user_id: str
    username: str
    full_name: str
    role: str
    device_id: str | None


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def create_access_token(
    settings: Settings,
    *,
    user_id: str,
    username: str,
    role: str,
    device_id: str | None,
) -> str:
    now = int(time.time())
    payload = {
        "uid": user_id,
        "username": username,
        "role": role,
        "device_id": device_id,
        "iat": now,
        "exp": now + settings.token_ttl_seconds,
    }
    body = _b64u_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = hmac.new(settings.token_secret_bytes, body.encode("ascii"), sha256).digest()
    return f"{body}.{_b64u_encode(sig)}"


def verify_access_token(settings: Settings, token: str) -> dict[str, Any]:
    try:
        body, sig_b64 = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed authentication token."
        ) from exc

    expected_sig = hmac.new(settings.token_secret_bytes, body.encode("ascii"), sha256).digest()
    try:
        actual_sig = _b64u_decode(sig_b64)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token encoding."
        ) from exc

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature."
        )

    payload = json.loads(_b64u_decode(body).decode("utf-8"))
    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token expired."
        )
    return payload


def authenticate_user(
    conn: sqlite3.Connection,
    settings: Settings,
    *,
    username: str,
    password: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Authenticate user credentials and verify bound device is not revoked."""
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username.strip(),)
    ).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        record_audit_event(
            conn,
            actor_id=username.strip() or "anonymous",
            action="USER_LOGIN",
            resource="auth",
            result="DENY",
            metadata={"reason": "invalid_credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if user["status"] != "ACTIVE":
        record_audit_event(
            conn,
            actor_id=user["user_id"],
            action="USER_LOGIN",
            resource="auth",
            result="DENY",
            metadata={"reason": "user_disabled"},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account disabled.")

    # Resolve device: either requested device_id or user's latest active device
    selected_device_id = device_id
    if selected_device_id:
        dev = conn.execute(
            "SELECT * FROM devices WHERE device_id = ? AND owner_id = ?",
            (selected_device_id, user["user_id"]),
        ).fetchone()
        if not dev:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Device not registered to this user.",
            )
        if dev["status"] == "REVOKED":
            now_iso = utc_now_iso()
            _record_decision_and_alert(
                conn,
                user_id=user["user_id"],
                username=user["username"],
                role=user["role"],
                device_id=dev["device_id"],
                device_status="REVOKED",
                source_service="client",
                destination_service="node-a",
                resource="auth",
                action="login",
                decision="DENY",
                reason="Login attempted from REVOKED device",
                reason_code="REVOKED_DEVICE",
                timestamp=now_iso,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Device '{dev['device_id']}' is REVOKED. Enroll a replacement device.",
            )
    else:
        dev = conn.execute(
            "SELECT * FROM devices WHERE owner_id = ? AND status = 'ACTIVE' ORDER BY registered_at DESC LIMIT 1",
            (user["user_id"],),
        ).fetchone()
        selected_device_id = dev["device_id"] if dev else None

    if selected_device_id:
        conn.execute(
            "UPDATE devices SET last_activity = ? WHERE device_id = ?",
            (utc_now_iso(), selected_device_id),
        )
        conn.commit()

    token = create_access_token(
        settings,
        user_id=user["user_id"],
        username=user["username"],
        role=user["role"],
        device_id=selected_device_id,
    )

    record_audit_event(
        conn,
        actor_id=user["user_id"],
        action="USER_LOGIN",
        resource="auth",
        result="ALLOW",
        metadata={"role": user["role"], "device_id": selected_device_id or "none"},
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "device_id": selected_device_id,
        },
    }


def _record_decision_and_alert(
    conn: sqlite3.Connection,
    *,
    user_id: str,
    username: str,
    role: str,
    device_id: str | None,
    device_status: str,
    source_service: str,
    destination_service: str,
    resource: str,
    action: str,
    decision: str,
    reason: str,
    reason_code: str = "",
    timestamp: str | None = None,
) -> dict[str, Any]:
    ts = timestamp or utc_now_iso()
    decision_id = f"dec-{uuid.uuid4().hex[:14]}"
    conn.execute(
        """
        INSERT INTO access_decisions (
            decision_id, user_id, username, role, device_id,
            source_service, destination_service, resource, action,
            decision, reason, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            decision_id,
            user_id,
            username,
            role,
            device_id,
            source_service,
            destination_service,
            resource,
            action,
            decision,
            reason,
            ts,
        ),
    )
    conn.commit()

    record_audit_event(
        conn,
        actor_id=user_id,
        action=f"ACCESS_{action.upper()}",
        resource=f"{destination_service}:{resource}",
        result=decision,
        metadata={
            "decision_id": decision_id,
            "role": role,
            "device_id": device_id or "none",
            "reason": reason,
        },
        timestamp=ts,
    )

    alerts = process_and_store_event(
        conn,
        SecurityEventInput(
            user_identity=username,
            role=role,
            device_id=device_id,
            device_status=device_status,
            source_service=source_service,
            destination_service=destination_service,
            resource=resource,
            action=action,
            decision=decision,
            event_time=ts,
            reason_code=reason_code,
        ),
    )
    return {
        "decision_id": decision_id,
        "decision": decision,
        "reason": reason,
        "timestamp": ts,
        "alerts_triggered": alerts,
    }


def check_permission_policy(
    conn: sqlite3.Connection, *, user_id: str, role: str, resource: str, action: str
) -> tuple[bool, str]:
    """Check explicit per-user resource permissions first, then RBAC defaults."""
    override = conn.execute(
        """
        SELECT allowed FROM resource_permissions
        WHERE user_id = ? AND resource = ? AND action = ?
        """,
        (user_id, resource, action),
    ).fetchone()
    if override is not None:
        if override["allowed"] == 1:
            return True, f"Explicit resource permission granted for {resource}:{action}"
        return False, f"Explicit resource permission denied for {resource}:{action}"

    role_perms = ROLE_DEFAULT_PERMISSIONS.get(role, {})
    allowed_actions = role_perms.get(resource, set())
    if action in allowed_actions:
        return True, f"Role '{role}' permitted for {resource}:{action}"
    return False, f"Role '{role}' lacks permission for {resource}:{action}"


def evaluate_zero_trust_access(
    conn: sqlite3.Connection,
    *,
    user_id: str,
    resource: str,
    action: str,
    device_id: str | None = None,
    source_service: str = "client",
    destination_service: str = "node-a",
) -> dict[str, Any]:
    """Perform full Zero-Trust check (identity, device status, node status, RBAC/ACL)."""
    user = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    device_status = "UNKNOWN"
    if device_id:
        dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if not dev or dev["owner_id"] != user_id:
            return _record_decision_and_alert(
                conn,
                user_id=user["user_id"],
                username=user["username"],
                role=user["role"],
                device_id=device_id,
                device_status="UNKNOWN",
                source_service=source_service,
                destination_service=destination_service,
                resource=resource,
                action=action,
                decision="DENY",
                reason=f"Device '{device_id}' not owned by user or unregistered.",
                reason_code="UNREGISTERED_DEVICE",
            )
        device_status = dev["status"]
        if dev["status"] == "REVOKED":
            return _record_decision_and_alert(
                conn,
                user_id=user["user_id"],
                username=user["username"],
                role=user["role"],
                device_id=device_id,
                device_status="REVOKED",
                source_service=source_service,
                destination_service=destination_service,
                resource=resource,
                action=action,
                decision="DENY",
                reason=f"Access blocked: device '{device_id}' is REVOKED.",
                reason_code="REVOKED_DEVICE",
            )

    # Check target service node status if destination is a service node
    if destination_service in {"node-a", "node-b", "node-c"}:
        node = conn.execute(
            "SELECT * FROM service_nodes WHERE node_id = ?", (destination_service,)
        ).fetchone()
        if node and node["status"] == "OFFLINE":
            return _record_decision_and_alert(
                conn,
                user_id=user["user_id"],
                username=user["username"],
                role=user["role"],
                device_id=device_id,
                device_status=device_status,
                source_service=source_service,
                destination_service=destination_service,
                resource=resource,
                action=action,
                decision="DENY",
                reason=f"Target '{node['name']}' is currently OFFLINE.",
                reason_code="NODE_OFFLINE",
            )
        if device_id:
            node_rev = conn.execute(
                """
                SELECT enforced, status FROM node_revocations
                WHERE node_id = ? AND device_id = ?
                """,
                (destination_service, device_id),
            ).fetchone()
            if node_rev and node_rev["enforced"] == 1:
                return _record_decision_and_alert(
                    conn,
                    user_id=user["user_id"],
                    username=user["username"],
                    role=user["role"],
                    device_id=device_id,
                    device_status="REVOKED",
                    source_service=source_service,
                    destination_service=destination_service,
                    resource=resource,
                    action=action,
                    decision="DENY",
                    reason=f"Node '{destination_service}' enforced revocation for device '{device_id}'.",
                    reason_code="REVOKED_DEVICE",
                )

    permitted, reason = check_permission_policy(
        conn, user_id=user["user_id"], role=user["role"], resource=resource, action=action
    )
    decision = "ALLOW" if permitted else "DENY"
    reason_code = "" if permitted else "PRIVILEGE_ESCALATION"

    if permitted and device_id:
        conn.execute(
            "UPDATE devices SET last_activity = ? WHERE device_id = ?",
            (utc_now_iso(), device_id),
        )
        conn.commit()

    return _record_decision_and_alert(
        conn,
        user_id=user["user_id"],
        username=user["username"],
        role=user["role"],
        device_id=device_id,
        device_status=device_status,
        source_service=source_service,
        destination_service=destination_service,
        resource=resource,
        action=action,
        decision=decision,
        reason=reason,
        reason_code=reason_code,
    )


def get_auth_context(
    request: Request,
    authorization: str | None = Header(default=None),
    x_device_id: str | None = Header(default=None),
    conn: sqlite3.Connection = Depends(get_db_session),
) -> AuthContext:
    """FastAPI dependency verifying bearer token, user status, and active device."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer authentication token.",
        )

    token = authorization.split(" ", 1)[1].strip()
    settings: Settings = request.app.state.settings

    claims = verify_access_token(settings, token)
    user = conn.execute(
        "SELECT user_id, username, full_name, role, status FROM users WHERE user_id = ?",
        (claims["uid"],),
    ).fetchone()
    if not user or user["status"] != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer active.",
        )

    device_id = x_device_id or claims.get("device_id")
    if device_id:
        dev = conn.execute(
            "SELECT device_id, owner_id, status FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if not dev or dev["owner_id"] != user["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session device is invalid or belongs to another user.",
            )
        if dev["status"] == "REVOKED":
            _record_decision_and_alert(
                conn,
                user_id=user["user_id"],
                username=user["username"],
                role=user["role"],
                device_id=device_id,
                device_status="REVOKED",
                source_service="client",
                destination_service="node-a",
                resource=request.url.path,
                action="access",
                decision="DENY",
                reason=f"Blocked request from REVOKED device '{device_id}'.",
                reason_code="REVOKED_DEVICE",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Device '{device_id}' has been REVOKED. Access denied.",
            )

    return AuthContext(
        user_id=user["user_id"],
        username=user["username"],
        full_name=user["full_name"],
        role=user["role"],
        device_id=device_id,
    )


def enforce_server_permission(
    conn: sqlite3.Connection,
    ctx: AuthContext,
    *,
    resource: str,
    action: str,
    source_service: str = "client",
    destination_service: str = "control-plane",
) -> None:
    """Enforce server-side authorization and record every allow/deny decision."""
    res = evaluate_zero_trust_access(
        conn,
        user_id=ctx.user_id,
        resource=resource,
        action=action,
        device_id=ctx.device_id,
        source_service=source_service,
        destination_service=destination_service,
    )
    if res["decision"] != "ALLOW":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=res["reason"],
        )
