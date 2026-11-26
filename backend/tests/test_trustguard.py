"""Automated test suite for TrustGuard Post-Quantum Zero Trust Platform."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure backend package is importable
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.audit import record_audit_event, verify_audit_chain
from app.config import Settings
from app.main import create_app


def _make_settings(db_path: str) -> Settings:
    return Settings(
        master_key_bytes=bytes.fromhex(secrets.token_hex(32)),
        token_secret_bytes=secrets.token_hex(32).encode("utf-8"),
        db_path=db_path,
        key_grace_versions=1,
        cors_origins=["http://localhost:5173"],
    )


@pytest.fixture()
def client_and_settings(tmp_path: Path):
    db_file = str(tmp_path / "test_trustguard.db")
    settings = _make_settings(db_file)
    app = create_app(settings)
    with TestClient(app) as client:
        yield client, app, settings, db_file


def _login(client: TestClient, username: str, password: str, device_id: str | None = None) -> dict:
    payload = {"username": username, "password": password}
    if device_id:
        payload["device_id"] = device_id
    resp = client.post("/api/auth/login", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _headers(token: str, device_id: str | None = None) -> dict[str, str]:
    h = {"Authorization": f"Bearer {token}"}
    if device_id:
        h["X-Device-ID"] = device_id
    return h


# 1. Authorized user access
def test_01_authorized_user_access(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    resp = client.get("/api/users", headers=_headers(admin["access_token"]))
    assert resp.status_code == 200
    usernames = {u["username"] for u in resp.json()}
    assert {"alice.admin", "bob.eng", "carol.viewer"}.issubset(usernames)

    # Employee can send messages / read vault docs
    emp = _login(client, "bob.eng", "EmpPass#2026!")
    check = client.post(
        "/api/access/check",
        headers=_headers(emp["access_token"]),
        json={
            "user_id": emp["user"]["user_id"],
            "device_id": emp["user"]["device_id"],
            "source_service": "node-a",
            "destination_service": "node-b",
            "resource": "messages",
            "action": "write",
        },
    )
    assert check.status_code == 200
    assert check.json()["decision"] == "ALLOW"


# 2. Unauthorized user access
def test_02_unauthorized_user_access(client_and_settings):
    client, _, _, _ = client_and_settings
    viewer = _login(client, "carol.viewer", "ViewPass#2026!")
    # Server-side enforcement must block Viewer from rotating keys or creating users
    resp_rotate = client.post(
        "/api/keys/rotate",
        headers=_headers(viewer["access_token"]),
        json={"purpose": "NODE_TRANSPORT", "owner_id": "system"},
    )
    assert resp_rotate.status_code == 403

    resp_create = client.post(
        "/api/users",
        headers=_headers(viewer["access_token"]),
        json={
            "username": "rogue.user",
            "full_name": "Rogue",
            "role": "Admin",
            "password": "Password123!",
        },
    )
    assert resp_create.status_code == 403


# 3. Successful key rotation
def test_03_successful_key_rotation(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    rot = client.post(
        "/api/keys/rotate",
        headers=hdrs,
        json={"purpose": "NODE_TRANSPORT", "owner_id": "system", "simulate_crash": False},
    )
    assert rot.status_code == 200, rot.text
    data = rot.json()
    assert data["interrupted"] is False
    assert data["rotation"]["state"] == "COMMITTED"
    assert data["new_key"]["algorithm"] == "ML-KEM-768"
    assert data["new_key"]["version"] == 2
    assert data["new_key"]["status"] == "ACTIVE"

    # Private keys must never appear in API responses
    keys_resp = client.get("/api/keys", headers=hdrs).json()
    for k in keys_resp["keys"]:
        assert "encrypted_private_key" not in k
        assert "private_key" not in k


# 4. Rejection of old keys after cutoff
def test_04_rejection_of_old_keys_after_cutoff(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Initially v1 is active (grace=1). Rotate twice -> v3 active, v2 retired (in grace), v1 EXPIRED_CUTOFF
    client.post(
        "/api/keys/rotate",
        headers=hdrs,
        json={"purpose": "NODE_TRANSPORT", "owner_id": "system"},
    )
    client.post(
        "/api/keys/rotate",
        headers=hdrs,
        json={"purpose": "NODE_TRANSPORT", "owner_id": "system"},
    )

    keys = client.get("/api/keys", headers=hdrs).json()["keys"]
    v1 = [k for k in keys if k["purpose"] == "NODE_TRANSPORT" and k["version"] == 1][0]
    v2 = [k for k in keys if k["purpose"] == "NODE_TRANSPORT" and k["version"] == 2][0]
    assert v1["status"] == "EXPIRED_CUTOFF"
    assert v2["status"] == "RETIRED"

    verify_v1 = client.post("/api/keys/verify-usage", headers=hdrs, json={"key_id": v1["key_id"]})
    assert verify_v1.status_code == 200
    assert verify_v1.json()["accepted"] is False

    verify_v2 = client.post("/api/keys/verify-usage", headers=hdrs, json={"key_id": v2["key_id"]})
    assert verify_v2.status_code == 200
    assert verify_v2.json()["accepted"] is True


# 5. Device revocation across all nodes (including offline node sync recovery)
def test_05_device_revocation_across_all_nodes(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Put node-c temporarily OFFLINE, then revoke Bob's device
    off = client.post("/api/nodes/node-c/status", headers=hdrs, json={"status": "OFFLINE"})
    assert off.status_code == 200

    rev = client.post(
        "/api/devices/dev-bob-01/revoke",
        headers=hdrs,
        json={"reason": "Laptop reported lost"},
    )
    assert rev.status_code == 200
    prop = {p["node_id"]: p for p in rev.json()["node_propagation"]}
    assert prop["node-a"]["status"] == "ENFORCED"
    assert prop["node-a"]["enforcement_ms"] > 0
    assert prop["node-b"]["status"] == "ENFORCED"
    assert prop["node-c"]["status"] == "PENDING_SYNC"

    # Bring node-c back ONLINE -> auto-sync catches up revocation
    on = client.post("/api/nodes/node-c/status", headers=hdrs, json={"status": "ONLINE"})
    assert on.status_code == 200
    assert on.json()["auto_sync"]["caught_up_revocations"] >= 1

    # Bob can enroll a replacement device and other users (Carol) remain unaffected
    rep = client.post(
        "/api/devices/replace",
        headers=hdrs,
        json={
            "revoked_device_id": "dev-bob-01",
            "new_device_name": "Bob Replacement ThinkPad",
            "device_type": "Workstation",
        },
    )
    assert rep.status_code == 200
    assert rep.json()["status"] == "ACTIVE"
    assert rep.json()["replaces_device_id"] == "dev-bob-01"

    carol = _login(client, "carol.viewer", "ViewPass#2026!")
    assert carol["user"]["device_id"] == "dev-carol-01"


# 6. Recovery after interrupted rotation
def test_06_recovery_after_interrupted_rotation(client_and_settings):
    client, _, settings, db_file = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    crash_rot = client.post(
        "/api/keys/rotate",
        headers=hdrs,
        json={"purpose": "NODE_TRANSPORT", "owner_id": "system", "simulate_crash": True},
    )
    assert crash_rot.status_code == 200
    assert crash_rot.json()["interrupted"] is True
    assert crash_rot.json()["rotation"]["state"] == "PENDING"
    assert crash_rot.json()["new_key"]["status"] == "PENDING"

    # Simulate application restart by booting a fresh app instance on the same SQLite DB
    restarted_app = create_app(settings)
    with TestClient(restarted_app) as restarted_client:
        admin2 = _login(restarted_client, "alice.admin", "AdminPass#2026!")
        keys_data = restarted_client.get("/api/keys", headers=_headers(admin2["access_token"])).json()
        latest_rot = keys_data["rotations"][0]
        assert latest_rot["state"] == "COMMITTED"
        assert latest_rot["recovered"] == 1
        active_transport = [
            k for k in keys_data["keys"] if k["purpose"] == "NODE_TRANSPORT" and k["status"] == "ACTIVE"
        ]
        assert len(active_transport) == 1
        assert active_transport[0]["version"] == 2


# 7. Corrupted backup detection (and revoked key non-resurrection)
def test_07_corrupted_backup_detection(client_and_settings):
    client, app, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Create backup
    bkp = client.post("/api/backups", headers=hdrs)
    assert bkp.status_code == 200
    backup_id = bkp.json()["backup_id"]

    # Verify clean backup passes
    v1 = client.post(f"/api/backups/{backup_id}/verify", headers=hdrs)
    assert v1.status_code == 200
    assert v1.json()["valid"] is True

    # Revoke a key AFTER backup, then restore valid backup -> revoked key MUST stay REVOKED
    keys = client.get("/api/keys", headers=hdrs).json()["keys"]
    bob_key = [k for k in keys if k["owner_id"] == "usr-bob"][0]
    rev_k = client.post(
        f"/api/keys/{bob_key['key_id']}/revoke",
        headers=hdrs,
        json={"reason": "Compromise drill"},
    )
    assert rev_k.status_code == 200
    rest = client.post(f"/api/backups/{backup_id}/restore", headers=hdrs)
    assert rest.status_code == 200
    assert rest.json()["revoked_preserved"] >= 1
    keys_after = client.get("/api/keys", headers=hdrs).json()["keys"]
    bob_key_after = [k for k in keys_after if k["key_id"] == bob_key["key_id"]][0]
    assert bob_key_after["status"] == "REVOKED"

    # Now inject 1-byte corruption into backup ciphertext -> verify & restore MUST fail
    corrupt = client.post(f"/api/backups/{backup_id}/simulate-corruption", headers=hdrs)
    assert corrupt.status_code == 200

    v2 = client.post(f"/api/backups/{backup_id}/verify", headers=hdrs)
    assert v2.status_code == 200
    assert v2.json()["valid"] is False
    assert v2.json()["corrupted"] is True

    rest_bad = client.post(f"/api/backups/{backup_id}/restore", headers=hdrs)
    assert rest_bad.status_code == 400


# 8. Audit log tampering detection (and log injection protection)
def test_08_audit_log_tampering_detection(client_and_settings):
    client, app, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Attempt log injection inside a resource/metadata string
    conn = app.state.conn
    record_audit_event(
        conn,
        actor_id="usr-bob",
        action="USER_NOTE",
        resource='note\n{"actor_id":"usr-alice","action":"ROOT_OVERRIDE"}',
        result="SUCCESS",
        metadata={"password": "should-never-be-logged", "note": "hello|world\nFAKE_EVENT"},
    )

    clean_verify = client.get("/api/audit/verify", headers=hdrs)
    assert clean_verify.status_code == 200
    assert clean_verify.json()["valid"] is True
    assert clean_verify.json()["tampered"] is False

    # Ensure secret metadata was stripped
    logs = client.get("/api/audit/logs", headers=hdrs).json()
    assert "should-never-be-logged" not in logs[0]["metadata_json"]

    # Directly tamper with an existing audit row in SQLite
    conn.execute(
        "UPDATE audit_logs SET result = 'TAMPERED_OVERRIDE' WHERE seq = (SELECT MAX(seq) FROM audit_logs)"
    )
    conn.commit()

    tamper_verify = client.get("/api/audit/verify", headers=hdrs)
    assert tamper_verify.status_code == 200
    assert tamper_verify.json()["valid"] is False
    assert tamper_verify.json()["tampered"] is True


# 9. Duplicate message rejection (replay protection)
def test_09_duplicate_message_rejection(client_and_settings):
    client, _, _, _ = client_and_settings
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    hdrs = _headers(bob["access_token"])

    env_resp = client.post(
        "/api/messages/create-envelope",
        headers=hdrs,
        json={"recipient_id": "usr-alice", "plaintext": "PQC confidential briefing"},
    )
    assert env_resp.status_code == 200
    envelope = env_resp.json()

    first = client.post("/api/messages/deliver-envelope", headers=hdrs, json={"envelope": envelope})
    assert first.status_code == 200
    assert first.json()["delivery_status"] == "DELIVERED"
    assert first.json()["forward_secret"] is True

    # Replay the exact same envelope / message_id
    replay = client.post("/api/messages/deliver-envelope", headers=hdrs, json={"envelope": envelope})
    assert replay.status_code == 409
    assert "REJECTED_REPLAY" in replay.json()["detail"]


# 10. Wrong recipient rejection
def test_10_wrong_recipient_rejection(client_and_settings):
    client, _, _, _ = client_and_settings
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    hdrs = _headers(bob["access_token"])

    env_resp = client.post(
        "/api/messages/create-envelope",
        headers=hdrs,
        json={"recipient_id": "usr-alice", "plaintext": "For Alice eyes only"},
    )
    assert env_resp.status_code == 200
    tampered_envelope = dict(env_resp.json())
    # Alter recipient from Alice to Carol
    tampered_envelope["recipient_id"] = "usr-carol"

    resp = client.post(
        "/api/messages/deliver-envelope", headers=hdrs, json={"envelope": tampered_envelope}
    )
    assert resp.status_code == 400
    assert "REJECTED_TAMPERED" in resp.json()["detail"]


# 11. Suspicious activity detection (live rules + graph + synthetic dataset metrics)
def test_11_suspicious_activity_detection(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Trigger unusual service-to-service lateral path (node-c -> node-a)
    sim = client.post(
        "/api/threats/simulate",
        headers=hdrs,
        json={
            "user_identity": "bob.eng",
            "role": "Employee",
            "device_id": "dev-bob-01",
            "device_status": "ACTIVE",
            "source_service": "node-c",
            "destination_service": "node-a",
            "resource": "keys",
            "action": "rotate",
            "decision": "DENY",
        },
    )
    assert sim.status_code == 200
    rules = {a["rule_triggered"] for a in sim.json()["alerts_triggered"]}
    assert "RULE_UNUSUAL_SERVICE_PATH" in rules
    assert "RULE_PRIVILEGE_ESCALATION" in rules

    # Evaluate labelled synthetic dataset
    eval_resp = client.post("/api/threats/evaluate-dataset", headers=hdrs)
    assert eval_resp.status_code == 200
    metrics = eval_resp.json()
    assert metrics["total_events"] >= 1000
    assert metrics["precision"] >= 0.9
    assert metrics["recall"] >= 0.9
    assert metrics["f1_score"] >= 0.9
    assert metrics["false_alerts_per_1000_benign"] < 10.0


# 12. Access after revocation
def test_12_access_after_revocation(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    bob = _login(client, "bob.eng", "EmpPass#2026!")

    # Bob's token is currently bound to dev-bob-01
    ok_before = client.get("/api/messages", headers=_headers(bob["access_token"]))
    assert ok_before.status_code == 200

    # Admin revokes Bob's device
    rev = client.post(
        "/api/devices/dev-bob-01/revoke",
        headers=_headers(admin["access_token"]),
        json={"reason": "Stolen device"},
    )
    assert rev.status_code == 200

    # Immediate access attempt with Bob's existing token & revoked device MUST be denied
    blocked = client.get("/api/messages", headers=_headers(bob["access_token"]))
    assert blocked.status_code == 403
    assert "REVOKED" in blocked.json()["detail"]

    # Logging in again with the revoked device must also be denied
    login_revoked = client.post(
        "/api/auth/login",
        json={"username": "bob.eng", "password": "EmpPass#2026!", "device_id": "dev-bob-01"},
    )
    assert login_revoked.status_code == 403
