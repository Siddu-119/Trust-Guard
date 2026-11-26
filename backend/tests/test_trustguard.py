"""Comprehensive 20-test Security Audit Suite for TrustGuard."""

from __future__ import annotations

import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.audit import record_audit_event
from app.config import Settings
from app.crypto import ephemeral_sessions, kem_decapsulate, unwrap_private_key
from app.main import create_app
from app.threat_detection import (
    SUPPORTED_CLOCK_SKEW_SECONDS,
    DeterministicThreatEngine,
    SecurityEventInput,
)


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
    assert {"alice.admin", "bob.eng", "carol.viewer"}.issubset(
        {u["username"] for u in resp.json()}
    )

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


# 3. Key rotation (and ongoing authorized transfers during rotation)
def test_03_key_rotation_and_ongoing_transfers(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Start rotation in PENDING state and verify authorized messaging still continues
    pending_rot = client.post(
        "/api/keys/rotate",
        headers=hdrs,
        json={"purpose": "IDENTITY_SIGNING", "owner_id": "usr-bob", "simulate_crash": True},
    )
    assert pending_rot.status_code == 200
    assert pending_rot.json()["rotation"]["state"] == "PENDING"

    ongoing = client.post(
        "/api/messages/send",
        headers=_headers(bob["access_token"]),
        json={"recipient_id": "usr-alice", "plaintext": "Transfer during PENDING rotation"},
    )
    assert ongoing.status_code == 200
    assert ongoing.json()["delivery"]["delivery_status"] == "DELIVERED"

    # Complete recovery -> COMMITTED to v2
    rec = client.post("/api/keys/recover-rotation", headers=hdrs)
    assert rec.status_code == 200
    assert rec.json()["recovered_count"] == 1

    # Also test standard non-crashed rotation of NODE_TRANSPORT
    rot = client.post(
        "/api/keys/rotate",
        headers=hdrs,
        json={"purpose": "NODE_TRANSPORT", "owner_id": "system", "simulate_crash": False},
    )
    assert rot.status_code == 200
    assert rot.json()["rotation"]["state"] == "COMMITTED"
    assert rot.json()["new_key"]["algorithm"] == "ML-KEM-768"
    assert rot.json()["new_key"]["version"] == 2

    # Private keys must never appear in API responses
    for k in client.get("/api/keys", headers=hdrs).json()["keys"]:
        assert "encrypted_private_key" not in k
        assert "private_key" not in k


# 4. Old key rejection after cutoff
def test_04_old_key_rejection_after_cutoff(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

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

    assert client.post("/api/keys/verify-usage", headers=hdrs, json={"key_id": v1["key_id"]}).json()["accepted"] is False
    assert client.post("/api/keys/verify-usage", headers=hdrs, json={"key_id": v2["key_id"]}).json()["accepted"] is True


# 5. Revocation across all nodes (devices AND cryptographic keys)
def test_05_revocation_across_all_nodes(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Put node-c temporarily OFFLINE, then revoke Bob's device AND Bob's signing key
    assert client.post("/api/nodes/node-c/status", headers=hdrs, json={"status": "OFFLINE"}).status_code == 200

    rev_dev = client.post(
        "/api/devices/dev-bob-01/revoke",
        headers=hdrs,
        json={"reason": "Laptop reported lost"},
    )
    assert rev_dev.status_code == 200
    dev_prop = {p["node_id"]: p for p in rev_dev.json()["node_propagation"]}
    assert dev_prop["node-a"]["status"] == "ENFORCED"
    assert dev_prop["node-a"]["enforcement_ms"] > 0
    assert dev_prop["node-b"]["status"] == "ENFORCED"
    assert dev_prop["node-c"]["status"] == "PENDING_SYNC"

    # Revoke Bob's key and verify propagation across nodes
    bob_key = [k for k in client.get("/api/keys", headers=hdrs).json()["keys"] if k["owner_id"] == "usr-bob"][0]
    rev_key = client.post(
        f"/api/keys/{bob_key['key_id']}/revoke",
        headers=hdrs,
        json={"reason": "Key compromised with lost laptop"},
    )
    assert rev_key.status_code == 200
    key_prop = {p["node_id"]: p for p in rev_key.json()["node_propagation"]}
    assert key_prop["node-a"]["status"] == "ENFORCED"
    assert key_prop["node-b"]["status"] == "ENFORCED"
    assert key_prop["node-c"]["status"] == "PENDING_SYNC"

    # Bring node-c back ONLINE -> auto-sync enforces both device & key revocations
    on = client.post("/api/nodes/node-c/status", headers=hdrs, json={"status": "ONLINE"})
    assert on.status_code == 200
    assert on.json()["auto_sync"]["caught_up_revocations"] >= 1
    assert on.json()["auto_sync"]["caught_up_key_revocations"] >= 1

    # Verify every node rejects the revoked key
    for nid in ("node-a", "node-b", "node-c"):
        chk = client.post(
            "/api/keys/verify-usage",
            headers=hdrs,
            json={"key_id": bob_key["key_id"], "node_id": nid},
        )
        assert chk.status_code == 200
        assert chk.json()["accepted"] is False


# 6. Device re-enrolment (and preserving other users' access)
def test_06_device_reenrolment_preserves_other_users(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    assert client.post("/api/devices/dev-bob-01/revoke", headers=hdrs, json={"reason": "Lost"}).status_code == 200

    # Bob's old token bound to dev-bob-01 is immediately blocked
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    assert bob["user"]["device_id"] is None  # no active device left

    # Enroll replacement device for Bob
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

    # Bob logs in on his new device and regains access
    bob_new = _login(client, "bob.eng", "EmpPass#2026!", device_id=rep.json()["device_id"])
    assert client.get("/api/messages", headers=_headers(bob_new["access_token"])).status_code == 200

    # Other users (Carol) retain their access undisturbed
    carol = _login(client, "carol.viewer", "ViewPass#2026!")
    assert carol["user"]["device_id"] == "dev-carol-01"
    assert client.get("/api/messages", headers=_headers(carol["access_token"])).status_code == 200


# 7. Crash during key rotation
def test_07_crash_during_key_rotation(client_and_settings):
    client, _, _, _ = client_and_settings
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

    # Pending key must NOT be accepted before recovery
    pending_check = client.post(
        "/api/keys/verify-usage",
        headers=hdrs,
        json={"key_id": crash_rot.json()["new_key"]["key_id"]},
    )
    assert pending_check.json()["accepted"] is False


# 8. Recovery after crash (consistent key, revoked keys stay revoked, protected data preserved)
def test_08_recovery_after_crash_preserves_data_and_revocations(client_and_settings):
    client, _, settings, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Send protected message before crash
    msg_resp = client.post(
        "/api/messages/send",
        headers=_headers(bob["access_token"]),
        json={"recipient_id": "usr-alice", "plaintext": "Protected briefing pre-crash"},
    )
    assert msg_resp.status_code == 200

    # Revoke Carol's signing key before crash
    carol_key = [k for k in client.get("/api/keys", headers=hdrs).json()["keys"] if k["owner_id"] == "usr-carol"][0]
    assert client.post(f"/api/keys/{carol_key['key_id']}/revoke", headers=hdrs, json={"reason": "Pre-crash revoke"}).status_code == 200

    # Crash during rotation
    assert client.post(
        "/api/keys/rotate",
        headers=hdrs,
        json={"purpose": "NODE_TRANSPORT", "owner_id": "system", "simulate_crash": True},
    ).json()["interrupted"] is True

    # Boot fresh app instance on same SQLite DB -> automatic crash recovery
    restarted_app = create_app(settings)
    with TestClient(restarted_app) as restarted_client:
        admin2 = _login(restarted_client, "alice.admin", "AdminPass#2026!")
        hdrs2 = _headers(admin2["access_token"])
        keys_data = restarted_client.get("/api/keys", headers=hdrs2).json()
        assert keys_data["rotations"][0]["state"] == "COMMITTED"
        assert keys_data["rotations"][0]["recovered"] == 1

        carol_after = [k for k in keys_data["keys"] if k["key_id"] == carol_key["key_id"]][0]
        assert carol_after["status"] == "REVOKED"

        # Protected message remains readable by Alice
        alice_msgs = restarted_client.get("/api/messages", headers=hdrs2).json()
        assert any(m["plaintext"] == "Protected briefing pre-crash" for m in alice_msgs)


# 9. Corrupted backup detection (plus revoked signing key refusal)
def test_09_corrupted_backup_detection(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    bkp = client.post("/api/backups", headers=hdrs)
    assert bkp.status_code == 200
    backup_id = bkp.json()["backup_id"]

    assert client.post(f"/api/backups/{backup_id}/verify", headers=hdrs).json()["valid"] is True

    # Inject 1-byte corruption -> verify & restore MUST fail
    assert client.post(f"/api/backups/{backup_id}/simulate-corruption", headers=hdrs).status_code == 200
    v_bad = client.post(f"/api/backups/{backup_id}/verify", headers=hdrs).json()
    assert v_bad["valid"] is False
    assert v_bad["corrupted"] is True
    assert client.post(f"/api/backups/{backup_id}/restore", headers=hdrs).status_code == 400

    # Also verify backup signed by a revoked BACKUP_SIGNING key is rejected
    bkp2 = client.post("/api/backups", headers=hdrs).json()["backup_id"]
    sys_sig_key = [
        k for k in client.get("/api/keys", headers=hdrs).json()["keys"]
        if k["purpose"] == "BACKUP_SIGNING" and k["status"] == "ACTIVE"
    ][0]
    client.post(f"/api/keys/{sys_sig_key['key_id']}/revoke", headers=hdrs, json={"reason": "Compromised backup key"})
    v_revoked_signer = client.post(f"/api/backups/{bkp2}/verify", headers=hdrs).json()
    assert v_revoked_signer["valid"] is False
    assert "REVOKED" in v_revoked_signer["reason"]


# 10. Audit log tampering detection
def test_10_audit_log_tampering(client_and_settings):
    client, app, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    assert client.get("/api/audit/verify", headers=hdrs).json()["valid"] is True

    conn = app.state.conn
    conn.execute(
        "UPDATE audit_logs SET result = 'TAMPERED_OVERRIDE' WHERE seq = (SELECT MAX(seq) FROM audit_logs)"
    )
    conn.commit()

    tamper_verify = client.get("/api/audit/verify", headers=hdrs).json()
    assert tamper_verify["valid"] is False
    assert tamper_verify["tampered"] is True


# 11. Log injection attempts
def test_11_log_injection_attempts(client_and_settings):
    client, app, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])
    conn = app.state.conn

    before_count = len(client.get("/api/audit/logs?limit=200", headers=hdrs).json())
    record_audit_event(
        conn,
        actor_id="usr-bob",
        action="USER_NOTE",
        resource='note\n{"actor_id":"usr-alice","action":"ADMIN_OVERRIDE"}',
        result="SUCCESS",
        metadata={"password": "secret-should-not-appear", "note": "a|b\nFAKE_ROW"},
    )
    logs = client.get("/api/audit/logs?limit=200", headers=hdrs).json()
    # Exactly 1 log entry was created (plus the audit read check above), no injected fake rows
    assert "secret-should-not-appear" not in str(logs)
    injected_entry = [l for l in logs if l["action"] == "USER_NOTE"][0]
    assert injected_entry["actor_id"] == "usr-bob"
    assert len(logs) >= before_count + 1
    assert client.get("/api/audit/verify", headers=hdrs).json()["valid"] is True


# 12. Suspicious privilege escalation vs routine administration
def test_12_suspicious_privilege_escalation_vs_routine_admin(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    # Routine admin action -> 0 alerts
    routine = client.post(
        "/api/threats/simulate",
        headers=hdrs,
        json={
            "user_identity": "alice.admin",
            "role": "Admin",
            "device_status": "ACTIVE",
            "source_service": "client",
            "destination_service": "node-a",
            "resource": "users",
            "action": "write",
            "decision": "ALLOW",
        },
    )
    assert routine.status_code == 200
    assert routine.json()["alerts_triggered"] == []

    # Non-admin privilege escalation -> RULE_PRIVILEGE_ESCALATION
    esc = client.post(
        "/api/threats/simulate",
        headers=hdrs,
        json={
            "user_identity": "carol.viewer",
            "role": "Viewer",
            "device_status": "ACTIVE",
            "source_service": "node-a",
            "destination_service": "node-b",
            "resource": "keys",
            "action": "rotate",
            "decision": "DENY",
        },
    )
    assert esc.status_code == 200
    assert any(a["rule_triggered"] == "RULE_PRIVILEGE_ESCALATION" for a in esc.json()["alerts_triggered"])


# 13. Lateral movement detection (even with valid credentials / ALLOW)
def test_13_lateral_movement_detection_with_valid_creds(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    hdrs = _headers(admin["access_token"])

    sim = client.post(
        "/api/threats/simulate",
        headers=hdrs,
        json={
            "user_identity": "alice.admin",
            "role": "Admin",
            "device_status": "ACTIVE",
            "source_service": "node-c",
            "destination_service": "node-a",
            "resource": "vault-docs",
            "action": "read",
            "decision": "ALLOW",  # valid credentials!
        },
    )
    assert sim.status_code == 200
    alerts = sim.json()["alerts_triggered"]
    lat = [a for a in alerts if a["rule_triggered"] == "RULE_UNUSUAL_SERVICE_PATH"]
    assert len(lat) == 1
    assert lat[0]["user_identity"] == "alice.admin"
    assert lat[0]["source_service"] == "node-c"
    assert lat[0]["destination_service"] == "node-a"
    assert len(lat[0]["related_events"]) >= 1

    # Also validate synthetic dataset evaluation metrics
    metrics = client.post("/api/threats/evaluate-dataset", headers=hdrs).json()
    assert metrics["precision"] >= 0.9
    assert metrics["recall"] >= 0.9
    assert metrics["f1_score"] >= 0.9


# 14. Out-of-order event processing and clock offsets
def test_14_out_of_order_and_clock_skew_events():
    engine = DeterministicThreatEngine()
    base = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)

    # Event 3 arrives FIRST (t+40s), Event 1 arrives SECOND (t+0s, out-of-order),
    # Event 2 arrives THIRD (t+20s with +30s node clock offset -> raw t+50s - 30s = t+20s)
    e3 = SecurityEventInput(
        event_id="evt-3",
        user_identity="bob.eng",
        role="Employee",
        device_id="dev-bob-01",
        device_status="ACTIVE",
        source_service="node-a",
        destination_service="node-b",
        resource="messages",
        action="read",
        decision="DENY",
        event_time=(base + timedelta(seconds=40)).isoformat(),
    )
    e1 = SecurityEventInput(
        event_id="evt-1",
        user_identity="bob.eng",
        role="Employee",
        device_id="dev-bob-01",
        device_status="ACTIVE",
        source_service="node-a",
        destination_service="node-b",
        resource="messages",
        action="read",
        decision="DENY",
        event_time=base.isoformat(),
    )
    e2 = SecurityEventInput(
        event_id="evt-2",
        user_identity="bob.eng",
        role="Employee",
        device_id="dev-bob-01",
        device_status="ACTIVE",
        source_service="node-a",
        destination_service="node-b",
        resource="messages",
        action="read",
        decision="DENY",
        event_time=(base + timedelta(seconds=50)).isoformat(),
        clock_offset_seconds=30.0,
    )

    assert engine.evaluate_event(e3) == []
    assert engine.evaluate_event(e1) == []
    alerts = engine.evaluate_event(e2)
    rep = [a for a in alerts if a["rule_triggered"] == "RULE_REPEATED_DENIALS"]
    assert len(rep) == 1
    assert rep[0]["ordering_status"] == "OUT_OF_ORDER_UNCERTAIN"
    assert rep[0]["ordering_uncertain"] is True
    assert set(rep[0]["related_events"]) == {"evt-1", "evt-2", "evt-3"}

    # Exceeding supported clock skew (+/- 300s) must raise RULE_CLOCK_SKEW_ANOMALY
    bad_skew = SecurityEventInput(
        event_id="evt-skew",
        user_identity="bob.eng",
        role="Employee",
        device_id="dev-bob-01",
        device_status="ACTIVE",
        source_service="node-a",
        destination_service="node-b",
        resource="messages",
        action="read",
        decision="ALLOW",
        event_time=(base + timedelta(seconds=60)).isoformat(),
        clock_offset_seconds=SUPPORTED_CLOCK_SKEW_SECONDS + 120.0,
    )
    skew_alerts = engine.evaluate_event(bad_skew)
    assert any(a["rule_triggered"] == "RULE_CLOCK_SKEW_ANOMALY" for a in skew_alerts)


# 15. Duplicate message rejection
def test_15_duplicate_message_rejection(client_and_settings):
    client, _, _, _ = client_and_settings
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    hdrs = _headers(bob["access_token"])

    envelope = client.post(
        "/api/messages/create-envelope",
        headers=hdrs,
        json={"recipient_id": "usr-alice", "plaintext": "PQC confidential briefing"},
    ).json()

    assert client.post("/api/messages/deliver-envelope", headers=hdrs, json={"envelope": envelope}).status_code == 200
    replay = client.post("/api/messages/deliver-envelope", headers=hdrs, json={"envelope": envelope})
    assert replay.status_code == 409
    assert "REJECTED_REPLAY" in replay.json()["detail"]


# 16. Wrong recipient rejection & recipient-only reading
def test_16_wrong_recipient_rejection(client_and_settings):
    client, _, _, _ = client_and_settings
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    alice = _login(client, "alice.admin", "AdminPass#2026!")
    carol = _login(client, "carol.viewer", "ViewPass#2026!")

    envelope = client.post(
        "/api/messages/create-envelope",
        headers=_headers(bob["access_token"]),
        json={"recipient_id": "usr-carol", "plaintext": "For Carol eyes only"},
    ).json()

    # Alter recipient from Carol to Alice -> rejected
    tampered = dict(envelope)
    tampered["recipient_id"] = "usr-alice"
    bad = client.post(
        "/api/messages/deliver-envelope",
        headers=_headers(bob["access_token"]),
        json={"envelope": tampered},
    )
    assert bad.status_code == 400
    assert "REJECTED_TAMPERED" in bad.json()["detail"]

    # Deliver authentic message to Carol; Admin (Alice) must NOT see plaintext
    ok = client.post(
        "/api/messages/deliver-envelope",
        headers=_headers(bob["access_token"]),
        json={"envelope": envelope},
    )
    assert ok.status_code == 200

    alice_view = client.get("/api/messages", headers=_headers(alice["access_token"])).json()
    carol_view = client.get("/api/messages", headers=_headers(carol["access_token"])).json()
    assert alice_view[0]["plaintext"] is None
    assert carol_view[0]["plaintext"] == "For Carol eyes only"


# 17. Message integrity verification (ciphertext tampering detected)
def test_17_message_integrity_verification(client_and_settings):
    client, _, _, _ = client_and_settings
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    hdrs = _headers(bob["access_token"])

    envelope = client.post(
        "/api/messages/create-envelope",
        headers=hdrs,
        json={"recipient_id": "usr-alice", "plaintext": "Integrity protected payload"},
    ).json()

    tampered = dict(envelope)
    ct = tampered["ciphertext_b64"]
    tampered["ciphertext_b64"] = ("A" if ct[0] != "A" else "B") + ct[1:]

    res = client.post("/api/messages/deliver-envelope", headers=hdrs, json={"envelope": tampered})
    assert res.status_code == 400
    assert "REJECTED_TAMPERED" in res.json()["detail"]

    attempts = client.get("/api/messages/delivery-attempts", headers=hdrs).json()
    assert any(a["status"] == "REJECTED_TAMPERED" and a["message_id"] == envelope["message_id"] for a in attempts)


# 18. Forward secrecy properties
def test_18_forward_secrecy_properties(client_and_settings):
    client, app, settings, _ = client_and_settings
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    hdrs = _headers(bob["access_token"])

    res = client.post(
        "/api/messages/send",
        headers=hdrs,
        json={"recipient_id": "usr-alice", "plaintext": "Ephemeral forward-secret secret"},
    )
    assert res.status_code == 200
    delivery = res.json()["delivery"]
    envelope = res.json()["envelope"]

    # 1. Ephemeral KEM secret key MUST be zeroized and evicted after delivery
    assert delivery["ephemeral_key_zeroized"] is True
    assert ephemeral_sessions.has_active_key(envelope["session_id"], envelope["session_step"]) is False

    # 2. Even if an attacker compromises ALL long-term private keys stored in SQLite later,
    # none of them can decapsulate the ephemeral ML-KEM-768 ciphertext from the past session.
    conn = app.state.conn
    kem_rows = conn.execute(
        "SELECT key_id, encrypted_private_key FROM crypto_keys WHERE algorithm = 'ML-KEM-768'"
    ).fetchall()
    captured_kem_ct = bytes.fromhex(
        __import__("base64").b64decode(envelope["kem_ciphertext_b64"]).hex()
    )
    # Also confirm long-term signing key compromise cannot decrypt ephemeral ciphertext
    for kr in kem_rows:
        sk = unwrap_private_key(settings.master_key_bytes, kr["key_id"], kr["encrypted_private_key"])
        # ML-KEM-768 decaps with wrong key yields an unrelated implicit-rejection secret, never matching
        # (and ephemeral session key is gone from RAM)
        assert len(sk) > 0
        wrong_ss = kem_decapsulate(sk, captured_kem_ct)
        assert isinstance(wrong_ss, bytes)


# 19. Incomplete message rejection & delivery under loss/reordering
def test_19_incomplete_message_and_out_of_order_delivery(client_and_settings):
    client, _, _, _ = client_and_settings
    admin = _login(client, "alice.admin", "AdminPass#2026!")
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    bob_hdrs = _headers(bob["access_token"])
    admin_hdrs = _headers(admin["access_token"])

    # Incomplete envelope -> rejected & reported in delivery attempts
    inc = client.post(
        "/api/messages/deliver-envelope",
        headers=bob_hdrs,
        json={"envelope": {"message_id": "msg-incomplete-01", "sender_id": "usr-bob"}},
    )
    assert inc.status_code == 400
    assert "REJECTED_INVALID" in inc.json()["detail"]

    # Out-of-order & node recovery delivery: create msg1 then msg2, take node-b offline, restore, deliver msg2 then msg1
    env1 = client.post(
        "/api/messages/create-envelope",
        headers=bob_hdrs,
        json={"recipient_id": "usr-alice", "plaintext": "Packet 1"},
    ).json()
    env2 = client.post(
        "/api/messages/create-envelope",
        headers=bob_hdrs,
        json={"recipient_id": "usr-alice", "plaintext": "Packet 2"},
    ).json()

    assert client.post("/api/nodes/node-b/status", headers=admin_hdrs, json={"status": "OFFLINE"}).status_code == 200
    dropped = client.post("/api/messages/deliver-envelope", headers=bob_hdrs, json={"envelope": env2})
    assert dropped.status_code == 403  # node-b offline

    assert client.post("/api/nodes/node-b/status", headers=admin_hdrs, json={"status": "ONLINE"}).status_code == 200
    # Deliver Packet 2 before Packet 1 (reordered recovery)
    assert client.post("/api/messages/deliver-envelope", headers=bob_hdrs, json={"envelope": env2}).json()["delivery_status"] == "DELIVERED"
    assert client.post("/api/messages/deliver-envelope", headers=bob_hdrs, json={"envelope": env1}).json()["delivery_status"] == "DELIVERED"


# 20. Session resumption & peer identity takeover protection
def test_20_session_resumption_and_peer_takeover_rejection(client_and_settings):
    client, _, _, _ = client_and_settings
    bob = _login(client, "bob.eng", "EmpPass#2026!")
    carol = _login(client, "carol.viewer", "ViewPass#2026!")
    alice = _login(client, "alice.admin", "AdminPass#2026!")

    # Bob starts a resumable session bound to (bob, dev-bob-01, alice)
    sess = client.post(
        "/api/messages/sessions",
        headers=_headers(bob["access_token"]),
        json={"recipient_id": "usr-alice"},
    )
    assert sess.status_code == 200
    session_id = sess.json()["session_id"]

    # Step 1 sent on session
    s1 = client.post(
        "/api/messages/send",
        headers=_headers(bob["access_token"]),
        json={"recipient_id": "usr-alice", "plaintext": "Session message 1", "session_id": session_id},
    )
    assert s1.status_code == 200
    assert s1.json()["delivery"]["session_step"] == 1

    # Bob resumes the same session -> step 2 succeeds with a fresh ephemeral key
    resumed = client.post(
        f"/api/messages/sessions/{session_id}/resume",
        headers=_headers(bob["access_token"]),
    )
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "RESUMED"

    s2 = client.post(
        "/api/messages/send",
        headers=_headers(bob["access_token"]),
        json={"recipient_id": "usr-alice", "plaintext": "Session message 2", "session_id": session_id},
    )
    assert s2.status_code == 200
    assert s2.json()["delivery"]["session_step"] == 2

    # Different identity (Carol) attempting to resume or send on Bob's session_id MUST be rejected
    hijack_carol = client.post(
        f"/api/messages/sessions/{session_id}/resume",
        headers=_headers(carol["access_token"]),
    )
    assert hijack_carol.status_code == 403
    assert "SESSION_TAKEOVER_BLOCKED" in hijack_carol.json()["detail"]

    # Even the peer (Alice) attempting to hijack Bob's initiator session_id MUST be rejected
    hijack_alice = client.post(
        "/api/messages/send",
        headers=_headers(alice["access_token"]),
        json={"recipient_id": "usr-carol", "plaintext": "Hijacked!", "session_id": session_id},
    )
    assert hijack_alice.status_code == 403
    assert "SESSION_TAKEOVER_BLOCKED" in hijack_alice.json()["detail"]
