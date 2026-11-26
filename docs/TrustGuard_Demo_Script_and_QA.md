# TrustGuard — 5-Minute Live Demo Script & Judge Q&A Guide

## 1. 30-Second Opening Pitch

> "Hi judges, I'm presenting **TrustGuard**, a Post-Quantum Zero Trust security platform for Track 4. Most prototypes only check security on a normal login. Real breaches happen during **transitions** — when a laptop is stolen, when keys rotate or crash mid-rotation, when a valid user moves laterally between services, or when clocks are out of sync. TrustGuard uses standardized NIST post-quantum algorithms (**ML-KEM-768** and **ML-DSA-65**), ephemeral forward-secret sessions, crash-safe key rotation, multi-node revocation, and deterministic threat detection with zero AI/ML."

---

## 2. Quick Reference: Synthetic Test Accounts & URLs

- **Web Console:** `http://127.0.0.1:5173/`
- **API Swagger Docs:** `http://127.0.0.1:8000/docs`
- **Automated Tests (`22 / 22` passing):** `backend\.venv\Scripts\python.exe -m pytest backend\tests\test_trustguard.py -v`

| Username | Role | Password | Default Device |
| :--- | :--- | :--- | :--- |
| `alice.admin` | `Admin` | `AdminPass#2026!` | `dev-alice-01` |
| `bob.eng` | `Employee` | `EmpPass#2026!` | `dev-bob-01` |
| `carol.viewer` | `Viewer` | `ViewPass#2026!` | `dev-carol-01` |

---

## 3. Step-by-Step 5-Minute Live Demo Script

### Minute 0:00 – 0:45 | Sign In, Overview & Zero-Trust RBAC
1. On the Sign-In screen, click **`alice.admin`** (`Admin`) -> **Authenticate & Bind Device**.
2. On **Overview**, point out:
   - KPI cards (users, active/revoked devices, active keys, suspicious activities) and Recharts graphs come **live from SQLite**, not hard-coded values.
   - Top bar shows **`ML-KEM-768 + ML-DSA-65 + AES-256-GCM`** and live status of **Service Nodes A, B, and C**.
3. Click **Users & Identities**: show the 3 roles (`Admin`, `Employee`, `Viewer`) and **Evaluate Zero-Trust Access**.
   - **Say:** *"Authorization is enforced on the FastAPI backend—never by hiding buttons in React. Every allow and deny decision is saved to SQLite and our audit chain."*

### Minute 0:45 – 1:45 | Key Rotation, Crash Recovery & Cutoff Policy
1. Click **Key Management**: show that **only public keys and metadata** appear—private keys are wrapped at rest with `TRUSTGUARD_MASTER_KEY` and never leave the server.
2. Check **Simulate mid-rotation crash** and click **Execute Key Rotation**: point out the rotation stops in **`PENDING`**.
   - **Say:** *"If the server loses power mid-rotation, the pending key cannot be used yet. On restart—or when I click **Recover Pending**—the server verifies the pending key's integrity and commits `PENDING -> COMMITTED`."*
3. Click **Recover Pending**, then rotate once more normally (`v1 -> v2 -> v3`).
4. Click **Test Cutoff** on `v1`: it is **rejected (`EXPIRED_CUTOFF`)** because the grace window is 1 previous version.

### Minute 1:45 – 2:45 | Multi-Node Revocation & Offline Sync
1. Click **Settings** and click **Simulate Offline** on **Service Node C**.
2. Click **Device Management** and click **Report Lost / Revoke** on `dev-bob-01`: Node A and Node B enforce revocation in milliseconds, while Node C shows `PENDING_SYNC`.
3. Go back to **Settings** and click **Bring Online & Sync** on **Service Node C**: Node C catches up missed revocations and key versions automatically.
4. Go back to **Device Management** and enroll a replacement device under **Enroll Replacement for Revoked Device** (`dev-bob-01`).
   - **Say:** *"Bob gets a replacement endpoint while Carol and Alice keep working normally."*

### Minute 2:45 – 3:45 | Forward-Secret Messaging, Replay & Session Hijack
1. Click **Switch Identity / Sign Out**, sign in as **`bob.eng`**, and open **Secure Messages**.
2. Click **Start Bound Session with Recipient** (`alice.admin`), type a message, and click **Send on Resumed Session**.
   - **Say:** *"Each message and each resumed step generates a fresh one-time ML-KEM-768 keypair in RAM, binds sender, recipient, and message ID in AES-256-GCM AAD, signs with ML-DSA-65, and zeroizes the ephemeral secret key immediately after delivery."*
3. Click the three buttons in **Delivery Gate Security Tests**:
   - **Replay Last Message ID** -> rejected (`REJECTED_REPLAY`, 409)
   - **Alter Recipient on Envelope** -> rejected (`REJECTED_TAMPERED`, 400)
   - **Send Incomplete Envelope** -> rejected (`REJECTED_INVALID`, 400)
4. Switch to **`carol.viewer`**, open **Secure Messages**, and click **Verify / Resume Session** on Bob's session -> blocked (`SESSION_TAKEOVER_BLOCKED`, 403).

### Minute 3:45 – 4:40 | Threat Detection, Audit Chain & Backups
1. Sign back in as **`alice.admin`** and open **Threat Detection**:
   - Click **Evaluate Labelled Synthetic Dataset** -> shows real computed metrics across **1,058 events**: `Precision = 1.0`, `Recall = 0.9565`, `F1 = 0.9778`, `Median Alert Time < 0.05 ms`, `False Alerts / 1k = 0.0`.
   - Point out the **Zero-Trust Directed Service Graph** (`node-c -> node-a` caught even with valid credentials) and the **`+-300s` clock-skew** policy.
2. Open **Audit Logs** -> click **Verify Audit Log Chain** -> verified clean from `GENESIS`.
3. Open **Recovery & Backups** -> click **Create Encrypted Backup** -> **Verify Integrity** (`VALID`) -> **Inject Corruption (Demo)** -> **Verify Integrity** (`CORRUPTED`, restore blocked).

### Minute 4:40 – 5:00 | Automated Test Proof
Switch to your terminal and run:
```powershell
& "backend\.venv\Scripts\python.exe" -m pytest backend\tests\test_trustguard.py -v
```
Show **`22 passed`** covering every requirement end-to-end.

---

## 4. Judge Q&A Cheat Sheet

1. **Did you write your own post-quantum cryptography?**
   No—never roll your own crypto. We use `pqcrypto 1.0.0`, which wraps standardized NIST FIPS 203 (`ML-KEM-768`) and FIPS 204 (`ML-DSA-65`), paired with `cryptography 50.0.2` for `HKDF-SHA256` and `AES-256-GCM`.
2. **How do you achieve Forward Secrecy?**
   Static KEM keys alone do not provide forward secrecy. For every message and resumed session step, `EphemeralSessionManager` generates a fresh one-time `ML-KEM-768` keypair in volatile RAM, derives the AES key via HKDF, and overwrites the secret key buffer with zeros immediately after decapsulation (`test_18`).
3. **Can someone still read old messages from the database inbox view?**
   We document that trade-off honestly: after ephemeral transport decryption succeeds at delivery, `inbox_sealed_b64` is sealed under `TRUSTGUARD_MASTER_KEY` so the intended recipient can reload their inbox in the UI. Only the intended recipient can unseal it (even Admins see `plaintext: None`); in a client-device deployment, decrypted messages would stay strictly on the recipient's local device.
4. **How does session resumption stop another user from stealing a `session_id`?**
   `messaging_sessions` binds each `session_id` to `(initiator_id, initiator_device_id, peer_id)`. Any other user—even the recipient—trying to resume or send on that `session_id` is blocked with `403 SESSION_TAKEOVER_BLOCKED`, logged, and triggers a `CRITICAL` `RULE_SESSION_HIJACK_ATTEMPT` alert (`test_20`).
5. **Where are private keys stored? Could the UI or logs leak them?**
   Private keys are wrapped at rest in SQLite with `AES-256-GCM` under HKDF keys derived from `TRUSTGUARD_MASTER_KEY` in `.env` (with `key_id` as AAD). `PUBLIC_KEY_COLUMNS` excludes `encrypted_private_key` from APIs, and `audit.py` strips forbidden keys (`password`, `private_key`, `plaintext`, `token`).
6. **What happens if the server crashes mid-rotation?**
   Rotation uses a two-phase `PENDING -> COMMITTED` state machine. On startup (or recovery), `recover_pending_rotations()` verifies the pending key unwraps cleanly and safely completes or rolls back the rotation without resurrecting revoked keys (`test_07`, `test_08`).
7. **Why have `Admin` / `Employee` / `Viewer` in the UI if you claim Zero Trust?**
   Zero Trust treats the UI as untrusted. Every endpoint enforces `get_auth_context` (token signature, user status, active device) and `enforce_server_permission` (RBAC + resource overrides). Direct API calls with a `Viewer` token or revoked device return `403` and are logged (`test_02`, `test_12`).
8. **Does Threat Detection use AI or an external LLM?**
   No—zero AI, ML, or external APIs. Everything runs 100% offline using deterministic rules and a directed zero-trust service graph (`ALLOWED_SERVICE_EDGES`).
9. **How do you catch lateral movement with valid credentials?**
   Even when an `ALLOW` event has valid credentials, the engine validates `(source_service, destination_service)` against `ALLOWED_SERVICE_EDGES`. Disallowed edges like `node-c -> node-a` trigger `RULE_UNUSUAL_SERVICE_PATH` (`test_13`).
10. **How do you handle out-of-order logs or clock offsets?**
    `DeterministicThreatEngine` normalizes timestamps by clock offset and inserts events into sorted sliding windows (`bisect.insort`) with `_best_span_window()`. Supported tolerance is `+-300s` (5 minutes); reordered/offset events (`>= 1s`) are flagged `OUT_OF_ORDER_UNCERTAIN`, and events outside `+-300s` trigger `RULE_CLOCK_SKEW_ANOMALY` (`test_14`).
11. **Why wasn't Recall 1.0 on the synthetic dataset?**
    We did not invent metrics. Our 1,058-event dataset includes 2 `stealth_slow_recon` probes spaced an hour apart. Because the repeated-denial window is 180s to keep false alerts at `0.0 per 1,000 benign`, those 2 slow probes fall outside the window, giving an honest Recall of `0.9565` and F1 of `0.9778`.
12. **How do you stop audit log injection or tampering?**
    Each event serializes into canonical sorted JSON (`json.dumps(..., sort_keys=True)`) and computes a SHA-256 hash chained from `previous_hash` (`GENESIS` at row 1). `actor_id` comes from the verified server session, and user text is JSON-escaped inside a single field so newlines or fake JSON cannot inject events (`test_10`, `test_11`).

---

## 5. Pre-Demo Reset Checklist
- To start with a clean seeded database before judges arrive: stop the backend, delete `backend/trustguard.db*`, and restart the backend—it automatically re-seeds the 3 synthetic users, 3 devices, 3 `ONLINE` nodes, and fresh PQC keys.
