# TrustGuard – Post-Quantum Zero Trust Security Platform

**Track 4 Hackathon Prototype** — Protecting confidential messages, cryptographic keys, and service access when keys rotate, devices are lost/revoked, or user permissions change.

---

## 1. Simple Architecture Overview

Think of **TrustGuard** as an armored post-quantum security checkpoint sitting in front of three internal microservices (`Service Node A`, `Service Node B`, `Service Node C`):

1. **Every request is verified (`Zero Trust`)**:
   - The backend checks your signed identity token, checks your role (`Admin`, `Employee`, `Viewer`) and explicit resource permissions, and checks whether the **device** you are using is still `ACTIVE` (not `REVOKED`).
   - Every allow/deny decision is recorded in SQLite and written to a **tamper-evident hash chain**.
2. **Post-Quantum Cryptography (`pqcrypto` + `cryptography`)**:
   - **ML-KEM-768 (NIST FIPS 203)** establishes shared secrets.
   - **HKDF-SHA256 + AES-256-GCM** derives per-message keys and encrypts data with Associated Authenticated Data (AAD) binding sender, recipient, message ID, and timestamp.
   - **ML-DSA-65 (NIST FIPS 204)** signs messages, metadata, and encrypted key backups.
   - Private keys are wrapped at rest using `TRUSTGUARD_MASTER_KEY` and are **never** sent to the frontend or written to logs.
3. **Ephemeral Forward Secrecy**:
   - Static long-term KEM keys alone do not provide forward secrecy. For every message, TrustGuard creates a fresh **ephemeral ML-KEM-768** keypair in volatile RAM, encapsulates the session secret, and zeroizes/deletes the ephemeral secret key immediately upon delivery.
4. **Recoverable Key Rotation (`PENDING → COMMITTED`)**:
   - Key rotation writes the new key in a `PENDING` state first, verifies it can be unwrapped cleanly, commits it to `ACTIVE`, retires the old key, enforces the cutoff grace window (`EXPIRED_CUTOFF`), and syncs across Service Nodes A, B, and C. If the app crashes mid-rotation, startup recovery safely completes or rolls back the `PENDING` rotation.
5. **Deterministic Threat Detection (No AI/ML)**:
   - Pure Python rules + a directed service-graph topology analyzer detect revoked device access, privilege escalation, unusual lateral service-to-service paths, multi-service fan-out, repeated denials, and suspicious key operations.

---

## 2. Folder Structure

```text
.
├── .env.example                          # Environment variable template (no real secrets)
├── .gitignore
├── README.md
├── backend/
│   ├── requirements.txt                  # FastAPI, pqcrypto, cryptography, pytest, httpx
│   ├── data/
│   │   └── synthetic_security_logs.json  # 1,058 labelled events for Threat Detection metrics
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py                     # Env-based settings loader
│   │   ├── database.py                   # SQLite WAL schema & synthetic seed data
│   │   ├── crypto.py                     # ML-KEM-768, ML-DSA-65, HKDF, AES-GCM, ephemeral RAM store
│   │   ├── audit.py                      # Canonical JSON SHA-256 hash-chained audit logs
│   │   ├── auth.py                       # scrypt passwords, HMAC tokens, server-side RBAC + device check
│   │   ├── nodes.py                      # Persistent Service Nodes A, B, C & offline sync recovery
│   │   ├── keys.py                       # Key generation, PENDING->COMMITTED rotation, cutoff policy
│   │   ├── devices.py                    # Enrollment, revocation propagation & per-node timing
│   │   ├── messaging.py                  # Forward-secret PQC messaging, replay & recipient checks
│   │   ├── threat_detection.py           # Deterministic rules, service graph & dataset evaluation
│   │   ├── backup.py                     # AES-GCM encrypted + ML-DSA signed backups & safe restore
│   │   └── main.py                       # FastAPI REST endpoints & startup crash recovery
│   └── tests/
│       └── test_trustguard.py            # 12 automated security tests
└── frontend/
    ├── package.json
    ├── vite.config.ts
    ├── tsconfig.json
    ├── index.html
    └── src/
        ├── main.tsx
        ├── App.tsx                       # Auth screen + 9-tab dashboard router
        ├── types.ts
        ├── api/client.ts
        ├── components/
        │   ├── Layout.tsx                # Dark cybersecurity sidebar + node status header
        │   └── StatusBadge.tsx
        └── pages/
            ├── OverviewPage.tsx
            ├── UsersPage.tsx
            ├── KeysPage.tsx
            ├── MessagesPage.tsx
            ├── DevicesPage.tsx
            ├── ThreatDetectionPage.tsx
            ├── AuditLogsPage.tsx
            ├── RecoveryBackupsPage.tsx
            └── SettingsPage.tsx
```

---

## 3. Setup & Run Instructions

### Prerequisites
- Python 3.11+ (tested with Python 3.14.2)
- Node.js 18+ and npm (tested with Node 22.23.5)

### Step 1: Configure Environment Variables
Copy `.env.example` to `.env` and populate fresh random secrets (never commit `.env`):
```powershell
Copy-Item .env.example .env
```
Update `TRUSTGUARD_MASTER_KEY` (64 hex characters = 32 bytes) and `TRUSTGUARD_TOKEN_SECRET` in `.env` with randomly generated values, e.g.:
```powershell
& "backend\.venv\Scripts\python.exe" -c "import secrets; print(secrets.token_hex(32))"
```

### Step 2: Install & Run Backend (Port 8000)
```powershell
python -m venv backend\.venv
& "backend\.venv\Scripts\python.exe" -m pip install -r backend\requirements.txt
& "backend\.venv\Scripts\uvicorn.exe" backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
On first startup, SQLite (`backend/trustguard.db`) initializes automatically with 3 synthetic users, 3 devices, 3 service nodes, PQC keys, and the `GENESIS` audit event.

### Step 3: Install & Run Frontend (Port 5173)
In a second terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open `http://127.0.0.1:5173` in your browser. Vite proxies `/api/*` requests to `http://127.0.0.1:8000`.

### Synthetic Test Identities
| Username | Role | Password | Initial Device |
| :--- | :--- | :--- | :--- |
| `alice.admin` | `Admin` | `AdminPass#2026!` | `dev-alice-01` |
| `bob.eng` | `Employee` | `EmpPass#2026!` | `dev-bob-01` |
| `carol.viewer` | `Viewer` | `ViewPass#2026!` | `dev-carol-01` |

---

## 4. Running Automated Tests

Run all 12 automated security tests (covering authorization, key rotation, cutoff rejection, device revocation across nodes, crash recovery, corrupted backup detection, audit log tampering, message replay, wrong recipient tampering, threat detection, and post-revocation denial):

```powershell
& "backend\.venv\Scripts\python.exe" -m pytest backend\tests\test_trustguard.py -v
```

---

## 5. Threat Model

| Threat | TrustGuard Mitigation |
| :--- | :--- |
| **Quantum / Harvest-Now-Decrypt-Later** | Uses standardized NIST FIPS 203 (`ML-KEM-768`) + `HKDF-SHA256` + `AES-256-GCM` and NIST FIPS 204 (`ML-DSA-65`). |
| **Long-term key compromise reading past traffic** | Ephemeral `ML-KEM-768` session keys are created in RAM per message and zeroized immediately after decapsulation. |
| **Stolen or lost endpoint device** | Immediate device revocation updates Service Nodes A/B/C with measured latency; any active bearer token tied to the revoked device is blocked server-side (`403`). |
| **Unauthorized frontend bypass** | All RBAC, resource overrides, and device checks execute server-side in FastAPI dependencies. |
| **Message replay or recipient substitution** | Unique `message_id` tracking blocks duplicates (`409`); `sender_id`, `recipient_id`, `session_id`, and `message_id` are bound in AES-GCM AAD and signed with `ML-DSA-65`. |
| **Audit log falsification or log injection** | Events use canonical JSON serialization (preventing field/newline injection) chained with SHA-256 hashes from `GENESIS`; secrets and plaintext messages are stripped/prohibited. |
| **Crash during key rotation or corrupted backup** | Two-phase `PENDING → COMMITTED` rotation recovers safely on restart; backups require valid `ML-DSA-65` signature, `AES-256-GCM` auth tag, and `SHA-256` match, and never resurrect revoked keys. |

---

## 6. Known Limitations

1. **Single-Process SQLite & In-Memory Ephemeral Store**: Ephemeral session secrets live in a single Python process memory space (`EphemeralSessionManager`), and Service Nodes A/B/C are simulated via persistent SQLite tables rather than separate networked containers. Multi-worker production deployment would require distributed node RPCs and out-of-process HSM/KMS wrapping.
2. **Inbox Persistence Trade-off**: For usability in the single-box hackathon UI, after ephemeral forward-secret decryption succeeds at the delivery gate, a recipient-sealed copy (`inbox_sealed_b64`) is stored so the recipient can view received messages across page reloads. In a pure end-to-end client-device deployment, decrypted messages would remain strictly on the recipient's local device storage.
3. **Rule-Based Slow-Recon Window**: Deterministic sliding-window rules (`120s` fan-out, `180s` repeated denials) intentionally avoid false positives on benign traffic, meaning very low-and-slow probes spaced hours apart are not flagged (demonstrated honestly by the `stealth_slow_recon` cases in `synthetic_security_logs.json`).
4. **Master Key Source**: `TRUSTGUARD_MASTER_KEY` is loaded from environment variables rather than a hardware HSM or OS TPM.
