"""Post-quantum and symmetric cryptography primitives for TrustGuard.

Uses standardized NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) via
the maintained `pqcrypto` library, paired with `cryptography` (HKDF-SHA256
and AES-256-GCM). Never implements custom cryptography or simulates checks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import pqcrypto
    from pqcrypto.kem import ml_kem_768
    from pqcrypto.sign import ml_dsa_65

    PQC_AVAILABLE = True
    PQC_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - defensive reporting if PQC lib missing
    pqcrypto = None  # type: ignore[assignment]
    ml_kem_768 = None  # type: ignore[assignment]
    ml_dsa_65 = None  # type: ignore[assignment]
    PQC_AVAILABLE = False
    PQC_IMPORT_ERROR = str(exc)


KEM_ALGORITHM = "ML-KEM-768"
SIGN_ALGORITHM = "ML-DSA-65"
SYMMETRIC_ALGORITHM = "HKDF-SHA256 + AES-256-GCM"


def ensure_pqc_available() -> None:
    """Fail loudly if standardized PQC primitives are unavailable."""
    if not PQC_AVAILABLE:
        raise RuntimeError(
            f"Post-quantum cryptography library (pqcrypto) is unavailable: {PQC_IMPORT_ERROR}"
        )


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization preventing delimiter/injection ambiguity."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Password hashing (scrypt + constant-time verification)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password with scrypt and a random 16-byte salt."""
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return f"scrypt${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored scrypt hash in constant time."""
    try:
        scheme, salt_hex, expected_hex = stored_hash.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except (ValueError, TypeError):
        return False

    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return hmac.compare_digest(derived, expected)


# ---------------------------------------------------------------------------
# Key derivation & authenticated encryption (HKDF-SHA256 + AES-256-GCM)
# ---------------------------------------------------------------------------

def derive_aes_key(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    """Derive a 32-byte AES-256 key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM and return (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext and authenticate AAD. Raises InvalidTag on failure."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# Private key envelope encryption at rest
# ---------------------------------------------------------------------------

def wrap_private_key(master_key: bytes, key_id: str, secret_key: bytes) -> str:
    """Encrypt a private key at rest using HKDF + AES-256-GCM bound to key_id."""
    salt = os.urandom(16)
    wrapping_key = derive_aes_key(
        master_key,
        salt=salt,
        info=f"trustguard:key-wrap:{key_id}".encode("utf-8"),
    )
    nonce, ct = aes_gcm_encrypt(
        wrapping_key,
        secret_key,
        aad=f"key_id={key_id}".encode("utf-8"),
    )
    envelope = {
        "v": 1,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ct": b64e(ct),
    }
    return json.dumps(envelope, separators=(",", ":"))


def unwrap_private_key(master_key: bytes, key_id: str, wrapped_json: str) -> bytes:
    """Decrypt and verify a wrapped private key bound to key_id."""
    envelope = json.loads(wrapped_json)
    salt = b64d(envelope["salt"])
    nonce = b64d(envelope["nonce"])
    ct = b64d(envelope["ct"])
    wrapping_key = derive_aes_key(
        master_key,
        salt=salt,
        info=f"trustguard:key-wrap:{key_id}".encode("utf-8"),
    )
    return aes_gcm_decrypt(
        wrapping_key,
        nonce,
        ct,
        aad=f"key_id={key_id}".encode("utf-8"),
    )


# ---------------------------------------------------------------------------
# Standardized Post-Quantum Primitives (ML-KEM-768 & ML-DSA-65)
# ---------------------------------------------------------------------------

def generate_kem_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 (public_key, secret_key) pair."""
    ensure_pqc_available()
    pk, sk = ml_kem_768.keygen()
    return bytes(pk), bytes(sk)


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret against an ML-KEM-768 public key -> (ciphertext, shared_secret)."""
    ensure_pqc_available()
    ct, ss = ml_kem_768.encaps(public_key)
    return bytes(ct), bytes(ss)


def kem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate an ML-KEM-768 ciphertext using secret_key -> shared_secret."""
    ensure_pqc_available()
    ss = ml_kem_768.decaps(secret_key, ciphertext)
    return bytes(ss)


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 (public_key, secret_key) pair."""
    ensure_pqc_available()
    pk, sk = ml_dsa_65.keygen()
    return bytes(pk), bytes(sk)


def sign_data(secret_key: bytes, payload: bytes) -> bytes:
    """Sign payload using ML-DSA-65."""
    ensure_pqc_available()
    return bytes(ml_dsa_65.sign(secret_key, payload))


def verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Returns False on any cryptographic failure."""
    ensure_pqc_available()
    try:
        ml_dsa_65.verify(public_key, payload, signature)
        return True
    except pqcrypto.InvalidSignatureError:
        return False
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Ephemeral Session Store for Forward-Secret Messaging
# ---------------------------------------------------------------------------

@dataclass
class EphemeralSession:
    session_id: str
    sender_id: str
    recipient_id: str
    public_key: bytes
    _secret_key_buf: bytearray
    created_at: float
    consumed: bool = False


class EphemeralSessionManager:
    """Holds one-time ephemeral ML-KEM-768 secret keys strictly in memory.

    Forward secrecy design:
    - Each message/session generates a fresh ephemeral ML-KEM-768 keypair.
    - The ephemeral secret key never touches SQLite or audit logs.
    - Upon decapsulation at delivery, the secret key buffer is overwritten with
      zeros and evicted, so later compromise of long-term ML-DSA signing keys or
      stored envelopes cannot recover past session keys.
    """

    def __init__(self, ttl_seconds: int = 900) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, EphemeralSession] = {}
        self._ttl_seconds = ttl_seconds

    def _cleanup_expired_locked(self, now: float) -> None:
        expired = [
            sid
            for sid, sess in self._sessions.items()
            if sess.consumed or (now - sess.created_at) > self._ttl_seconds
        ]
        for sid in expired:
            sess = self._sessions.pop(sid)
            for i in range(len(sess._secret_key_buf)):
                sess._secret_key_buf[i] = 0

    def create_session(self, sender_id: str, recipient_id: str) -> tuple[str, bytes]:
        """Create a one-time ephemeral ML-KEM-768 session and return (session_id, eph_public_key)."""
        pk, sk = generate_kem_keypair()
        session_id = f"eph-{secrets.token_hex(12)}"
        now = time.time()
        with self._lock:
            self._cleanup_expired_locked(now)
            self._sessions[session_id] = EphemeralSession(
                session_id=session_id,
                sender_id=sender_id,
                recipient_id=recipient_id,
                public_key=pk,
                _secret_key_buf=bytearray(sk),
                created_at=now,
            )
        return session_id, pk

    def consume_decapsulate(
        self, session_id: str, sender_id: str, recipient_id: str, kem_ciphertext: bytes
    ) -> bytes:
        """Decapsulate once and immediately zeroize & remove the ephemeral secret key."""
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None or sess.consumed:
                raise ValueError("Ephemeral session missing, expired, or already consumed.")
            if (time.time() - sess.created_at) > self._ttl_seconds:
                self._cleanup_expired_locked(time.time())
                raise ValueError("Ephemeral session expired.")
            if sess.sender_id != sender_id or sess.recipient_id != recipient_id:
                raise ValueError("Ephemeral session bound to different sender/recipient.")

            try:
                sk_bytes = bytes(sess._secret_key_buf)
                return kem_decapsulate(sk_bytes, kem_ciphertext)
            finally:
                sess.consumed = True
                for i in range(len(sess._secret_key_buf)):
                    sess._secret_key_buf[i] = 0
                self._sessions.pop(session_id, None)


ephemeral_sessions = EphemeralSessionManager()

__all__ = [
    "InvalidTag",
    "KEM_ALGORITHM",
    "PQC_AVAILABLE",
    "PQC_IMPORT_ERROR",
    "SIGN_ALGORITHM",
    "SYMMETRIC_ALGORITHM",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "b64d",
    "b64e",
    "canonical_json",
    "derive_aes_key",
    "ensure_pqc_available",
    "ephemeral_sessions",
    "generate_kem_keypair",
    "generate_signing_keypair",
    "hash_password",
    "kem_decapsulate",
    "kem_encapsulate",
    "sha256_hex",
    "sign_data",
    "unwrap_private_key",
    "verify_password",
    "verify_signature",
    "wrap_private_key",
]
