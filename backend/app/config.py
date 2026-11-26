"""Application configuration loaded strictly from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root if present
ROOT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(ROOT_DIR / ".env")


@dataclass(frozen=True)
class Settings:
    """Runtime settings for TrustGuard."""

    master_key_bytes: bytes
    token_secret_bytes: bytes
    db_path: str
    key_grace_versions: int
    cors_origins: list[str]
    token_ttl_seconds: int = 3600 * 8


def load_settings() -> Settings:
    """Load and validate configuration from environment variables."""
    master_hex = os.environ.get("TRUSTGUARD_MASTER_KEY", "").strip()
    if not master_hex:
        raise RuntimeError(
            "TRUSTGUARD_MASTER_KEY environment variable is required. "
            "Copy .env.example to .env and configure a 64-hex-char (32-byte) key."
        )
    try:
        master_key_bytes = bytes.fromhex(master_hex)
    except ValueError as exc:
        raise RuntimeError("TRUSTGUARD_MASTER_KEY must be valid hexadecimal.") from exc
    if len(master_key_bytes) != 32:
        raise RuntimeError("TRUSTGUARD_MASTER_KEY must decode to exactly 32 bytes (64 hex chars).")

    token_secret = os.environ.get("TRUSTGUARD_TOKEN_SECRET", "").strip()
    if not token_secret or token_secret == "replace-with-a-random-64-char-local-secret":
        raise RuntimeError(
            "TRUSTGUARD_TOKEN_SECRET environment variable must be set to a non-placeholder secret."
        )

    db_path = os.environ.get("TRUSTGUARD_DB_PATH", str(ROOT_DIR / "backend" / "trustguard.db")).strip()
    grace_versions = int(os.environ.get("TRUSTGUARD_KEY_GRACE_VERSIONS", "1"))
    if grace_versions < 0:
        raise RuntimeError("TRUSTGUARD_KEY_GRACE_VERSIONS must be >= 0.")

    cors_raw = os.environ.get(
        "TRUSTGUARD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    )
    cors_origins = [origin.strip() for origin in cors_raw.split(",") if origin.strip()]

    return Settings(
        master_key_bytes=master_key_bytes,
        token_secret_bytes=token_secret.encode("utf-8"),
        db_path=db_path,
        key_grace_versions=grace_versions,
        cors_origins=cors_origins,
    )
