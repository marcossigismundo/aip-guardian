"""HMAC key management with multiple key sources.

Provides a deterministic key-resolution chain:
1. ``GUARDIAN_HMAC_KEY`` environment variable (raw hex or base64).
2. ``GUARDIAN_HMAC_KEY_FILE`` path to a file containing the raw key bytes.
3. PBKDF2 derivation from ``GUARDIAN_SECRET_KEY`` (fallback).

ISO 16363 §5.2.2 — cryptographic key management for authenticity tokens.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path

from guardian.config import get_settings


class KeyManager:
    """Resolve and manage the HMAC signing key."""

    _PBKDF2_ITERATIONS: int = 100_000
    _PBKDF2_SALT_PREFIX: bytes = b"guardian-hmac-salt-v1"
    _KEY_LENGTH: int = 32  # 256 bits

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def get_key(cls) -> bytes:
        """Return the HMAC key, trying three sources in priority order.

        Raises
        ------
        RuntimeError
            If none of the three sources can provide a usable key.
        """
        # Source 1: environment variable / settings
        key = cls._key_from_env()
        if key is not None:
            return key

        # Source 2: key file on disk
        key = cls._key_from_file()
        if key is not None:
            return key

        # Source 3: derive from the application secret
        settings = get_settings()
        secret = settings.guardian_secret_key
        if secret and secret != "change-me-in-production":
            return cls.derive_key(secret)

        raise RuntimeError(
            "No HMAC key available.  Set GUARDIAN_HMAC_KEY, "
            "GUARDIAN_HMAC_KEY_FILE, or a non-default GUARDIAN_SECRET_KEY."
        )

    @staticmethod
    def derive_key(secret: str, salt: bytes | None = None) -> bytes:
        """Derive a 256-bit key from *secret* using PBKDF2-SHA256.

        Parameters
        ----------
        secret:
            Passphrase or application secret.
        salt:
            Optional salt bytes.  When ``None`` a deterministic salt is
            derived from a fixed prefix so the same secret always yields the
            same key (necessary for HMAC verification across restarts).
        """
        if salt is None:
            salt = KeyManager._PBKDF2_SALT_PREFIX

        return hashlib.pbkdf2_hmac(
            "sha256",
            secret.encode("utf-8"),
            salt,
            KeyManager._PBKDF2_ITERATIONS,
            dklen=KeyManager._KEY_LENGTH,
        )

    @staticmethod
    def generate_key_file(path: str) -> None:
        """Generate a 32-byte random key and write it to *path*.

        The file is created with ``0o600`` permissions (owner-only read/write)
        to protect the key material at rest.
        """
        key_bytes = secrets.token_bytes(KeyManager._KEY_LENGTH)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(key_bytes)

        # Restrict permissions — best-effort on platforms that support it.
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # Windows or restrictive FS — permissions set at creation time.
            pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _key_from_env() -> bytes | None:
        """Attempt to read the key from the GUARDIAN_HMAC_KEY setting."""
        settings = get_settings()
        raw = settings.guardian_hmac_key
        if not raw:
            return None

        # Accept hex-encoded keys (64 hex chars = 32 bytes)
        try:
            decoded = bytes.fromhex(raw)
            if len(decoded) == KeyManager._KEY_LENGTH:
                return decoded
        except ValueError:
            pass

        # Fall back to raw UTF-8 encoding (for passphrases)
        return raw.encode("utf-8")

    @staticmethod
    def _key_from_file() -> bytes | None:
        """Attempt to read the key from the file at GUARDIAN_HMAC_KEY_FILE."""
        settings = get_settings()
        path = settings.guardian_hmac_key_file
        if not path:
            return None

        target = Path(path)
        if not target.is_file():
            return None

        data = target.read_bytes().strip()
        if not data:
            return None

        return data
