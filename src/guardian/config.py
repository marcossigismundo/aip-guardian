"""Application configuration via Pydantic Settings."""

from __future__ import annotations

import logging
import sys
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = frozenset({
    "change-me-in-production",
    "change-me-generate-a-secure-token",
})


class Settings(BaseSettings):
    """Central configuration loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    guardian_secret_key: str = "change-me-in-production"
    guardian_debug: bool = False
    guardian_allowed_hosts: str = "localhost,127.0.0.1"
    guardian_api_token: str = "change-me-generate-a-secure-token"
    guardian_log_level: str = "INFO"

    # --- Database ---
    database_url: str = "postgresql+asyncpg://guardian:password@localhost:5432/guardian_db"

    # --- Celery ---
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # --- HMAC ---
    guardian_hmac_key: str = ""
    guardian_hmac_key_file: str = ""

    # --- Archivematica ---
    archivematica_ss_url: str = "http://localhost:8000"
    archivematica_ss_user: str = "admin"
    archivematica_ss_api_key: str = ""
    archivematica_storage_path: str = "/var/archivematica/sharedDirectory"

    # --- RFC 3161 ---
    guardian_tsa_url: str = "https://freetsa.org/tsr"
    guardian_tsa_fallback_url: str = "https://timestamp.digicert.com"

    # --- Notifications ---
    guardian_admin_email: str = ""
    guardian_smtp_host: str = "localhost"
    guardian_smtp_port: int = 587
    guardian_smtp_user: str = ""
    guardian_smtp_password: str = ""
    guardian_webhook_url: str = ""

    # --- Database pool ---
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # --- Paths ---
    base_dir: Path = Path(__file__).resolve().parent.parent.parent

    @property
    def sync_database_url(self) -> str:
        """Return a synchronous database URL (for Alembic / Celery)."""
        return self.database_url.replace("postgresql+asyncpg://", "postgresql://")

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [h.strip() for h in self.guardian_allowed_hosts.split(",") if h.strip()]

    def validate_production_secrets(self) -> None:
        """Abort startup if insecure default secrets are still in use.

        In debug mode this emits warnings instead of crashing, so that
        local development remains friction-free.
        """
        issues: list[str] = []

        if self.guardian_secret_key in _INSECURE_DEFAULTS:
            issues.append(
                "GUARDIAN_SECRET_KEY is still set to the insecure default. "
                "Generate a strong key: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if self.guardian_api_token in _INSECURE_DEFAULTS:
            issues.append(
                "GUARDIAN_API_TOKEN is still set to the insecure default. "
                "Generate a strong token: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        if not issues:
            return

        for msg in issues:
            if self.guardian_debug:
                logger.warning("INSECURE CONFIG (debug mode): %s", msg)
            else:
                logger.critical("STARTUP BLOCKED: %s", msg)

        if not self.guardian_debug:
            sys.exit(
                "\n[FATAL] Insecure default secrets detected. "
                "Set GUARDIAN_SECRET_KEY and GUARDIAN_API_TOKEN in your .env file "
                "or set GUARDIAN_DEBUG=true for development.\n"
            )


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
