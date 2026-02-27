#!/usr/bin/env python3
"""Interactive CLI setup wizard for AIP Integrity Guardian.

Walks the administrator through initial configuration:

1. Check Python version >= 3.12
2. Check PostgreSQL is reachable
3. Check Redis is reachable
4. Generate .env file from user inputs
5. Generate HMAC key
6. Run alembic upgrade head
7. Create initial admin token
8. Optionally register existing AIPs
9. Print summary with next steps

Usage:
    python scripts/setup_wizard.py
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Color helpers (graceful fallback if colorama is unavailable)
# ---------------------------------------------------------------------------

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _GREEN = Fore.GREEN
    _RED = Fore.RED
    _YELLOW = Fore.YELLOW
    _CYAN = Fore.CYAN
    _BOLD = Style.BRIGHT
    _RESET = Style.RESET_ALL
except ImportError:
    _GREEN = ""
    _RED = ""
    _YELLOW = ""
    _CYAN = ""
    _BOLD = ""
    _RESET = ""


def _ok(msg: str) -> str:
    return f"{_GREEN}[OK]{_RESET} {msg}"


def _fail(msg: str) -> str:
    return f"{_RED}[FAIL]{_RESET} {msg}"


def _warn(msg: str) -> str:
    return f"{_YELLOW}[WARN]{_RESET} {msg}"


def _info(msg: str) -> str:
    return f"{_CYAN}[INFO]{_RESET} {msg}"


def _header(title: str) -> None:
    width = 60
    print()
    print(f"{_BOLD}{'=' * width}{_RESET}")
    print(f"{_BOLD}  {title}{_RESET}")
    print(f"{_BOLD}{'=' * width}{_RESET}")
    print()


def _prompt(label: str, default: str = "") -> str:
    """Prompt the user for input, showing a default value."""
    suffix = f" [{default}]" if default else ""
    answer = input(f"  {label}{suffix}: ").strip()
    return answer if answer else default


# ---------------------------------------------------------------------------
# Step 1: Check Python version
# ---------------------------------------------------------------------------

def check_python_version() -> bool:
    """Verify Python >= 3.12."""
    _header("Step 1/8: Python Version Check")
    major, minor = sys.version_info[:2]
    version_str = f"{major}.{minor}.{sys.version_info[2]}"

    if (major, minor) >= (3, 12):
        print(_ok(f"Python {version_str}"))
        return True
    else:
        print(_fail(f"Python {version_str} detected. Python >= 3.12 is required."))
        return False


# ---------------------------------------------------------------------------
# Step 2: Check PostgreSQL
# ---------------------------------------------------------------------------

def check_postgresql(db_url: str) -> bool:
    """Try connecting to PostgreSQL."""
    _header("Step 2/8: PostgreSQL Connection")

    try:
        import psycopg2

        # Convert async URL to sync for psycopg2
        sync_url = db_url.replace("postgresql+asyncpg://", "postgresql://")
        conn = psycopg2.connect(sync_url, connect_timeout=5)
        conn.close()
        print(_ok("PostgreSQL is reachable."))
        return True
    except ImportError:
        print(_warn("psycopg2 is not installed. Skipping database check."))
        return True
    except Exception as exc:
        print(_fail(f"Cannot connect to PostgreSQL: {exc}"))
        print(_info("Make sure PostgreSQL is running and the connection URL is correct."))
        return False


# ---------------------------------------------------------------------------
# Step 3: Check Redis
# ---------------------------------------------------------------------------

def check_redis(redis_url: str) -> bool:
    """Try pinging Redis."""
    _header("Step 3/8: Redis Connection")

    try:
        import redis

        r = redis.Redis.from_url(redis_url, socket_timeout=5)
        r.ping()
        print(_ok("Redis is reachable."))
        return True
    except ImportError:
        print(_warn("redis-py is not installed. Skipping Redis check."))
        return True
    except Exception as exc:
        print(_fail(f"Cannot connect to Redis: {exc}"))
        print(_info("Make sure Redis is running and the URL is correct."))
        return False


# ---------------------------------------------------------------------------
# Step 4: Generate .env file
# ---------------------------------------------------------------------------

def generate_env_file(config: dict[str, str]) -> Path:
    """Generate a .env file from the collected configuration."""
    _header("Step 4/8: Generate .env File")

    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        print(_warn(f".env file already exists at {env_path}"))
        answer = _prompt("Overwrite?", "no")
        if answer.lower() not in ("yes", "y"):
            print(_info("Keeping existing .env file."))
            return env_path

    lines = [
        "# =============================================================================",
        "# AIP Integrity Guardian — Environment Configuration",
        "# Generated by setup_wizard.py",
        "# =============================================================================",
        "",
        "# --- Application ---",
        f"GUARDIAN_SECRET_KEY={config['secret_key']}",
        f"GUARDIAN_DEBUG={config.get('debug', 'false')}",
        f"GUARDIAN_ALLOWED_HOSTS={config.get('allowed_hosts', 'localhost,127.0.0.1')}",
        f"GUARDIAN_API_TOKEN={config['api_token']}",
        f"GUARDIAN_LOG_LEVEL={config.get('log_level', 'INFO')}",
        "",
        "# --- Database (PostgreSQL) ---",
        f"DATABASE_URL={config['database_url']}",
        "",
        "# --- Celery (Redis) ---",
        f"CELERY_BROKER_URL={config['celery_broker_url']}",
        f"CELERY_RESULT_BACKEND={config['celery_result_backend']}",
        "",
        "# --- HMAC Key ---",
        f"GUARDIAN_HMAC_KEY_FILE={config.get('hmac_key_file', './secrets/hmac.key')}",
        "",
        "# --- Archivematica Storage Service ---",
        f"ARCHIVEMATICA_SS_URL={config.get('archivematica_ss_url', 'http://localhost:8000')}",
        f"ARCHIVEMATICA_SS_USER={config.get('archivematica_ss_user', 'admin')}",
        f"ARCHIVEMATICA_SS_API_KEY={config.get('archivematica_ss_api_key', '')}",
        f"ARCHIVEMATICA_STORAGE_PATH={config.get('archivematica_storage_path', '/var/archivematica/sharedDirectory')}",
        "",
        "# --- RFC 3161 Timestamp Authority ---",
        f"GUARDIAN_TSA_URL={config.get('tsa_url', 'https://freetsa.org/tsr')}",
        "",
        "# --- Notifications ---",
        f"GUARDIAN_ADMIN_EMAIL={config.get('admin_email', '')}",
        f"GUARDIAN_SMTP_HOST={config.get('smtp_host', 'localhost')}",
        f"GUARDIAN_SMTP_PORT={config.get('smtp_port', '587')}",
        f"GUARDIAN_WEBHOOK_URL={config.get('webhook_url', '')}",
        "",
    ]

    env_path.write_text("\n".join(lines), encoding="utf-8")
    print(_ok(f".env file written to {env_path}"))
    return env_path


# ---------------------------------------------------------------------------
# Step 5: Generate HMAC key
# ---------------------------------------------------------------------------

def generate_hmac_key(output_path: str) -> bool:
    """Generate a 32-byte HMAC key."""
    _header("Step 5/8: HMAC Key Generation")

    target = Path(output_path)
    if target.exists():
        print(_warn(f"HMAC key already exists at {target}"))
        answer = _prompt("Overwrite?", "no")
        if answer.lower() not in ("yes", "y"):
            print(_info("Keeping existing HMAC key."))
            return True

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        key_bytes = secrets.token_bytes(32)
        target.write_bytes(key_bytes)

        # Restrict permissions (best-effort on Windows).
        try:
            import stat
            os.chmod(str(target), stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        print(_ok(f"HMAC key written to {target.resolve()}"))
        print(_info(f"Hex: {key_bytes.hex()}"))
        return True
    except Exception as exc:
        print(_fail(f"Failed to generate HMAC key: {exc}"))
        return False


# ---------------------------------------------------------------------------
# Step 6: Run Alembic migrations
# ---------------------------------------------------------------------------

def run_migrations() -> bool:
    """Execute ``alembic upgrade head``."""
    _header("Step 6/8: Database Migrations")

    alembic_ini = PROJECT_ROOT / "alembic.ini"
    if not alembic_ini.exists():
        print(_fail(f"alembic.ini not found at {alembic_ini}"))
        return False

    try:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print(_ok("Database migrations applied successfully."))
            if result.stdout.strip():
                print(f"  {result.stdout.strip()}")
            return True
        else:
            print(_fail("Migration failed."))
            if result.stderr.strip():
                print(f"  {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print(_fail("Alembic is not installed."))
        return False
    except subprocess.TimeoutExpired:
        print(_fail("Migration timed out after 60 seconds."))
        return False
    except Exception as exc:
        print(_fail(f"Error running migrations: {exc}"))
        return False


# ---------------------------------------------------------------------------
# Step 7: Create admin token
# ---------------------------------------------------------------------------

def create_admin_token() -> str:
    """Generate a secure API token."""
    _header("Step 7/8: Admin API Token")
    token = secrets.token_urlsafe(32)
    print(_ok(f"Generated API token: {token}"))
    print(_info("This token will be used in the GUARDIAN_API_TOKEN setting."))
    return token


# ---------------------------------------------------------------------------
# Step 8: Register existing AIPs (optional)
# ---------------------------------------------------------------------------

def register_existing_aips() -> None:
    """Optionally run the bulk registration script."""
    _header("Step 8/8: Register Existing AIPs")

    answer = _prompt("Register existing AIPs from Archivematica? (yes/no)", "no")
    if answer.lower() not in ("yes", "y"):
        print(_info("Skipping AIP registration. You can run this later with:"))
        print(f"  python scripts/register_existing_aips.py")
        return

    script = PROJECT_ROOT / "scripts" / "register_existing_aips.py"
    if not script.exists():
        print(_fail(f"Registration script not found at {script}"))
        return

    try:
        subprocess.run(
            [sys.executable, str(script)],
            cwd=str(PROJECT_ROOT),
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        print(_warn("Registration timed out after 10 minutes."))
    except Exception as exc:
        print(_fail(f"Error during registration: {exc}"))


# ---------------------------------------------------------------------------
# Main wizard flow
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the interactive setup wizard."""
    _header("AIP Integrity Guardian — Setup Wizard")
    print("  This wizard will guide you through the initial setup.")
    print("  Press Ctrl+C at any time to abort.")
    print()

    # --- Step 1: Python version ---
    if not check_python_version():
        print(_fail("Setup cannot continue with an unsupported Python version."))
        sys.exit(1)

    # --- Collect configuration ---
    _header("Configuration")
    print("  Please provide the following values (press Enter for defaults):")
    print()

    config: dict[str, str] = {}

    # Secret key
    config["secret_key"] = secrets.token_hex(32)

    # Database
    config["database_url"] = _prompt(
        "Database URL",
        "postgresql+asyncpg://guardian:password@localhost:5432/guardian_db",
    )

    # Redis
    config["celery_broker_url"] = _prompt(
        "Celery broker URL (Redis)",
        "redis://localhost:6379/0",
    )
    config["celery_result_backend"] = _prompt(
        "Celery result backend URL",
        "redis://localhost:6379/1",
    )

    # Archivematica
    config["archivematica_ss_url"] = _prompt(
        "Archivematica Storage Service URL",
        "http://localhost:8000",
    )
    config["archivematica_ss_user"] = _prompt(
        "Archivematica SS username",
        "admin",
    )
    config["archivematica_ss_api_key"] = _prompt(
        "Archivematica SS API key",
        "",
    )
    config["archivematica_storage_path"] = _prompt(
        "Archivematica storage path",
        "/var/archivematica/sharedDirectory",
    )

    # HMAC key file
    config["hmac_key_file"] = _prompt(
        "HMAC key file path",
        "./secrets/hmac.key",
    )

    # Notifications
    config["admin_email"] = _prompt("Admin email (for alerts)", "")
    config["webhook_url"] = _prompt("Webhook URL (optional)", "")

    # --- Step 2: PostgreSQL ---
    check_postgresql(config["database_url"])

    # --- Step 3: Redis ---
    check_redis(config["celery_broker_url"])

    # --- Step 7 (early): Generate token ---
    config["api_token"] = create_admin_token()

    # --- Step 4: Generate .env ---
    generate_env_file(config)

    # --- Step 5: HMAC key ---
    generate_hmac_key(config["hmac_key_file"])

    # --- Step 6: Migrations ---
    answer = _prompt("Run database migrations now? (yes/no)", "yes")
    if answer.lower() in ("yes", "y"):
        run_migrations()
    else:
        print(_info("Skipping migrations. Run manually with:"))
        print("  alembic upgrade head")

    # --- Step 8: Register existing AIPs ---
    register_existing_aips()

    # --- Summary ---
    _header("Setup Complete!")
    print(f"  {_GREEN}AIP Integrity Guardian has been configured.{_RESET}")
    print()
    print("  Next steps:")
    print(f"    1. Start the application:")
    print(f"       docker compose up -d")
    print(f"       # or: uvicorn guardian.main:app --host 0.0.0.0 --port 8001")
    print()
    print(f"    2. Access the dashboard:")
    print(f"       http://localhost:8001/")
    print()
    print(f"    3. API documentation:")
    print(f"       http://localhost:8001/docs")
    print()
    print(f"    4. API token for authentication:")
    print(f"       {config['api_token']}")
    print()
    print(f"  Configuration file: {PROJECT_ROOT / '.env'}")
    print(f"  HMAC key file:      {Path(config['hmac_key_file']).resolve()}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{_YELLOW}Setup cancelled by user.{_RESET}")
        sys.exit(1)
