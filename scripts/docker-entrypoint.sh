#!/bin/bash
# =============================================================================
# AIP Integrity Guardian — Docker Entrypoint
# =============================================================================
# Handles: HMAC key generation, database migrations, and application startup.
# =============================================================================
set -e

echo "=== AIP Integrity Guardian — Starting ==="

# ---------------------------------------------------------------------------
# 1. Generate HMAC key if not present
# ---------------------------------------------------------------------------
HMAC_KEY_FILE="${GUARDIAN_HMAC_KEY_FILE:-/run/secrets/hmac_key}"
if [ -n "$GUARDIAN_HMAC_KEY_FILE" ] && [ ! -f "$GUARDIAN_HMAC_KEY_FILE" ]; then
    echo "[entrypoint] HMAC key file not found at $GUARDIAN_HMAC_KEY_FILE"
    # Only auto-generate in writable locations
    HMAC_DIR=$(dirname "$GUARDIAN_HMAC_KEY_FILE")
    if [ -w "$HMAC_DIR" ] 2>/dev/null; then
        echo "[entrypoint] Generating HMAC key..."
        python -c "import secrets; open('$GUARDIAN_HMAC_KEY_FILE', 'wb').write(secrets.token_bytes(32))"
        echo "[entrypoint] HMAC key generated at $GUARDIAN_HMAC_KEY_FILE"
    else
        echo "[entrypoint] WARNING: Cannot write to $HMAC_DIR — provide HMAC key via Docker secrets or GUARDIAN_HMAC_KEY env var"
    fi
fi

# ---------------------------------------------------------------------------
# 2. Run database migrations
# ---------------------------------------------------------------------------
echo "[entrypoint] Running database migrations..."
if alembic upgrade head 2>&1; then
    echo "[entrypoint] Database migrations complete."
else
    echo "[entrypoint] WARNING: Database migration failed. The database may need manual intervention."
    echo "[entrypoint] Continuing startup — the application will fail if tables are missing."
fi

# ---------------------------------------------------------------------------
# 3. Compile translations (if .po files are newer than .mo)
# ---------------------------------------------------------------------------
if command -v pybabel &> /dev/null; then
    pybabel compile -d /app/src/guardian/locale 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 4. Start the requested service
# ---------------------------------------------------------------------------
echo "[entrypoint] Executing: $@"
exec "$@"
