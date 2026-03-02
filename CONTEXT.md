# AIP Integrity Guardian — Project Context

> **Version**: 1.0.0 | **License**: AGPL-3.0-or-later | **Python**: 3.12+
> **Repository**: https://github.com/marcossigismundo/aip-guardian

## Purpose

AIP Integrity Guardian is a standalone service that complements Archivematica with
continuous, autonomous integrity verification for AIP (Archival Information Package)
storage. It addresses critical gaps in Archivematica's post-storage integrity
monitoring, raising ISO 16363 compliance from ~48% to ~89%.

## Problem

Archivematica generates SHA-256/SHA-512 checksums during ingest but **never verifies
them again** after storage. This leaves AIPs vulnerable to:

- **Silent bit rot** — undetected disk corruption
- **Coordinated tampering** — attacker modifies both file and manifest hash
- **Insider threats** — administrators with filesystem + database access
- **Accidental deletion** — no automated detection or recovery

## Architecture

Six independent, complementary components:

| # | Component | ISO 16363 | Description |
|---|-----------|-----------|-------------|
| 1 | Fixity Verifier | §4.3.3.1 | Periodic SHA-256/SHA-512 recalculation against BagIt manifests |
| 2 | HMAC Authenticator | §4.3.3 | HMAC-SHA256 authentication of manifests with separate secret key |
| 3 | Audit Log | §4.3.2.1 | Immutable hash-chained log in PostgreSQL (append-only, triggers block UPDATE/DELETE) |
| 4 | Change Detector | §4.3.1 | Content fingerprinting to prevent unnecessary re-ingestion |
| 5 | Auto-Repair | §4.3.4 | Automatic recovery from replicas when corruption is detected |
| 6 | External Anchor | §5.2.2 | RFC 3161 timestamps + Merkle trees for external trust |

## Tech Stack

- **Python 3.12+** / FastAPI / SQLAlchemy 2.0 (async) / Pydantic v2
- **PostgreSQL 16** with immutability triggers
- **Celery 5.x + Redis 7** for async task processing (AOF persistence enabled)
- **Jinja2 + Tailwind CSS + Alpine.js** for the dashboard UI
- **Docker Compose** for deployment (5 services with resource limits)
- **Trilingual UI**: English, Spanish, Portuguese (Babel/gettext)

## Standards Compliance

- **OAIS ISO 14721:2012** — Open Archival Information System reference model
- **ISO 16363:2025** — Audit and certification of trustworthy digital repositories
- **RFC 8493** — BagIt File Packaging Format
- **RFC 2104** — HMAC: Keyed-Hashing for Message Authentication
- **RFC 3161** — Internet X.509 PKI Time-Stamp Protocol
- **PREMIS 3.0** — Preservation Metadata Implementation Strategies

---

## Autonomous Monitoring Cycle

Once deployed with valid credentials, the system operates **fully autonomously**
via Celery Beat scheduled tasks. No human intervention is required for routine
operations.

### Scheduled Tasks (celery_app.py)

| Task | Schedule | What It Does |
|------|----------|-------------|
| `verify_all_aips` | Sunday 02:00 UTC | Fans out one `verify_single_aip` per registered AIP, running in parallel across workers |
| `pipeline_health_check` | Daily 06:00 UTC | Verifies Database, Redis, and Archivematica Storage Service are reachable |
| `submit_daily_anchor` | Daily 23:00 UTC | Collects today's audit log records and submits them as a batch to an RFC 3161 TSA |
| `verify_audit_chain` | Monday 03:00 UTC | Walks the full hash chain validating every record's integrity |

### Per-AIP Verification Flow (verify_single_aip)

```
For each registered AIP:
1. Fixity verification — recalculate SHA-256/SHA-512 for ALL payload + tag files
   against BagIt manifests (manifest-sha256.txt, tagmanifest-sha256.txt)
2. HMAC verification — validate manifest HMAC-SHA256 signatures
3. Tamper detection — if fixity passed but HMAC failed → tamper_detected event
4. Auto-repair — if fixity failed:
   a. Locate healthy replicas via Archivematica Storage Service API
   b. Restore corrupted files from healthy replica
   c. Notify admin of result (email + webhook)
5. Update AIPStatus record (valid / corrupted / repaired)
```

### Reaction Flow (corruption detected)

```
Corruption detected
  → audit log event (hash-chained, immutable)
  → dispatch repair_corrupted_aip task
     → query Archivematica SS for replica locations
     → restore files from healthy replica
     → success → notify_repair_success (email + webhook)
     → failure → notify_repair_failure (email + webhook)
     → ALL replicas corrupted → notify_all_replicas_corrupted (CRITICAL)
```

### New AIP Registration

- **Existing AIPs**: Run `python scripts/register_existing_aips.py` (one-time bulk import)
- **New AIPs**: Configure `scripts/post_store_hook.py` as an Archivematica post-store hook for automatic registration on ingest

---

## Security Hardening (v1.0.0)

### Authentication & Authorization

- **API**: Bearer token authentication (`Authorization: Bearer <GUARDIAN_API_TOKEN>`)
- **Dashboard**: Session-based login using the API token as password
- **Token comparison**: Uses `hmac.compare_digest()` for timing-safe comparison (prevents timing side-channels)
- **CSRF protection**: Every form includes a session-bound CSRF token, verified with `hmac.compare_digest()`
- **Session middleware**: Starlette SessionMiddleware with `GUARDIAN_SECRET_KEY`

### Startup Validation

`config.py:validate_production_secrets()` runs on every startup:
- **Production mode** (`GUARDIAN_DEBUG=false`): Blocks startup with `sys.exit()` if `GUARDIAN_SECRET_KEY` or `GUARDIAN_API_TOKEN` still have insecure default values
- **Debug mode** (`GUARDIAN_DEBUG=true`): Emits warnings but allows startup

### Production Mode Restrictions

When `GUARDIAN_DEBUG=false`:
- `/docs` (Swagger UI) is disabled
- `/redoc` is disabled
- Insecure default secrets cause startup failure

### Sensitive Data Masking

The `/settings` dashboard page masks:
- Database URL (shows first 20 chars)
- Redis URL (shows first 10 chars)
- Archivematica API key (shows first 4 chars)
- Webhook URL (shows first 10 chars)

### Docker Security

- Non-root user (`guardian:1000`) inside container
- HMAC key injected via Docker secrets (`/run/secrets/hmac_key`)
- Resource limits on all 5 services (CPU + memory)
- Redis AOF persistence with dedicated volume
- Read-only mount for Archivematica storage volume (`:ro`)
- No default secret values in docker-compose.yml (requires explicit `.env`)

### Hash Chain Integrity

- Audit log uses SHA-256 hash chain: each record's hash includes `previous_hash`
- Single canonical hash computation in `services/hash_utils.py` (shared by AuditLogger and ChainVerifier)
- PostgreSQL triggers block UPDATE and DELETE on the `aip_integrity_audit_log` table
- Weekly automated verification of the entire chain

---

## Integration with Archivematica

Connects via 4 extension points (**no Archivematica source code modification required**):

1. **Post-store callback** — `scripts/post_store_hook.py` registers new AIPs automatically on ingest
2. **Storage Service API** — `connector/archivematica_client.py` uses `amclient` library to:
   - List all AIPs (`list_all_aips`)
   - Resolve physical filesystem paths (`get_aip_path`)
   - Extract packages (ZIP/tar.gz) securely (`extract_aip`)
   - Discover replica locations (`get_replicas`)
3. **Celery Beat** — scheduled verification, anchoring, chain audits
4. **REST API + Dashboard** — management and monitoring interface

### Required Archivematica Configuration

```env
ARCHIVEMATICA_SS_URL=http://archivematica-ss:8000    # Storage Service URL
ARCHIVEMATICA_SS_USER=admin                           # SS API username
ARCHIVEMATICA_SS_API_KEY=your-api-key                 # SS API key
ARCHIVEMATICA_STORAGE_PATH=/var/archivematica/sharedDirectory  # AIP storage root
```

---

## Project Structure

```
aip-guardian/
├── CONTEXT.md                     # This file
├── INSTALL.md                     # Detailed installation manual
├── pyproject.toml                 # Python dependencies (PEP 621)
├── requirements.txt               # pip-compatible dependency list
├── Dockerfile                     # Multi-stage build (Python 3.12-slim)
├── docker-compose.yml             # 5 services: web, worker, beat, db, redis
├── .env.example                   # Environment template
├── alembic.ini                    # Migration config
├── .github/
│   └── workflows/ci.yml           # CI: ruff lint, mypy, pytest (SQLite+PostgreSQL), Docker build
├── alembic/
│   └── versions/001_initial_schema.py   # 6 tables + immutability triggers
├── scripts/
│   ├── docker-entrypoint.sh       # Auto HMAC key gen, migrations, translations
│   ├── setup_wizard.py            # Interactive setup
│   ├── generate_hmac_key.py       # HMAC key generation utility
│   ├── register_existing_aips.py  # Batch AIP registration from Archivematica
│   ├── post_store_hook.py         # Archivematica post-store hook
│   └── health_check.py            # Standalone health check
├── src/guardian/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app factory (CORS, sessions, lifespan)
│   ├── config.py                  # Pydantic Settings + startup validation
│   ├── database.py                # SQLAlchemy async engine (configurable pool)
│   ├── celery_app.py              # Celery + Beat schedule (4 periodic tasks)
│   ├── i18n.py                    # Babel/gettext (EN + ES + PT)
│   ├── models/                    # 6 SQLAlchemy ORM models
│   │   ├── aip_status.py          # AIP registration and verification state
│   │   ├── audit_log.py           # Immutable hash-chained audit trail
│   │   ├── hmac_registry.py       # HMAC-SHA256 manifest signatures
│   │   ├── content_fingerprint.py # Content fingerprints for change detection
│   │   ├── anchor_registry.py     # RFC 3161 timestamp tokens and Merkle roots
│   │   └── repair_record.py       # Auto-repair history
│   ├── schemas/                   # Pydantic v2 request/response schemas
│   │   ├── aip.py
│   │   ├── audit.py
│   │   ├── anchor.py
│   │   └── dashboard.py
│   ├── services/                  # Business logic layer
│   │   ├── hash_utils.py          # Single canonical SHA-256 record hash computation
│   │   ├── fixity_verifier.py     # BagIt-based SHA-256/SHA-512 verification
│   │   ├── hmac_authenticator.py  # HMAC-SHA256 manifest authentication
│   │   ├── audit_logger.py        # Hash-chained audit logging
│   │   ├── chain_verifier.py      # Audit chain integrity verification
│   │   ├── auto_repair.py         # Automated corruption repair from replicas
│   │   ├── replica_manager.py     # Replica location management
│   │   ├── change_detector.py     # Content fingerprint comparison
│   │   ├── rfc3161_anchor.py      # RFC 3161 timestamp submission
│   │   ├── merkle_tree.py         # Merkle tree construction for batch anchoring
│   │   ├── key_manager.py         # HMAC key loading and rotation
│   │   ├── anchor_verifier.py     # Timestamp token verification
│   │   └── notification.py        # Email (SMTP) + webhook notifications
│   ├── tasks/                     # Celery task modules
│   │   ├── fixity_tasks.py        # verify_all_aips, verify_single_aip, pipeline_health_check
│   │   ├── audit_tasks.py         # verify_audit_chain
│   │   ├── anchor_tasks.py        # submit_daily_anchor
│   │   └── repair_tasks.py        # repair_corrupted_aip
│   ├── api/                       # REST API endpoints
│   │   ├── router.py              # API router aggregator
│   │   ├── deps.py                # Dependencies (DB session, auth)
│   │   ├── aips.py                # AIP CRUD + verification trigger
│   │   ├── audit.py               # Audit log queries + chain status
│   │   ├── anchors.py             # Anchor queries + verification
│   │   ├── dashboard.py           # Dashboard summary metrics
│   │   └── health.py              # Health check endpoint
│   ├── web/                       # Dashboard UI
│   │   ├── routes.py              # All dashboard routes (auth, CSRF, i18n)
│   │   ├── static/css/app.css     # Custom styles
│   │   ├── static/js/app.js       # Alpine.js interactions
│   │   └── templates/             # Jinja2 templates
│   │       ├── base.html          # Layout with navbar, lang switcher
│   │       ├── login.html         # Authentication page
│   │       ├── dashboard.html     # Overview with stats, events, chain status
│   │       ├── aips.html          # AIP list with search/filter/pagination
│   │       ├── aip_detail.html    # AIP detail with audit events, HMAC, repairs
│   │       ├── audit_log.html     # Full audit log with filters
│   │       ├── anchors.html       # RFC 3161 anchor list
│   │       ├── settings.html      # System configuration viewer
│   │       ├── setup.html         # Installation wizard
│   │       └── partials/          # Reusable template fragments
│   │           ├── navbar.html
│   │           ├── lang_switcher.html
│   │           └── status_badge.html
│   ├── connector/
│   │   └── archivematica_client.py # amclient-based SS connector
│   └── locale/                    # Translation files (.po/.mo)
│       ├── en/LC_MESSAGES/
│       ├── es/LC_MESSAGES/
│       └── pt/LC_MESSAGES/
└── tests/                         # Test suite
    ├── conftest.py                # Fixtures (SQLite in-memory, test client)
    ├── fixtures/                  # Test BagIt packages
    ├── test_api_aips.py
    ├── test_api_audit.py
    ├── test_auto_repair.py
    ├── test_chain_verifier.py
    ├── test_fixity_verifier.py
    ├── test_hmac_authenticator.py
    └── test_merkle_tree.py
```

---

## Docker Deployment

### Services (docker-compose.yml)

| Service | Image | Resources | Purpose |
|---------|-------|-----------|---------|
| `guardian-web` | Custom (Python 3.12-slim) | 1G RAM / 2 CPU | FastAPI ASGI app (uvicorn, 4 workers) |
| `guardian-worker` | Custom (Python 3.12-slim) | 2G RAM / 2 CPU | Celery worker (configurable concurrency) |
| `guardian-beat` | Custom (Python 3.12-slim) | 256M RAM / 0.5 CPU | Celery Beat scheduler |
| `guardian-db` | postgres:16-alpine | 1G RAM / 1 CPU | PostgreSQL database |
| `guardian-redis` | redis:7-alpine | 512M RAM / 0.5 CPU | Celery broker + result backend (AOF persistence) |

### Volumes

| Volume | Purpose |
|--------|---------|
| `guardian-pgdata` | PostgreSQL data persistence |
| `guardian-redis-data` | Redis AOF persistence |
| `archivematica-storage` | External volume — Archivematica AIP storage (read-only mount) |

### Docker Entrypoint (scripts/docker-entrypoint.sh)

Runs automatically on container start:
1. Generates HMAC key if the configured key file doesn't exist (writable dirs only)
2. Runs `alembic upgrade head` (graceful failure — warns but doesn't crash)
3. Compiles translations (`pybabel compile`)
4. Executes the container's CMD

### Healthchecks

- **guardian-web**: `curl -f http://localhost:8001/api/v1/health` (30s interval, 45s start period)
- **guardian-db**: `pg_isready -U guardian` (10s interval)
- **guardian-redis**: `redis-cli ping` (10s interval)

---

## CI/CD (.github/workflows/ci.yml)

Three jobs, sequential with dependencies:

1. **lint** — `ruff check src/ tests/` + `mypy src/guardian/ --ignore-missing-imports`
2. **test** — `pytest tests/ -v` with SQLite (default) + PostgreSQL service container
3. **docker** — `docker build` + verify container starts (depends on lint + test passing)

---

## API Endpoints

All API endpoints require `Authorization: Bearer <GUARDIAN_API_TOKEN>` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/aips/` | List AIPs (paginated, filterable by status) |
| GET | `/api/v1/aips/{uuid}` | AIP details with verification history |
| POST | `/api/v1/aips/register` | Register new AIP |
| POST | `/api/v1/aips/{uuid}/verify` | Trigger on-demand verification |
| GET | `/api/v1/audit/` | Paginated audit log with filters |
| GET | `/api/v1/audit/chain-status` | Hash chain integrity status |
| GET | `/api/v1/anchors/` | List RFC 3161 anchors |
| GET | `/api/v1/anchors/{id}/verify` | Verify specific anchor |
| GET | `/api/v1/dashboard/summary` | Dashboard summary metrics |
| GET | `/api/v1/health` | Health check (DB + Redis + Archivematica) |

## Dashboard Pages

All dashboard routes require session authentication (login with `GUARDIAN_API_TOKEN`).

| URL | Description |
|-----|-------------|
| `/login` | Authentication page |
| `/logout` | Clear session and redirect to login |
| `/dashboard` | Overview: stats cards, recent events, chain status, last anchor |
| `/aips` | AIP list with search, status filter, pagination (25/page) |
| `/aips/{uuid}` | AIP detail: audit events, HMAC records, repair history |
| `/audit-log` | Full audit log: filter by AIP, event type, status, date range (50/page) |
| `/anchors` | RFC 3161 timestamp anchor list |
| `/settings` | System configuration viewer (sensitive values masked) |
| `/setup` | Step-by-step installation wizard |
| `POST /set-language` | Switch UI language (EN/ES/PT) via cookie |

---

## Database Tables

| Table | Purpose |
|-------|---------|
| `aip_integrity_status` | AIP registration, storage path, verification state, file counts |
| `hmac_registry` | HMAC-SHA256 values for each manifest file |
| `aip_integrity_audit_log` | Immutable hash-chained audit trail (triggers block UPDATE/DELETE) |
| `content_fingerprint` | Content fingerprints (SHA-256 of all payload files) |
| `anchor_registry` | RFC 3161 timestamp tokens, batch hashes, Merkle roots |
| `repair_record` | Auto-repair history (source replica, repaired files, status) |

---

## Configuration Reference (.env)

### Required for Production

| Variable | Description |
|----------|-------------|
| `GUARDIAN_SECRET_KEY` | Session encryption key — `python -c "import secrets; print(secrets.token_hex(32))"` |
| `GUARDIAN_API_TOKEN` | API + dashboard authentication token |
| `POSTGRES_PASSWORD` | PostgreSQL password |

### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_DEBUG` | `false` | Enable debug mode (allows insecure defaults, enables /docs) |
| `GUARDIAN_ALLOWED_HOSTS` | `localhost,127.0.0.1` | CORS allowed origins (comma-separated) |
| `GUARDIAN_LOG_LEVEL` | `INFO` | Logging level |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://guardian:password@localhost:5432/guardian_db` | Async DB URL |
| `DB_POOL_SIZE` | `10` | SQLAlchemy connection pool size |
| `DB_MAX_OVERFLOW` | `20` | Maximum pool overflow connections |

### Celery / Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Redis broker URL |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Redis result backend |
| `CELERY_CONCURRENCY` | `4` | Worker concurrency |

### HMAC Key

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_HMAC_KEY` | *(empty)* | Direct HMAC key (development) |
| `GUARDIAN_HMAC_KEY_FILE` | *(empty)* | Path to HMAC key file (production — Docker secrets) |

### Archivematica

| Variable | Default | Description |
|----------|---------|-------------|
| `ARCHIVEMATICA_SS_URL` | `http://localhost:8000` | Storage Service URL |
| `ARCHIVEMATICA_SS_USER` | `admin` | SS API username |
| `ARCHIVEMATICA_SS_API_KEY` | *(empty)* | SS API key |
| `ARCHIVEMATICA_STORAGE_PATH` | `/var/archivematica/sharedDirectory` | AIP storage root |

### RFC 3161 Timestamping

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_TSA_URL` | `https://freetsa.org/tsr` | Primary TSA endpoint |
| `GUARDIAN_TSA_FALLBACK_URL` | `https://timestamp.digicert.com` | Fallback TSA endpoint |

### Notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_ADMIN_EMAIL` | *(empty)* | Admin email for alerts |
| `GUARDIAN_SMTP_HOST` | `localhost` | SMTP server |
| `GUARDIAN_SMTP_PORT` | `587` | SMTP port |
| `GUARDIAN_SMTP_USER` | *(empty)* | SMTP username (enables STARTTLS when set) |
| `GUARDIAN_SMTP_PASSWORD` | *(empty)* | SMTP password |
| `GUARDIAN_WEBHOOK_URL` | *(empty)* | Webhook URL for JSON event notifications |

---

## Notification System

When corruption is detected or repair completes, notifications are sent via **all configured channels**:

### Email (SMTP)
- Plain-text emails with subject prefixed by `[AIP Guardian]`
- STARTTLS enabled when SMTP credentials are configured
- Event types: `CORRUPTION DETECTED`, `Repair SUCCESS`, `Repair FAILED`, `ALL REPLICAS CORRUPTED` (critical)

### Webhook
- JSON POST to configured URL with 15-second timeout
- Payload includes: `event`, `aip_uuid`, `subject`, `details`
- Compatible with Slack, Discord, PagerDuty, and custom integrations

---

## Quick Start — Docker (Recommended)

### Prerequisites
- Docker Desktop with Docker Compose v2

### Steps

```bash
# 1. Clone and enter directory
git clone https://github.com/marcossigismundo/aip-guardian.git
cd aip-guardian

# 2. Generate HMAC key
mkdir secrets
python -c "import os; open('secrets/hmac.key','wb').write(os.urandom(32))"

# 3. Create .env from template and edit with secure values
cp .env.example .env
# MUST change: GUARDIAN_SECRET_KEY, GUARDIAN_API_TOKEN, POSTGRES_PASSWORD

# 4. Create external volume for Archivematica storage
docker volume create archivematica-storage

# 5. Build and start
docker compose up -d --build

# 6. Verify
# Dashboard:    http://localhost:8001/dashboard (login with GUARDIAN_API_TOKEN)
# API docs:     http://localhost:8001/docs (debug mode only)
# Health:       http://localhost:8001/api/v1/health
```

### Register Existing AIPs

```bash
# Dry run first
docker compose exec guardian-web python scripts/register_existing_aips.py --dry-run

# Actual registration
docker compose exec guardian-web python scripts/register_existing_aips.py
```

---

## Quick Start — Local Development

```bash
# 1. Create virtualenv
python -m venv .venv
.venv\Scripts\activate       # Windows
source .venv/bin/activate    # Linux/Mac

# 2. Install with dev dependencies
pip install -e ".[dev]"

# 3. Configure
cp .env.example .env
# Edit .env with local PostgreSQL and Redis URLs

# 4. Run migrations
alembic upgrade head

# 5. Start services (3 terminals)
uvicorn guardian.main:app --host 0.0.0.0 --port 8001 --reload
celery -A guardian.celery_app:celery worker --loglevel=info
celery -A guardian.celery_app:celery beat --loglevel=info
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v                                          # SQLite in-memory (default)
pytest tests/ -v --cov=src/guardian --cov-report=html     # With coverage report

# PostgreSQL tests
TEST_DATABASE_URL="postgresql+asyncpg://guardian:pass@localhost:5432/guardian_test" \
  pytest tests/ -v -m "not slow"
```

---

## Key Design Decisions

1. **Hash chain deduplication**: Single `hash_utils.compute_record_hash()` used by both `AuditLogger` and `ChainVerifier` — prevents formula drift
2. **Timing-safe comparisons**: All secret/hash comparisons use `hmac.compare_digest()` — prevents timing attacks
3. **Celery task retries**: All tasks use `bind=True, max_retries=3` with exponential countdown (60–300 seconds)
4. **Sync engine for Celery**: Workers use synchronous SQLAlchemy sessions (`create_engine` + `Session`) since Celery doesn't support asyncio natively
5. **Fan-out pattern**: `verify_all_aips` dispatches individual `verify_single_aip` tasks for parallel execution across workers
6. **No Archivematica modification**: Integration via API + hooks only — no patching of Archivematica source code

---

## Release v1.0.0

GitHub Release: https://github.com/marcossigismundo/aip-guardian/releases/tag/v1.0.0

The release archive (`aip-guardian-v1.0.0-production.tar.gz`) contains only production-necessary files:
- `src/` — Full application source
- `alembic/` — Database migrations
- `scripts/` — Entrypoint, setup wizard, health check, HMAC key generator
- `Dockerfile` & `docker-compose.yml` — Container deployment
- `pyproject.toml` & `requirements.txt` — Dependencies
- `.env.example` — Configuration template
- `INSTALL.md` — Complete installation guide

Excludes: tests, CI config, IDE files, development tools.
