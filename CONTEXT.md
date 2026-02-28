# AIP Integrity Guardian — Project Context

## Purpose

AIP Integrity Guardian is a standalone service that complements Archivematica with
continuous integrity verification for AIP (Archival Information Package) storage.
It addresses critical gaps in Archivematica's post-storage integrity monitoring,
raising ISO 16363 compliance from ~48% to ~89%.

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
| 3 | Audit Log | §4.3.2.1 | Immutable hash-chained log in PostgreSQL (append-only) |
| 4 | Change Detector | §4.3.1 | Content fingerprinting to prevent unnecessary re-ingestion |
| 5 | Auto-Repair | §4.3.4 | Automatic recovery from replicas when corruption is detected |
| 6 | External Anchor | §5.2.2 | RFC 3161 timestamps + Merkle trees for external trust |

## Tech Stack

- **Python 3.12+** / FastAPI / SQLAlchemy 2.0 (async) / Pydantic v2
- **PostgreSQL 16** with immutability triggers
- **Celery 5.x + Redis 7** for async task processing
- **Jinja2 + Tailwind CSS + Alpine.js** for the dashboard UI
- **Docker Compose** for deployment (5 services)
- **Bilingual UI**: English + Spanish (Babel/gettext)

## Standards Compliance

- **OAIS ISO 14721:2012** — Open Archival Information System reference model
- **ISO 16363:2025** — Audit and certification of trustworthy digital repositories
- **RFC 8493** — BagIt File Packaging Format
- **RFC 2104** — HMAC: Keyed-Hashing for Message Authentication
- **RFC 3161** — Internet X.509 PKI Time-Stamp Protocol
- **PREMIS 3.0** — Preservation Metadata Implementation Strategies

## Integration

Connects to Archivematica via 4 extension points (no source code modification):

1. **Post-store callback** — automation-tools hook registers new AIPs
2. **Storage Service API** — lists and accesses AIP packages
3. **Celery Beat** — scheduled verification, anchoring, chain audits
4. **REST API + Dashboard** — management interface

## Project Structure

```
aip-guardian/
├── CONTEXT.md                     # This file
├── pyproject.toml                 # Python dependencies (PEP 621)
├── Dockerfile                     # Multi-stage build (Python 3.12-slim)
├── docker-compose.yml             # 5 services: web, worker, beat, db, redis
├── .env.example                   # Environment template
├── alembic.ini                    # Migration config
├── alembic/
│   └── versions/001_initial_schema.py   # 6 tables + immutability triggers
├── src/guardian/
│   ├── main.py                    # FastAPI app factory
│   ├── config.py                  # Pydantic Settings
│   ├── database.py                # SQLAlchemy async engine
│   ├── celery_app.py              # Celery + Beat schedule
│   ├── i18n.py                    # Babel/gettext (EN + ES)
│   ├── models/                    # 6 SQLAlchemy ORM models
│   ├── schemas/                   # Pydantic v2 request/response schemas
│   ├── services/                  # 12 service modules (business logic)
│   ├── tasks/                     # 4 Celery task modules
│   ├── api/                       # 10 REST API endpoints
│   ├── web/                       # Dashboard UI (Jinja2 templates)
│   ├── connector/                 # Archivematica client
│   └── locale/                    # .po/.mo translation files
├── scripts/
│   ├── setup_wizard.py            # Interactive setup
│   ├── generate_hmac_key.py       # HMAC key generation
│   ├── register_existing_aips.py  # Batch AIP registration
│   ├── post_store_hook.py         # Archivematica automation-tools hook
│   └── health_check.py            # Standalone health check
└── tests/                         # 50+ test cases with BagIt fixtures
```

## Repository

- **GitHub**: https://github.com/marcossigismundo/aip-guardian
- **Branch**: `master`
- **Location**: `C:\Users\marco\aip-guardian\`

## Quick Start — Docker (Recommended)

### Prerequisites
- Docker Desktop with Docker Compose v2
- No Archivematica needed for initial testing (uses mock data)

### Step 1: Generate HMAC key
```bash
cd C:\Users\marco\aip-guardian
mkdir secrets
python -c "import os; open('secrets/hmac.key','wb').write(os.urandom(32))"
```

### Step 2: Create .env from template
```bash
copy .env.example .env
```
Edit `.env` — the defaults work for Docker testing (PostgreSQL/Redis are inside Docker).

### Step 3: Create the external volume (one time)
```bash
docker volume create archivematica-storage
```

### Step 4: Build and start
```bash
docker compose up -d --build
```
This starts 5 containers: `guardian-web`, `guardian-worker`, `guardian-beat`, `guardian-db`, `guardian-redis`.

### Step 5: Run database migrations
```bash
docker compose exec guardian-web alembic upgrade head
```

### Step 6: Verify
- **Dashboard**: http://localhost:8001/
- **API Swagger docs**: http://localhost:8001/docs
- **ReDoc**: http://localhost:8001/redoc
- **Health check**: http://localhost:8001/api/v1/health

### Step 7: Test the API
```bash
# Register a test AIP
curl -X POST http://localhost:8001/api/v1/aips/register \
  -H "Content-Type: application/json" \
  -d '{"archivematica_uuid":"11111111-1111-1111-1111-111111111111","storage_path":"/tmp/test-aip","storage_location":"local"}'

# List AIPs
curl http://localhost:8001/api/v1/aips/

# Dashboard summary
curl http://localhost:8001/api/v1/dashboard/summary
```

## Quick Start — Local Development (No Docker)

### Prerequisites
- Python 3.12+
- PostgreSQL 16 running locally
- Redis 7 running locally

### Step 1: Create virtualenv and install
```bash
cd C:\Users\marco\aip-guardian
python -m venv .venv
.venv\Scripts\activate       # Windows
pip install -e ".[dev]"
```

### Step 2: Configure
```bash
copy .env.example .env
# Edit .env with your local PostgreSQL and Redis URLs
```

### Step 3: Run migrations
```bash
alembic upgrade head
```

### Step 4: Start FastAPI
```bash
uvicorn guardian.main:app --host 0.0.0.0 --port 8001 --reload
```

### Step 5: Start Celery worker (separate terminal)
```bash
celery -A guardian.celery_app:celery worker --loglevel=info
```

### Step 6: Start Celery Beat (separate terminal)
```bash
celery -A guardian.celery_app:celery beat --loglevel=info
```

## Running Tests

```bash
cd C:\Users\marco\aip-guardian
pip install -e ".[dev]"
pytest tests/ -v
pytest tests/ -v --cov=src/guardian --cov-report=html  # with coverage
```

Tests use SQLite in-memory by default (via `aiosqlite`). Set `TEST_DATABASE_URL` for PostgreSQL.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/aips/` | List AIPs (paginated, filterable) |
| GET | `/api/v1/aips/{uuid}` | AIP details |
| POST | `/api/v1/aips/register` | Register new AIP |
| POST | `/api/v1/aips/{uuid}/verify` | Trigger verification |
| GET | `/api/v1/audit/` | Paginated audit log |
| GET | `/api/v1/audit/chain-status` | Hash chain integrity |
| GET | `/api/v1/anchors/` | External anchors |
| GET | `/api/v1/anchors/{id}/verify` | Verify anchor |
| GET | `/api/v1/dashboard/summary` | Dashboard metrics |
| GET | `/api/v1/health` | Health check |

## Dashboard Pages

| URL | Description |
|-----|-------------|
| `/dashboard` | Main overview with stats cards and recent events |
| `/aips` | AIP list with search, filters, pagination |
| `/aips/{uuid}` | AIP detail with verification history, HMAC, repairs |
| `/audit-log` | Full audit log with filters |
| `/anchors` | RFC 3161 timestamp anchors |
| `/settings` | System configuration viewer |
| `/setup` | Step-by-step installation wizard |

## Database Tables

1. `aip_integrity_status` — AIP registration and verification state
2. `hmac_registry` — HMAC-SHA256 values for manifest authentication
3. `aip_integrity_audit_log` — Immutable hash-chained audit trail (UPDATE/DELETE trigger blocked)
4. `content_fingerprint` — Content fingerprints for change detection
5. `anchor_registry` — RFC 3161 timestamp tokens and Merkle roots
6. `repair_record` — Auto-repair history

## Celery Scheduled Tasks

| Task | Schedule | Description |
|------|----------|-------------|
| `verify_all_aips` | Weekly (Sun 02:00) | Fan-out fixity checks |
| `submit_daily_anchor` | Daily (23:00) | RFC 3161 batch anchoring |
| `verify_audit_chain` | Weekly (Mon 03:00) | Hash chain integrity |

## References

- `docs/metodologia-verificacao-aip-archivematica.md` — Full methodology document
- `docs/guia-desenvolvimento-aip-guardian.md` — Developer implementation guide
