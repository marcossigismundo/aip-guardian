# AIP Integrity Guardian — Installation Manual

Complete guide to install, configure, and deploy the AIP Integrity Guardian
in a production environment.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start (Docker)](#2-quick-start-docker)
3. [Step-by-Step Production Deployment](#3-step-by-step-production-deployment)
4. [Local Development Setup](#4-local-development-setup)
5. [Configuration Reference](#5-configuration-reference)
6. [Archivematica Integration](#6-archivematica-integration)
7. [Backup & Restore](#7-backup--restore)
8. [Monitoring & Troubleshooting](#8-monitoring--troubleshooting)
9. [Updating](#9-updating)
10. [Security Checklist](#10-security-checklist)

---

## 1. Prerequisites

### System Requirements

| Component      | Minimum          | Recommended       |
|----------------|------------------|--------------------|
| CPU            | 2 cores          | 4+ cores           |
| RAM            | 4 GB             | 8+ GB              |
| Disk           | 20 GB            | 50+ GB (SSD)       |
| OS             | Linux (x86_64)   | Ubuntu 22.04+ LTS  |
| Docker         | 24.0+            | Latest stable       |
| Docker Compose | v2.20+           | Latest stable       |

### Software Requirements

- **Docker** and **Docker Compose** (for containerized deployment)
- **Python 3.12+** (for local development only)
- **PostgreSQL 16+** (included in Docker Compose)
- **Redis 7+** (included in Docker Compose)
- **Archivematica** with Storage Service accessible via API

### Network Requirements

- Port **8001** (Guardian web UI and API)
- Port **5432** (PostgreSQL, internal only)
- Port **6379** (Redis, internal only)
- Outbound HTTPS to RFC 3161 TSA servers (freetsa.org, digicert.com)
- Network access to Archivematica Storage Service API

---

## 2. Quick Start (Docker)

The fastest way to get Guardian running for evaluation:

```bash
# 1. Clone the repository
git clone https://github.com/marcossigismundo/aip-guardian.git
cd aip-guardian

# 2. Copy and edit environment file
cp .env.example .env

# 3. Generate required secrets
python -c "import secrets; print('GUARDIAN_SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('GUARDIAN_API_TOKEN=' + secrets.token_hex(32))"
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(16))"
# Copy the output values into your .env file

# 4. Generate HMAC key
mkdir -p secrets
python -c "import secrets; open('secrets/hmac.key', 'wb').write(secrets.token_bytes(32))"

# 5. Create the external volume for Archivematica storage
docker volume create archivematica-storage

# 6. Build and start
docker compose up -d --build

# 7. Check health
curl http://localhost:8001/api/v1/health
```

The dashboard is available at **http://localhost:8001**. Log in with your
`GUARDIAN_API_TOKEN` value.

---

## 3. Step-by-Step Production Deployment

### 3.1 Clone the Repository

```bash
git clone https://github.com/marcossigismundo/aip-guardian.git
cd aip-guardian
```

### 3.2 Generate Secrets

Generate all required secrets. Never reuse values between environments.

```bash
# Generate secret key (session encryption)
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate API token (API + dashboard authentication)
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate database password
python3 -c "import secrets; print(secrets.token_hex(16))"

# Generate HMAC key file (manifest authentication)
mkdir -p secrets
python3 -c "import secrets; open('secrets/hmac.key', 'wb').write(secrets.token_bytes(32))"
chmod 600 secrets/hmac.key
```

### 3.3 Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your production values:

```bash
# REQUIRED — must be changed from defaults
GUARDIAN_SECRET_KEY=<your-generated-secret-key>
GUARDIAN_API_TOKEN=<your-generated-api-token>
POSTGRES_PASSWORD=<your-generated-db-password>

# REQUIRED — disable debug mode for production
GUARDIAN_DEBUG=false

# REQUIRED — set your server hostname(s)
GUARDIAN_ALLOWED_HOSTS=guardian.yourdomain.com,localhost

# RECOMMENDED — Archivematica connection
ARCHIVEMATICA_SS_URL=http://your-archivematica-host:8000
ARCHIVEMATICA_SS_USER=admin
ARCHIVEMATICA_SS_API_KEY=<your-archivematica-api-key>
ARCHIVEMATICA_STORAGE_PATH=/var/archivematica/sharedDirectory

# RECOMMENDED — notification email
GUARDIAN_ADMIN_EMAIL=admin@yourdomain.com
GUARDIAN_SMTP_HOST=smtp.yourdomain.com
GUARDIAN_SMTP_PORT=587
GUARDIAN_SMTP_USER=guardian@yourdomain.com
GUARDIAN_SMTP_PASSWORD=<smtp-password>
```

### 3.4 Create External Volume

The Archivematica shared directory must be accessible as a Docker volume:

```bash
# Option A: Create a named volume pointing to existing directory
docker volume create \
  --driver local \
  --opt type=none \
  --opt device=/var/archivematica/sharedDirectory \
  --opt o=bind \
  archivematica-storage

# Option B: If Archivematica runs on a remote server via NFS
docker volume create \
  --driver local \
  --opt type=nfs \
  --opt o=addr=nfs-server.local,rw \
  --opt device=:/exports/archivematica \
  archivematica-storage
```

### 3.5 Build and Deploy

```bash
# Build all containers
docker compose build

# Start services (detached)
docker compose up -d

# Watch logs during first startup
docker compose logs -f guardian-web
```

### 3.6 Verify Deployment

```bash
# Check all services are running
docker compose ps

# Test health endpoint
curl -s http://localhost:8001/api/v1/health | python3 -m json.tool

# Test API authentication
curl -s -H "Authorization: Bearer <your-api-token>" \
  http://localhost:8001/api/v1/aips/ | python3 -m json.tool

# Check database migrations were applied
docker compose exec guardian-web alembic current
```

### 3.7 Register Existing AIPs

If you have existing AIPs in Archivematica, register them:

```bash
# Via the provided script
docker compose exec guardian-web \
  python -m scripts.register_existing_aips

# Or via API
curl -X POST http://localhost:8001/api/v1/aips/register \
  -H "Authorization: Bearer <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "archivematica_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "storage_path": "/var/archivematica/sharedDirectory/xxxx/...",
    "storage_location": "default"
  }'
```

### 3.8 Set Up Reverse Proxy (Recommended)

For production, place Guardian behind a reverse proxy with TLS:

**Nginx example:**

```nginx
server {
    listen 443 ssl;
    server_name guardian.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/guardian.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/guardian.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 4. Local Development Setup

```bash
# 1. Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# 2. Install with dev dependencies
pip install -e ".[dev]"

# 3. Copy environment file
cp .env.example .env
# Edit .env — keep GUARDIAN_DEBUG=true for development

# 4. Start PostgreSQL and Redis (Docker)
docker compose up -d guardian-db guardian-redis

# 5. Run database migrations
alembic upgrade head

# 6. Start the application
uvicorn guardian.main:app --reload --port 8001

# 7. Start Celery worker (separate terminal)
celery -A guardian.celery_app:celery worker --loglevel=info

# 8. Start Celery Beat (separate terminal)
celery -A guardian.celery_app:celery beat --loglevel=info

# 9. Run tests
pytest tests/ -v

# 10. Run tests with coverage
pytest tests/ -v --cov=src/guardian --cov-report=html
```

---

## 5. Configuration Reference

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GUARDIAN_SECRET_KEY` | Session encryption key (hex, 32+ bytes) | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `GUARDIAN_API_TOKEN` | API and dashboard authentication token | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `POSTGRES_PASSWORD` | PostgreSQL database password | Strong random string |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://guardian:pass@host:5432/guardian_db` |

### HMAC Configuration (choose one)

| Variable | Description |
|----------|-------------|
| `GUARDIAN_HMAC_KEY` | Direct HMAC key (hex string, dev only) |
| `GUARDIAN_HMAC_KEY_FILE` | Path to HMAC key file (production recommended) |

### Archivematica Integration

| Variable | Description | Default |
|----------|-------------|---------|
| `ARCHIVEMATICA_SS_URL` | Storage Service base URL | `http://localhost:8000` |
| `ARCHIVEMATICA_SS_USER` | Storage Service username | `admin` |
| `ARCHIVEMATICA_SS_API_KEY` | Storage Service API key | (empty) |
| `ARCHIVEMATICA_STORAGE_PATH` | AIP storage mount point | `/var/archivematica/sharedDirectory` |

### Performance Tuning

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_POOL_SIZE` | SQLAlchemy connection pool size | `10` |
| `DB_MAX_OVERFLOW` | Max extra connections beyond pool | `20` |
| `CELERY_CONCURRENCY` | Celery worker processes | `4` |

### Notifications

| Variable | Description |
|----------|-------------|
| `GUARDIAN_ADMIN_EMAIL` | Email for alerts |
| `GUARDIAN_SMTP_HOST` | SMTP server hostname |
| `GUARDIAN_SMTP_PORT` | SMTP port (587 for STARTTLS) |
| `GUARDIAN_SMTP_USER` | SMTP authentication user |
| `GUARDIAN_SMTP_PASSWORD` | SMTP authentication password |
| `GUARDIAN_WEBHOOK_URL` | Webhook URL for notifications |

### Scheduled Tasks

| Task | Default Schedule | Description |
|------|------------------|-------------|
| Fixity verification | Sunday 02:00 UTC | Full AIP integrity check |
| Health check | Daily 06:00 UTC | System dependencies check |
| RFC 3161 anchoring | Daily 23:00 UTC | Audit log external timestamping |
| Chain verification | Monday 03:00 UTC | Hash chain integrity check |

---

## 6. Archivematica Integration

Guardian integrates with Archivematica via four extension points — no
source code modifications are required.

### 6.1 Post-Store Hook (Automatic AIP Registration)

Configure Archivematica's automation-tools to call Guardian when a new AIP
is stored:

```bash
# Copy the hook script to your automation-tools directory
cp scripts/post_store_hook.py /path/to/automation-tools/hooks/

# Configure the hook environment
export GUARDIAN_API_URL=http://guardian-host:8001
export GUARDIAN_API_TOKEN=<your-api-token>
```

### 6.2 Storage Access

Guardian needs read-only access to the Archivematica shared directory.
This is configured via the Docker volume mount:

```yaml
# docker-compose.yml (already configured)
volumes:
  - archivematica-storage:/var/archivematica/sharedDirectory:ro
```

### 6.3 Storage Service API

Guardian queries the Storage Service API for AIP metadata and replica
locations. Ensure the API credentials have read access:

```bash
ARCHIVEMATICA_SS_URL=http://archivematica-storage-service:8000
ARCHIVEMATICA_SS_USER=admin
ARCHIVEMATICA_SS_API_KEY=<api-key-from-storage-service>
```

---

## 7. Backup & Restore

### 7.1 Database Backup

```bash
# Create a backup
docker compose exec guardian-db \
  pg_dump -U guardian -d guardian_db -Fc -f /tmp/guardian_backup.dump

# Copy backup from container
docker cp guardian-db:/tmp/guardian_backup.dump ./backups/

# Automated daily backup (add to crontab)
0 1 * * * docker compose exec -T guardian-db pg_dump -U guardian -d guardian_db -Fc > /backups/guardian_$(date +\%Y\%m\%d).dump
```

### 7.2 Database Restore

```bash
# Stop the application
docker compose stop guardian-web guardian-worker guardian-beat

# Restore from backup
docker cp ./backups/guardian_backup.dump guardian-db:/tmp/
docker compose exec guardian-db \
  pg_restore -U guardian -d guardian_db -c /tmp/guardian_backup.dump

# Restart services
docker compose start guardian-web guardian-worker guardian-beat
```

### 7.3 HMAC Key Backup

The HMAC key is critical — if lost, all HMAC signatures become
unverifiable. Store it securely:

```bash
# Backup
cp secrets/hmac.key /secure-backup-location/guardian-hmac.key

# Restore
cp /secure-backup-location/guardian-hmac.key secrets/hmac.key
chmod 600 secrets/hmac.key
```

### 7.4 Full System Backup Checklist

- [ ] PostgreSQL database dump
- [ ] `secrets/hmac.key` file
- [ ] `.env` file (contains all configuration)
- [ ] Docker volumes: `guardian-pgdata`, `guardian-redis-data`

---

## 8. Monitoring & Troubleshooting

### 8.1 Health Check

```bash
# Quick health check
curl -s http://localhost:8001/api/v1/health | python3 -m json.tool

# Response example:
# {
#   "status": "healthy",        # healthy | degraded | unhealthy
#   "version": "1.0.0",
#   "database": true,
#   "redis": true,
#   "celery": true,
#   "archivematica": true
# }
```

### 8.2 Viewing Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f guardian-web
docker compose logs -f guardian-worker

# Last 100 lines
docker compose logs --tail=100 guardian-web
```

### 8.3 Common Issues

#### Application won't start: "STARTUP BLOCKED: Insecure default secrets"

**Cause:** Production secrets have not been set.
**Fix:** Set `GUARDIAN_SECRET_KEY` and `GUARDIAN_API_TOKEN` in `.env` with
strong random values. Or set `GUARDIAN_DEBUG=true` for development.

#### Health check shows "unhealthy"

**Cause:** One or more dependencies are down.
**Fix:** Check individual services:
```bash
docker compose ps                    # Are all containers running?
docker compose logs guardian-db      # PostgreSQL issues?
docker compose logs guardian-redis   # Redis issues?
```

#### Celery tasks not running

**Cause:** Worker or Beat is not processing.
**Fix:**
```bash
docker compose logs guardian-worker  # Check for errors
docker compose logs guardian-beat    # Check Beat is scheduling
docker compose restart guardian-worker guardian-beat
```

#### "Volume archivematica-storage not found"

**Cause:** External volume not created.
**Fix:**
```bash
docker volume create archivematica-storage
```

#### HMAC key file not found

**Cause:** `secrets/hmac.key` does not exist.
**Fix:**
```bash
mkdir -p secrets
python3 -c "import secrets; open('secrets/hmac.key', 'wb').write(secrets.token_bytes(32))"
chmod 600 secrets/hmac.key
```

#### Database migration errors

**Fix:** Run migrations manually:
```bash
docker compose exec guardian-web alembic upgrade head
```

### 8.4 Dashboard Access

The web dashboard is at **http://your-host:8001/dashboard**.
Login with your `GUARDIAN_API_TOKEN` value.

**Dashboard pages:**
- `/dashboard` — System overview, status counts, recent events
- `/aips` — AIP list with search and filtering
- `/aips/<uuid>` — AIP detail with audit history
- `/audit-log` — Full audit log browser
- `/anchors` — RFC 3161 timestamp anchors
- `/settings` — System configuration (masked credentials)

---

## 9. Updating

### 9.1 Standard Update

```bash
# Pull latest code
git pull origin master

# Rebuild containers
docker compose build

# Apply database migrations
docker compose run --rm guardian-web alembic upgrade head

# Restart all services
docker compose up -d
```

### 9.2 Zero-Downtime Update (if using load balancer)

```bash
# Build new image
docker compose build

# Scale up new workers
docker compose up -d --no-deps --scale guardian-worker=2 guardian-worker

# Apply migrations
docker compose run --rm guardian-web alembic upgrade head

# Update web service
docker compose up -d --no-deps guardian-web

# Scale back to 1 worker
docker compose up -d --no-deps --scale guardian-worker=1 guardian-worker
```

---

## 10. Security Checklist

Before deploying to production, verify all items:

### Secrets
- [ ] `GUARDIAN_SECRET_KEY` is a unique random hex string (64+ chars)
- [ ] `GUARDIAN_API_TOKEN` is a unique random hex string (64+ chars)
- [ ] `POSTGRES_PASSWORD` is a strong random password
- [ ] `secrets/hmac.key` exists and has permissions `0600`
- [ ] `GUARDIAN_DEBUG` is set to `false`

### Network
- [ ] Guardian runs behind a TLS reverse proxy (nginx/traefik)
- [ ] PostgreSQL (5432) is NOT exposed to the internet
- [ ] Redis (6379) is NOT exposed to the internet
- [ ] Only port 8001 (or proxy port 443) is publicly accessible

### Access Control
- [ ] Dashboard requires authentication (login page)
- [ ] API requires Bearer token for all endpoints (except /health)
- [ ] Archivematica API key has minimal required permissions

### Monitoring
- [ ] Health check endpoint is monitored (uptime service)
- [ ] Admin email is configured for corruption alerts
- [ ] Log aggregation is configured (ELK/Grafana/CloudWatch)
- [ ] Database backups are automated and tested

### ISO 16363 Compliance
- [ ] Audit log immutability trigger is active (PostgreSQL)
- [ ] Hash chain verification runs weekly (Celery Beat)
- [ ] RFC 3161 anchoring runs daily (external timestamping)
- [ ] HMAC key is stored securely (file or Docker secret)
- [ ] Auto-repair is configured with valid replica locations

---

## API Quick Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/health` | No | System health check |
| GET | `/api/v1/aips/` | Yes | List AIPs (paginated) |
| GET | `/api/v1/aips/{uuid}` | Yes | AIP detail |
| POST | `/api/v1/aips/register` | Yes | Register new AIP |
| POST | `/api/v1/aips/{uuid}/verify` | Yes | Trigger fixity check |
| GET | `/api/v1/audit/` | Yes | Audit log (paginated) |
| GET | `/api/v1/audit/chain-status` | Yes | Hash chain status |
| GET | `/api/v1/anchors/` | Yes | RFC 3161 anchors |
| GET | `/api/v1/anchors/{id}/verify` | Yes | Verify anchor |
| GET | `/api/v1/dashboard/summary` | Yes | Dashboard summary |

**Authentication:** `Authorization: Bearer <GUARDIAN_API_TOKEN>`

---

## Support

- **Issues:** https://github.com/marcossigismundo/aip-guardian/issues
- **License:** AGPL-3.0-or-later
- **Author:** Tainacan (dev@tainacan.org)
