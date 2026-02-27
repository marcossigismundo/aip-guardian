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

## References

- `docs/metodologia-verificacao-aip-archivematica.md` — Full methodology document
- `docs/guia-desenvolvimento-aip-guardian.md` — Developer implementation guide
