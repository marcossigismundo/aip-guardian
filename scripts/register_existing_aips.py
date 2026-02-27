#!/usr/bin/env python3
"""Register existing Archivematica AIPs in AIP Integrity Guardian.

This CLI script connects to the Archivematica Storage Service, enumerates
all AIPs, and registers any that are not yet tracked by Guardian.  For each
newly registered AIP it computes HMAC signatures and a content fingerprint,
and creates an audit-log entry.

Usage:
    python scripts/register_existing_aips.py --dry-run
    python scripts/register_existing_aips.py --batch-size 100
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project source is importable
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from guardian.config import get_settings
from guardian.connector.archivematica_client import ArchivematicaConnector
from guardian.models.aip_status import AIPStatus
from guardian.models.audit_log import AuditLog
from guardian.models.base import Base
from guardian.services.audit_logger import AuditLogger
from guardian.services.hmac_authenticator import ManifestAuthenticator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _progress_bar(current: int, total: int, width: int = 40) -> str:
    """Return a simple text progress bar."""
    if total == 0:
        return "[" + "=" * width + "] 100%"
    pct = current / total
    filled = int(width * pct)
    bar = "=" * filled + "-" * (width - filled)
    return f"[{bar}] {pct:6.1%}  ({current}/{total})"


def _compute_fingerprint(aip_path: str) -> str:
    """Compute a content fingerprint for an AIP by hashing all payload files."""
    bag_root = Path(aip_path)
    data_dir = bag_root / "data"
    if not data_dir.is_dir():
        return ""

    hasher = hashlib.sha256()
    file_count = 0
    for filepath in sorted(data_dir.rglob("*")):
        if filepath.is_file():
            file_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
            hasher.update(f"{filepath.relative_to(bag_root)}:{file_hash}\n".encode())
            file_count += 1

    return hasher.hexdigest() if file_count > 0 else ""


def register_aips(
    dry_run: bool = False,
    batch_size: int = 50,
) -> dict[str, int]:
    """Main registration workflow.

    Returns
    -------
    dict
        Summary counts: ``registered``, ``already_existed``, ``errors``.
    """
    settings = get_settings()
    connector = ArchivematicaConnector(settings)

    logger.info("Connecting to Archivematica Storage Service at %s ...", settings.archivematica_ss_url)
    all_aips = connector.list_all_aips()
    logger.info("Found %d AIP(s) in the Storage Service.", len(all_aips))

    if not all_aips:
        logger.warning("No AIPs found. Nothing to register.")
        return {"registered": 0, "already_existed": 0, "errors": 0}

    # Create a sync engine for direct DB access.
    sync_url = settings.sync_database_url
    engine = create_engine(sync_url, pool_pre_ping=True)

    registered = 0
    already_existed = 0
    errors = 0

    try:
        hmac_auth = ManifestAuthenticator()
    except RuntimeError:
        logger.warning("HMAC key not available — HMAC registration will be skipped.")
        hmac_auth = None

    with Session(engine) as session:
        for idx, aip_info in enumerate(all_aips):
            # Progress output
            sys.stdout.write(f"\r  {_progress_bar(idx + 1, len(all_aips))}")
            sys.stdout.flush()

            am_uuid_str = aip_info.get("uuid", "")
            if not am_uuid_str:
                logger.warning("AIP entry missing UUID — skipping: %s", aip_info)
                errors += 1
                continue

            try:
                am_uuid = uuid.UUID(am_uuid_str)
            except ValueError:
                logger.warning("Invalid UUID format '%s' — skipping.", am_uuid_str)
                errors += 1
                continue

            # Check if already registered.
            exists = session.execute(
                select(AIPStatus).where(AIPStatus.archivematica_uuid == am_uuid)
            ).scalar_one_or_none()

            if exists is not None:
                already_existed += 1
                continue

            if dry_run:
                logger.info("[DRY RUN] Would register AIP %s", am_uuid_str)
                registered += 1
                continue

            try:
                aip_path = connector.get_aip_path(am_uuid_str)
                storage_location = aip_info.get("current_location", "")

                # Count payload files.
                data_dir = Path(aip_path) / "data"
                total_files = sum(1 for f in data_dir.rglob("*") if f.is_file()) if data_dir.is_dir() else 0

                # Compute content fingerprint.
                fingerprint = _compute_fingerprint(aip_path)

                aip = AIPStatus(
                    aip_uuid=uuid.uuid4(),
                    archivematica_uuid=am_uuid,
                    storage_path=aip_path,
                    storage_location=storage_location,
                    last_status="pending",
                    content_fingerprint=fingerprint,
                    total_files=total_files,
                )
                session.add(aip)
                session.flush()

                # Register HMAC records.
                if hmac_auth is not None:
                    try:
                        hmac_auth.register_aip(session, str(aip.aip_uuid), aip_path)
                    except Exception:
                        logger.exception("Failed to register HMAC for AIP %s", am_uuid_str)

                # Create audit-log entry.
                try:
                    AuditLogger.log(
                        session,
                        aip_uuid=str(aip.aip_uuid),
                        event_type="aip_registered",
                        status="pass",
                        details={
                            "archivematica_uuid": am_uuid_str,
                            "storage_path": aip_path,
                            "method": "bulk_registration",
                        },
                    )
                except Exception:
                    logger.exception("Failed to create audit log for AIP %s", am_uuid_str)

                registered += 1

                # Commit in batches.
                if registered % batch_size == 0:
                    session.commit()
                    logger.info("Committed batch of %d registrations.", batch_size)

            except Exception:
                logger.exception("Error registering AIP %s", am_uuid_str)
                errors += 1
                session.rollback()

        # Final commit for any remaining records.
        if not dry_run:
            session.commit()

    # Newline after progress bar
    sys.stdout.write("\n")
    return {"registered": registered, "already_existed": already_existed, "errors": errors}


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Register existing Archivematica AIPs in AIP Integrity Guardian.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="List AIPs that would be registered without making changes.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Number of AIPs to commit per database batch (default: 50).",
    )
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("AIP Integrity Guardian — Bulk AIP Registration")
    logger.info("=" * 60)
    if args.dry_run:
        logger.info("** DRY RUN MODE — no changes will be written **")

    t0 = time.monotonic()
    summary = register_aips(dry_run=args.dry_run, batch_size=args.batch_size)
    elapsed = time.monotonic() - t0

    logger.info("")
    logger.info("=" * 60)
    logger.info("Registration Summary")
    logger.info("=" * 60)
    logger.info("  Registered:      %d", summary["registered"])
    logger.info("  Already existed: %d", summary["already_existed"])
    logger.info("  Errors:          %d", summary["errors"])
    logger.info("  Duration:        %.1f seconds", elapsed)
    logger.info("=" * 60)

    if summary["errors"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
