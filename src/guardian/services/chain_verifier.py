"""Audit-chain integrity verifier.

Validates the tamper-evident hash chain stored in the ``aip_integrity_audit_log``
table by recalculating each record's hash and checking the ``previous_hash``
linkage.  Uses :func:`hmac.compare_digest` for all comparisons to prevent
timing side-channels.

This service uses **synchronous** SQLAlchemy sessions (called from Celery
workers or management commands).
"""

from __future__ import annotations

import hmac as hmac_mod
import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.models.audit_log import AuditLog
from guardian.services.hash_utils import compute_record_hash

logger = logging.getLogger(__name__)

_GENESIS_HASH: str = "GENESIS"


class ChainVerifier:
    """Verify the integrity of the audit-log hash chain."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def verify_full_chain(cls, session: Session) -> dict:
        """Walk the entire audit-log chain and verify every link.

        Returns
        -------
        dict
            ``total_records``            – number of records checked.
            ``chain_valid``              – True when every link is sound.
            ``broken_links``             – list of record IDs where a break
                                           was detected.
            ``verification_time_seconds`` – wall-clock duration.
        """
        stmt = select(AuditLog).order_by(AuditLog.id.asc())
        records: list[AuditLog] = list(session.execute(stmt).scalars().all())
        return cls._verify_records(records)

    @classmethod
    def verify_recent(cls, session: Session, hours: int = 24) -> dict:
        """Verify only records created within the last *hours* hours.

        The ``previous_hash`` of the first record in the window is checked
        against the immediately preceding record (if any) so a gap at the
        boundary is detected.

        Returns the same dictionary shape as :meth:`verify_full_chain`.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Fetch the single record just before the window so we can verify
        # the boundary link.
        boundary_stmt = (
            select(AuditLog)
            .where(AuditLog.created_at < cutoff)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        boundary_record = session.execute(boundary_stmt).scalar_one_or_none()

        # Fetch all records inside the window.
        window_stmt = (
            select(AuditLog)
            .where(AuditLog.created_at >= cutoff)
            .order_by(AuditLog.id.asc())
        )
        records: list[AuditLog] = list(session.execute(window_stmt).scalars().all())

        # Prepend the boundary record so the first in-window record can
        # have its ``previous_hash`` validated.
        if boundary_record is not None:
            records.insert(0, boundary_record)

        return cls._verify_records(records)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _verify_records(cls, records: list[AuditLog]) -> dict:
        """Core verification loop shared by full and recent checks."""
        t0 = time.monotonic()
        broken_links: list[int] = []
        previous_hash: str = _GENESIS_HASH

        for record in records:
            # 1. Check that this record's previous_hash matches the
            #    hash of the preceding record.
            if not hmac_mod.compare_digest(record.previous_hash, previous_hash):
                broken_links.append(record.id)
                logger.warning(
                    "Chain break at record %d: expected previous_hash=%s…, got %s…",
                    record.id,
                    previous_hash[:12],
                    record.previous_hash[:12],
                )

            # 2. Recalculate the record_hash and compare.
            expected_hash = cls._compute_record_hash(record)
            if not hmac_mod.compare_digest(record.record_hash, expected_hash):
                if record.id not in broken_links:
                    broken_links.append(record.id)
                logger.warning(
                    "Hash mismatch at record %d: stored=%s…, computed=%s…",
                    record.id,
                    record.record_hash[:12],
                    expected_hash[:12],
                )

            previous_hash = record.record_hash

        elapsed = time.monotonic() - t0
        chain_valid = len(broken_links) == 0

        logger.info(
            "Chain verification complete: %d records, valid=%s, breaks=%d (%.2fs)",
            len(records),
            chain_valid,
            len(broken_links),
            elapsed,
        )

        return {
            "total_records": len(records),
            "chain_valid": chain_valid,
            "broken_links": broken_links,
            "verification_time_seconds": round(elapsed, 4),
        }

    @staticmethod
    def _compute_record_hash(record: AuditLog) -> str:
        """Recalculate the SHA-256 hash of an existing record.

        Delegates to :func:`hash_utils.compute_record_hash` which is the
        single canonical implementation shared with :class:`AuditLogger`.
        """
        return compute_record_hash(
            aip_uuid=str(record.aip_uuid),
            event_type=record.event_type,
            status=record.status,
            details=record.details if record.details else {},
            previous_hash=record.previous_hash,
            timestamp=record.created_at,
        )
