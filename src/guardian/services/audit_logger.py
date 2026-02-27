"""Immutable hash-chained audit logger — Component 3 (ISO 16363 §4.3.2.1).

Every audit record includes a SHA-256 hash of its own content plus a pointer
to the previous record's hash, forming a tamper-evident chain similar to a
blockchain.

This service uses **synchronous** SQLAlchemy sessions because it is designed
to be called from Celery tasks that operate within sync workers.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.models.audit_log import AuditLog
from guardian.services.fixity_verifier import VerificationResult

logger = logging.getLogger(__name__)

_GENESIS_HASH: str = "GENESIS"


class AuditLogger:
    """Class-method interface for writing hash-chained audit records."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def log(
        cls,
        session: Session,
        aip_uuid: str,
        event_type: str,
        status: str,
        details: dict | None = None,
    ) -> AuditLog:
        """Create a new hash-chained audit-log record.

        Parameters
        ----------
        session:
            A **synchronous** SQLAlchemy ``Session``.
        aip_uuid:
            UUID of the AIP this event pertains to (as string).
        event_type:
            One of :pyattr:`AuditLog.EVENT_TYPES`.
        status:
            One of :pyattr:`AuditLog.STATUS_CHOICES`.
        details:
            Optional JSON-serialisable details dictionary.

        Returns
        -------
        AuditLog
            The newly created (and flushed) record.
        """
        if details is None:
            details = {}

        # Fetch the hash of the most recent record to form the chain.
        previous_hash = cls._get_previous_hash(session)

        # Deterministic timestamp for hashing reproducibility.
        now = datetime.now(timezone.utc)

        # Compute the record hash.
        record_hash = cls._compute_record_hash(
            aip_uuid=aip_uuid,
            event_type=event_type,
            status=status,
            details=details,
            previous_hash=previous_hash,
            timestamp=now,
        )

        record = AuditLog(
            aip_uuid=aip_uuid,
            event_type=event_type,
            status=status,
            details=details,
            previous_hash=previous_hash,
            record_hash=record_hash,
            created_at=now,
        )
        session.add(record)
        session.flush()  # Assign the DB-generated ``id`` immediately.

        logger.info(
            "Audit [%s] %s:%s for AIP %s (hash=%s…)",
            record.id,
            event_type,
            status,
            aip_uuid,
            record_hash[:12],
        )
        return record

    @classmethod
    def log_fixity_check(
        cls,
        session: Session,
        aip_uuid: str,
        result: VerificationResult,
    ) -> AuditLog:
        """Convenience wrapper: log the outcome of a fixity verification.

        Parameters
        ----------
        session:
            Synchronous SQLAlchemy session.
        aip_uuid:
            UUID of the verified AIP.
        result:
            The :class:`VerificationResult` returned by the fixity verifier.
        """
        details: dict = {
            "files_checked": result.files_checked,
            "files_failed": result.files_failed,
            "duration_seconds": result.duration_seconds,
        }
        if result.failures:
            details["failures"] = [
                {
                    "path": f.path,
                    "expected": f.expected,
                    "actual": f.actual,
                    "algorithm": f.algorithm,
                }
                for f in result.failures
            ]
        if result.error:
            details["error"] = result.error

        status = result.status  # pass | fail | error
        return cls.log(
            session,
            aip_uuid=aip_uuid,
            event_type="fixity_check",
            status=status,
            details=details,
        )

    @classmethod
    def get_history(
        cls,
        session: Session,
        aip_uuid: str,
        limit: int = 100,
    ) -> list[AuditLog]:
        """Return the most recent audit records for a given AIP.

        Records are returned newest-first.
        """
        stmt = (
            select(AuditLog)
            .where(AuditLog.aip_uuid == aip_uuid)
            .order_by(AuditLog.id.desc())
            .limit(limit)
        )
        return list(session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _get_previous_hash(cls, session: Session) -> str:
        """Return the ``record_hash`` of the latest audit record, or GENESIS."""
        stmt = (
            select(AuditLog.record_hash)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        row = session.execute(stmt).scalar_one_or_none()
        return row if row is not None else _GENESIS_HASH

    @staticmethod
    def _compute_record_hash(
        *,
        aip_uuid: str,
        event_type: str,
        status: str,
        details: dict,
        previous_hash: str,
        timestamp: datetime,
    ) -> str:
        """Compute the SHA-256 hash that seals this record into the chain.

        The hash input is the concatenation (with ``|`` separator) of:
        ``aip_uuid | event_type | status | details_json | previous_hash | iso_timestamp``
        """
        details_json = json.dumps(details, sort_keys=True, default=str)
        iso_ts = timestamp.isoformat()

        payload = "|".join([
            str(aip_uuid),
            event_type,
            status,
            details_json,
            previous_hash,
            iso_ts,
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
