"""Celery tasks for audit-log chain verification."""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from guardian.config import get_settings

logger = logging.getLogger(__name__)


@shared_task
def verify_audit_chain() -> dict[str, Any]:
    """Verify the full integrity of the audit-log hash chain.

    Uses ``ChainVerifier.verify_full_chain()`` to walk through every
    ``AuditLog`` record and confirm that each ``record_hash`` matches
    the expected value computed from the record content and its
    ``previous_hash``.

    The result is itself logged as a ``chain_verify`` audit event so
    that the verification is part of the immutable record.

    Returns
    -------
    dict
        ``{"total_records": <int>, "chain_valid": <bool>,
        "broken_links": [<int>, ...]}``
    """
    from guardian.services.chain_verifier import ChainVerifier
    from guardian.services.audit_logger import AuditLogger

    settings = get_settings()
    sync_engine = create_engine(settings.sync_database_url)

    try:
        with Session(sync_engine) as session:
            result = ChainVerifier.verify_full_chain(session)

            chain_valid: bool = result.get("chain_valid", False)
            total_records: int = result.get("total_records", 0)
            broken_links: list[int] = result.get("broken_links", [])

            AuditLogger.log(
                session,
                aip_uuid="00000000-0000-0000-0000-000000000000",
                event_type="chain_verify",
                status="pass" if chain_valid else "fail",
                details={
                    "total_records": total_records,
                    "chain_valid": chain_valid,
                    "broken_links": broken_links,
                },
            )
            session.commit()

        logger.info(
            "Audit chain verification: valid=%s, records=%d, broken=%d",
            chain_valid,
            total_records,
            len(broken_links),
        )
        return {
            "total_records": total_records,
            "chain_valid": chain_valid,
            "broken_links": broken_links,
        }

    except Exception:
        logger.exception("Audit chain verification failed")
        raise
    finally:
        sync_engine.dispose()
