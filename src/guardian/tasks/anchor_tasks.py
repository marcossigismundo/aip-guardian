"""Celery tasks for RFC 3161 timestamp anchoring."""

from __future__ import annotations

import logging
from datetime import date, datetime, time, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from guardian.config import get_settings

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def submit_daily_anchor(self: Any) -> dict[str, Any]:
    """Anchor today's unanchored audit records via RFC 3161.

    Steps
    -----
    1. Query all ``AuditLog`` records created today that have not yet
       been included in an anchor batch.
    2. Submit them as a batch to ``RFC3161Anchor.submit_batch()``.
    3. Log an ``anchor_submitted`` audit event with the result.

    Returns
    -------
    dict
        ``{"records_anchored": <int>, "success": <bool>}``
    """
    from guardian.models.audit_log import AuditLog
    from guardian.models.anchor_registry import AnchorRegistry
    from guardian.services.rfc3161_anchor import RFC3161Anchor

    settings = get_settings()
    sync_engine = create_engine(settings.sync_database_url)

    try:
        with Session(sync_engine) as session:
            # Determine the boundary: start of today (UTC)
            today_start = datetime.combine(date.today(), time.min, tzinfo=timezone.utc)

            # Find the latest anchor's batch_end_id to know where we left off
            latest_anchor = session.execute(
                select(AnchorRegistry)
                .order_by(AnchorRegistry.id.desc())
                .limit(1)
            ).scalar_one_or_none()

            last_anchored_id: int = latest_anchor.batch_end_id if latest_anchor else 0

            # Get unanchored audit records from today
            unanchored_records = (
                session.execute(
                    select(AuditLog)
                    .where(
                        AuditLog.id > last_anchored_id,
                        AuditLog.created_at >= today_start,
                    )
                    .order_by(AuditLog.id.asc())
                )
                .scalars()
                .all()
            )

            if not unanchored_records:
                logger.info("No unanchored audit records for today — skipping anchor")
                return {"records_anchored": 0, "success": False}

            # Convert ORM objects to dicts expected by submit_batch
            batch_records = [
                {"id": r.id, "record_hash": r.record_hash}
                for r in unanchored_records
            ]

            # Submit the batch
            anchor_service = RFC3161Anchor()
            anchor_result = anchor_service.submit_batch(session, batch_records)

            session.commit()

        logger.info(
            "Daily anchor submitted: %d records, success=%s",
            len(unanchored_records),
            anchor_result.success,
        )
        return {
            "records_anchored": anchor_result.batch_size,
            "success": anchor_result.success,
            "tsa_url": anchor_result.tsa_url,
            "batch_hash": anchor_result.batch_hash,
        }

    except Exception as exc:
        logger.exception("submit_daily_anchor failed, retrying")
        raise self.retry(exc=exc, countdown=180) from exc
    finally:
        sync_engine.dispose()
