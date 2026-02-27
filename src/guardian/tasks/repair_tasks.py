"""Celery tasks for automated AIP repair."""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from guardian.config import get_settings

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=1)
def repair_corrupted_aip(
    self: Any,
    aip_uuid: str,
    corruption_report: dict[str, Any],
) -> dict[str, Any]:
    """Attempt automated repair of a corrupted AIP.

    Uses ``AutoRepair.repair()`` to locate a healthy replica and restore
    the corrupted files.  On completion (success or failure) a
    notification is sent to the configured admin channel.

    Parameters
    ----------
    aip_uuid:
        String representation of the AIP UUID to repair.
    corruption_report:
        Dict produced by ``FixityVerifier.verify()`` describing which
        files failed their checksums.

    Returns
    -------
    dict
        ``{"repaired": <bool>, "details": {...}}``
    """
    from guardian.models.aip_status import AIPStatus
    from guardian.services.auto_repair import AutoRepair
    from guardian.services.fixity_verifier import FixityVerifier
    from guardian.services.hmac_authenticator import ManifestAuthenticator
    from guardian.services.replica_manager import ReplicaManager
    from guardian.connector.archivematica_client import ArchivematicaConnector
    from guardian.services.notification import NotificationService

    settings = get_settings()
    sync_engine = create_engine(settings.sync_database_url)

    try:
        with Session(sync_engine) as session:
            aip = session.get(AIPStatus, aip_uuid)
            if aip is None:
                logger.error("Repair: AIP %s not found in database", aip_uuid)
                return {"repaired": False, "details": {"error": "AIP not found"}}

            # Build collaborators for AutoRepair
            fixity_verifier = FixityVerifier()
            hmac_authenticator = ManifestAuthenticator()
            connector = ArchivematicaConnector(settings)
            replica_manager = ReplicaManager(connector)

            repair_service = AutoRepair(fixity_verifier, hmac_authenticator, replica_manager)
            repair_result = repair_service.repair(
                session, aip_uuid, aip.storage_path, corruption_report,
            )

            repaired: bool = repair_result.status == "success"

            # Update AIP status if repair succeeded
            if repaired:
                aip.last_status = "repaired"
            elif repair_result.status == "partial":
                aip.last_status = "repaired"

            session.commit()

        # --- Notifications ---
        notifier = NotificationService(settings)
        repair_details = {
            "status": repair_result.status,
            "repaired_files": repair_result.repaired_files,
            "source_replica": repair_result.source_replica,
            **repair_result.details,
        }
        if repaired:
            notifier.notify_repair_success(aip_uuid, repair_details)
            logger.info("AIP %s repaired successfully", aip_uuid)
        else:
            notifier.notify_repair_failure(aip_uuid, repair_details)
            logger.error("AIP %s repair failed", aip_uuid)

        return {"repaired": repaired, "details": repair_details}

    except Exception as exc:
        logger.exception("repair_corrupted_aip failed for %s, retrying", aip_uuid)
        raise self.retry(exc=exc, countdown=300) from exc
    finally:
        sync_engine.dispose()
