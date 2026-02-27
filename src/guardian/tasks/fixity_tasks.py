"""Celery tasks for AIP fixity verification and pipeline health checks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from guardian.config import get_settings

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def verify_all_aips(self: Any) -> dict[str, Any]:
    """Dispatch individual verification tasks for every registered AIP.

    This is the entry-point task triggered by Celery Beat on a weekly
    schedule.  It fans out one ``verify_single_aip`` task per AIP so that
    verifications run in parallel across workers.

    Returns
    -------
    dict
        ``{"total_dispatched": <int>}`` indicating how many tasks were
        queued.
    """
    from guardian.models.aip_status import AIPStatus

    settings = get_settings()
    sync_engine = create_engine(settings.sync_database_url)

    try:
        with Session(sync_engine) as session:
            aip_uuids: list[str] = [
                str(row.aip_uuid)
                for row in session.execute(select(AIPStatus)).scalars().all()
            ]

        dispatched = 0
        for aip_uuid in aip_uuids:
            verify_single_aip.delay(aip_uuid)
            dispatched += 1

        logger.info("verify_all_aips dispatched %d tasks", dispatched)
        return {"total_dispatched": dispatched}

    except Exception as exc:
        logger.exception("verify_all_aips failed, retrying")
        raise self.retry(exc=exc, countdown=60) from exc
    finally:
        sync_engine.dispose()


@shared_task(bind=True, max_retries=3)
def verify_single_aip(self: Any, aip_uuid: str) -> dict[str, Any]:
    """Run fixity + HMAC verification for a single AIP.

    Steps
    -----
    1. Load the ``AIPStatus`` record from the database.
    2. Run ``FixityVerifier.verify()`` and log the result via ``AuditLogger``.
    3. Run ``ManifestAuthenticator.verify_aip()`` and log the HMAC result.
    4. If the fixity check passed but HMAC failed, log a ``tamper_detected``
       event.
    5. If the fixity check found corruption, dispatch
       ``repair_corrupted_aip``.
    6. Update the ``AIPStatus`` record with the latest results.

    Parameters
    ----------
    aip_uuid:
        String representation of the AIP UUID to verify.

    Returns
    -------
    dict
        Summary of the verification including ``fixity_ok`` and ``hmac_ok``
        flags.
    """
    from guardian.models.aip_status import AIPStatus
    from guardian.services.fixity_verifier import FixityVerifier
    from guardian.services.hmac_authenticator import ManifestAuthenticator
    from guardian.services.audit_logger import AuditLogger

    settings = get_settings()
    sync_engine = create_engine(settings.sync_database_url)

    try:
        with Session(sync_engine) as session:
            aip = session.get(AIPStatus, aip_uuid)
            if aip is None:
                logger.error("AIP %s not found in database", aip_uuid)
                return {"error": f"AIP {aip_uuid} not found"}

            now = datetime.now(timezone.utc)

            # --- Fixity verification ---
            verifier = FixityVerifier()
            fixity_result = verifier.verify(str(aip.aip_uuid), aip.storage_path)
            fixity_ok: bool = fixity_result.passed

            AuditLogger.log(
                session,
                aip_uuid=aip_uuid,
                event_type="fixity_check",
                status="pass" if fixity_ok else "fail",
                details={
                    "files_checked": fixity_result.files_checked,
                    "files_failed": fixity_result.files_failed,
                    "duration_seconds": fixity_result.duration_seconds,
                },
            )
            logger.info(
                "Fixity check for %s: %s",
                aip_uuid,
                "pass" if fixity_ok else "fail",
            )

            # --- HMAC / manifest authentication ---
            authenticator = ManifestAuthenticator()
            hmac_result = authenticator.verify_aip(session, str(aip.aip_uuid), aip.storage_path)
            hmac_ok: bool = hmac_result.get("valid", False)

            AuditLogger.log(
                session,
                aip_uuid=aip_uuid,
                event_type="hmac_verify",
                status="pass" if hmac_ok else "fail",
                details=hmac_result,
            )
            logger.info(
                "HMAC check for %s: %s",
                aip_uuid,
                "pass" if hmac_ok else "fail",
            )

            # --- Tamper detection ---
            if fixity_ok and not hmac_ok:
                AuditLogger.log(
                    session,
                    aip_uuid=aip_uuid,
                    event_type="tamper_detected",
                    status="fail",
                    details={
                        "reason": "Fixity passed but HMAC verification failed — "
                                  "possible manifest tampering.",
                        "hmac_tampered": hmac_result.get("tampered", []),
                    },
                )
                logger.warning(
                    "Tamper detected for AIP %s: fixity OK but HMAC failed",
                    aip_uuid,
                )

            # --- Dispatch repair if corrupted ---
            if not fixity_ok:
                from guardian.tasks.repair_tasks import repair_corrupted_aip

                corruption_report = {
                    "corrupted_files": [
                        {
                            "path": f.path,
                            "expected_hash": f.expected,
                            "actual_hash": f.actual,
                            "algorithm": f.algorithm,
                        }
                        for f in fixity_result.failures
                    ],
                }
                repair_corrupted_aip.delay(aip_uuid, corruption_report)
                logger.info("Dispatched repair task for corrupted AIP %s", aip_uuid)

            # --- Update AIPStatus ---
            aip.last_verified = now
            aip.last_status = "valid" if fixity_ok else "corrupted"
            aip.last_hmac_check = now
            aip.total_verifications = (aip.total_verifications or 0) + 1
            if not fixity_ok:
                aip.total_failures = (aip.total_failures or 0) + 1

            session.commit()

        return {
            "aip_uuid": aip_uuid,
            "fixity_ok": fixity_ok,
            "hmac_ok": hmac_ok,
        }

    except Exception as exc:
        logger.exception("verify_single_aip failed for %s, retrying", aip_uuid)
        raise self.retry(exc=exc, countdown=120) from exc
    finally:
        sync_engine.dispose()


@shared_task
def pipeline_health_check() -> dict[str, Any]:
    """Check the health of all system dependencies and log the result.

    Checks
    ------
    * **Database** — execute a lightweight ``SELECT 1``.
    * **Redis** — attempt a ``PING`` via the Celery broker URL.
    * **Archivematica Storage Service** — HTTP GET to the API root.

    The results are recorded as a ``health_check`` audit event.

    Returns
    -------
    dict
        Mapping of component names to their health status booleans plus
        an overall ``healthy`` flag.
    """
    import redis
    import httpx
    from guardian.models.aip_status import AIPStatus  # noqa: F401 — ensure model loaded
    from guardian.services.audit_logger import AuditLogger

    settings = get_settings()
    sync_engine = create_engine(settings.sync_database_url)
    health: dict[str, Any] = {}

    # --- Database ---
    try:
        with sync_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        health["database"] = True
    except Exception:
        logger.exception("Health check: database unreachable")
        health["database"] = False

    # --- Redis ---
    try:
        r = redis.Redis.from_url(settings.celery_broker_url, socket_timeout=5)
        r.ping()
        health["redis"] = True
    except Exception:
        logger.exception("Health check: Redis unreachable")
        health["redis"] = False

    # --- Archivematica Storage Service ---
    try:
        resp = httpx.get(
            f"{settings.archivematica_ss_url}/api/v2/pipeline/",
            headers={
                "Authorization": (
                    f"ApiKey {settings.archivematica_ss_user}:"
                    f"{settings.archivematica_ss_api_key}"
                ),
            },
            timeout=10,
        )
        health["archivematica"] = resp.status_code < 500
    except Exception:
        logger.exception("Health check: Archivematica SS unreachable")
        health["archivematica"] = False

    health["healthy"] = all(health.values())

    # --- Log to audit ---
    try:
        with Session(sync_engine) as session:
            AuditLogger.log(
                session,
                aip_uuid="00000000-0000-0000-0000-000000000000",
                event_type="health_check",
                status="pass" if health["healthy"] else "warning",
                details=health,
            )
            session.commit()
    except Exception:
        logger.exception("Health check: failed to write audit log")
    finally:
        sync_engine.dispose()

    logger.info("Pipeline health check: %s", health)
    return health
