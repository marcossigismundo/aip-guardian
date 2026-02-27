"""Health-check endpoint — no authentication required."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.api.deps import get_db_session
from guardian.config import get_settings
from guardian.schemas.dashboard import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db_session),
) -> HealthResponse:
    """Return the health status of all system components.

    This endpoint is **exempt from authentication** so that external
    monitoring tools and load balancers can probe it freely.

    Checks
    ------
    * **Database** -- execute ``SELECT 1`` via the async session.
    * **Redis** -- ``PING`` the Celery broker URL.
    * **Celery** -- inspect active workers via the Celery app.
    * **Archivematica** -- HTTP GET to the Storage Service API.
    """
    import redis
    import httpx

    settings = get_settings()

    # --- Database ---
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        logger.warning("Health check: database unreachable")

    # --- Redis ---
    redis_ok = False
    try:
        r = redis.Redis.from_url(settings.celery_broker_url, socket_timeout=5)
        r.ping()
        redis_ok = True
    except Exception:
        logger.warning("Health check: Redis unreachable")

    # --- Celery workers ---
    celery_ok = False
    try:
        from guardian.celery_app import celery as celery_app

        inspect = celery_app.control.inspect(timeout=3)
        active = inspect.active()
        celery_ok = active is not None and len(active) > 0
    except Exception:
        logger.warning("Health check: no Celery workers responding")

    # --- Archivematica Storage Service ---
    archivematica_ok = False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.archivematica_ss_url}/api/v2/pipeline/",
                headers={
                    "Authorization": (
                        f"ApiKey {settings.archivematica_ss_user}:"
                        f"{settings.archivematica_ss_api_key}"
                    ),
                },
            )
            archivematica_ok = resp.status_code < 500
    except Exception:
        logger.warning("Health check: Archivematica SS unreachable")

    # --- Overall status ---
    all_ok = all([db_ok, redis_ok, celery_ok, archivematica_ok])
    critical_ok = db_ok and redis_ok
    if all_ok:
        overall = "healthy"
    elif critical_ok:
        overall = "degraded"
    else:
        overall = "unhealthy"

    from guardian import __version__

    return HealthResponse(
        status=overall,
        version=__version__,
        database=db_ok,
        redis=redis_ok,
        celery=celery_ok,
        archivematica=archivematica_ok,
    )
