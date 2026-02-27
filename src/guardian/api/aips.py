"""API endpoints for AIP management and verification."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.api.deps import get_db_session
from guardian.models.aip_status import AIPStatus
from guardian.schemas.aip import (
    AIPListResponse,
    AIPRegisterRequest,
    AIPStatusResponse,
    VerifyResponse,
)

router = APIRouter()


@router.get("/", response_model=AIPListResponse)
async def list_aips(
    db: AsyncSession = Depends(get_db_session),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=200, description="Records per page"),
    last_status: str | None = Query(default=None, description="Filter by status (e.g. verified, corrupted, pending)"),
    verified_before: datetime | None = Query(default=None, description="Filter AIPs verified before this timestamp"),
) -> AIPListResponse:
    """Return a paginated list of all registered AIPs.

    Supports optional filtering by ``last_status`` and ``verified_before``.
    """
    stmt = select(AIPStatus)
    count_stmt = select(func.count()).select_from(AIPStatus)

    if last_status is not None:
        stmt = stmt.where(AIPStatus.last_status == last_status)
        count_stmt = count_stmt.where(AIPStatus.last_status == last_status)

    if verified_before is not None:
        stmt = stmt.where(AIPStatus.last_verified < verified_before)
        count_stmt = count_stmt.where(AIPStatus.last_verified < verified_before)

    total: int = (await db.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = stmt.order_by(AIPStatus.created_at.desc()).offset(offset).limit(page_size)
    items = (await db.execute(stmt)).scalars().all()

    return AIPListResponse(
        items=[AIPStatusResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{aip_uuid}", response_model=AIPStatusResponse)
async def get_aip(
    aip_uuid: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AIPStatusResponse:
    """Return the status record for a single AIP, including recent audit
    history in the response details."""
    aip = await db.get(AIPStatus, aip_uuid)
    if aip is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AIP {aip_uuid} not found",
        )

    return AIPStatusResponse.model_validate(aip)


@router.post("/register", response_model=AIPStatusResponse, status_code=status.HTTP_201_CREATED)
async def register_aip(
    body: AIPRegisterRequest,
    db: AsyncSession = Depends(get_db_session),
) -> AIPStatusResponse:
    """Register a new AIP for integrity monitoring.

    Creates a new ``AIPStatus`` record and logs an ``aip_registered``
    audit event.
    """
    # Check for duplicate archivematica_uuid
    existing = (
        await db.execute(
            select(AIPStatus).where(
                AIPStatus.archivematica_uuid == body.archivematica_uuid
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"AIP with archivematica_uuid {body.archivematica_uuid} already registered",
        )

    aip = AIPStatus(
        aip_uuid=uuid.uuid4(),
        archivematica_uuid=body.archivematica_uuid,
        storage_path=body.storage_path,
        storage_location=body.storage_location,
        last_status="pending",
    )
    db.add(aip)
    await db.flush()

    # Audit log entry via hash-chained logger (run sync logger within async session)
    from guardian.services.audit_logger import AuditLogger

    def _log_registration(sync_session: object) -> None:
        AuditLogger.log(
            sync_session,  # type: ignore[arg-type]
            aip_uuid=str(aip.aip_uuid),
            event_type="aip_registered",
            status="pass",
            details={
                "archivematica_uuid": str(body.archivematica_uuid),
                "storage_path": body.storage_path,
                "storage_location": body.storage_location,
            },
        )

    await db.run_sync(_log_registration)

    return AIPStatusResponse.model_validate(aip)


@router.post("/{aip_uuid}/verify", response_model=VerifyResponse)
async def trigger_verify(
    aip_uuid: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> VerifyResponse:
    """Enqueue an on-demand fixity verification for the specified AIP.

    Returns immediately with the Celery task ID so the caller can poll
    for results.
    """
    aip = await db.get(AIPStatus, aip_uuid)
    if aip is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AIP {aip_uuid} not found",
        )

    from guardian.tasks.fixity_tasks import verify_single_aip

    task = verify_single_aip.delay(str(aip_uuid))

    return VerifyResponse(
        task_id=task.id,
        aip_uuid=aip_uuid,
        message=f"Fixity verification enqueued for AIP {aip_uuid}",
    )
