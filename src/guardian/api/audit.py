"""API endpoints for audit-log inspection and chain verification."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.api.deps import get_db_session
from guardian.models.audit_log import AuditLog
from guardian.schemas.audit import (
    AuditLogListResponse,
    AuditLogResponse,
    ChainStatusResponse,
)

router = APIRouter()


@router.get("/", response_model=AuditLogListResponse)
async def list_audit_logs(
    db: AsyncSession = Depends(get_db_session),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=200, description="Records per page"),
    aip_uuid: uuid.UUID | None = Query(default=None, description="Filter by AIP UUID"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
    status: str | None = Query(default=None, description="Filter by status (pass, fail, warning, error)"),
    created_after: datetime | None = Query(default=None, description="Records created after this timestamp"),
    created_before: datetime | None = Query(default=None, description="Records created before this timestamp"),
) -> AuditLogListResponse:
    """Return a paginated, filterable list of audit-log records.

    All filter parameters are optional and can be combined.
    """
    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)

    if aip_uuid is not None:
        stmt = stmt.where(AuditLog.aip_uuid == aip_uuid)
        count_stmt = count_stmt.where(AuditLog.aip_uuid == aip_uuid)

    if event_type is not None:
        stmt = stmt.where(AuditLog.event_type == event_type)
        count_stmt = count_stmt.where(AuditLog.event_type == event_type)

    if status is not None:
        stmt = stmt.where(AuditLog.status == status)
        count_stmt = count_stmt.where(AuditLog.status == status)

    if created_after is not None:
        stmt = stmt.where(AuditLog.created_at >= created_after)
        count_stmt = count_stmt.where(AuditLog.created_at >= created_after)

    if created_before is not None:
        stmt = stmt.where(AuditLog.created_at <= created_before)
        count_stmt = count_stmt.where(AuditLog.created_at <= created_before)

    total: int = (await db.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = stmt.order_by(AuditLog.id.desc()).offset(offset).limit(page_size)
    items = (await db.execute(stmt)).scalars().all()

    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/chain-status", response_model=ChainStatusResponse)
async def get_chain_status(
    db: AsyncSession = Depends(get_db_session),
) -> ChainStatusResponse:
    """Verify the audit-log hash chain and return the result.

    Walks the entire chain in-process (async) and returns a summary
    including any broken links.
    """
    import hashlib
    from datetime import datetime, timezone

    total: int = (
        await db.execute(select(func.count()).select_from(AuditLog))
    ).scalar_one()

    # Walk the chain in ascending order
    stmt = select(AuditLog).order_by(AuditLog.id.asc())
    records = (await db.execute(stmt)).scalars().all()

    broken_links: list[int] = []
    expected_previous = "GENESIS"

    for record in records:
        # Verify the previous_hash linkage
        if record.previous_hash != expected_previous:
            broken_links.append(record.id)

        # Recompute the record hash to detect tampering
        payload = (
            f"{record.id}|{record.aip_uuid}|{record.event_type}|"
            f"{record.status}|{record.previous_hash}"
        )
        computed_hash = hashlib.sha256(payload.encode()).hexdigest()
        if record.record_hash and record.record_hash != computed_hash:
            if record.id not in broken_links:
                broken_links.append(record.id)

        expected_previous = record.record_hash or expected_previous

    return ChainStatusResponse(
        total_records=total,
        chain_valid=len(broken_links) == 0,
        broken_links=broken_links,
        verified_at=datetime.now(timezone.utc),
    )
