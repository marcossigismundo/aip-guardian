"""API endpoints for RFC 3161 anchor records."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.api.deps import get_db_session
from guardian.models.anchor_registry import AnchorRegistry
from guardian.schemas.anchor import (
    AnchorListResponse,
    AnchorResponse,
    AnchorVerifyResponse,
)

router = APIRouter()


@router.get("/", response_model=AnchorListResponse)
async def list_anchors(
    db: AsyncSession = Depends(get_db_session),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=200, description="Records per page"),
) -> AnchorListResponse:
    """Return a paginated list of all anchor records, newest first."""
    total: int = (
        await db.execute(select(func.count()).select_from(AnchorRegistry))
    ).scalar_one()

    offset = (page - 1) * page_size
    stmt = (
        select(AnchorRegistry)
        .order_by(AnchorRegistry.id.desc())
        .offset(offset)
        .limit(page_size)
    )
    items = (await db.execute(stmt)).scalars().all()

    return AnchorListResponse(
        items=[AnchorResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{anchor_id}/verify", response_model=AnchorVerifyResponse)
async def verify_anchor(
    anchor_id: int,
    db: AsyncSession = Depends(get_db_session),
) -> AnchorVerifyResponse:
    """Verify a single anchor record.

    Re-computes the batch hash from the referenced audit-log records and
    (if a timestamp token is present) validates the RFC 3161 response.
    """
    import hashlib

    from guardian.models.audit_log import AuditLog

    anchor = await db.get(AnchorRegistry, anchor_id)
    if anchor is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anchor {anchor_id} not found",
        )

    # Re-compute batch hash from the audit records in the batch range
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.id >= anchor.batch_start_id,
            AuditLog.id <= anchor.batch_end_id,
        )
        .order_by(AuditLog.id.asc())
    )
    records = (await db.execute(stmt)).scalars().all()

    if not records:
        return AnchorVerifyResponse(
            anchor_id=anchor_id,
            valid=False,
            details={"error": "No audit records found for the anchor batch range"},
        )

    # Compute combined hash of all record hashes in the batch
    hasher = hashlib.sha256()
    for record in records:
        hasher.update((record.record_hash or "").encode())
    computed_batch_hash = hasher.hexdigest()

    batch_hash_valid = computed_batch_hash == anchor.batch_hash

    details: dict[str, object] = {
        "batch_start_id": anchor.batch_start_id,
        "batch_end_id": anchor.batch_end_id,
        "records_in_batch": len(records),
        "stored_batch_hash": anchor.batch_hash,
        "computed_batch_hash": computed_batch_hash,
        "batch_hash_valid": batch_hash_valid,
        "has_timestamp_token": anchor.timestamp_token is not None,
    }

    return AnchorVerifyResponse(
        anchor_id=anchor_id,
        valid=batch_hash_valid,
        details=details,
    )
