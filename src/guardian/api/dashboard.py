"""API endpoint for the dashboard summary."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.api.deps import get_db_session
from guardian.models.aip_status import AIPStatus
from guardian.models.anchor_registry import AnchorRegistry
from guardian.models.audit_log import AuditLog
from guardian.schemas.dashboard import DashboardSummaryResponse

router = APIRouter()


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db_session),
) -> DashboardSummaryResponse:
    """Return aggregate counts and high-level system state for the dashboard.

    Queries
    -------
    * Total registered AIPs
    * AIPs in each status category (verified, corrupted, repaired, pending)
    * Timestamp of the most recent full verification run
    * Whether the audit-log hash chain is intact (quick check via the
      latest ``chain_verify`` event)
    * Timestamp of the most recent external anchor
    """
    # Total AIPs
    total_aips: int = (
        await db.execute(select(func.count()).select_from(AIPStatus))
    ).scalar_one()

    # Status counts
    verified_ok: int = (
        await db.execute(
            select(func.count())
            .select_from(AIPStatus)
            .where(AIPStatus.last_status == "valid")
        )
    ).scalar_one()

    corrupted: int = (
        await db.execute(
            select(func.count())
            .select_from(AIPStatus)
            .where(AIPStatus.last_status == "corrupted")
        )
    ).scalar_one()

    repaired: int = (
        await db.execute(
            select(func.count())
            .select_from(AIPStatus)
            .where(AIPStatus.last_status == "repaired")
        )
    ).scalar_one()

    never_verified: int = (
        await db.execute(
            select(func.count())
            .select_from(AIPStatus)
            .where(AIPStatus.last_verified.is_(None))
        )
    ).scalar_one()

    # Most recent full verification (last_verified across all AIPs)
    last_full_check = (
        await db.execute(
            select(func.max(AIPStatus.last_verified))
        )
    ).scalar_one()

    # Audit chain validity — look at the latest chain_verify event
    latest_chain_event = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.event_type == "chain_verify")
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    if latest_chain_event is not None:
        audit_chain_valid = latest_chain_event.status == "pass"
    else:
        # No chain verification has run yet — assume valid (no records to break)
        audit_chain_valid = True

    # Most recent anchor timestamp
    last_anchor_at = (
        await db.execute(
            select(func.max(AnchorRegistry.anchored_at))
        )
    ).scalar_one()

    return DashboardSummaryResponse(
        total_aips=total_aips,
        verified_ok=verified_ok,
        corrupted=corrupted,
        repaired=repaired,
        never_verified=never_verified,
        last_full_check=last_full_check,
        audit_chain_valid=audit_chain_valid,
        last_anchor_at=last_anchor_at,
    )
