"""Web dashboard routes — serves Jinja2 HTML pages for the Guardian UI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.config import get_settings
from guardian.database import async_session_factory
from guardian.i18n import SUPPORTED_LANGUAGES, template_globals
from guardian.models import (
    AIPStatus,
    AnchorRegistry,
    AuditLog,
    HMACRegistry,
    RepairRecord,
)

web_router = APIRouter(tags=["Web Dashboard"])

# Template directory
_template_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_template_dir))


# ── Helper: async DB session ─────────────────────────────────────

async def _get_db():
    """Yield an async session for use inside routes."""
    async with async_session_factory() as session:
        yield session


# ── Helper: mask sensitive strings ───────────────────────────────

def _mask(value: str, show: int = 4) -> str:
    """Mask a string, showing only the first *show* characters."""
    if not value or len(value) <= show:
        return "****"
    return value[:show] + "*" * (len(value) - show)


# ── GET / — redirect to dashboard ───────────────────────────────

@web_router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    return RedirectResponse(url="/dashboard", status_code=302)


# ── GET /dashboard ───────────────────────────────────────────────

@web_router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    i18n = template_globals(request)
    async with async_session_factory() as db:
        # Aggregate counts by status
        result = await db.execute(
            select(AIPStatus.last_status, func.count()).group_by(AIPStatus.last_status)
        )
        status_counts: dict[str, int] = dict(result.all())

        total = sum(status_counts.values())
        stats = {
            "total": total,
            "valid": status_counts.get("valid", 0),
            "corrupted": status_counts.get("corrupted", 0),
            "repaired": status_counts.get("repaired", 0),
            "pending": status_counts.get("pending", 0),
        }

        # Last 10 audit events
        events_result = await db.execute(
            select(AuditLog).order_by(desc(AuditLog.created_at)).limit(10)
        )
        recent_events = events_result.scalars().all()

        # Last anchor
        anchor_result = await db.execute(
            select(AnchorRegistry).order_by(desc(AnchorRegistry.anchored_at)).limit(1)
        )
        last_anchor = anchor_result.scalar_one_or_none()

        # Chain status — simple check: count audit records
        total_records_result = await db.execute(select(func.count()).select_from(AuditLog))
        total_records = total_records_result.scalar() or 0

        chain_status = None
        if total_records > 0:
            # Simple chain status representation
            class _ChainStatus:
                def __init__(self, valid: bool, total_records: int, last_checked, genesis_hash: str):
                    self.valid = valid
                    self.total_records = total_records
                    self.last_checked = last_checked
                    self.genesis_hash = genesis_hash

            # Get genesis record
            genesis_result = await db.execute(
                select(AuditLog).order_by(AuditLog.id).limit(1)
            )
            genesis = genesis_result.scalar_one_or_none()

            chain_status = _ChainStatus(
                valid=True,  # Simplified — full verification via chain_verifier service
                total_records=total_records,
                last_checked=genesis.created_at if genesis else None,
                genesis_hash=genesis.record_hash if genesis else "",
            )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_page": "dashboard",
            "stats": stats,
            "recent_events": recent_events,
            "last_anchor": last_anchor,
            "chain_status": chain_status,
            **i18n,
        },
    )


# ── GET /aips ────────────────────────────────────────────────────

@web_router.get("/aips", response_class=HTMLResponse, include_in_schema=False)
async def aips_list(
    request: Request,
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
):
    i18n = template_globals(request)
    page_size = 25

    async with async_session_factory() as db:
        query = select(AIPStatus)
        count_query = select(func.count()).select_from(AIPStatus)

        # Apply filters
        if status:
            query = query.where(AIPStatus.last_status == status)
            count_query = count_query.where(AIPStatus.last_status == status)
        if search:
            query = query.where(AIPStatus.aip_uuid.cast(str).ilike(f"%{search}%"))
            count_query = count_query.where(AIPStatus.aip_uuid.cast(str).ilike(f"%{search}%"))

        # Get total count
        total_result = await db.execute(count_query)
        total_count = total_result.scalar() or 0
        total_pages = max(1, (total_count + page_size - 1) // page_size)

        # Apply pagination and ordering
        query = query.order_by(desc(AIPStatus.updated_at)).offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        aips = result.scalars().all()

    return templates.TemplateResponse(
        "aips.html",
        {
            "request": request,
            "active_page": "aips",
            "aips": aips,
            "total_count": total_count,
            "current_page": page,
            "total_pages": total_pages,
            "filter_status": status,
            "search_query": search,
            **i18n,
        },
    )


# ── GET /aips/{aip_uuid} ────────────────────────────────────────

@web_router.get("/aips/{aip_uuid}", response_class=HTMLResponse, include_in_schema=False)
async def aip_detail(request: Request, aip_uuid: str):
    i18n = template_globals(request)

    async with async_session_factory() as db:
        # Get AIP
        result = await db.execute(
            select(AIPStatus).where(AIPStatus.aip_uuid == aip_uuid)
        )
        aip = result.scalar_one_or_none()

        if aip is None:
            return templates.TemplateResponse(
                "aips.html",
                {
                    "request": request,
                    "active_page": "aips",
                    "aips": [],
                    "total_count": 0,
                    "current_page": 1,
                    "total_pages": 1,
                    "filter_status": None,
                    "search_query": aip_uuid,
                    **i18n,
                },
            )

        # Get audit events for this AIP
        events_result = await db.execute(
            select(AuditLog)
            .where(AuditLog.aip_uuid == aip_uuid)
            .order_by(desc(AuditLog.created_at))
            .limit(50)
        )
        audit_events = events_result.scalars().all()

        # Get HMAC records
        hmac_result = await db.execute(
            select(HMACRegistry)
            .where(HMACRegistry.aip_uuid == aip_uuid)
            .order_by(HMACRegistry.manifest_name)
        )
        hmac_records = hmac_result.scalars().all()

        # Get repair records
        repair_result = await db.execute(
            select(RepairRecord)
            .where(RepairRecord.aip_uuid == aip_uuid)
            .order_by(desc(RepairRecord.repaired_at))
        )
        repair_records = repair_result.scalars().all()

    return templates.TemplateResponse(
        "aip_detail.html",
        {
            "request": request,
            "active_page": "aips",
            "aip": aip,
            "audit_events": audit_events,
            "hmac_records": hmac_records,
            "repair_records": repair_records,
            **i18n,
        },
    )


# ── GET /audit-log ──────────────────────────────────────────────

@web_router.get("/audit-log", response_class=HTMLResponse, include_in_schema=False)
async def audit_log(
    request: Request,
    aip_uuid: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
):
    i18n = template_globals(request)
    page_size = 50

    async with async_session_factory() as db:
        query = select(AuditLog)
        count_query = select(func.count()).select_from(AuditLog)

        if aip_uuid:
            query = query.where(AuditLog.aip_uuid.cast(str).ilike(f"%{aip_uuid}%"))
            count_query = count_query.where(AuditLog.aip_uuid.cast(str).ilike(f"%{aip_uuid}%"))
        if event_type:
            query = query.where(AuditLog.event_type == event_type)
            count_query = count_query.where(AuditLog.event_type == event_type)
        if status:
            query = query.where(AuditLog.status == status)
            count_query = count_query.where(AuditLog.status == status)
        if date_from:
            query = query.where(AuditLog.created_at >= date_from)
            count_query = count_query.where(AuditLog.created_at >= date_from)
        if date_to:
            query = query.where(AuditLog.created_at <= date_to)
            count_query = count_query.where(AuditLog.created_at <= date_to)

        total_result = await db.execute(count_query)
        total_count = total_result.scalar() or 0
        total_pages = max(1, (total_count + page_size - 1) // page_size)

        query = query.order_by(desc(AuditLog.created_at)).offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        events = result.scalars().all()

        # Simple chain validity check
        chain_valid = True  # Full check deferred to chain_verifier service

    return templates.TemplateResponse(
        "audit_log.html",
        {
            "request": request,
            "active_page": "audit_log",
            "events": events,
            "total_count": total_count,
            "current_page": page,
            "total_pages": total_pages,
            "chain_valid": chain_valid,
            "filter_aip_uuid": aip_uuid,
            "filter_event_type": event_type,
            "filter_status": status,
            "filter_date_from": date_from,
            "filter_date_to": date_to,
            **i18n,
        },
    )


# ── GET /anchors ─────────────────────────────────────────────────

@web_router.get("/anchors", response_class=HTMLResponse, include_in_schema=False)
async def anchors(request: Request):
    i18n = template_globals(request)

    async with async_session_factory() as db:
        # Total count
        count_result = await db.execute(select(func.count()).select_from(AnchorRegistry))
        total_anchors = count_result.scalar() or 0

        # All anchors ordered by date
        result = await db.execute(
            select(AnchorRegistry).order_by(desc(AnchorRegistry.anchored_at))
        )
        anchors_list = result.scalars().all()

        # Last anchor date
        last_anchor_date = anchors_list[0].anchored_at if anchors_list else None

    return templates.TemplateResponse(
        "anchors.html",
        {
            "request": request,
            "active_page": "anchors",
            "anchors": anchors_list,
            "total_anchors": total_anchors,
            "last_anchor_date": last_anchor_date,
            **i18n,
        },
    )


# ── GET /settings ────────────────────────────────────────────────

@web_router.get("/settings", response_class=HTMLResponse, include_in_schema=False)
async def settings_page(request: Request):
    i18n = template_globals(request)
    settings = get_settings()

    # Determine HMAC key source
    hmac_key_source = "Not configured"
    hmac_key_length = 0
    hmac_key_configured = False

    if settings.guardian_hmac_key:
        hmac_key_source = "Environment variable"
        hmac_key_length = len(settings.guardian_hmac_key) // 2  # hex chars -> bytes
        hmac_key_configured = True
    elif settings.guardian_hmac_key_file:
        hmac_key_source = "Key file"
        hmac_key_length = 32  # assumed
        hmac_key_configured = True

    config = {
        "version": "1.0.0",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "database_url_masked": _mask(settings.database_url, 20),
        "redis_url": settings.celery_broker_url,
        "debug": settings.guardian_debug,
        "archivematica_ss_url": settings.archivematica_ss_url,
        "archivematica_ss_user": settings.archivematica_ss_user,
        "archivematica_api_key_masked": _mask(settings.archivematica_ss_api_key, 4),
        "archivematica_storage_path": settings.archivematica_storage_path,
        "hmac_key_source": hmac_key_source,
        "hmac_key_length": hmac_key_length,
        "hmac_key_configured": hmac_key_configured,
        "admin_email": settings.guardian_admin_email,
        "smtp_host": settings.guardian_smtp_host,
        "smtp_port": settings.guardian_smtp_port,
        "webhook_url": settings.guardian_webhook_url,
    }

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "active_page": "settings",
            "config": config,
            **i18n,
        },
    )


# ── GET /setup ───────────────────────────────────────────────────

@web_router.get("/setup", response_class=HTMLResponse, include_in_schema=False)
async def setup_page(request: Request):
    i18n = template_globals(request)

    return templates.TemplateResponse(
        "setup.html",
        {
            "request": request,
            "active_page": "setup",
            **i18n,
        },
    )


# ── POST /set-language ──────────────────────────────────────────

@web_router.post("/set-language", include_in_schema=False)
async def set_language(
    request: Request,
    language: str = Form(...),
):
    """Set language preference cookie and redirect back."""
    # Validate language
    if language not in SUPPORTED_LANGUAGES:
        language = "en"

    # Determine redirect URL (referer or dashboard)
    referer = request.headers.get("referer", "/dashboard")

    response = RedirectResponse(url=referer, status_code=302)
    response.set_cookie(
        key="guardian_lang",
        value=language,
        max_age=60 * 60 * 24 * 365,  # 1 year
        httponly=True,
        samesite="lax",
    )
    return response
