"""Pydantic v2 schemas for dashboard and health-check endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DashboardSummaryResponse(BaseModel):
    """High-level overview of the Guardian system state."""

    total_aips: int = Field(..., ge=0, description="Total registered AIPs")
    verified_ok: int = Field(..., ge=0, description="AIPs whose last fixity check passed")
    corrupted: int = Field(..., ge=0, description="AIPs with detected corruption")
    repaired: int = Field(..., ge=0, description="AIPs successfully auto-repaired")
    never_verified: int = Field(
        ..., ge=0, description="AIPs that have never been verified"
    )
    last_full_check: datetime | None = Field(
        default=None, description="Timestamp of the most recent full verification run"
    )
    audit_chain_valid: bool = Field(
        ..., description="Whether the audit-log hash chain is intact"
    )
    last_anchor_at: datetime | None = Field(
        default=None,
        description="Timestamp of the most recent external anchor",
    )


class HealthResponse(BaseModel):
    """Service health check result."""

    status: str = Field(..., description="Overall health status (healthy / degraded / unhealthy)")
    version: str = Field(..., description="Application version string")
    database: bool = Field(..., description="True if the database is reachable")
    redis: bool = Field(..., description="True if Redis is reachable")
    celery: bool = Field(..., description="True if at least one Celery worker is responding")
    archivematica: bool = Field(
        ..., description="True if Archivematica Storage Service is reachable"
    )
