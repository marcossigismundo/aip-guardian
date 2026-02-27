"""Pydantic v2 schemas for audit-log API endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AuditLogResponse(BaseModel):
    """Single audit-log record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    aip_uuid: uuid.UUID
    event_type: str
    status: str
    details: dict
    previous_hash: str
    record_hash: str
    created_at: datetime


class AuditLogListResponse(BaseModel):
    """Paginated list of audit-log records."""

    items: list[AuditLogResponse]
    total: int = Field(..., ge=0, description="Total number of records matching the query")
    page: int = Field(..., ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(..., ge=1, description="Number of records per page")


class ChainStatusResponse(BaseModel):
    """Result of an audit-chain integrity verification."""

    total_records: int = Field(..., ge=0, description="Number of records examined")
    chain_valid: bool = Field(..., description="True if the full hash chain is intact")
    broken_links: list[int] = Field(
        default_factory=list,
        description="Record IDs where the hash chain is broken",
    )
    verified_at: datetime = Field(..., description="Timestamp when verification completed")
