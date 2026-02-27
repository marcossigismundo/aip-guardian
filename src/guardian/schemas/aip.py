"""Pydantic v2 schemas for AIP-related API endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AIPRegisterRequest(BaseModel):
    """Request body for registering a new AIP in Guardian."""

    archivematica_uuid: uuid.UUID = Field(
        ..., description="UUID assigned by Archivematica to this AIP"
    )
    storage_path: str = Field(
        ..., min_length=1, description="Absolute path to the AIP on storage"
    )
    storage_location: str = Field(
        default="", description="Archivematica storage location identifier"
    )


class AIPStatusResponse(BaseModel):
    """Full status record for a single AIP."""

    model_config = ConfigDict(from_attributes=True)

    aip_uuid: uuid.UUID
    archivematica_uuid: uuid.UUID
    storage_location: str
    storage_path: str
    last_verified: datetime | None
    last_status: str
    last_hmac_check: datetime | None
    content_fingerprint: str
    total_verifications: int
    total_failures: int
    total_files: int
    created_at: datetime
    updated_at: datetime


class AIPListResponse(BaseModel):
    """Paginated list of AIP status records."""

    items: list[AIPStatusResponse]
    total: int = Field(..., ge=0, description="Total number of records matching the query")
    page: int = Field(..., ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(..., ge=1, description="Number of records per page")


class VerifyResponse(BaseModel):
    """Response returned when a fixity verification task is enqueued."""

    task_id: str = Field(..., description="Celery task ID for tracking")
    aip_uuid: uuid.UUID = Field(..., description="UUID of the AIP being verified")
    message: str = Field(..., description="Human-readable status message")
