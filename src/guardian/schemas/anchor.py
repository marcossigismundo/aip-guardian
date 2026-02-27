"""Pydantic v2 schemas for anchor-registry API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class AnchorResponse(BaseModel):
    """Single anchor-registry record.

    The ``timestamp_token`` field is serialised as a hex string for
    JSON transport (the DB stores raw bytes).
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    batch_start_id: int
    batch_end_id: int
    batch_hash: str
    merkle_root: str
    tsa_url: str
    timestamp_token: str | None = Field(
        default=None,
        description="RFC 3161 timestamp token encoded as hex string",
    )
    publication_method: str
    publication_proof: dict
    anchored_at: datetime

    @field_serializer("timestamp_token")
    def _serialize_token(self, value: bytes | str | None, _info: Any) -> str | None:
        """Convert raw bytes coming from the ORM into a hex string."""
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.hex()
        return value


class AnchorListResponse(BaseModel):
    """Paginated list of anchor records."""

    items: list[AnchorResponse]
    total: int = Field(..., ge=0, description="Total number of anchor records")
    page: int = Field(default=1, ge=1, description="Current page number")
    page_size: int = Field(default=50, ge=1, description="Records per page")


class AnchorVerifyResponse(BaseModel):
    """Result of verifying a single anchor record."""

    anchor_id: int
    valid: bool
    details: dict = Field(default_factory=dict)
