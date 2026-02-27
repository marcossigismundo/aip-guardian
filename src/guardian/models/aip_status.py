"""AIPStatus model — integrity status for each monitored AIP."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian.models.base import Base


class AIPStatus(Base):
    """
    Table 1: Integrity status per AIP.
    One record per AIP monitored by Guardian.
    """

    __tablename__ = "aip_integrity_status"

    aip_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    archivematica_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, nullable=False
    )
    storage_location: Mapped[str] = mapped_column(String(500), default="")
    storage_path: Mapped[str] = mapped_column(String(1000), default="")

    last_verified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    last_hmac_check: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    content_fingerprint: Mapped[str] = mapped_column(String(64), default="")

    total_verifications: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_files: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    hmac_records: Mapped[list["HMACRegistry"]] = relationship(  # noqa: F821
        back_populates="aip", cascade="all, delete-orphan"
    )
    fingerprints: Mapped[list["ContentFingerprint"]] = relationship(  # noqa: F821
        back_populates="aip", cascade="all, delete-orphan"
    )
    repair_records: Mapped[list["RepairRecord"]] = relationship(  # noqa: F821
        back_populates="aip", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<AIPStatus {self.archivematica_uuid} [{self.last_status}]>"
