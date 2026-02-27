"""HMACRegistry model — HMAC authentication records for AIP manifests."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian.models.base import Base


class HMACRegistry(Base):
    """
    Table 2: HMAC records for manifest authentication.
    Each AIP has one HMAC per manifest file (manifest-sha256.txt, etc.).
    ISO 16363 §4.3.3, §5.2.2
    """

    __tablename__ = "hmac_registry"
    __table_args__ = (
        UniqueConstraint("aip_uuid", "manifest_name", name="uq_hmac_aip_manifest"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    aip_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("aip_integrity_status.aip_uuid", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    manifest_name: Mapped[str] = mapped_column(String(100), nullable=False)
    hmac_value: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(20), default="hmac-sha256", nullable=False)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship
    aip: Mapped["AIPStatus"] = relationship(back_populates="hmac_records")  # noqa: F821

    def __repr__(self) -> str:
        return f"<HMACRegistry {self.aip_uuid}:{self.manifest_name}>"
