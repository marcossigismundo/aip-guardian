"""ContentFingerprint model — content fingerprints for change detection."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian.models.base import Base


class ContentFingerprint(Base):
    """
    Table 4: Content fingerprints for detecting real changes.
    Used by Component 4 (Change Detector) to prevent unnecessary re-ingestion.
    ISO 16363 §4.3.1
    """

    __tablename__ = "content_fingerprint"
    __table_args__ = (
        Index("idx_fp_aip_computed", "aip_uuid", "computed_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    aip_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("aip_integrity_status.aip_uuid", ondelete="CASCADE"),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_hash: Mapped[str] = mapped_column(String(64), default="")
    files_hash: Mapped[str] = mapped_column(String(64), default="")
    files_count: Mapped[int] = mapped_column(Integer, default=0)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationship
    aip: Mapped["AIPStatus"] = relationship(back_populates="fingerprints")  # noqa: F821

    def __repr__(self) -> str:
        return f"<ContentFingerprint {self.aip_uuid} @ {self.computed_at}>"
