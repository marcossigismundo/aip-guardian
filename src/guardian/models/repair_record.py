"""RepairRecord model — records of auto-repair operations."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian.models.base import Base


class RepairRecord(Base):
    """
    Table 6: Auto-repair records.
    Documents every repair operation including source replica and result.
    ISO 16363 §4.3.3.1, §4.3.4
    """

    __tablename__ = "repair_record"
    __table_args__ = (
        Index("idx_repair_aip", "aip_uuid"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    aip_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("aip_integrity_status.aip_uuid", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # success, partial, failed
    source_replica: Mapped[str] = mapped_column(String(500), default="")
    files_repaired: Mapped[dict] = mapped_column(JSONB, default=list)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    repaired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationship
    aip: Mapped["AIPStatus"] = relationship(back_populates="repair_records")  # noqa: F821

    def __repr__(self) -> str:
        return f"<RepairRecord {self.aip_uuid} [{self.status}]>"
