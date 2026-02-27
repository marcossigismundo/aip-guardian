"""AuditLog model — immutable hash-chained audit log."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from guardian.models.base import Base


class AuditLog(Base):
    """
    Table 3: Immutable audit log with hash chain.
    Protected by PostgreSQL trigger preventing UPDATE/DELETE.
    ISO 16363 §4.3.2.1, §4.6.1
    """

    __tablename__ = "aip_integrity_audit_log"
    __table_args__ = (
        Index("idx_audit_aip_uuid", "aip_uuid"),
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_created_at", "created_at"),
        Index("idx_audit_fail_status", "status", postgresql_where="status != 'pass'"),
    )

    # Valid event types
    EVENT_TYPES = (
        "fixity_check",
        "hmac_verify",
        "tamper_detected",
        "auto_repair",
        "anchor_submitted",
        "anchor_confirmed",
        "aip_registered",
        "health_check",
        "chain_verify",
    )

    # Valid status values
    STATUS_CHOICES = ("pass", "fail", "warning", "error")

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    aip_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # Hash chain fields
    previous_hash: Mapped[str] = mapped_column(String(64), default="GENESIS", nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<AuditLog #{self.id} {self.event_type}:{self.status}>"
