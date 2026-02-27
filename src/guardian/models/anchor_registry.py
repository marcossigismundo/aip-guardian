"""AnchorRegistry model — external cryptographic anchors (RFC 3161 / Merkle)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian.models.base import Base


class AnchorRegistry(Base):
    """
    Table 5: External anchor records.
    Stores RFC 3161 timestamp tokens and Merkle tree roots.
    ISO 16363 §5.2.2, §5.2.3
    """

    __tablename__ = "anchor_registry"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    batch_start_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    batch_end_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    batch_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), default="")
    tsa_url: Mapped[str] = mapped_column(String(500), default="")
    timestamp_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    publication_method: Mapped[str] = mapped_column(String(50), default="")
    publication_proof: Mapped[dict] = mapped_column(JSONB, default=dict)
    anchored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<AnchorRegistry #{self.id} [{self.publication_method}]>"
