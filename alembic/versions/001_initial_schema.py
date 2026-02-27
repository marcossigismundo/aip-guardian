"""Initial schema — 6 tables + immutability triggers.

Revision ID: 001
Revises: None
Create Date: 2026-02-26
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable pgcrypto for gen_random_uuid()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # Table 1: AIP integrity status
    op.create_table(
        "aip_integrity_status",
        sa.Column("aip_uuid", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("archivematica_uuid", UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("storage_location", sa.String(500), server_default=""),
        sa.Column("storage_path", sa.String(1000), server_default=""),
        sa.Column("last_verified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("last_hmac_check", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_fingerprint", sa.String(64), server_default=""),
        sa.Column("total_verifications", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_files", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "last_status IN ('pending','valid','corrupted','repaired','error')",
            name="ck_aip_status_value",
        ),
    )

    # Table 2: HMAC registry
    op.create_table(
        "hmac_registry",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("aip_uuid", UUID(as_uuid=True), sa.ForeignKey("aip_integrity_status.aip_uuid", ondelete="CASCADE"), nullable=False),
        sa.Column("manifest_name", sa.String(100), nullable=False),
        sa.Column("hmac_value", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(20), nullable=False, server_default="hmac-sha256"),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("aip_uuid", "manifest_name", name="uq_hmac_aip_manifest"),
    )
    op.create_index("idx_hmac_aip", "hmac_registry", ["aip_uuid"])

    # Table 3: Audit log (immutable, hash-chained)
    op.create_table(
        "aip_integrity_audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("aip_uuid", UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("previous_hash", sa.String(64), nullable=False, server_default="GENESIS"),
        sa.Column("record_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "status IN ('pass','fail','warning','error')",
            name="ck_audit_status_value",
        ),
    )
    op.create_index("idx_audit_aip_uuid", "aip_integrity_audit_log", ["aip_uuid"])
    op.create_index("idx_audit_event_type", "aip_integrity_audit_log", ["event_type"])
    op.create_index("idx_audit_created_at", "aip_integrity_audit_log", ["created_at"])

    # Partial index for non-pass statuses (fast failure queries)
    op.execute(
        "CREATE INDEX idx_audit_fail_status ON aip_integrity_audit_log(status) WHERE status != 'pass'"
    )

    # Immutability trigger — prevent UPDATE and DELETE on audit log
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_audit_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Audit log records are immutable. Operation % denied.', TG_OP;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER audit_immutability
            BEFORE UPDATE OR DELETE ON aip_integrity_audit_log
            FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
    """)

    # Table 4: Content fingerprint
    op.create_table(
        "content_fingerprint",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("aip_uuid", UUID(as_uuid=True), sa.ForeignKey("aip_integrity_status.aip_uuid", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("metadata_hash", sa.String(64), server_default=""),
        sa.Column("files_hash", sa.String(64), server_default=""),
        sa.Column("files_count", sa.Integer, server_default="0"),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_fp_aip_computed", "content_fingerprint", ["aip_uuid", "computed_at"])

    # Table 5: Anchor registry
    op.create_table(
        "anchor_registry",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("batch_start_id", sa.BigInteger, nullable=False),
        sa.Column("batch_end_id", sa.BigInteger, nullable=False),
        sa.Column("batch_hash", sa.String(64), nullable=False),
        sa.Column("merkle_root", sa.String(64), server_default=""),
        sa.Column("tsa_url", sa.String(500), server_default=""),
        sa.Column("timestamp_token", sa.LargeBinary, nullable=True),
        sa.Column("publication_method", sa.String(50), server_default=""),
        sa.Column("publication_proof", JSONB, server_default=sa.text("'{}'")),
        sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )

    # Table 6: Repair records
    op.create_table(
        "repair_record",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("aip_uuid", UUID(as_uuid=True), sa.ForeignKey("aip_integrity_status.aip_uuid", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("source_replica", sa.String(500), server_default=""),
        sa.Column("files_repaired", JSONB, server_default=sa.text("'[]'")),
        sa.Column("details", JSONB, server_default=sa.text("'{}'")),
        sa.Column("repaired_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "status IN ('success','partial','failed')",
            name="ck_repair_status_value",
        ),
    )
    op.create_index("idx_repair_aip", "repair_record", ["aip_uuid"])


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_immutability ON aip_integrity_audit_log")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_modification()")
    op.drop_table("repair_record")
    op.drop_table("anchor_registry")
    op.drop_table("content_fingerprint")
    op.drop_table("aip_integrity_audit_log")
    op.drop_table("hmac_registry")
    op.drop_table("aip_integrity_status")
