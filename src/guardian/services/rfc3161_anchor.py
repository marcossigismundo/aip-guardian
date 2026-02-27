"""RFC 3161 Timestamp Anchor Service — external cryptographic anchoring.

Component 6 — ISO 16363 §5.2.2

Batches audit-log record hashes, constructs a Merkle tree, and submits
the root to one or more RFC 3161 Time-Stamp Authorities (TSAs).  The
resulting timestamp token is persisted in the :class:`AnchorRegistry`
for later independent verification.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

import rfc3161ng
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.models.anchor_registry import AnchorRegistry
from guardian.services.merkle_tree import MerkleTreeBuilder

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class AnchorResult:
    """Outcome of a batch anchor submission."""

    batch_size: int = 0
    """Number of audit records included in the batch."""

    batch_hash: str = ""
    """SHA-256 hex digest of the concatenated record hashes."""

    merkle_root: str = ""
    """Hex-encoded Merkle root of the batch."""

    tsa_url: str = ""
    """The TSA URL that successfully issued the timestamp token."""

    success: bool = False
    """Whether the anchoring operation succeeded."""

    details: dict = field(default_factory=dict)
    """Additional context (errors, token info, etc.)."""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class RFC3161Anchor:
    """Submit audit-log batches to RFC 3161 TSAs and record the results.

    Maintains a prioritised list of TSA endpoints and falls through to
    the next one on failure.
    """

    TSA_URLS: list[str] = [
        "https://freetsa.org/tsr",
        "https://timestamp.digicert.com",
        "http://timestamp.sectigo.com",
    ]

    # ------------------------------------------------------------------
    # Batch submission
    # ------------------------------------------------------------------

    def submit_batch(
        self,
        session: Session,
        batch_records: list[dict],
    ) -> AnchorResult:
        """Anchor a batch of audit records via RFC 3161.

        Parameters
        ----------
        session:
            Active SQLAlchemy session (caller manages commit).
        batch_records:
            List of dicts, each containing at least ``"id"`` (int) and
            ``"record_hash"`` (str, hex SHA-256).

        Returns
        -------
        AnchorResult
        """
        from guardian.services.audit_logger import AuditLogger

        if not batch_records:
            logger.warning("submit_batch called with an empty batch.")
            return AnchorResult(success=False, details={"error": "Empty batch."})

        # --- 1. Compute batch hash ------------------------------------------
        record_hashes = [r["record_hash"] for r in batch_records]
        batch_hash = self._compute_batch_hash(record_hashes)

        # --- 2. Build Merkle tree -------------------------------------------
        try:
            tree = MerkleTreeBuilder.build(record_hashes)
            merkle_root = tree.root
        except ValueError:
            logger.exception("Failed to build Merkle tree for batch.")
            return AnchorResult(
                batch_size=len(batch_records),
                batch_hash=batch_hash,
                success=False,
                details={"error": "Merkle tree construction failed."},
            )

        # --- 3. Submit to TSA (try each until success) ----------------------
        timestamp_token: bytes | None = None
        used_tsa: str = ""

        data_to_stamp = merkle_root.encode("utf-8")

        for tsa_url in self.TSA_URLS:
            try:
                token = rfc3161ng.get_timestamp(
                    tsa_url,
                    data=data_to_stamp,
                    hashname="sha256",
                )
                if token is not None:
                    timestamp_token = token
                    used_tsa = tsa_url
                    logger.info(
                        "Timestamp token obtained from %s for batch hash %s",
                        tsa_url,
                        batch_hash[:16],
                    )
                    break
                else:
                    logger.warning("TSA %s returned empty token.", tsa_url)
            except Exception:
                logger.exception("TSA request to %s failed.", tsa_url)
                continue

        success = timestamp_token is not None

        if not success:
            logger.error(
                "All TSA endpoints failed for batch hash %s. "
                "Anchor will be stored without a timestamp token.",
                batch_hash[:16],
            )

        # --- 4. Persist AnchorRegistry record --------------------------------
        batch_ids = [r["id"] for r in batch_records]
        batch_start = min(batch_ids)
        batch_end = max(batch_ids)

        anchor = AnchorRegistry(
            batch_start_id=batch_start,
            batch_end_id=batch_end,
            batch_hash=batch_hash,
            merkle_root=merkle_root,
            tsa_url=used_tsa,
            timestamp_token=timestamp_token,
            publication_method="rfc3161" if success else "pending",
            publication_proof={
                "merkle_root": merkle_root,
                "batch_size": len(batch_records),
                "record_ids": batch_ids,
            },
        )
        session.add(anchor)

        logger.info(
            "Anchor record created: batch %d\u2013%d, hash=%s, tsa=%s, success=%s",
            batch_start,
            batch_end,
            batch_hash[:16],
            used_tsa or "(none)",
            success,
        )

        # --- 5. Write audit entry for the anchor event -----------------------
        try:
            AuditLogger.log(
                session,
                aip_uuid="00000000-0000-0000-0000-000000000000",
                event_type="anchor_submitted",
                status="pass" if success else "warning",
                details={
                    "batch_start_id": batch_start,
                    "batch_end_id": batch_end,
                    "batch_hash": batch_hash,
                    "merkle_root": merkle_root,
                    "tsa_url": used_tsa,
                },
            )
        except Exception:
            logger.exception("Failed to write audit log for anchor submission.")

        return AnchorResult(
            batch_size=len(batch_records),
            batch_hash=batch_hash,
            merkle_root=merkle_root,
            tsa_url=used_tsa,
            success=success,
            details={"batch_start_id": batch_start, "batch_end_id": batch_end},
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_anchor(self, session: Session, anchor_id: int) -> dict:
        """Verify that an existing anchor record matches its audit data.

        Loads the :class:`AnchorRegistry` row identified by *anchor_id*,
        retrieves the corresponding audit-log records, recalculates the
        batch hash, and compares it with the stored value.

        Parameters
        ----------
        session:
            Active SQLAlchemy session.
        anchor_id:
            Primary key of the anchor to verify.

        Returns
        -------
        dict
            ``{"valid": bool, "anchor_id": int, "details": ...}``
        """
        from guardian.models.audit_log import AuditLog

        anchor: AnchorRegistry | None = session.get(AnchorRegistry, anchor_id)
        if anchor is None:
            logger.warning("Anchor %d not found.", anchor_id)
            return {"valid": False, "anchor_id": anchor_id, "details": "Anchor not found."}

        # Fetch audit records in the batch range.
        stmt = (
            select(AuditLog)
            .where(
                AuditLog.id >= anchor.batch_start_id,
                AuditLog.id <= anchor.batch_end_id,
            )
            .order_by(AuditLog.id)
        )
        audit_records = list(session.execute(stmt).scalars().all())

        if not audit_records:
            logger.warning("No audit records found for anchor %d.", anchor_id)
            return {
                "valid": False,
                "anchor_id": anchor_id,
                "details": "No audit records in batch range.",
            }

        # Recompute batch hash.
        record_hashes = [r.record_hash for r in audit_records]
        recomputed = self._compute_batch_hash(record_hashes)

        is_valid = recomputed == anchor.batch_hash
        if not is_valid:
            logger.warning(
                "Anchor %d hash mismatch: stored=%s, recomputed=%s",
                anchor_id,
                anchor.batch_hash[:16],
                recomputed[:16],
            )
        else:
            logger.info("Anchor %d verified successfully.", anchor_id)

        return {
            "valid": is_valid,
            "anchor_id": anchor_id,
            "stored_hash": anchor.batch_hash,
            "recomputed_hash": recomputed,
            "records_count": len(audit_records),
            "details": "Hash match." if is_valid else "Hash mismatch.",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_batch_hash(record_hashes: list[str]) -> str:
        """SHA-256 of all record hashes concatenated in order."""
        hasher = hashlib.sha256()
        for h in record_hashes:
            hasher.update(h.encode("utf-8"))
        return hasher.hexdigest()
