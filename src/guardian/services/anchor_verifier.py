"""Anchor Verifier — validate stored RFC 3161 / Merkle anchors.

Provides convenience methods that iterate over :class:`AnchorRegistry`
records and verify each one against the audit log, using the
:class:`RFC3161Anchor` service for the actual comparison logic.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian.models.anchor_registry import AnchorRegistry
from guardian.services.rfc3161_anchor import RFC3161Anchor

logger = logging.getLogger(__name__)


class AnchorVerifier:
    """High-level verification of stored anchor records."""

    def __init__(self) -> None:
        self._anchor_service = RFC3161Anchor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_all_anchors(self, session: Session) -> dict:
        """Verify every anchor record in the database.

        Returns
        -------
        dict
            ``{"total": int, "valid": int, "invalid": int, "details": list[dict]}``
        """
        stmt = select(AnchorRegistry).order_by(AnchorRegistry.id)
        anchors: list[AnchorRegistry] = list(session.execute(stmt).scalars().all())

        total = len(anchors)
        valid = 0
        invalid = 0
        details: list[dict] = []

        logger.info("Starting verification of %d anchor record(s).", total)

        for anchor in anchors:
            try:
                result = self._anchor_service.verify_anchor(session, anchor.id)
                if result.get("valid", False):
                    valid += 1
                else:
                    invalid += 1
                details.append(result)
            except Exception:
                logger.exception("Error verifying anchor %d.", anchor.id)
                invalid += 1
                details.append({
                    "valid": False,
                    "anchor_id": anchor.id,
                    "details": "Verification raised an exception.",
                })

        summary = {
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "details": details,
        }

        logger.info(
            "Anchor verification complete: %d total, %d valid, %d invalid.",
            total,
            valid,
            invalid,
        )
        return summary

    def verify_recent_anchor(self, session: Session) -> dict:
        """Verify only the most recently created anchor record.

        Returns
        -------
        dict
            Verification result for the latest anchor, or an error dict
            if no anchors exist.
        """
        stmt = (
            select(AnchorRegistry)
            .order_by(AnchorRegistry.anchored_at.desc())
            .limit(1)
        )
        anchor: AnchorRegistry | None = session.execute(stmt).scalar_one_or_none()

        if anchor is None:
            logger.warning("No anchor records found in the database.")
            return {
                "total": 0,
                "valid": 0,
                "invalid": 0,
                "details": "No anchor records exist.",
            }

        try:
            result = self._anchor_service.verify_anchor(session, anchor.id)
        except Exception:
            logger.exception("Error verifying most recent anchor %d.", anchor.id)
            result = {
                "valid": False,
                "anchor_id": anchor.id,
                "details": "Verification raised an exception.",
            }

        logger.info(
            "Recent anchor %d verification: valid=%s",
            anchor.id,
            result.get("valid"),
        )
        return result
