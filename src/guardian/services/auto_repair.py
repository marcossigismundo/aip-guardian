"""Auto-Repair Service — automated recovery from AIP corruption.

Component 5 — ISO 16363 §4.3.3.1, §4.3.4

When corruption is detected, this service locates a healthy replica,
verifies its integrity, copies the affected files, and re-verifies the
repaired AIP.  Every step is logged to the audit trail.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from guardian.models.repair_record import RepairRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RepairResult:
    """Outcome of an auto-repair attempt."""

    status: str
    """One of ``"success"``, ``"partial"``, ``"failed"``."""

    repaired_files: list[str] = field(default_factory=list)
    """Relative paths of files that were successfully repaired."""

    source_replica: str = ""
    """Location name / path of the replica used as the repair source."""

    details: dict = field(default_factory=dict)
    """Additional context (errors, skipped files, etc.)."""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class AutoRepair:
    """Attempt to repair a corrupted AIP from a healthy replica.

    Collaborators
    -------------
    * ``fixity_verifier`` — verifies BagIt fixity; exposes ``verify(aip_uuid, path) -> VerificationResult``.
    * ``hmac_authenticator`` — verifies manifest HMAC; exposes ``register_aip(session, aip_uuid, path)``.
    * ``replica_manager`` — locates and validates replicas;
      exposes ``find_healthy_replica(aip_uuid, fixity_verifier, hmac_authenticator) -> dict | None``.
    """

    def __init__(
        self,
        fixity_verifier: object,
        hmac_authenticator: object,
        replica_manager: object,
    ) -> None:
        self._fixity = fixity_verifier
        self._hmac = hmac_authenticator
        self._replicas = replica_manager

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def repair(
        self,
        session: Session,
        aip_uuid: str,
        aip_path: str,
        corruption_report: dict,
    ) -> RepairResult:
        """Run the full auto-repair workflow.

        Parameters
        ----------
        session:
            Active SQLAlchemy session (caller manages commit / rollback).
        aip_uuid:
            UUID of the corrupted AIP.
        aip_path:
            Filesystem path to the primary (corrupted) copy.
        corruption_report:
            Output from a fixity check, expected to contain at least
            ``{"corrupted_files": [{"path": str, "expected_hash": str, ...}, ...]}``

        Returns
        -------
        RepairResult
        """
        from guardian.services.audit_logger import AuditLogger

        corrupted_files: list[dict] = corruption_report.get("corrupted_files", [])
        if not corrupted_files:
            logger.info("No corrupted files reported for AIP %s; nothing to repair.", aip_uuid)
            return RepairResult(status="success", details={"message": "No corrupted files."})

        # --- Step 1: locate a healthy replica --------------------------------
        healthy = self._replicas.find_healthy_replica(
            aip_uuid, self._fixity, self._hmac,
        )
        if healthy is None:
            logger.error(
                "No healthy replica available for AIP %s. Repair aborted.",
                aip_uuid,
            )
            AuditLogger.log(
                session,
                aip_uuid=aip_uuid,
                event_type="auto_repair",
                status="fail",
                details={"error": "No healthy replica found."},
            )
            return RepairResult(
                status="failed",
                details={"error": "No healthy replica found for repair."},
            )

        source_path: str = healthy.get("path", "")
        source_name: str = healthy.get("location_name", source_path)

        logger.info(
            "Using replica '%s' (%s) as repair source for AIP %s.",
            source_name,
            source_path,
            aip_uuid,
        )

        # --- Step 2 & 3: copy corrupted files from healthy replica -----------
        repaired: list[str] = []
        errors: list[dict] = []

        for entry in corrupted_files:
            file_rel_path = entry.get("path", "")
            expected_hash = entry.get("expected_hash", "")

            if not file_rel_path:
                logger.warning("Corruption entry missing 'path'; skipping: %s", entry)
                errors.append({"file": "(unknown)", "error": "Missing path in report."})
                continue

            source_file = Path(source_path) / file_rel_path
            target_file = Path(aip_path) / file_rel_path

            try:
                # Verify the source file hash *before* copying.
                if expected_hash and not self._verify_file_hash(source_file, expected_hash):
                    msg = (
                        f"Source file {source_file} hash mismatch; "
                        f"expected {expected_hash}. Skipping."
                    )
                    logger.warning(msg)
                    errors.append({"file": file_rel_path, "error": msg})
                    continue

                # Ensure target directory exists.
                target_file.parent.mkdir(parents=True, exist_ok=True)

                # Copy with metadata preservation.
                shutil.copy2(str(source_file), str(target_file))
                repaired.append(file_rel_path)
                logger.info("Repaired file: %s", file_rel_path)

            except OSError:
                logger.exception("Failed to repair file %s", file_rel_path)
                errors.append({"file": file_rel_path, "error": "Copy failed (OS error)."})

        # --- Step 4: re-verify entire AIP after repair -----------------------
        post_repair_valid = False
        try:
            fixity_result = self._fixity.verify(aip_uuid, aip_path)
            post_repair_valid = fixity_result.passed
        except Exception:
            logger.exception("Post-repair fixity check failed for AIP %s", aip_uuid)

        # --- Step 5: re-register HMAC if successful --------------------------
        if post_repair_valid and not errors:
            try:
                self._hmac.register_aip(session, aip_uuid, aip_path)
                logger.info("HMAC re-registered for repaired AIP %s.", aip_uuid)
            except Exception:
                logger.exception("Failed to re-register HMAC for AIP %s after repair.", aip_uuid)
                errors.append({"file": "(hmac)", "error": "HMAC re-registration failed."})

        # --- Determine final status ------------------------------------------
        if not repaired:
            final_status = "failed"
        elif errors or not post_repair_valid:
            final_status = "partial"
        else:
            final_status = "success"

        result = RepairResult(
            status=final_status,
            repaired_files=repaired,
            source_replica=source_name,
            details={
                "errors": errors,
                "post_repair_valid": post_repair_valid,
                "files_attempted": len(corrupted_files),
                "files_repaired": len(repaired),
            },
        )

        # --- Step 6: audit logging -------------------------------------------
        AuditLogger.log(
            session,
            aip_uuid=aip_uuid,
            event_type="auto_repair",
            status="pass" if final_status == "success" else "fail",
            details=result.details,
        )
        self._record_repair(
            session,
            aip_uuid,
            status=final_status,
            source_replica=source_name,
            repaired_files=repaired,
            details=result.details,
        )

        logger.info(
            "Repair completed for AIP %s: status=%s, repaired=%d/%d",
            aip_uuid,
            final_status,
            len(repaired),
            len(corrupted_files),
        )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verify_file_hash(file_path: Path, expected_hash: str) -> bool:
        """Compute SHA-256 of *file_path* and compare with *expected_hash*."""
        if not file_path.is_file():
            logger.warning("Source file does not exist: %s", file_path)
            return False

        sha256 = hashlib.sha256()
        try:
            with file_path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65_536), b""):
                    sha256.update(chunk)
        except OSError:
            logger.exception("Failed to hash file %s", file_path)
            return False

        return sha256.hexdigest().lower() == expected_hash.lower()

    @staticmethod
    def _record_repair(
        session: Session,
        aip_uuid: str,
        *,
        status: str,
        source_replica: str,
        repaired_files: list[str],
        details: dict,
    ) -> None:
        """Persist a :class:`RepairRecord` row."""
        try:
            record = RepairRecord(
                aip_uuid=aip_uuid,
                status=status,
                source_replica=source_replica,
                files_repaired=repaired_files,
                details=details,
            )
            session.add(record)
        except Exception:
            logger.exception("Failed to write repair record for AIP %s.", aip_uuid)
