"""Change Detector — content fingerprinting for real-change detection.

Component 4 — ISO 16363 §4.3.1

Generates a stable SHA-256 fingerprint from file hashes and metadata,
excluding volatile fields that change on every access (view counters,
cache timestamps, etc.).  The fingerprint is compared against the
previously stored value to decide whether a new fixity cycle is needed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.models.content_fingerprint import ContentFingerprint

logger = logging.getLogger(__name__)


class ChangeDetector:
    """Detect *meaningful* changes in AIP content and metadata.

    Volatile metadata fields (counters, timestamps used only for display)
    are excluded from the fingerprint so that cosmetic updates do not
    trigger expensive re-verification cycles.
    """

    # Fields that may change without affecting archival integrity.
    VOLATILE_FIELDS: set[str] = frozenset({
        "lastModified",
        "accessDate",
        "editLock",
        "viewCount",
        "cacheTimestamp",
    })

    # ------------------------------------------------------------------
    # Fingerprint computation
    # ------------------------------------------------------------------

    def compute_fingerprint(
        self,
        aip_path: str,
        metadata: dict | None = None,
    ) -> str:
        """Compute a deterministic SHA-256 fingerprint for an AIP.

        The fingerprint covers:
        * The sorted list of ``(relative_path, sha256_hex)`` pairs
          derived from the BagIt manifest (``manifest-sha256.txt``).
        * All metadata keys *not* in :attr:`VOLATILE_FIELDS`, serialised
          as sorted JSON.

        Parameters
        ----------
        aip_path:
            Filesystem path to the root of an extracted AIP / Bag.
        metadata:
            Optional dictionary of AIP-level metadata.  Volatile keys
            are stripped before hashing.

        Returns
        -------
        str
            64-character lowercase hex SHA-256 digest.
        """
        hasher = hashlib.sha256()

        # --- 1. File hashes from manifest -----------------------------------
        files_hash, files_count = self._hash_manifest_files(aip_path)
        hasher.update(files_hash.encode("utf-8"))

        # --- 2. Stable metadata ---------------------------------------------
        metadata_hash = self._hash_stable_metadata(metadata)
        hasher.update(metadata_hash.encode("utf-8"))

        fingerprint = hasher.hexdigest()
        logger.debug(
            "Computed fingerprint for %s: %s (%d files, metadata_hash=%s)",
            aip_path,
            fingerprint,
            files_count,
            metadata_hash[:16],
        )
        return fingerprint

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def has_changed(
        self,
        session: Session,
        aip_uuid: UUID,
        current_fingerprint: str,
    ) -> bool:
        """Return ``True`` if *current_fingerprint* differs from the stored one.

        Uses :func:`hmac.compare_digest` for timing-safe comparison so
        that an external observer cannot infer partial fingerprint matches
        from response latency.

        Parameters
        ----------
        session:
            Active SQLAlchemy session.
        aip_uuid:
            UUID of the AIP to check.
        current_fingerprint:
            The freshly computed fingerprint to compare.

        Returns
        -------
        bool
            ``True`` if the AIP content has changed (or no previous
            fingerprint exists), ``False`` otherwise.
        """
        stmt = (
            select(ContentFingerprint)
            .where(ContentFingerprint.aip_uuid == aip_uuid)
            .order_by(ContentFingerprint.computed_at.desc())
            .limit(1)
        )
        stored: ContentFingerprint | None = session.execute(stmt).scalar_one_or_none()

        if stored is None:
            logger.info("No prior fingerprint for AIP %s — treating as changed.", aip_uuid)
            return True

        changed = not hmac.compare_digest(stored.fingerprint, current_fingerprint)
        if changed:
            logger.info(
                "AIP %s fingerprint changed: stored=%s, current=%s",
                aip_uuid,
                stored.fingerprint[:16] + "...",
                current_fingerprint[:16] + "...",
            )
        else:
            logger.debug("AIP %s fingerprint unchanged.", aip_uuid)

        return changed

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def record_fingerprint(
        self,
        session: Session,
        aip_uuid: UUID,
        fingerprint: str,
        metadata_hash: str = "",
        files_hash: str = "",
        files_count: int = 0,
    ) -> ContentFingerprint:
        """Persist a new :class:`ContentFingerprint` row.

        Parameters
        ----------
        session:
            Active SQLAlchemy session (caller is responsible for commit).
        aip_uuid:
            UUID of the AIP.
        fingerprint:
            The full 64-char hex fingerprint.
        metadata_hash:
            Optional sub-hash of the stable metadata portion.
        files_hash:
            Optional sub-hash of the manifest file listing.
        files_count:
            Number of files in the manifest.

        Returns
        -------
        ContentFingerprint
            The newly created (but not yet committed) ORM instance.
        """
        record = ContentFingerprint(
            aip_uuid=aip_uuid,
            fingerprint=fingerprint,
            metadata_hash=metadata_hash,
            files_hash=files_hash,
            files_count=files_count,
        )
        session.add(record)
        logger.info(
            "Recorded fingerprint for AIP %s: %s (%d files)",
            aip_uuid,
            fingerprint[:16] + "...",
            files_count,
        )
        return record

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash_manifest_files(self, aip_path: str) -> tuple[str, int]:
        """Read ``manifest-sha256.txt`` and return a deterministic hash.

        Returns
        -------
        tuple[str, int]
            ``(hex_digest, file_count)``
        """
        manifest_path = Path(aip_path) / "manifest-sha256.txt"
        entries: list[tuple[str, str]] = []

        if manifest_path.is_file():
            try:
                with manifest_path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        # BagIt format: <hash>  <filepath>  (two spaces)
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            file_hash, file_path = parts
                            # Normalise path separators for cross-platform determinism.
                            normalised = file_path.replace(os.sep, "/")
                            entries.append((normalised, file_hash))
            except OSError:
                logger.exception("Failed to read manifest at %s", manifest_path)
        else:
            logger.warning(
                "No manifest-sha256.txt found at %s; file hash portion will be empty.",
                aip_path,
            )

        # Sort for deterministic ordering.
        entries.sort()

        hasher = hashlib.sha256()
        for path, file_hash in entries:
            hasher.update(f"{path}:{file_hash}\n".encode("utf-8"))

        return hasher.hexdigest(), len(entries)

    def _hash_stable_metadata(self, metadata: dict | None) -> str:
        """Hash only the non-volatile subset of *metadata*."""
        if not metadata:
            return hashlib.sha256(b"").hexdigest()

        stable = {
            key: value
            for key, value in metadata.items()
            if key not in self.VOLATILE_FIELDS
        }

        serialised = json.dumps(stable, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialised).hexdigest()
