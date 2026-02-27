"""Fixity verification service — Component 1 (ISO 16363 §4.3.3.1).

Validates the integrity of BagIt-packaged AIPs by:
* Recalculating checksums for every payload file.
* Comparing against the stored manifest using timing-safe comparison.
* Verifying tag files against the tag manifest.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import bagit

logger = logging.getLogger(__name__)

_CHUNK_SIZE: int = 65_536  # 64 KB streaming reads


@dataclass(frozen=True, slots=True)
class FileFailure:
    """Detail record for a single file that failed verification."""

    path: str
    expected: str
    actual: str
    algorithm: str


@dataclass(slots=True)
class VerificationResult:
    """Structured outcome of a full AIP fixity check."""

    aip_uuid: str
    status: str = "pending"           # pass | fail | error
    files_checked: int = 0
    files_failed: int = 0
    duration_seconds: float = 0.0
    failures: list[FileFailure] = field(default_factory=list)
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "pass"


class FixityVerifier:
    """BagIt-based fixity verifier for Archivematica AIPs."""

    ALGORITHMS: list[str] = ["sha256", "sha512"]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(self, aip_uuid: str, aip_path: str) -> VerificationResult:
        """Run a full fixity check on the AIP at *aip_path*.

        Parameters
        ----------
        aip_uuid:
            Guardian-assigned UUID (used only for logging/result tagging).
        aip_path:
            Filesystem path to the root of the BagIt bag.

        Returns
        -------
        VerificationResult
            Structured result including per-file failure details.
        """
        result = VerificationResult(aip_uuid=aip_uuid)
        t0 = time.monotonic()

        try:
            bag = bagit.Bag(aip_path)
        except bagit.BagError as exc:
            result.status = "error"
            result.error = f"Failed to open bag: {exc}"
            result.duration_seconds = time.monotonic() - t0
            logger.error("Bag open failed for %s: %s", aip_uuid, exc)
            return result

        bag_root = Path(aip_path)

        # ----- Payload verification (manifest-*.txt) -----
        self._verify_manifests(bag, bag_root, result)

        # ----- Tag verification (tagmanifest-*.txt) -----
        self._verify_tag_manifests(bag, bag_root, result)

        result.status = "pass" if result.files_failed == 0 else "fail"
        result.duration_seconds = time.monotonic() - t0

        logger.info(
            "Fixity check for %s: %s (%d files, %d failures, %.2fs)",
            aip_uuid,
            result.status,
            result.files_checked,
            result.files_failed,
            result.duration_seconds,
        )
        return result

    def verify_single_file(
        self,
        filepath: str,
        expected_hash: str,
        algorithm: str = "sha256",
    ) -> bool:
        """Check a single file against an expected hash digest.

        Uses :func:`hmac.compare_digest` for timing-safe comparison.
        """
        actual = self._compute_hash(filepath, algorithm)
        return hmac.compare_digest(actual, expected_hash)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_hash(filepath: str, algorithm: str = "sha256") -> str:
        """Stream-hash a file in 64 KB chunks and return the hex digest."""
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _verify_manifests(
        self,
        bag: bagit.Bag,
        bag_root: Path,
        result: VerificationResult,
    ) -> None:
        """Verify payload files listed in manifest-sha256.txt (and others)."""
        for algorithm in self.ALGORITHMS:
            manifest_name = f"manifest-{algorithm}.txt"
            manifest_path = bag_root / manifest_name
            if not manifest_path.is_file():
                continue

            entries = self._parse_manifest_file(str(manifest_path))
            for rel_path, expected_hash in entries.items():
                abs_path = bag_root / rel_path
                result.files_checked += 1

                if not abs_path.is_file():
                    failure = FileFailure(
                        path=rel_path,
                        expected=expected_hash,
                        actual="FILE_MISSING",
                        algorithm=algorithm,
                    )
                    result.failures.append(failure)
                    result.files_failed += 1
                    continue

                actual_hash = self._compute_hash(str(abs_path), algorithm)
                if not hmac.compare_digest(actual_hash, expected_hash):
                    failure = FileFailure(
                        path=rel_path,
                        expected=expected_hash,
                        actual=actual_hash,
                        algorithm=algorithm,
                    )
                    result.failures.append(failure)
                    result.files_failed += 1

    def _verify_tag_manifests(
        self,
        bag: bagit.Bag,
        bag_root: Path,
        result: VerificationResult,
    ) -> None:
        """Verify tag files listed in tagmanifest-*.txt."""
        for algorithm in self.ALGORITHMS:
            tagmanifest_name = f"tagmanifest-{algorithm}.txt"
            tagmanifest_path = bag_root / tagmanifest_name
            if not tagmanifest_path.is_file():
                continue

            entries = self._parse_manifest_file(str(tagmanifest_path))
            for rel_path, expected_hash in entries.items():
                abs_path = bag_root / rel_path
                result.files_checked += 1

                if not abs_path.is_file():
                    failure = FileFailure(
                        path=rel_path,
                        expected=expected_hash,
                        actual="FILE_MISSING",
                        algorithm=algorithm,
                    )
                    result.failures.append(failure)
                    result.files_failed += 1
                    continue

                actual_hash = self._compute_hash(str(abs_path), algorithm)
                if not hmac.compare_digest(actual_hash, expected_hash):
                    failure = FileFailure(
                        path=rel_path,
                        expected=expected_hash,
                        actual=actual_hash,
                        algorithm=algorithm,
                    )
                    result.failures.append(failure)
                    result.files_failed += 1

    @staticmethod
    def _parse_manifest_file(manifest_path: str) -> dict[str, str]:
        """Parse a BagIt manifest file into ``{filepath: hash}``."""
        entries: dict[str, str] = {}
        with open(manifest_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                # Format: "<hash>  <path>" (two spaces)
                parts = line.split(None, 1)
                if len(parts) == 2:
                    hash_value, file_path = parts
                    entries[file_path] = hash_value
        return entries
