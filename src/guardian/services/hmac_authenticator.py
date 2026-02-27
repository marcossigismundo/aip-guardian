"""HMAC manifest authenticator — Component 2 (ISO 16363 §4.3.3, §5.2.2).

Generates and verifies HMAC-SHA256 signatures over BagIt manifest files to
detect tampering of the manifest themselves (which would defeat fixity
verification).

Uses :class:`KeyManager` for key resolution and stores HMAC records in the
``hmac_registry`` table.  All comparisons use :func:`hmac.compare_digest`
to prevent timing side-channels.

This service uses **synchronous** SQLAlchemy sessions (called from Celery
workers).
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.models.hmac_registry import HMACRegistry
from guardian.services.key_manager import KeyManager

logger = logging.getLogger(__name__)


class ManifestAuthenticator:
    """HMAC-SHA256 authenticator for BagIt manifest files."""

    MANIFEST_FILES: list[str] = [
        "manifest-sha256.txt",
        "manifest-sha512.txt",
        "tagmanifest-sha256.txt",
    ]

    def __init__(self) -> None:
        self._key: bytes = KeyManager.get_key()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_hmac(self, manifest_path: str) -> str:
        """Compute HMAC-SHA256 over the contents of *manifest_path*.

        Returns
        -------
        str
            Hex-encoded HMAC digest.
        """
        content = Path(manifest_path).read_bytes()
        return hmac_mod.new(self._key, content, hashlib.sha256).hexdigest()

    def verify_hmac(self, manifest_path: str, stored_hmac: str) -> bool:
        """Verify *stored_hmac* against the current file content.

        Uses :func:`hmac.compare_digest` for timing-safe comparison.
        """
        current_hmac = self.generate_hmac(manifest_path)
        return hmac_mod.compare_digest(current_hmac, stored_hmac)

    def register_aip(
        self,
        session: Session,
        aip_uuid: str,
        aip_path: str,
    ) -> dict:
        """Register HMAC values for every manifest file in an AIP.

        Existing records for the same ``(aip_uuid, manifest_name)`` are
        updated in-place; new records are inserted.

        Parameters
        ----------
        session:
            Synchronous SQLAlchemy session.
        aip_uuid:
            UUID of the AIP being registered.
        aip_path:
            Filesystem path to the root of the BagIt bag.

        Returns
        -------
        dict
            ``{"registered": int, "manifests": {name: hmac_hex, ...}}``
        """
        bag_root = Path(aip_path)
        registered: dict[str, str] = {}

        for manifest_name in self.MANIFEST_FILES:
            manifest_path = bag_root / manifest_name
            if not manifest_path.is_file():
                continue

            hmac_value = self.generate_hmac(str(manifest_path))

            # Upsert: update if exists, insert otherwise.
            stmt = select(HMACRegistry).where(
                HMACRegistry.aip_uuid == aip_uuid,
                HMACRegistry.manifest_name == manifest_name,
            )
            existing: HMACRegistry | None = session.execute(stmt).scalar_one_or_none()

            if existing is not None:
                existing.hmac_value = hmac_value
                existing.algorithm = "hmac-sha256"
                existing.registered_at = datetime.now(timezone.utc)
            else:
                record = HMACRegistry(
                    aip_uuid=aip_uuid,
                    manifest_name=manifest_name,
                    hmac_value=hmac_value,
                    algorithm="hmac-sha256",
                    registered_at=datetime.now(timezone.utc),
                )
                session.add(record)

            registered[manifest_name] = hmac_value

        session.flush()

        logger.info(
            "Registered %d manifest HMACs for AIP %s",
            len(registered),
            aip_uuid,
        )
        return {"registered": len(registered), "manifests": registered}

    def verify_aip(
        self,
        session: Session,
        aip_uuid: str,
        aip_path: str,
    ) -> dict:
        """Verify all stored HMAC values for an AIP against disk.

        Parameters
        ----------
        session:
            Synchronous SQLAlchemy session.
        aip_uuid:
            UUID of the AIP.
        aip_path:
            Filesystem path to the bag root.

        Returns
        -------
        dict
            ``{"valid": bool, "manifests": {name: {stored, current, match}}, "tampered": [name, ...]}``
        """
        bag_root = Path(aip_path)

        # Load all stored HMAC records for this AIP.
        stmt = select(HMACRegistry).where(HMACRegistry.aip_uuid == aip_uuid)
        records: list[HMACRegistry] = list(
            session.execute(stmt).scalars().all()
        )

        manifests: dict[str, dict] = {}
        tampered: list[str] = []

        for record in records:
            manifest_path = bag_root / record.manifest_name
            if not manifest_path.is_file():
                manifests[record.manifest_name] = {
                    "stored": record.hmac_value,
                    "current": None,
                    "match": False,
                    "error": "FILE_MISSING",
                }
                tampered.append(record.manifest_name)
                continue

            current_hmac = self.generate_hmac(str(manifest_path))
            match = hmac_mod.compare_digest(current_hmac, record.hmac_value)

            manifests[record.manifest_name] = {
                "stored": record.hmac_value,
                "current": current_hmac,
                "match": match,
            }

            if not match:
                tampered.append(record.manifest_name)
                logger.warning(
                    "HMAC mismatch for %s in AIP %s",
                    record.manifest_name,
                    aip_uuid,
                )

            # Update last-verified timestamp.
            record.last_verified_at = datetime.now(timezone.utc)

        session.flush()

        all_valid = len(tampered) == 0 and len(records) > 0

        logger.info(
            "HMAC verification for AIP %s: valid=%s, checked=%d, tampered=%d",
            aip_uuid,
            all_valid,
            len(records),
            len(tampered),
        )

        return {
            "valid": all_valid,
            "manifests": manifests,
            "tampered": tampered,
        }
