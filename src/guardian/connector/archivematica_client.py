"""Archivematica Storage Service connector.

Provides a high-level Python interface to the Archivematica Storage
Service REST API via the ``amclient`` library.  Used by Guardian to
enumerate AIPs, resolve physical paths, extract packages, and discover
replica locations.
"""

from __future__ import annotations

import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from amclient import AMClient

logger = logging.getLogger(__name__)


class ArchivematicaConnector:
    """Interact with the Archivematica Storage Service.

    Parameters
    ----------
    settings:
        A :class:`guardian.config.Settings` instance (or compatible
        duck-typed object) providing Storage Service connection details.
    """

    def __init__(self, settings: object) -> None:
        ss_url: str = getattr(settings, "archivematica_ss_url", "http://localhost:8000")
        ss_user: str = getattr(settings, "archivematica_ss_user", "admin")
        ss_api_key: str = getattr(settings, "archivematica_ss_api_key", "")
        storage_path: str = getattr(settings, "archivematica_storage_path", "")

        self._storage_path = storage_path
        self._client = AMClient(
            ss_url=ss_url.rstrip("/"),
            ss_user_name=ss_user,
            ss_api_key=ss_api_key,
        )

        logger.info(
            "ArchivematicaConnector initialised: ss_url=%s, ss_user=%s",
            ss_url,
            ss_user,
        )

    # ------------------------------------------------------------------
    # AIP listing
    # ------------------------------------------------------------------

    def list_all_aips(self) -> list[dict]:
        """List all AIPs known to the Storage Service.

        Returns
        -------
        list[dict]
            Each dict contains at minimum ``uuid``, ``current_path``,
            and ``status``.  An empty list is returned on error.
        """
        try:
            response = self._client.aips()

            if isinstance(response, dict):
                aips_raw = response.get("objects", [])
            elif isinstance(response, list):
                aips_raw = response
            else:
                logger.warning(
                    "Unexpected response type from amclient.aips(): %s",
                    type(response).__name__,
                )
                return []

            result: list[dict] = []
            for aip in aips_raw:
                result.append({
                    "uuid": aip.get("uuid", ""),
                    "current_path": aip.get("current_path", ""),
                    "status": aip.get("status", "UPLOADED"),
                    "size": aip.get("size", 0),
                    "origin_pipeline": aip.get("origin_pipeline", ""),
                    "current_location": aip.get("current_location", ""),
                })

            logger.info("Listed %d AIP(s) from Storage Service.", len(result))
            return result

        except Exception:
            logger.exception("Failed to list AIPs from Storage Service.")
            return []

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def get_aip_path(self, aip_uuid: str) -> str:
        """Resolve the physical filesystem path of an AIP.

        The method first queries the Storage Service API for the
        ``current_path`` and combines it with the configured storage
        root.  If the API call fails, a best-effort path is constructed
        from the UUID.

        Parameters
        ----------
        aip_uuid:
            UUID of the AIP to locate.

        Returns
        -------
        str
            Absolute filesystem path to the AIP package.
        """
        try:
            self._client.aip_uuid = aip_uuid
            aip_details = self._client.get_aip_details(aip_uuid)

            if isinstance(aip_details, dict):
                current_path = aip_details.get("current_path", "")
                if current_path:
                    full_path = os.path.join(self._storage_path, current_path)
                    logger.debug("Resolved AIP %s path: %s", aip_uuid, full_path)
                    return full_path

        except Exception:
            logger.exception("Failed to get AIP details for %s", aip_uuid)

        # Fallback: construct a conventional path.
        fallback = os.path.join(
            self._storage_path,
            aip_uuid[:4],
            aip_uuid,
        )
        logger.warning(
            "Using fallback path for AIP %s: %s",
            aip_uuid,
            fallback,
        )
        return fallback

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def extract_aip(self, aip_uuid: str, target_dir: str) -> str:
        """Extract an AIP package (ZIP or tar) into *target_dir*.

        Parameters
        ----------
        aip_uuid:
            UUID of the AIP to extract.
        target_dir:
            Directory where the package contents will be placed.

        Returns
        -------
        str
            Path to the extracted directory.

        Raises
        ------
        FileNotFoundError
            If the AIP package cannot be located on disk.
        ValueError
            If the package format is not supported.
        """
        aip_path = self.get_aip_path(aip_uuid)

        # Archivematica stores packages as files (tar.gz / 7z / zip)
        # or sometimes as uncompressed directories.
        pkg = Path(aip_path)

        if pkg.is_dir():
            logger.info("AIP %s is already an extracted directory: %s", aip_uuid, aip_path)
            return aip_path

        if not pkg.is_file():
            raise FileNotFoundError(f"AIP package not found at {aip_path}")

        extract_root = Path(target_dir)
        extract_root.mkdir(parents=True, exist_ok=True)

        suffix_lower = "".join(pkg.suffixes).lower()

        try:
            if suffix_lower.endswith(".zip"):
                return self._extract_zip(pkg, extract_root, aip_uuid)
            elif ".tar" in suffix_lower:
                return self._extract_tar(pkg, extract_root, aip_uuid)
            else:
                raise ValueError(
                    f"Unsupported package format for AIP {aip_uuid}: {suffix_lower}"
                )
        except (zipfile.BadZipFile, tarfile.TarError) as exc:
            logger.error("Corrupt archive for AIP %s: %s", aip_uuid, exc)
            raise

    # ------------------------------------------------------------------
    # Replicas
    # ------------------------------------------------------------------

    def get_replicas(self, aip_uuid: str) -> list[dict]:
        """List replica locations for an AIP.

        Each returned dict has the keys ``location_name``, ``path``,
        and ``type``.

        Parameters
        ----------
        aip_uuid:
            UUID of the AIP.

        Returns
        -------
        list[dict]
        """
        try:
            self._client.aip_uuid = aip_uuid
            aip_details = self._client.get_aip_details(aip_uuid)

            replicas: list[dict] = []

            if isinstance(aip_details, dict):
                # The primary location counts as a replica.
                primary_path = aip_details.get("current_path", "")
                primary_location = aip_details.get("current_location", "")
                if primary_path:
                    replicas.append({
                        "location_name": self._location_label(primary_location) or "primary",
                        "path": os.path.join(self._storage_path, primary_path),
                        "type": "primary",
                    })

                # Replicas are listed under 'replicas' or 'replicated_to'.
                for field_name in ("replicas", "replicated_to"):
                    replica_entries = aip_details.get(field_name, [])
                    if isinstance(replica_entries, list):
                        for entry in replica_entries:
                            if isinstance(entry, dict):
                                replicas.append({
                                    "location_name": entry.get("location_name", "replica"),
                                    "path": entry.get("current_path", ""),
                                    "type": "replication",
                                })
                            elif isinstance(entry, str):
                                replicas.append({
                                    "location_name": "replica",
                                    "path": entry,
                                    "type": "replication",
                                })

            logger.info("Found %d replica(s) for AIP %s.", len(replicas), aip_uuid)
            return replicas

        except Exception:
            logger.exception("Failed to retrieve replicas for AIP %s.", aip_uuid)
            return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_zip(pkg: Path, extract_root: Path, aip_uuid: str) -> str:
        """Extract a ZIP archive and return the extraction directory."""
        with zipfile.ZipFile(pkg, "r") as zf:
            zf.extractall(extract_root)
        logger.info("Extracted ZIP for AIP %s to %s", aip_uuid, extract_root)
        return str(extract_root)

    @staticmethod
    def _extract_tar(pkg: Path, extract_root: Path, aip_uuid: str) -> str:
        """Extract a tar(.gz/.bz2/.xz) archive and return the extraction directory."""
        with tarfile.open(pkg, "r:*") as tf:
            # Security: filter out absolute paths and path traversals.
            members = []
            for member in tf.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    logger.warning(
                        "Skipping suspicious tar member in AIP %s: %s",
                        aip_uuid,
                        member.name,
                    )
                    continue
                members.append(member)
            tf.extractall(extract_root, members=members)
        logger.info("Extracted tar for AIP %s to %s", aip_uuid, extract_root)
        return str(extract_root)

    @staticmethod
    def _location_label(location_uri: str) -> str:
        """Extract a human-friendly label from a Storage Service location URI.

        The SS typically returns URIs like ``/api/v2/location/<uuid>/``.
        We return the UUID portion as a label.
        """
        if not location_uri:
            return ""
        parts = [p for p in location_uri.strip("/").split("/") if p]
        return parts[-1] if parts else location_uri
