"""Replica Manager — locate and validate AIP replicas.

Works with the :class:`ArchivematicaConnector` to enumerate replica
storage locations and identify a healthy copy that can serve as the
source for auto-repair.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class ReplicaManager:
    """Locate AIP replicas and find a healthy one for repair."""

    def __init__(self, archivematica_connector: object) -> None:
        """Initialise with an Archivematica connector.

        Parameters
        ----------
        archivematica_connector:
            An :class:`~guardian.connector.archivematica_client.ArchivematicaConnector`
            instance (or compatible duck-typed object) that exposes
            ``get_replicas(aip_uuid)``.
        """
        self._connector = archivematica_connector

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_replicas(self, aip_uuid: str) -> list[dict]:
        """Return a list of known replica locations for an AIP.

        Each entry is a dictionary with at minimum the keys:

        * ``location_name`` — human-readable location label
        * ``path`` — filesystem or URI path to the replica
        * ``type`` — replica type (e.g. ``"local"``, ``"remote"``, ``"replication"``)

        Parameters
        ----------
        aip_uuid:
            The UUID of the AIP to look up.

        Returns
        -------
        list[dict]
            Possibly empty list of replica descriptors.
        """
        try:
            replicas = self._connector.get_replicas(aip_uuid)
            logger.info(
                "Found %d replica(s) for AIP %s.",
                len(replicas),
                aip_uuid,
            )
            return replicas
        except Exception:
            logger.exception("Error retrieving replicas for AIP %s", aip_uuid)
            return []

    def find_healthy_replica(
        self,
        aip_uuid: str,
        fixity_verifier: object,
        hmac_authenticator: object,
    ) -> dict | None:
        """Find the first replica that passes fixity checks.

        Iterates over all replicas returned by :meth:`find_replicas` and
        runs the provided *fixity_verifier* against each one.  The first
        replica that passes fixity verification is returned.

        Parameters
        ----------
        aip_uuid:
            UUID of the AIP.
        fixity_verifier:
            An object whose ``verify(aip_uuid, path)`` method returns a
            :class:`VerificationResult` with a ``passed`` property.
        hmac_authenticator:
            An object with ``verify_aip(session, aip_uuid, path)`` —
            currently not used here (HMAC check requires a DB session
            and is done post-repair); kept for interface compatibility.

        Returns
        -------
        dict | None
            The first healthy replica descriptor, or ``None`` if no
            replica passes validation.
        """
        replicas = self.find_replicas(aip_uuid)

        if not replicas:
            logger.warning("No replicas found for AIP %s.", aip_uuid)
            return None

        for replica in replicas:
            replica_path = replica.get("path", "")
            location_name = replica.get("location_name", "unknown")

            if not replica_path:
                logger.warning(
                    "Replica '%s' for AIP %s has no path; skipping.",
                    location_name,
                    aip_uuid,
                )
                continue

            try:
                # --- Fixity check ---
                fixity_result = fixity_verifier.verify(aip_uuid, replica_path)
                if not fixity_result.passed:
                    logger.warning(
                        "Replica '%s' at %s failed fixity verification for AIP %s.",
                        location_name,
                        replica_path,
                        aip_uuid,
                    )
                    continue

                logger.info(
                    "Healthy replica found for AIP %s: '%s' at %s.",
                    aip_uuid,
                    location_name,
                    replica_path,
                )
                return replica

            except Exception:
                logger.exception(
                    "Error verifying replica '%s' at %s for AIP %s.",
                    location_name,
                    replica_path,
                    aip_uuid,
                )
                continue

        logger.error("No healthy replica found for AIP %s.", aip_uuid)
        return None
