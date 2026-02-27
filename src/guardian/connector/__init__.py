"""Archivematica connector package — re-export the main client class."""

from guardian.connector.archivematica_client import ArchivematicaConnector

__all__ = ["ArchivematicaConnector"]
