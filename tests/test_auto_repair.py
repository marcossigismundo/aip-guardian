"""Tests for the auto-repair service (Component 5).

ISO 16363 section 4.3.3.1, section 4.3.4 — Automated recovery from AIP corruption.
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from guardian.models.audit_log import AuditLog
from guardian.models.repair_record import RepairRecord
from guardian.services.auto_repair import AutoRepair, RepairResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def aip_uuid() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def mock_fixity():
    """Mock fixity verifier that always reports valid after repair."""
    mock = MagicMock()
    mock.verify.return_value = {"valid": True}
    return mock


@pytest.fixture
def mock_hmac():
    """Mock HMAC authenticator."""
    mock = MagicMock()
    mock.verify.return_value = {"valid": True}
    mock.update.return_value = None
    return mock


@pytest.fixture
def mock_session():
    """Mock SQLAlchemy session."""
    return MagicMock()


def _make_healthy_replica(replica_path: str) -> dict:
    return {
        "path": replica_path,
        "location_name": "test-replica",
        "type": "replication",
    }


# -------------------------------------------------------------------------
# 1. test_successful_repair — 1 file fixed from replica
# -------------------------------------------------------------------------

class TestSuccessfulRepair:
    def test_successful_repair(
        self,
        tmp_path: Path,
        aip_uuid: str,
        mock_fixity,
        mock_hmac,
        mock_session,
    ) -> None:
        """One corrupted file should be repaired from a healthy replica."""
        # Set up primary AIP (corrupted).
        primary = tmp_path / "primary"
        primary.mkdir()
        (primary / "data").mkdir()
        (primary / "data" / "file1.txt").write_bytes(b"CORRUPTED")

        # Set up replica (healthy).
        replica = tmp_path / "replica"
        replica.mkdir()
        (replica / "data").mkdir()
        good_content = b"Hello, this is test file 1"
        (replica / "data" / "file1.txt").write_bytes(good_content)
        expected_hash = hashlib.sha256(good_content).hexdigest()

        mock_replicas = MagicMock()
        mock_replicas.find_healthy_replica.return_value = _make_healthy_replica(str(replica))

        repair = AutoRepair(mock_fixity, mock_hmac, mock_replicas)

        corruption_report = {
            "corrupted_files": [
                {
                    "path": "data/file1.txt",
                    "expected_hash": expected_hash,
                }
            ]
        }

        result = repair.repair(mock_session, aip_uuid, str(primary), corruption_report)

        assert result.status == "success"
        assert "data/file1.txt" in result.repaired_files
        assert (primary / "data" / "file1.txt").read_bytes() == good_content


# -------------------------------------------------------------------------
# 2. test_no_replicas — no replicas available -> status='failed'
# -------------------------------------------------------------------------

class TestNoReplicas:
    def test_no_replicas(
        self,
        tmp_path: Path,
        aip_uuid: str,
        mock_fixity,
        mock_hmac,
        mock_session,
    ) -> None:
        """When no healthy replica is found, repair should fail."""
        mock_replicas = MagicMock()
        mock_replicas.find_healthy_replica.return_value = None

        repair = AutoRepair(mock_fixity, mock_hmac, mock_replicas)

        corruption_report = {
            "corrupted_files": [
                {"path": "data/file1.txt", "expected_hash": "abc123"},
            ]
        }

        result = repair.repair(mock_session, aip_uuid, str(tmp_path), corruption_report)

        assert result.status == "failed"


# -------------------------------------------------------------------------
# 3. test_all_replicas_corrupted — all bad -> status='failed'
# -------------------------------------------------------------------------

class TestAllReplicasCorrupted:
    def test_all_replicas_corrupted(
        self,
        tmp_path: Path,
        aip_uuid: str,
        mock_fixity,
        mock_hmac,
        mock_session,
    ) -> None:
        """When the replica manager cannot find a healthy replica (all
        corrupted), the repair should fail."""
        mock_replicas = MagicMock()
        mock_replicas.find_healthy_replica.return_value = None

        repair = AutoRepair(mock_fixity, mock_hmac, mock_replicas)

        corruption_report = {
            "corrupted_files": [
                {"path": "data/file1.txt", "expected_hash": "abc123"},
            ]
        }

        result = repair.repair(mock_session, aip_uuid, str(tmp_path), corruption_report)

        assert result.status == "failed"
        assert "No healthy replica found" in result.details.get("error", "")


# -------------------------------------------------------------------------
# 4. test_verify_before_copy — source hash checked before copy
# -------------------------------------------------------------------------

class TestVerifyBeforeCopy:
    def test_verify_before_copy(
        self,
        tmp_path: Path,
        aip_uuid: str,
        mock_fixity,
        mock_hmac,
        mock_session,
    ) -> None:
        """The repair service should verify the source file hash BEFORE
        copying it to the primary location."""
        primary = tmp_path / "primary"
        primary.mkdir()
        (primary / "data").mkdir()
        (primary / "data" / "file1.txt").write_bytes(b"CORRUPTED")

        # Replica with WRONG content (hash mismatch).
        replica = tmp_path / "replica"
        replica.mkdir()
        (replica / "data").mkdir()
        (replica / "data" / "file1.txt").write_bytes(b"ALSO WRONG CONTENT")

        mock_replicas = MagicMock()
        mock_replicas.find_healthy_replica.return_value = _make_healthy_replica(str(replica))

        # Post-repair fixity indicates not valid since file is still wrong.
        mock_fixity.verify.return_value = {"valid": False}

        repair = AutoRepair(mock_fixity, mock_hmac, mock_replicas)

        expected_hash = hashlib.sha256(b"Hello, this is test file 1").hexdigest()
        corruption_report = {
            "corrupted_files": [
                {"path": "data/file1.txt", "expected_hash": expected_hash},
            ]
        }

        result = repair.repair(mock_session, aip_uuid, str(primary), corruption_report)

        # The file should NOT have been copied (source hash does not match).
        assert "data/file1.txt" not in result.repaired_files
        # The original corrupted content should remain.
        assert (primary / "data" / "file1.txt").read_bytes() == b"CORRUPTED"


# -------------------------------------------------------------------------
# 5. test_partial_repair — 2 corrupted, 1 fixed -> status='partial'
# -------------------------------------------------------------------------

class TestPartialRepair:
    def test_partial_repair(
        self,
        tmp_path: Path,
        aip_uuid: str,
        mock_fixity,
        mock_hmac,
        mock_session,
    ) -> None:
        """When some files are repaired and some are not, the status
        should be 'partial'."""
        primary = tmp_path / "primary"
        primary.mkdir()
        (primary / "data").mkdir()
        (primary / "data" / "file1.txt").write_bytes(b"CORRUPTED1")
        (primary / "data" / "file2.txt").write_bytes(b"CORRUPTED2")

        good_content_1 = b"Hello, this is test file 1"
        good_content_2 = b"Hello, this is test file 2"
        hash1 = hashlib.sha256(good_content_1).hexdigest()
        hash2 = hashlib.sha256(good_content_2).hexdigest()

        # Replica has file1 correct but file2 is ALSO corrupted.
        replica = tmp_path / "replica"
        replica.mkdir()
        (replica / "data").mkdir()
        (replica / "data" / "file1.txt").write_bytes(good_content_1)
        (replica / "data" / "file2.txt").write_bytes(b"REPLICA ALSO BAD")

        mock_replicas = MagicMock()
        mock_replicas.find_healthy_replica.return_value = _make_healthy_replica(str(replica))

        # Post-repair fixity fails (one file still wrong).
        mock_fixity.verify.return_value = {"valid": False}

        repair = AutoRepair(mock_fixity, mock_hmac, mock_replicas)

        corruption_report = {
            "corrupted_files": [
                {"path": "data/file1.txt", "expected_hash": hash1},
                {"path": "data/file2.txt", "expected_hash": hash2},
            ]
        }

        result = repair.repair(mock_session, aip_uuid, str(primary), corruption_report)

        assert result.status == "partial"
        assert "data/file1.txt" in result.repaired_files
        assert "data/file2.txt" not in result.repaired_files


# -------------------------------------------------------------------------
# 6. test_audit_log_entry — repair creates audit log
# -------------------------------------------------------------------------

class TestAuditLogEntry:
    def test_audit_log_entry(
        self,
        tmp_path: Path,
        aip_uuid: str,
        mock_fixity,
        mock_hmac,
        mock_session,
    ) -> None:
        """A repair operation should add an AuditLog entry to the session."""
        primary = tmp_path / "primary"
        primary.mkdir()
        (primary / "data").mkdir()
        (primary / "data" / "file1.txt").write_bytes(b"CORRUPTED")

        replica = tmp_path / "replica"
        replica.mkdir()
        (replica / "data").mkdir()
        good_content = b"Hello, this is test file 1"
        (replica / "data" / "file1.txt").write_bytes(good_content)

        mock_replicas = MagicMock()
        mock_replicas.find_healthy_replica.return_value = _make_healthy_replica(str(replica))

        repair = AutoRepair(mock_fixity, mock_hmac, mock_replicas)

        corruption_report = {
            "corrupted_files": [
                {
                    "path": "data/file1.txt",
                    "expected_hash": hashlib.sha256(good_content).hexdigest(),
                }
            ]
        }

        repair.repair(mock_session, aip_uuid, str(primary), corruption_report)

        # Check that session.add was called with AuditLog and RepairRecord objects.
        added_objects = [c.args[0] for c in mock_session.add.call_args_list]
        audit_entries = [o for o in added_objects if isinstance(o, AuditLog)]
        assert len(audit_entries) >= 1
        assert audit_entries[0].event_type == "auto_repair"


# -------------------------------------------------------------------------
# 7. test_hmac_updated — HMAC recalculated after repair
# -------------------------------------------------------------------------

class TestHMACUpdated:
    def test_hmac_updated(
        self,
        tmp_path: Path,
        aip_uuid: str,
        mock_fixity,
        mock_hmac,
        mock_session,
    ) -> None:
        """After a successful repair, the HMAC should be updated."""
        primary = tmp_path / "primary"
        primary.mkdir()
        (primary / "data").mkdir()
        (primary / "data" / "file1.txt").write_bytes(b"CORRUPTED")

        replica = tmp_path / "replica"
        replica.mkdir()
        (replica / "data").mkdir()
        good_content = b"Hello, this is test file 1"
        (replica / "data" / "file1.txt").write_bytes(good_content)

        mock_replicas = MagicMock()
        mock_replicas.find_healthy_replica.return_value = _make_healthy_replica(str(replica))

        repair = AutoRepair(mock_fixity, mock_hmac, mock_replicas)

        corruption_report = {
            "corrupted_files": [
                {
                    "path": "data/file1.txt",
                    "expected_hash": hashlib.sha256(good_content).hexdigest(),
                }
            ]
        }

        result = repair.repair(mock_session, aip_uuid, str(primary), corruption_report)

        assert result.status == "success"
        # The HMAC authenticator's update method should have been called.
        mock_hmac.update.assert_called_once_with(str(primary))
