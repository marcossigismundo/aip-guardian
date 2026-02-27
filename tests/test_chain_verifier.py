"""Tests for the audit-chain integrity verifier.

Validates that the hash-chain verification detects breaks, gaps,
and tampered records.  ISO 16363 section 4.3.2.1.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from guardian.models.audit_log import AuditLog
from guardian.services.chain_verifier import ChainVerifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(
    record_id: int,
    aip_uuid: str,
    event_type: str,
    status: str,
    details: dict,
    previous_hash: str,
    created_at: datetime,
) -> AuditLog:
    """Create an AuditLog instance with a correctly computed record_hash."""
    details_json = json.dumps(details, sort_keys=True, default=str)
    iso_ts = created_at.isoformat()
    payload = "|".join([
        str(aip_uuid),
        event_type,
        status,
        details_json,
        previous_hash,
        iso_ts,
    ])
    record_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    record = AuditLog()
    record.id = record_id
    record.aip_uuid = uuid.UUID(aip_uuid)
    record.event_type = event_type
    record.status = status
    record.details = details
    record.previous_hash = previous_hash
    record.record_hash = record_hash
    record.created_at = created_at

    return record


def _build_chain(count: int = 10) -> list[AuditLog]:
    """Build a valid chain of *count* audit-log records."""
    records: list[AuditLog] = []
    previous_hash = "GENESIS"
    aip_uuid_str = str(uuid.uuid4())

    for i in range(1, count + 1):
        ts = datetime(2026, 1, 1, 0, 0, i, tzinfo=timezone.utc)
        record = _make_record(
            record_id=i,
            aip_uuid=aip_uuid_str,
            event_type="fixity_check",
            status="pass",
            details={"index": i},
            previous_hash=previous_hash,
            created_at=ts,
        )
        records.append(record)
        previous_hash = record.record_hash

    return records


def _mock_session(records: list[AuditLog]) -> MagicMock:
    """Create a mock SQLAlchemy session that returns the given records."""
    session = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = records
    execute_mock = MagicMock()
    execute_mock.scalars.return_value = scalars_mock
    session.execute.return_value = execute_mock
    return session


# -------------------------------------------------------------------------
# 1. test_valid_chain — 10+ records, chain is valid
# -------------------------------------------------------------------------

class TestValidChain:
    def test_valid_chain(self) -> None:
        """A correctly built chain of 10+ records should verify successfully."""
        records = _build_chain(count=12)
        session = _mock_session(records)

        result = ChainVerifier.verify_full_chain(session)

        assert result["chain_valid"] is True
        assert result["total_records"] == 12
        assert result["broken_links"] == []
        assert result["verification_time_seconds"] >= 0


# -------------------------------------------------------------------------
# 2. test_broken_chain — modify one record_hash -> chain_valid=False
# -------------------------------------------------------------------------

class TestBrokenChain:
    def test_broken_chain(self) -> None:
        """Modifying a record_hash in the middle of the chain should be detected."""
        records = _build_chain(count=10)

        # Tamper with record at index 5 (record_id=6).
        records[5].record_hash = "0" * 64

        session = _mock_session(records)
        result = ChainVerifier.verify_full_chain(session)

        assert result["chain_valid"] is False
        assert len(result["broken_links"]) >= 1
        # The break should be detected at record 6 (tampered) and/or record 7
        # (whose previous_hash no longer matches).


# -------------------------------------------------------------------------
# 3. test_deleted_record — gap in chain -> detected
# -------------------------------------------------------------------------

class TestDeletedRecord:
    def test_deleted_record(self) -> None:
        """Removing a record from the middle of the chain should be detected
        as a break because the next record's previous_hash will not match."""
        records = _build_chain(count=10)

        # Delete the record at index 4 (record_id=5).
        del records[4]

        session = _mock_session(records)
        result = ChainVerifier.verify_full_chain(session)

        assert result["chain_valid"] is False
        assert len(result["broken_links"]) >= 1


# -------------------------------------------------------------------------
# 4. test_genesis_record — first record has previous_hash='GENESIS'
# -------------------------------------------------------------------------

class TestGenesisRecord:
    def test_genesis_record(self) -> None:
        """The first record in the chain must have previous_hash='GENESIS'."""
        records = _build_chain(count=3)

        assert records[0].previous_hash == "GENESIS"

        session = _mock_session(records)
        result = ChainVerifier.verify_full_chain(session)

        assert result["chain_valid"] is True

    def test_invalid_genesis(self) -> None:
        """If the first record does NOT have previous_hash='GENESIS', it
        should be flagged as a broken link."""
        records = _build_chain(count=3)

        # Tamper with the genesis record's previous_hash.
        records[0].previous_hash = "NOT_GENESIS"

        session = _mock_session(records)
        result = ChainVerifier.verify_full_chain(session)

        assert result["chain_valid"] is False
        assert records[0].id in result["broken_links"]
