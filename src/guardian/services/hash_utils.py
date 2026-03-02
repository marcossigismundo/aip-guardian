"""Shared hash computation for audit-log records.

Both :class:`AuditLogger` and :class:`ChainVerifier` need to compute the
same SHA-256 hash for audit records.  This module provides a single
canonical implementation to avoid formula drift.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime


def compute_record_hash(
    *,
    aip_uuid: str,
    event_type: str,
    status: str,
    details: dict,
    previous_hash: str,
    timestamp: datetime,
) -> str:
    """Compute the SHA-256 hash that seals an audit record into the chain.

    The hash input is the concatenation (with ``|`` separator) of:
    ``aip_uuid | event_type | status | details_json | previous_hash | iso_timestamp``
    """
    details_json = json.dumps(details, sort_keys=True, default=str)
    iso_ts = timestamp.isoformat()

    payload = "|".join([
        str(aip_uuid),
        event_type,
        status,
        details_json,
        previous_hash,
        iso_ts,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
