"""API tests for the Audit endpoint (/api/v1/audit)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


# -------------------------------------------------------------------------
# 1. test_list_audit_empty
# -------------------------------------------------------------------------

class TestListAuditEmpty:
    @pytest.mark.asyncio
    async def test_list_audit_empty(self, app_client: AsyncClient) -> None:
        """GET /api/v1/audit/ with no records should return an empty list."""
        resp = await app_client.get("/api/v1/audit/")

        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0
        assert body["page"] == 1


# -------------------------------------------------------------------------
# 2. test_chain_status_empty
# -------------------------------------------------------------------------

class TestChainStatusEmpty:
    @pytest.mark.asyncio
    async def test_chain_status_empty(self, app_client: AsyncClient) -> None:
        """GET /api/v1/audit/chain-status with no records should report
        the chain as valid (vacuously true) with zero records."""
        resp = await app_client.get("/api/v1/audit/chain-status")

        assert resp.status_code == 200
        body = resp.json()
        assert body["total_records"] == 0
        assert body["chain_valid"] is True
        assert body["broken_links"] == []
        assert "verified_at" in body
