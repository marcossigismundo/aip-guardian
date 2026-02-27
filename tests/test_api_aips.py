"""API tests for the AIPs endpoint (/api/v1/aips)."""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# -------------------------------------------------------------------------
# 1. test_list_aips_empty
# -------------------------------------------------------------------------

class TestListAIPsEmpty:
    @pytest.mark.asyncio
    async def test_list_aips_empty(self, app_client: AsyncClient) -> None:
        """GET /api/v1/aips/ with no registered AIPs should return an empty list."""
        resp = await app_client.get("/api/v1/aips/")

        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0
        assert body["page"] == 1


# -------------------------------------------------------------------------
# 2. test_register_aip
# -------------------------------------------------------------------------

class TestRegisterAIP:
    @pytest.mark.asyncio
    async def test_register_aip(self, app_client: AsyncClient) -> None:
        """POST /api/v1/aips/register should create a new AIP record."""
        am_uuid = str(uuid.uuid4())
        payload = {
            "archivematica_uuid": am_uuid,
            "storage_path": "/var/archivematica/storage/test-aip",
            "storage_location": "default-location",
        }

        resp = await app_client.post("/api/v1/aips/register", json=payload)

        assert resp.status_code == 201
        body = resp.json()
        assert body["archivematica_uuid"] == am_uuid
        assert body["storage_path"] == "/var/archivematica/storage/test-aip"
        assert body["last_status"] == "pending"

    @pytest.mark.asyncio
    async def test_register_duplicate_aip(self, app_client: AsyncClient) -> None:
        """Registering the same AIP twice should return 409 Conflict."""
        am_uuid = str(uuid.uuid4())
        payload = {
            "archivematica_uuid": am_uuid,
            "storage_path": "/var/archivematica/storage/test-aip",
        }

        resp1 = await app_client.post("/api/v1/aips/register", json=payload)
        assert resp1.status_code == 201

        resp2 = await app_client.post("/api/v1/aips/register", json=payload)
        assert resp2.status_code == 409


# -------------------------------------------------------------------------
# 3. test_get_aip
# -------------------------------------------------------------------------

class TestGetAIP:
    @pytest.mark.asyncio
    async def test_get_aip(self, app_client: AsyncClient) -> None:
        """GET /api/v1/aips/{aip_uuid} should return the registered AIP."""
        am_uuid = str(uuid.uuid4())
        payload = {
            "archivematica_uuid": am_uuid,
            "storage_path": "/storage/test",
        }

        create_resp = await app_client.post("/api/v1/aips/register", json=payload)
        assert create_resp.status_code == 201
        aip_uuid = create_resp.json()["aip_uuid"]

        get_resp = await app_client.get(f"/api/v1/aips/{aip_uuid}")
        assert get_resp.status_code == 200
        assert get_resp.json()["aip_uuid"] == aip_uuid

    @pytest.mark.asyncio
    async def test_get_nonexistent_aip(self, app_client: AsyncClient) -> None:
        """GET for a non-existent AIP UUID should return 404."""
        fake_uuid = str(uuid.uuid4())
        resp = await app_client.get(f"/api/v1/aips/{fake_uuid}")
        assert resp.status_code == 404


# -------------------------------------------------------------------------
# 4. test_verify_aip (mock celery)
# -------------------------------------------------------------------------

class TestVerifyAIP:
    @pytest.mark.asyncio
    async def test_verify_aip(self, app_client: AsyncClient) -> None:
        """POST /api/v1/aips/{uuid}/verify should enqueue a task and return
        a task ID (with Celery mocked)."""
        from unittest.mock import MagicMock, patch

        am_uuid = str(uuid.uuid4())
        payload = {
            "archivematica_uuid": am_uuid,
            "storage_path": "/storage/test",
        }

        create_resp = await app_client.post("/api/v1/aips/register", json=payload)
        assert create_resp.status_code == 201
        aip_uuid = create_resp.json()["aip_uuid"]

        mock_task = MagicMock()
        mock_task.id = "test-task-id-123"

        with patch(
            "guardian.api.aips.verify_single_aip",
            create=True,
        ) as mock_verify:
            mock_verify.delay.return_value = mock_task

            with patch(
                "guardian.tasks.fixity_tasks.verify_single_aip",
                mock_verify,
            ):
                resp = await app_client.post(f"/api/v1/aips/{aip_uuid}/verify")

        assert resp.status_code == 200
        body = resp.json()
        assert body["task_id"] == "test-task-id-123"
        assert body["aip_uuid"] == aip_uuid


# -------------------------------------------------------------------------
# 5. test_list_filter_by_status
# -------------------------------------------------------------------------

class TestListFilterByStatus:
    @pytest.mark.asyncio
    async def test_list_filter_by_status(self, app_client: AsyncClient) -> None:
        """GET /api/v1/aips/?last_status=pending should only return
        AIPs with that status."""
        # Register two AIPs (both will have status=pending).
        for _ in range(2):
            payload = {
                "archivematica_uuid": str(uuid.uuid4()),
                "storage_path": "/storage/test",
            }
            resp = await app_client.post("/api/v1/aips/register", json=payload)
            assert resp.status_code == 201

        # Filter by pending.
        resp = await app_client.get("/api/v1/aips/?last_status=pending")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        for item in body["items"]:
            assert item["last_status"] == "pending"

        # Filter by a status that none have.
        resp = await app_client.get("/api/v1/aips/?last_status=corrupted")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


# -------------------------------------------------------------------------
# 6. test_auth_required (no token -> 401)
# -------------------------------------------------------------------------

class TestAuthRequired:
    @pytest.mark.asyncio
    async def test_auth_required(self, async_engine) -> None:
        """Requests without a Bearer token should receive 401 Unauthorized."""
        from guardian.api.deps import get_db_session
        from guardian.main import create_app
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        app = create_app()

        session_factory = async_sessionmaker(
            async_engine, class_=AsyncSession, expire_on_commit=False
        )

        async def _override_db():
            async with session_factory() as session:
                try:
                    yield session
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise

        app.dependency_overrides[get_db_session] = _override_db

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
            # No Authorization header!
        ) as client:
            resp = await client.get("/api/v1/aips/")
            assert resp.status_code == 401

        app.dependency_overrides.clear()
