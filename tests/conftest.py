"""Shared pytest fixtures for AIP Integrity Guardian test suite."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from guardian.models.base import Base

# ---------------------------------------------------------------------------
# Paths to static test fixtures
# ---------------------------------------------------------------------------
FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Test database configuration
# ---------------------------------------------------------------------------
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "sqlite+aiosqlite:///",  # in-memory SQLite for portability
)


@pytest_asyncio.fixture
async def async_engine():
    """Create an async engine and initialise the schema."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def async_session(async_engine) -> AsyncGenerator[AsyncSession, None]:
    """Yield an async session bound to the test engine."""
    session_factory = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def app_client(async_engine) -> AsyncGenerator[AsyncClient, None]:
    """Yield an httpx.AsyncClient wired to the FastAPI test app.

    The client uses the test database and includes the Bearer token
    so that authenticated endpoints are accessible.
    """
    from guardian.api.deps import get_db_session
    from guardian.main import create_app

    app = create_app()

    # Override the DB dependency to use the test engine.
    session_factory = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
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
        headers={"Authorization": "Bearer change-me-generate-a-secure-token"},
    ) as client:
        yield client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# BagIt test fixture paths
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_bag_path() -> Path:
    """Return the path to the pre-built valid BagIt fixture."""
    return FIXTURES_DIR / "valid_bag"


@pytest.fixture
def corrupted_bag_path() -> Path:
    """Return the path to the pre-built corrupted BagIt fixture."""
    return FIXTURES_DIR / "corrupted_bag"


@pytest.fixture
def invalid_bag_path() -> Path:
    """Return the path to the pre-built invalid BagIt fixture (no bagit.txt)."""
    return FIXTURES_DIR / "invalid_bag"


# ---------------------------------------------------------------------------
# Dynamic BagIt fixture factories
# ---------------------------------------------------------------------------

@pytest.fixture
def make_bag(tmp_path: Path):
    """Factory fixture that creates a BagIt bag in a temp directory.

    Returns a callable:

        make_bag(files: dict[str, bytes]) -> Path

    The *files* dict maps relative paths under ``data/`` to their content.
    """

    def _make(
        files: dict[str, bytes] | None = None,
        *,
        extra_files: dict[str, bytes] | None = None,
    ) -> Path:
        if files is None:
            files = {
                "data/file1.txt": b"Hello, this is test file 1",
                "data/file2.txt": b"Hello, this is test file 2",
            }

        bag_root = tmp_path / f"bag_{uuid.uuid4().hex[:8]}"
        bag_root.mkdir()

        # Write payload files and compute manifest
        manifest_lines: list[str] = []
        for rel_path, content in sorted(files.items()):
            abs_path = bag_root / rel_path
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            abs_path.write_bytes(content)
            file_hash = hashlib.sha256(content).hexdigest()
            manifest_lines.append(f"{file_hash}  {rel_path}")

        # Write manifest-sha256.txt
        manifest_content = "\n".join(manifest_lines) + "\n"
        (bag_root / "manifest-sha256.txt").write_text(manifest_content, encoding="utf-8")

        # Write bagit.txt
        bagit_content = "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n"
        (bag_root / "bagit.txt").write_text(bagit_content, encoding="utf-8")

        # Write bag-info.txt
        total_size = sum(len(c) for c in files.values())
        bag_info_content = (
            f"Bag-Software-Agent: AIP Guardian Test Suite\n"
            f"Payload-Oxum: {total_size}.{len(files)}\n"
        )
        (bag_root / "bag-info.txt").write_text(bag_info_content, encoding="utf-8")

        # Write tagmanifest-sha256.txt
        tag_lines: list[str] = []
        for tag_file in ["bagit.txt", "bag-info.txt", "manifest-sha256.txt"]:
            tag_content = (bag_root / tag_file).read_bytes()
            tag_hash = hashlib.sha256(tag_content).hexdigest()
            tag_lines.append(f"{tag_hash}  {tag_file}")

        tagmanifest_content = "\n".join(tag_lines) + "\n"
        (bag_root / "tagmanifest-sha256.txt").write_text(
            tagmanifest_content, encoding="utf-8"
        )

        # Write any extra files (for testing unlisted files etc.)
        if extra_files:
            for rel_path, content in extra_files.items():
                abs_path = bag_root / rel_path
                abs_path.parent.mkdir(parents=True, exist_ok=True)
                abs_path.write_bytes(content)

        return bag_root

    return _make


@pytest.fixture
def empty_bag(make_bag) -> Path:
    """Return a valid bag with no payload files."""
    return make_bag(files={})
