"""FastAPI dependency functions for database sessions, auth, and i18n."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.config import get_settings
from guardian.database import async_session_factory
from guardian.i18n import get_locale


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session, committing on success or rolling back
    on error.

    Use as a FastAPI dependency::

        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db_session)):
            ...
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def verify_token(request: Request) -> None:
    """Validate the ``Authorization: Bearer <token>`` header.

    The expected token is compared against ``settings.guardian_api_token``.
    The ``/health`` endpoint is exempt from authentication so that load
    balancers and monitoring probes can reach it without credentials.

    Raises
    ------
    HTTPException
        401 Unauthorized if the token is missing or invalid.
    """
    # Skip authentication for the health endpoint
    if request.url.path.rstrip("/").endswith("/health"):
        return

    settings = get_settings()
    auth_header: str | None = request.headers.get("Authorization")

    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format — expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if parts[1] != settings.guardian_api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_lang(request: Request) -> str:
    """Return the current locale string derived from the request.

    Checks (in order):

    1. ``guardian_lang`` cookie
    2. ``Accept-Language`` header
    3. Falls back to the default language (English).
    """
    return get_locale(request)
