"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from guardian.config import get_settings
from guardian.i18n import _load_translations

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown lifecycle."""
    _load_translations()
    yield


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title="AIP Integrity Guardian",
        description=(
            "Continuous integrity verification for Archivematica AIPs. "
            "ISO 16363 & OAIS ISO 14721 compliant."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Middleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.guardian_secret_key,
    )

    # Static files
    static_dir = Path(__file__).parent / "web" / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # API routes
    from guardian.api.router import api_router
    app.include_router(api_router, prefix="/api/v1")

    # Web dashboard routes
    from guardian.web.routes import web_router
    app.include_router(web_router)

    return app


app = create_app()
