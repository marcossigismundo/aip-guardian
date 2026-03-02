"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from guardian.config import get_settings
from guardian.i18n import _load_translations

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown lifecycle."""
    settings.validate_production_secrets()
    _load_translations()
    logger.info(
        "AIP Integrity Guardian started (debug=%s, hosts=%s)",
        settings.guardian_debug,
        settings.guardian_allowed_hosts,
    )
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
        docs_url="/docs" if settings.guardian_debug else None,
        redoc_url="/redoc" if settings.guardian_debug else None,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_hosts_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # Session middleware
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
