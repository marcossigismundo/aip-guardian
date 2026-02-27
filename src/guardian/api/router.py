"""Main API router — aggregates all sub-routers."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from guardian.api.deps import verify_token

# Create the top-level router with a shared auth dependency.
# Individual endpoints (like /health) can opt out via their router config.
api_router = APIRouter(dependencies=[Depends(verify_token)])

# --- Sub-routers ----------------------------------------------------------
from guardian.api.aips import router as aips_router  # noqa: E402
from guardian.api.audit import router as audit_router  # noqa: E402
from guardian.api.anchors import router as anchors_router  # noqa: E402
from guardian.api.dashboard import router as dashboard_router  # noqa: E402
from guardian.api.health import router as health_router  # noqa: E402

api_router.include_router(aips_router, prefix="/aips", tags=["AIPs"])
api_router.include_router(audit_router, prefix="/audit", tags=["Audit"])
api_router.include_router(anchors_router, prefix="/anchors", tags=["Anchors"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(health_router, tags=["Health"])
