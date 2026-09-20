"""Health/version handlers prepared for future authorized mounting."""

from fastapi import APIRouter, Depends, Request

from app import __version__
from app.auth.boundary import require_system_access


router = APIRouter(dependencies=[Depends(require_system_access)])


@router.get("/health")
async def health(request: Request) -> dict[str, str]:
    # This states foundation lifecycle readiness, not camera/recording health.
    return {"foundation": "ready" if request.app.state.ready else "unavailable"}


@router.get("/version")
async def version() -> dict[str, str]:
    return {"version": __version__}
