"""Prepared Owner-only diagnostic route; production mounting remains closed."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.auth.boundary import require_owner_access, require_system_access
from app.diagnostics import DiagnosticExportEndpoint, DiagnosticExportError


class DiagnosticExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    selected_media_ids: list[str] = Field(default_factory=list, max_length=100)


# Owner authorization precedes the handler, so an invited non-Owner identity
# never reaches diagnostic collection or a selected-media lookup.
router = APIRouter(dependencies=[Depends(require_system_access),
                                 Depends(require_owner_access)])


@router.post("/diagnostics/export")
async def export_diagnostics(payload: DiagnosticExportRequest,
                             request: Request) -> dict[str, object]:
    endpoint: DiagnosticExportEndpoint | None = getattr(
        request.app.state, "diagnostic_export_endpoint", None)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Not Found")
    try:
        result = await endpoint.export(tuple(payload.selected_media_ids))
    except DiagnosticExportError:
        # Export errors are already value free; the route still reports only a
        # fixed status so no local failure detail reaches the HTTP boundary.
        raise HTTPException(
            status_code=503, detail="Service Unavailable") from None
    except ValueError:
        # A rejected selection must not echo the submitted identifiers back.
        raise HTTPException(status_code=400, detail="Bad Request") from None
    return {
        "bundle_name": result.bundle_path.name,
        "included_categories": result.included_categories,
        "included_media_count": result.included_media_count,
    }
