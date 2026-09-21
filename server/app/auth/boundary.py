"""Injectable boundary with no authentication, sessions or trusted-header policy."""

from typing import Protocol

from fastapi import HTTPException, Request


class HumanAuthorizer(Protocol):
    async def require_system_access(self, request: Request) -> None:
        """Deny unless an approved policy authorizes this system request."""

    async def require_owner_access(self, request: Request) -> None:
        """Deny unless this caller is the deployment Owner.

        System/human access is not ownership: an invited non-Owner identity and a
        capture-node credential both fail here. Owner-only routes depend on this
        in addition to `require_system_access`.
        """


class DenyAll:
    async def require_system_access(self, request: Request) -> None:
        raise HTTPException(status_code=404, detail="Not Found")

    async def require_owner_access(self, request: Request) -> None:
        raise HTTPException(status_code=404, detail="Not Found")


async def require_system_access(request: Request) -> None:
    authorizer: HumanAuthorizer = request.app.state.human_authorizer
    await authorizer.require_system_access(request)


async def require_owner_access(request: Request) -> None:
    """Fail closed when the composed authorizer implements no Owner check."""
    authorizer = getattr(request.app.state, "human_authorizer", None)
    gate = getattr(authorizer, "require_owner_access", None)
    if not callable(gate):
        raise HTTPException(status_code=404, detail="Not Found")
    await gate(request)
