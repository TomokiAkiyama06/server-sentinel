"""Injectable boundary with no authentication, sessions or trusted-header policy."""

from typing import Protocol

from fastapi import HTTPException, Request


class HumanAuthorizer(Protocol):
    async def require_system_access(self, request: Request) -> None:
        """Deny unless an approved policy authorizes this system request."""


class DenyAll:
    async def require_system_access(self, request: Request) -> None:
        raise HTTPException(status_code=404, detail="Not Found")


async def require_system_access(request: Request) -> None:
    authorizer: HumanAuthorizer = request.app.state.human_authorizer
    await authorizer.require_system_access(request)
