"""Application construction and lifespan. No listener starts during import."""

import asyncio
from contextlib import asynccontextmanager, closing, suppress
import logging
from typing import Callable, ContextManager

from fastapi import FastAPI
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.boundary import DenyAll, HumanAuthorizer
from app.audit import AuditStore, DenyAllOwners, OwnerAuditService, OwnerAuthorizer
from app.audit.integration import OwnerAdministration
from app.audit.runtime import AuditRetentionRuntime
from app.cameras.registry import CameraRegistry
from app.logging import Event
from app.settings import Settings
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


class ClosedHumanSurface:
    """Keep every HTTP and WebSocket path closed until Issues #6/#10 land.

    This intentionally does not read paths, query parameters, request bodies or
    identity headers. Replacing an injected authorizer cannot open any route.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            body = b'{"detail":"Not Found"}'
            await send({"type": "http.response.start", "status": 404, "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ]})
            await send({"type": "http.response.body", "body": body})
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await self.app(scope, receive, send)


def create_app(settings: Settings, *, database: Database | None = None,
               human_authorizer: HumanAuthorizer | None = None,
               owner_authorizer: OwnerAuthorizer | None = None,
               audit_cleanup_interval_seconds: float = 24 * 60 * 60,
               storage_reservation: Callable[[], ContextManager] | None = None) -> FastAPI:
    store = database or Database(settings.database_path)
    # The deployment injects the Main Server storage admission reservation once
    # its storage policy is bound, so audit writes and retention cleanup cannot
    # spend the hard filesystem reserve.
    audit_store = AuditStore(store, reservation=storage_reservation)
    audit_service = OwnerAuditService(audit_store, owner_authorizer or DenyAllOwners())
    owner_administration = OwnerAdministration(audit_service, CameraRegistry(store))
    audit_retention = AuditRetentionRuntime(
        audit_store, interval_seconds=audit_cleanup_interval_seconds,
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.ready = False
        try:
            with closing(store.connect()) as connection:
                migrate(connection, APPLICATION_MIGRATIONS)
            audit_retention.startup_cleanup()
        except Exception:
            logging.getLogger(__name__).error(Event.STARTUP_FAILED)
            # Lifespan failures must not pass SQLite/config values to servers.
            raise RuntimeError("application startup failed") from None
        application.state.ready = True
        cleanup_task = asyncio.create_task(audit_retention.run())
        logging.getLogger(__name__).info(Event.STARTED)
        try:
            yield
        finally:
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
            application.state.ready = False
            logging.getLogger(__name__).info(Event.STOPPED)

    application = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None,
        debug=False, lifespan=lifespan,
    )
    application.state.ready = False
    application.state.database = store
    application.state.human_authorizer = human_authorizer or DenyAll()
    application.state.audit_store = audit_store
    application.state.audit_retention = audit_retention
    application.state.owner_administration = owner_administration
    # Do not include api.system.router before approved permission enforcement.
    application.add_middleware(ClosedHumanSurface)
    return application
