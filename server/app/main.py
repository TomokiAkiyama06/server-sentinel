"""Application construction and lifespan. No listener starts during import."""

from contextlib import asynccontextmanager, closing
import logging

from fastapi import FastAPI
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.boundary import DenyAll, HumanAuthorizer
from app.diagnostics import DiagnosticExportEndpoint
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
               diagnostic_export_endpoint: DiagnosticExportEndpoint | None = None) -> FastAPI:
    store = database or Database(settings.database_path)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.ready = False
        try:
            with closing(store.connect()) as connection:
                migrate(connection, APPLICATION_MIGRATIONS)
        except Exception:
            logging.getLogger(__name__).error(Event.STARTUP_FAILED)
            # Lifespan failures must not pass SQLite/config values to servers.
            raise RuntimeError("application startup failed") from None
        application.state.ready = True
        logging.getLogger(__name__).info(Event.STARTED)
        try:
            yield
        finally:
            application.state.ready = False
            logging.getLogger(__name__).info(Event.STOPPED)

    application = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None,
        debug=False, lifespan=lifespan,
    )
    application.state.ready = False
    application.state.database = store
    application.state.human_authorizer = human_authorizer or DenyAll()
    application.state.diagnostic_export_endpoint = diagnostic_export_endpoint
    # Do not include human routers before approved permission enforcement.
    application.add_middleware(ClosedHumanSurface)
    return application
