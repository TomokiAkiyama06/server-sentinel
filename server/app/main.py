"""Application construction and lifespan. No listener starts during import."""

import asyncio
from contextlib import asynccontextmanager, closing, suppress
import logging
from typing import Callable, ContextManager, Iterable

from fastapi import FastAPI
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.boundary import DenyAll, HumanAuthorizer
from app.audit import (
    AuditStore, DenyAllOwners, OwnerAuditService, OwnerAuthorizer,
    UnboundStorageAdmission,
)
from app.audit.integration import OwnerAdministration
from app.audit.runtime import AuditRetentionRuntime
from app.cameras.registry import CameraRegistry
from app.diagnostics import DiagnosticExportEndpoint
from app.logging import Event
from app.monitoring.config import MonitoringConfiguration
from app.monitoring.runtime import MonitoringDependencies, MonitoringRuntime, RuntimeState
from app.settings import Settings
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


class RuntimeStorageAdmission:
    """Audit storage admission that follows the monitoring runtime's policy.

    Until a monitoring runtime with configured storage thresholds is running,
    it behaves exactly like `UnboundStorageAdmission` and refuses audit writes.
    Once bound, each audit write holds the Main storage policy's reservation on
    the policy's owning worker through commit.
    """

    def __init__(self) -> None:
        self._runtime: MonitoringRuntime | None = None

    @property
    def bound(self) -> bool:
        runtime = self._runtime
        return runtime is not None and runtime.bound

    def bind(self, runtime: MonitoringRuntime | None) -> None:
        self._runtime = runtime

    def __call__(self) -> ContextManager:
        runtime = self._runtime
        if runtime is None or not runtime.bound:
            return UnboundStorageAdmission()()
        return runtime.reservation()


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
               storage_reservation: Callable[[], ContextManager] | None = None,
               audit_retention_stores: Iterable[object] = (),
               diagnostic_export_endpoint: DiagnosticExportEndpoint | None = None,
               monitoring: MonitoringConfiguration | None = None,
               monitoring_dependencies: MonitoringDependencies | None = None) -> FastAPI:
    store = database or Database(settings.database_path)
    # The Main Server storage policy is bound by the monitoring runtime when
    # the deployment configures storage thresholds, so audit writes and
    # retention cleanup cannot spend the hard filesystem reserve. Without those
    # thresholds the admission stays unbound: writes are refused rather than
    # admitted against a reserve this process cannot verify.
    runtime_admission = RuntimeStorageAdmission()
    monitoring_runtime = (
        MonitoringRuntime(monitoring, store, monitoring_dependencies)
        if monitoring is not None and monitoring.storage_configured else None
    )
    audit_store = AuditStore(store, reservation=storage_reservation or runtime_admission)
    audit_service = OwnerAuditService(audit_store, owner_authorizer or DenyAllOwners())
    owner_administration = OwnerAdministration(audit_service, CameraRegistry(store))
    audit_retention = AuditRetentionRuntime(
        audit_store, *tuple(audit_retention_stores),
        interval_seconds=audit_cleanup_interval_seconds,
    )

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
        monitoring_task = None
        if monitoring_runtime is None:
            # Explicit fail-closed state, never a silently healthy default.
            application.state.monitoring_state = RuntimeState.UNCONFIGURED
            logging.getLogger(__name__).warning(Event.MONITORING_UNCONFIGURED)
        else:
            await monitoring_runtime.start()
            application.state.monitoring_state = monitoring_runtime.status.state
            if monitoring_runtime.bound:
                runtime_admission.bind(monitoring_runtime)
            monitoring_task = asyncio.create_task(monitoring_runtime.run())
        application.state.audit_storage_admitted = (
            storage_reservation is not None or runtime_admission.bound
        )
        try:
            await audit_retention.startup_cleanup()
        except Exception:
            # A refused storage admission or transient database fault must not
            # take physical-security monitoring offline. The bounded degraded
            # retention state stays visible and the scheduled run retries it.
            logging.getLogger(__name__).error(Event.AUDIT_RETENTION_DEGRADED)
        application.state.ready = True
        cleanup_task = asyncio.create_task(audit_retention.run())
        logging.getLogger(__name__).info(Event.STARTED)
        try:
            yield
        finally:
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
            if monitoring_task is not None:
                monitoring_task.cancel()
                with suppress(asyncio.CancelledError):
                    await monitoring_task
            if monitoring_runtime is not None:
                runtime_admission.bind(None)
                application.state.audit_storage_admitted = storage_reservation is not None
                await monitoring_runtime.stop()
                application.state.monitoring_state = monitoring_runtime.status.state
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
    # Whether audit writes are admitted is explicit deployment state, not an
    # assumption: it is false until the Main Server storage policy is bound.
    application.state.audit_storage_admitted = storage_reservation is not None
    application.state.audit_retention = audit_retention
    # Internal runtime state only; no route exposes it before #6/#10.
    application.state.monitoring = monitoring_runtime
    application.state.monitoring_state = (
        RuntimeState.STARTING if monitoring_runtime is not None else RuntimeState.UNCONFIGURED
    )
    application.state.owner_administration = owner_administration
    application.state.diagnostic_export_endpoint = diagnostic_export_endpoint
    # Do not include human routers before approved permission enforcement.
    application.add_middleware(ClosedHumanSurface)
    return application
