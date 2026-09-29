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
from app.cameras.uvc.config import LocalUvcConfiguration
from app.cameras.uvc.runtime import LocalUvcDependencies, LocalUvcRuntime, LocalUvcRuntimeState
from app.diagnostics import DiagnosticExportEndpoint
from app.logging import Event
from app.media.live.local_preview import LocalPreviewHub
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
               monitoring_dependencies: MonitoringDependencies | None = None,
               local_uvc: LocalUvcConfiguration | None = None,
               local_uvc_dependencies: LocalUvcDependencies | None = None) -> FastAPI:
    store = database or Database(settings.database_path)
    # Local UVC capture is driven only by the deployment's list of approved
    # logical sources. Frames go to a bounded preview hub that retains nothing
    # without authorized live viewer demand; no route reads it (#10/#19).
    if local_uvc is not None and not isinstance(local_uvc, LocalUvcConfiguration):
        raise TypeError("local UVC configuration is invalid")
    uvc_dependencies = local_uvc_dependencies or LocalUvcDependencies()
    local_preview = LocalPreviewHub(local_uvc.source_ids if local_uvc is not None else ())
    local_uvc_runtime = (
        LocalUvcRuntime(
            local_uvc, CameraRegistry(store), on_frame=local_preview.on_frame,
            health_sink=uvc_dependencies.health_sink,
            discovery=uvc_dependencies.discovery,
            capture_factory=uvc_dependencies.capture_factory,
        ) if local_uvc is not None else None
    )
    # The Main Server storage policy is bound by the monitoring runtime when
    # the deployment configures storage thresholds, so audit writes and
    # retention cleanup cannot spend the hard filesystem reserve. Without those
    # thresholds the admission stays unbound: writes are refused rather than
    # admitted against a reserve this process cannot verify.
    runtime_admission = RuntimeStorageAdmission()
    monitoring_runtime = (
        MonitoringRuntime(monitoring, store, monitoring_dependencies,
                          migrations=APPLICATION_MIGRATIONS)
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
        # Schema migrations are metadata writes and are admitted like any
        # other: the monitoring runtime migrates on its worker inside the
        # verified storage policy (identity + hard reserve); an embedder's
        # injected reservation covers them otherwise. Without either admission
        # nothing is written, so an unconfigured app never spends the reserve.
        try:
            if monitoring_runtime is not None:
                await monitoring_runtime.start()
            elif storage_reservation is not None:
                with storage_reservation():
                    with closing(store.connect()) as connection:
                        migrate(connection, APPLICATION_MIGRATIONS)
        except Exception:
            if monitoring_runtime is not None:
                with suppress(Exception):
                    await monitoring_runtime.stop()
            logging.getLogger(__name__).error(Event.STARTUP_FAILED)
            # Lifespan failures must not pass SQLite/config values to servers.
            raise RuntimeError("application startup failed") from None
        monitoring_task = None

        uvc_lifecycle = {"deferred": None, "stopping": False}

        def local_uvc_storage_admitted() -> bool:
            if monitoring_runtime is not None:
                # A monitoring runtime whose startup open failed (missing or
                # replaced recording filesystem, unopenable database) has not
                # migrated or verified storage; its admission refuses writes.
                return monitoring_runtime.status.state == RuntimeState.RUNNING
            return storage_reservation is not None

        async def start_local_uvc() -> None:
            # Never a silent default: every outcome is an explicit state.
            if local_uvc_runtime is None:
                application.state.local_uvc_state = LocalUvcRuntimeState.UNCONFIGURED
                logging.getLogger(__name__).warning(Event.LOCAL_UVC_UNCONFIGURED)
                return
            if not local_uvc_storage_admitted():
                # No schema was migrated and no write is admitted, so the
                # approval store and source health cannot be trusted. Capture
                # stays off rather than running against unverified storage;
                # a later successful monitoring retry starts it.
                application.state.local_uvc_state = LocalUvcRuntimeState.STORAGE_UNADMITTED
                logging.getLogger(__name__).error(Event.LOCAL_UVC_STORAGE_UNADMITTED)
                return
            try:
                # Registry reads and thread starts must not block the loop.
                status = await asyncio.to_thread(local_uvc_runtime.start)
                application.state.local_uvc_state = status.state
            except Exception:
                # Camera capture failure must not take audit/monitoring down.
                application.state.local_uvc_state = LocalUvcRuntimeState.FAILED
                logging.getLogger(__name__).error(Event.LOCAL_UVC_STARTUP_FAILED)

        async def stop_local_uvc() -> None:
            if local_uvc_runtime is None:
                return
            try:
                # Bounded joins; physical capture closes before storage stops.
                status = await asyncio.to_thread(local_uvc_runtime.stop)
                application.state.local_uvc_state = status.state
            except Exception:
                application.state.local_uvc_state = LocalUvcRuntimeState.STOP_FAILED
                logging.getLogger(__name__).error(Event.LOCAL_UVC_STOP_FAILED)
            local_preview.clear()

        def refresh_monitoring_state() -> None:
            # Snapshots follow the live runtime, e.g. a retried startup open
            # that later succeeds, instead of freezing the first result.
            application.state.monitoring_state = monitoring_runtime.status.state
            application.state.audit_storage_admitted = (
                storage_reservation is not None or runtime_admission.bound
            )
            if (local_uvc_runtime is not None and not uvc_lifecycle["stopping"]
                    and uvc_lifecycle["deferred"] is None
                    and application.state.local_uvc_state
                    is LocalUvcRuntimeState.STORAGE_UNADMITTED
                    and local_uvc_storage_admitted()):
                # Storage became admitted after a failed startup open: start
                # capture once. Shutdown awaits this task before stopping.
                uvc_lifecycle["deferred"] = asyncio.create_task(start_local_uvc())

        if monitoring_runtime is None:
            # Explicit fail-closed fault, never a silently healthy default.
            # The mandatory startup/daily hardware integrity check and daily
            # recording self-test cannot run here, so the production entry
            # points (`app.deployment`, `python -m app`) refuse to serve in
            # this state; it is reachable only by embedding `create_app()`.
            # No schema migration runs here without an injected reservation.
            application.state.monitoring_state = RuntimeState.UNCONFIGURED
            logging.getLogger(__name__).error(Event.MONITORING_UNCONFIGURED)
        else:
            # Admission follows the live runtime state: a runtime that failed
            # startup refuses writes until its retried open succeeds.
            runtime_admission.bind(monitoring_runtime)
            monitoring_task = asyncio.create_task(
                monitoring_runtime.run(after_tick=refresh_monitoring_state)
            )
        application.state.audit_storage_admitted = (
            storage_reservation is not None or runtime_admission.bound
        )
        if monitoring_runtime is not None:
            refresh_monitoring_state()
        try:
            await audit_retention.startup_cleanup()
        except Exception:
            # A refused storage admission or transient database fault must not
            # take physical-security monitoring offline. The bounded degraded
            # retention state stays visible and the scheduled run retries it.
            logging.getLogger(__name__).error(Event.AUDIT_RETENTION_DEGRADED)
        await start_local_uvc()
        application.state.ready = True
        cleanup_task = asyncio.create_task(audit_retention.run())
        logging.getLogger(__name__).info(Event.STARTED)
        try:
            yield
        finally:
            uvc_lifecycle["stopping"] = True
            if uvc_lifecycle["deferred"] is not None:
                # start() and stop() serialize on the runtime lock; let a
                # deferred start finish so stop() sees its workers.
                with suppress(Exception):
                    await asyncio.shield(uvc_lifecycle["deferred"])
            await stop_local_uvc()
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
    # Internal only: no route exposes local capture state or preview frames.
    application.state.local_uvc = local_uvc_runtime
    application.state.local_uvc_state = (
        LocalUvcRuntimeState.STARTING if local_uvc_runtime is not None
        else LocalUvcRuntimeState.UNCONFIGURED
    )
    application.state.local_preview = local_preview
    application.state.diagnostic_export_endpoint = diagnostic_export_endpoint
    # Do not include human routers before approved permission enforcement.
    application.add_middleware(ClosedHumanSurface)
    return application
