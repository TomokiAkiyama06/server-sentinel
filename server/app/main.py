"""Application construction and lifespan. No listener starts during import."""

import asyncio
from contextlib import asynccontextmanager, closing, suppress
from dataclasses import replace
import logging
from typing import Callable, ContextManager, Iterable

from fastapi import FastAPI
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.boundary import DenyAll, HumanAuthorizer
from app.auth.human_surface import HumanAccess, HumanSurface, send_generic_denial
from app.audit import (
    AuditStore, DenyAllOwners, OwnerAuditService, OwnerAuthorizer,
    UnboundStorageAdmission,
)
from app.audit.model import ActorCategory, AuditAction, AuditOutcome, TargetKind
from app.audit.integration import OwnerAdministration
from app.audit.runtime import AuditRetentionRuntime
from app.cameras.registry import CameraRegistry
from app.cameras.uvc.config import LocalUvcConfiguration
from app.cameras.uvc.runtime import LocalUvcDependencies, LocalUvcRuntime, LocalUvcRuntimeState
from app.completion import run_to_completion
from app.detection.roi.calibration_service import (
    SceneCalibrationConfiguration, SceneCalibrationService, TransientReferences,
)
from app.detection.roi.runtime import (
    ArchiveCalibrationProvider, SceneMonitoringConfiguration, SceneMonitoringDependencies,
    SceneMonitoringRuntime, SceneRuntimeState,
)
from app.diagnostics import DiagnosticExportEndpoint
from app.logging import Event
from app.media.live.frame_pull import LiveFrameService
from app.media.live.local_preview import LocalPreviewHub
from app.monitoring.access import AccessFaultMonitor
from app.monitoring.cameras import CameraOfflineMonitor
from app.monitoring.config import MonitoringConfiguration
from app.monitoring.runtime import MonitoringDependencies, MonitoringRuntime, RuntimeState
from app.notifications.service import NotificationKind
from app.presence.delivery import NotificationAdapter
from app.presence.runtime import CriticalDispatcher, SceneTimeline, SceneTimelineConfiguration
from app.settings import Settings
from app.storage.database import Database, PinnedDatabase
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


# Issue #301 item 2: without a scene critical dispatcher (whose shutdown
# settle already waits for every pending notification), shutdown waits at
# most this long for a camera offline notification still being delivered,
# longer than the 10 s Slack timeout, before the monitoring runtime stops.
# The scene calibration notices (#205) use the same bound.
CAMERA_OFFLINE_SETTLE_SECONDS = 12.0


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


class HumanAccessCompositionRefused(TypeError):
    """``create_app`` refused the ``human_access`` composition it was given.

    A ``TypeError`` (the existing contract for an invalid argument), but its
    own class, so the launcher serves closed and alerts only on this refusal
    and an unrelated ``TypeError`` from a bug still propagates (Issue #283
    item 2). Carries no configuration value.
    """

    def __init__(self, message: str = "human access composition is invalid") -> None:
        super().__init__(message)


class ClosedHumanSurface:
    """Keep every HTTP and WebSocket path closed (the default).

    This intentionally does not read paths, query parameters, request bodies or
    identity headers. Replacing an injected authorizer cannot open any route;
    only a validated ``HumanAccess`` composition replaces this surface (Issue
    #10 phase 1, ``app.auth.human_surface``).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            await send_generic_denial(send)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await self.app(scope, receive, send)


def _assets_from_settings(human_access: HumanAccess, settings: Settings) -> bool:
    """Whether the composition serves the Web build at ``settings.web_assets_dir``."""
    if settings.web_assets_dir is None:
        return False
    try:
        return human_access.assets.directory == settings.web_assets_dir.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False


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
               local_uvc_dependencies: LocalUvcDependencies | None = None,
               scene_monitoring: SceneMonitoringConfiguration | None = None,
               scene_monitoring_dependencies: SceneMonitoringDependencies | None = None,
               scene_timeline: SceneTimelineConfiguration | None = None,
               scene_calibration: SceneCalibrationConfiguration | None = None,
               human_access: HumanAccess | None = None) -> FastAPI:
    # Closed unless the embedder passes a validated composition: it exists
    # only when the deployment explicitly enabled human access and the
    # hostname reservation check is fully configured. In production only the
    # deployment key `human_access` builds one (`app.auth.composition`, through
    # `app.deployment`); without it, and for `python -m app`, it stays closed.
    if human_access is not None and not isinstance(human_access, HumanAccess):
        raise HumanAccessCompositionRefused()
    if human_access is not None and human_access.store.invitation_lifetime != settings.invitation_lifetime:
        # Issue #235 item 3: Owner-issued invitations expire after the
        # deployment's ``invitation_lifetime_hours``; a store left at another
        # lifetime (the 24-hour default, say) would issue codes with the
        # wrong expiry or refuse every one.
        raise HumanAccessCompositionRefused()
    if human_access is not None and not _assets_from_settings(human_access, settings):
        # Issue #10 phase 2 S5b: the served Web build is the one the
        # deployment settings name, never one an embedder picked elsewhere.
        raise HumanAccessCompositionRefused()
    access_faults = monitoring_dependencies.access_faults if monitoring_dependencies is not None else None
    if access_faults is not None and (monitoring is None or not monitoring.storage_configured):
        # Only the monitoring runtime drains the monitor (Codex PR #271):
        # without one an emitted fault would leave the check's retry queue
        # and never reach the Owner or the health status.
        raise TypeError("access fault monitor requires the monitoring runtime")
    if (human_access is not None and access_faults is None
            and any(isinstance(sink, AccessFaultMonitor) for sink in
                    (human_access.reservation.fault_sink, human_access.ceremonies.findings))):
        # Codex PR #271: a monitor installed as a sink but not handed to the
        # monitoring runtime is never drained, so its faults would be lost.
        raise HumanAccessCompositionRefused()
    if (human_access is not None and access_faults is None
            and monitoring is not None and monitoring.storage_configured):
        # Issue #281 item 1: wherever a monitoring runtime runs (every
        # production deployment, which refuses to start without one), a human
        # composition must report to its AccessFaultMonitor; without one a
        # closed check or a credential finding would never reach the Owner.
        raise HumanAccessCompositionRefused(
            "human access composition requires the access fault monitor")
    if human_access is not None and access_faults is not None:
        # Issue #232 item 4 (Owner decision 2026-10-16): with a configured
        # monitor, every reservation fault and credential finding of this
        # composition must reach it, so none bypasses the immediate Owner
        # notification and degraded health.
        if (human_access.reservation.fault_sink is not access_faults
                or human_access.ceremonies.findings is not access_faults
                or access_faults.attached not in (None, human_access)):
            raise HumanAccessCompositionRefused()
    store = database or Database(settings.database_path)
    # Local UVC capture is driven only by the deployment's list of approved
    # logical sources. Frames go to a bounded preview hub that retains nothing
    # without authorized live viewer demand; only the S7 frame pull reads it.
    if local_uvc is not None and not isinstance(local_uvc, LocalUvcConfiguration):
        raise TypeError("local UVC configuration is invalid")
    uvc_dependencies = local_uvc_dependencies or LocalUvcDependencies()
    local_preview = LocalPreviewHub(local_uvc.source_ids if local_uvc is not None else ())
    # Calibrated ROI movement / camera tamper (#205). Capture threads only
    # hand it a bounded sample; detection runs on its own worker and confirmed
    # observations go to the injected durable critical recorder. Without a
    # recorder or a re-bindable stored calibration it stays unknown.
    if scene_monitoring is not None and not isinstance(scene_monitoring,
                                                       SceneMonitoringConfiguration):
        raise TypeError("scene monitoring configuration is invalid")
    # The Main Server storage policy is bound by the monitoring runtime when
    # the deployment configures storage thresholds, so audit writes and
    # retention cleanup cannot spend the hard filesystem reserve. Without those
    # thresholds the admission stays unbound: writes are refused rather than
    # admitted against a reserve this process cannot verify.
    runtime_admission = RuntimeStorageAdmission()
    # Issue #301 item 2 (Owner decision 2026-10-22): a configured local UVC
    # source that stays offline for `camera_offline_notification.after_seconds`
    # notifies the Owner through the monitoring runtime's
    # `NotificationService`, the same durable row and optional Slack delivery
    # as a hardware-integrity failure. The monitor is fed by the capture
    # runtime's health sink and status (below) and drained on the monitoring
    # worker. Without a monitoring runtime there is no notification service.
    if monitoring_dependencies is not None and monitoring_dependencies.camera_offline is not None:
        # Owned here, like the scene timeline's recorder: it must observe
        # exactly the capture runtime this application starts and stops.
        raise TypeError("the application owns the camera offline monitor")
    camera_offline = None
    if (local_uvc is not None and monitoring is not None
            and monitoring.storage_configured):
        dependencies = monitoring_dependencies or MonitoringDependencies()
        camera_offline = CameraOfflineMonitor(
            local_uvc.source_ids, after_seconds=monitoring.camera_offline.after_seconds,
            hourly_limit=monitoring.camera_offline.hourly_limit,
            monotonic=dependencies.monotonic)
        monitoring_dependencies = replace(dependencies, camera_offline=camera_offline)
    # Built before the scene timeline, whose critical notification port
    # submits through this runtime's `NotificationService` (Issue #26).
    monitoring_runtime = (
        MonitoringRuntime(monitoring, store, monitoring_dependencies,
                          migrations=APPLICATION_MIGRATIONS)
        if monitoring is not None and monitoring.storage_configured else None
    )
    # Presence timeline for scene evidence (#205): with `scene_timeline` the
    # application owns the durable critical recorder, the count-only
    # undelivered sink and the outbox session lifecycle (see lifespan).
    timeline = None
    critical_dispatcher = None
    if scene_timeline is not None:
        if not isinstance(scene_timeline, SceneTimelineConfiguration):
            raise TypeError("scene timeline configuration is invalid")
        if scene_monitoring is None:
            raise TypeError("scene timeline requires scene monitoring")
        if scene_monitoring_dependencies is not None and (
                scene_monitoring_dependencies.recorder is not None
                or scene_monitoring_dependencies.undelivered is not None):
            # The recorder and the sink must both be this outbox's, or the
            # stop/close ordering below would not cover what they record.
            raise TypeError("scene timeline owns the critical recorder and undelivered sink")
        scene_holder = []

        def scene_detection_armed() -> bool:
            # Presence `critical_detection`: armed only while the scene
            # runtime is running; degraded, unavailable or stopped is not.
            return bool(scene_holder) and (scene_holder[0].status().state
                                           is SceneRuntimeState.RUNNING)

        # Confirmed server movement / camera tamper notify the Owner through
        # the monitoring runtime's `NotificationService`: the same durable
        # `notification_events` row and optional Slack delivery as a hardware
        # integrity or recording-health failure (Issue #26, #21). The port
        # runs on that runtime's worker (`CriticalDispatcher` below). Without
        # a monitoring runtime there is no notification service, so the path
        # stays reported unavailable. No evidence-preservation port exists
        # yet (a separate recording decision): `critical_evidence` stays
        # unavailable.
        notification_port = (
            NotificationAdapter(lambda: monitoring_runtime.notifications, NotificationKind,
                                provided=True,
                                # Without Slack the local `disabled` event is
                                # still recorded, but the path is unavailable
                                # from the start (SPECIFICATION #205 runtime).
                                configured=lambda: monitoring.slack is not None,
                                # Issue #318: an outcome already stored for the
                                # observation (an alert attempted while its
                                # record was refused) is taken, not resent.
                                outcomes=lambda ids: monitoring_runtime.notification_outcomes(ids))
            if monitoring_runtime is not None else None)
        timeline = SceneTimeline(scene_timeline, store, storage_reservation or runtime_admission,
                                 detection=scene_detection_armed,
                                 notifications=notification_port)
        if monitoring_runtime is not None:
            def critical_dispatch_step() -> int:
                return timeline.dispatch(reconcile=monitoring_runtime.notification_outcomes)

            def unrecorded_alert_step() -> int:
                # Issue #318: confirmed criticals whose record storage refused
                # still attempt Slack (Owner decision 2026-10-22).
                return timeline.unrecorded.drain(at=monitoring_runtime.dependencies.utcnow())

            critical_dispatcher = CriticalDispatcher(
                timeline,
                lambda step: monitoring_runtime.call(monitoring_runtime.dispatch_notifications, step),
                critical_dispatch_step,
                alerts=unrecorded_alert_step if timeline.unrecorded is not None else None)
        scene_monitoring_dependencies = replace(
            scene_monitoring_dependencies or SceneMonitoringDependencies(),
            recorder=timeline.recorder, undelivered=timeline.undelivered)
    # The Owner calibration and the restart re-acquisition of scene
    # references (#205, Owner decision 2026-10-22, option A). With
    # `scene_calibration` the application owns the runtime's calibration
    # provider: stored provenance (read-only) plus the reference frames this
    # process holds in memory. Nothing derived from an image is persisted.
    calibration_references = None
    if scene_calibration is not None:
        if not isinstance(scene_calibration, SceneCalibrationConfiguration):
            raise TypeError("scene calibration configuration is invalid")
        if scene_monitoring is None:
            raise TypeError("scene calibration requires scene monitoring")
        if (scene_monitoring_dependencies is not None
                and scene_monitoring_dependencies.calibrations is not None):
            raise TypeError("scene calibration owns the calibration provider")
        if monitoring_runtime is None:
            # A re-acquired reference must reach the Owner at once (DET-004)
            # through the monitoring runtime's `NotificationService`; without
            # it a notice could only be logged and dropped (Codex P2, #330).
            raise TypeError("scene calibration requires the monitoring notification runtime")
        calibration_references = TransientReferences()
        scene_monitoring_dependencies = replace(
            scene_monitoring_dependencies or SceneMonitoringDependencies(),
            calibrations=ArchiveCalibrationProvider(store.connect_read_only,
                                                    references=calibration_references))
    scene_runtime = (SceneMonitoringRuntime(scene_monitoring, scene_monitoring_dependencies)
                     if scene_monitoring is not None else None)
    if timeline is not None:
        scene_holder.append(scene_runtime)
    scene_calibration_service = (
        SceneCalibrationService(scene_calibration, scene_runtime, store.connect_read_only,
                                references=calibration_references)
        if scene_calibration is not None else None)

    def on_local_frame(source_id, frame) -> None:
        # Both sinks are non-blocking and never raise into the capture worker.
        local_preview.on_frame(source_id, frame)
        if scene_runtime is not None:
            scene_runtime.on_uvc_frame(source_id, frame)

    def on_local_camera_state(event) -> None:
        local_preview.on_health(event)
        if scene_runtime is not None:
            scene_runtime.on_uvc_health(event)

    injected_health_sink = uvc_dependencies.health_sink

    def monitored_health_sink(event) -> None:
        # On the capture runtime's health-sink delivery thread, never a
        # capture worker; the monitor only latches state and never raises.
        camera_offline.health_sink(event)
        if injected_health_sink is not None:
            injected_health_sink(event)

    local_health_sink = (monitored_health_sink if camera_offline is not None
                         else injected_health_sink)
    # Capture workers write source health, negotiated profiles, last-seen
    # timestamps and approval session markers continuously. They are admitted
    # exactly like audit writes, so a hard stop or a missing/replaced recording
    # filesystem after startup refuses them (capture then fails visibly and
    # retries) instead of writing past the reserve or to a fallback path.
    local_uvc_runtime = (
        LocalUvcRuntime(
            local_uvc,
            # Reads, too, open only the database file pinned under admission
            # and never create one, so a lost or replaced filesystem after
            # startup cannot make a worker open/create a fallback database.
            CameraRegistry(PinnedDatabase(store),
                           reservation=storage_reservation or runtime_admission),
            on_frame=on_local_frame,
            # A non-online camera transition drops that source's retained
            # preview frame in memory, in transition order, independently of
            # the optional downstream sink, which may be slow or hang; so it
            # is never served as live.
            on_camera_state=on_local_camera_state,
            health_sink=local_health_sink,
            discovery=uvc_dependencies.discovery,
            capture_factory=uvc_dependencies.capture_factory,
        ) if local_uvc is not None else None
    )
    audit_store = AuditStore(store, reservation=storage_reservation or runtime_admission)
    if human_access is not None:
        # Human-access writes (challenges, sessions, revocation) are admitted
        # exactly like audit writes; an unbound runtime admission refuses them.
        # That admission verifies this application's database only, so an
        # access store on any other database is refused here.
        human_access.bind_storage_admission(storage_reservation or runtime_admission, database=store)
        # S7 interim live (Owner decision D10, #10/#19): the authorized frame
        # pull is the only reader of the preview hub; it retains nothing
        # without polling live:view viewers and starts/stops with run().
        human_access.attach_live(LiveFrameService(local_preview, human_access.store))
        if scene_calibration_service is not None:
            # The Owner's calibration routes (#205); without the service
            # they stay the generic denial. The routes write the history
            # through the access store's database while the provider and the
            # service read it from `store`; `bind_storage_admission` above
            # already refused an access store on any other database, so the
            # history cannot split (Claude review proposal 7).
            human_access.attach_scene_calibration(scene_calibration_service)
    audit_service = OwnerAuditService(audit_store, owner_authorizer or DenyAllOwners())
    owner_administration = OwnerAdministration(audit_service, CameraRegistry(store))
    audit_retention = AuditRetentionRuntime(
        audit_store, *tuple(audit_retention_stores),
        # The owned presence timeline expires with the same schedule (Codex
        # PR #296): timeline payloads after the recording retention, Owner
        # control audit rows after the audit retention.
        *(timeline.retention_stores if timeline is not None else ()),
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
        except BaseException as error:
            # A cancelled startup (embedder shutdown or startup timeout) stops
            # the monitoring worker exactly like a failed one.
            if monitoring_runtime is not None:
                with suppress(Exception):
                    await run_to_completion(monitoring_runtime.stop())
            if not isinstance(error, Exception):
                raise
            logging.getLogger(__name__).error(Event.STARTUP_FAILED)
            # Lifespan failures must not pass SQLite/config values to servers.
            raise RuntimeError("application startup failed") from None
        monitoring_task = None
        cleanup_task = None
        uvc_watch_task = None
        human_task = None
        # The scene watcher may be started late, by the timeline task, once
        # a deferred outbox open succeeds; shutdown reads it from here.
        scene_lifecycle = {"watch": None, "timeline": None, "dispatch": None, "calibration": None,
                           "notified": False, "stopping": False}

        uvc_lifecycle = {"deferred": None, "stopping": False}

        def local_uvc_storage_admitted() -> bool:
            if monitoring_runtime is not None:
                # A monitoring runtime whose startup open failed (missing or
                # replaced recording filesystem, unopenable database) has not
                # migrated or verified storage; its admission refuses writes.
                return monitoring_runtime.status.state == RuntimeState.RUNNING
            return storage_reservation is not None

        async def start_scene_monitoring() -> None:
            if scene_runtime is None:
                application.state.scene_monitoring_state = SceneRuntimeState.UNCONFIGURED
                logging.getLogger(__name__).warning(Event.SCENE_MONITORING_UNCONFIGURED)
                return
            try:
                status = await run_to_completion(asyncio.to_thread(scene_runtime.start))
                application.state.scene_monitoring_state = status.state
            except Exception:
                # Scene detection failure must not take capture/monitoring down;
                # every scene conclusion stays unknown.
                application.state.scene_monitoring_state = SceneRuntimeState.UNAVAILABLE
                logging.getLogger(__name__).error(Event.SCENE_MONITORING_STARTUP_FAILED)
                return
            logging.getLogger(__name__).log(
                logging.INFO if status.state is SceneRuntimeState.RUNNING else logging.ERROR,
                Event.SCENE_MONITORING_STARTED if status.state is SceneRuntimeState.RUNNING
                else Event.SCENE_MONITORING_UNAVAILABLE)

        async def watch_scene_monitoring() -> None:
            # The application snapshot follows the live runtime, like the UVC
            # watcher: critical backpressure (DEGRADED), its recovery, or a
            # failed/dead worker or delivery thread (UNAVAILABLE, which the
            # runtime status itself derives) is reflected here instead of
            # the startup result staying RUNNING until shutdown. A recorder
            # call stalled in flight, a camera loss, a stale source or any
            # other lowered source is DEGRADED. Shutdown cancels this task
            # before stop() writes the final state.
            live = (SceneRuntimeState.RUNNING, SceneRuntimeState.DEGRADED)
            while application.state.scene_monitoring_state in live:
                await asyncio.sleep(scene_runtime.refresh_interval_seconds)
                try:
                    status = await asyncio.to_thread(scene_runtime.status)
                    state = status.state
                    lost = state in live and not (status.worker_running
                                                  and status.delivery_running)
                except Exception:
                    state, lost = SceneRuntimeState.UNAVAILABLE, True
                if lost:
                    # A worker or delivery thread that is gone (or a status
                    # that cannot be read) evaluates or delivers nothing.
                    # Logged once here (the loop ends on a non-live state); an
                    # `unavailable` the runtime status reports itself was
                    # already logged by the runtime and is not logged again.
                    state = SceneRuntimeState.UNAVAILABLE
                    logging.getLogger(__name__).error(Event.SCENE_MONITORING_UNAVAILABLE)
                application.state.scene_monitoring_state = state

        async def stop_scene_monitoring():
            """Stop scene monitoring; the returned status (None if it raised)
            decides whether the timeline outbox may close cleanly."""
            if scene_runtime is None:
                return None
            try:
                status = await run_to_completion(asyncio.to_thread(scene_runtime.stop))
                application.state.scene_monitoring_state = status.state
            except Exception:
                application.state.scene_monitoring_state = SceneRuntimeState.STOP_FAILED
                logging.getLogger(__name__).error(Event.SCENE_MONITORING_STOP_FAILED)
                return None
            return status

        async def launch_scene_monitoring() -> None:
            await start_scene_monitoring()
            if scene_runtime is not None and not scene_lifecycle["stopping"]:
                scene_lifecycle["watch"] = asyncio.create_task(watch_scene_monitoring())

        def system_commit(source_id, prepare, persist):
            """The restart re-acquisition's commit (#205, Owner decision A).

            The new version's provenance and a `system` audit record commit
            in one transaction under the storage admission; a commit that
            fails leaves a `failed` record (best effort) and nothing stored.
            A refused acquisition (`prepare`) is not a change and is not
            audited: the status and the Owner notification report it.
            """
            calibration = prepare()
            try:
                with audit_store.transaction(write=True) as connection:
                    record = persist(connection, calibration)
                    audit_store.append_on(
                        connection, actor_category=ActorCategory.SYSTEM,
                        action=AuditAction.REACQUIRE_SCENE_REFERENCE,
                        target_kind=TargetKind.SCENE_CALIBRATION, target_logical_id=source_id,
                        outcome=AuditOutcome.SUCCEEDED)
                return record
            except BaseException:
                with suppress(Exception):
                    audit_store.append(
                        actor_category=ActorCategory.SYSTEM,
                        action=AuditAction.REACQUIRE_SCENE_REFERENCE,
                        target_kind=TargetKind.SCENE_CALIBRATION, target_logical_id=source_id,
                        outcome=AuditOutcome.FAILED)
                raise

        async def deliver_calibration_notices() -> None:
            # The Owner is told at once through the monitoring runtime's
            # `NotificationService` (the same durable row and optional Slack
            # delivery as a hardware-integrity failure). Fixed kinds only: no
            # source, image or reason. A notice the service cannot take yet
            # (storage not admitted) is kept, in memory, for the next pass.
            notices = scene_calibration_service.take_notices()
            if not notices:
                return
            submitted = []

            def step():
                # A submitted notice has its `notification_events` row (its
                # outcome, `failed` included, is recorded there) and is not
                # submitted again under the same event id.
                for notice in notices:
                    monitoring_runtime.notifications.record(
                        NotificationKind(notice.kind), at=notice.at, confirmed=True,
                        event_id=notice.event_id)
                    submitted.append(notice)
                    scene_lifecycle["notified"] = True
                return len(submitted)

            try:
                await run_to_completion(monitoring_runtime.call(
                    monitoring_runtime.dispatch_notifications, step))
            except Exception:
                pass
            finally:
                # Also when this pass is cancelled (run_to_completion re-raises
                # the cancellation after the step finished): an unsubmitted
                # notice is never lost here.
                undelivered = [notice for notice in notices if notice not in submitted]
                if undelivered:
                    scene_calibration_service.return_notices(undelivered)

        async def reacquire_source(source_id) -> None:
            await run_to_completion(asyncio.to_thread(
                scene_calibration_service.reacquire, source_id, system_commit))
            # Its own outcome is notified at once, not after the other
            # sources' attempts (Codex P1 on PR #330, DET-004 "immediately").
            await deliver_calibration_notices()

        async def run_scene_calibration() -> None:
            # Once scene monitoring runs, every source with a stored
            # calibration has its reference re-acquired (Owner decision
            # 2026-10-22, option A), and a failed attempt is retried at the
            # configured interval; the Owner is notified of both outcomes.
            # The sources (at most MAXIMUM_SOURCES) are re-acquired
            # independently and concurrently: a camera that gives no frame
            # delays neither another source's detection nor its notice.
            live = (SceneRuntimeState.RUNNING, SceneRuntimeState.DEGRADED)
            started = False
            while True:
                if scene_lifecycle["stopping"]:
                    return
                if not started and application.state.scene_monitoring_state in live:
                    await run_to_completion(asyncio.to_thread(scene_calibration_service.start))
                    started = True
                if started:
                    pending = scene_calibration_service.pending_reacquisitions()
                    if pending and not scene_lifecycle["stopping"]:
                        # A cancelled gather still waits for every attempt
                        # (each defers its cancellation until its thread
                        # returns; `close()` ends the acquisitions first).
                        outcomes = await asyncio.gather(
                            *(reacquire_source(source_id) for source_id in pending),
                            return_exceptions=True)
                        if any(isinstance(item, Exception) for item in outcomes):
                            # One source's unexpected failure ends neither
                            # the others nor the retry loop; value-free.
                            logging.getLogger(__name__).error(Event.SCENE_REACQUISITION_FAILED)
                await deliver_calibration_notices()
                await asyncio.sleep(scene_calibration.reacquire_retry_seconds if started
                                    else scene_runtime.refresh_interval_seconds)

        async def open_timeline() -> bool:
            # Issue #205 condition 5: scene monitoring starts only after the
            # outbox session is open, so no undelivered count can reach an
            # outbox that would refuse it.
            return await run_to_completion(asyncio.to_thread(timeline.open))

        async def run_timeline() -> None:
            # Retries a deferred outbox open (storage not yet admitted, for
            # example a monitoring runtime still retrying its startup open)
            # and then starts scene monitoring; afterwards it writes counted
            # loss to the durable gap marker on every interval.
            configuration = timeline.configuration
            while not timeline.opened:
                await asyncio.sleep(configuration.open_retry_seconds)
                if scene_lifecycle["stopping"]:
                    return
                if await open_timeline() and not scene_lifecycle["stopping"]:
                    await launch_scene_monitoring()
            while True:
                await asyncio.sleep(configuration.flush_interval_seconds)
                await run_to_completion(asyncio.to_thread(timeline.flush))

        async def finish_timeline(scene_status) -> None:
            # Issue #205 conditions 2, 3, 6 and 8: only after scene stop()
            # returned; flushed first; closed only after a clean stop whose
            # undelivered count was recorded, otherwise left open so the
            # next start records an interrupted gap.
            if timeline is None:
                return
            with suppress(Exception):
                application.state.scene_timeline_finish = await run_to_completion(
                    asyncio.to_thread(timeline.finish, scene_status))

        async def settle_critical_dispatch() -> None:
            # Issue #26: after scene stop() returned (its final pass may have
            # recorded confirmed critical observations) and while storage is
            # still admitted, submit what is queued once more, then wait a
            # bounded time for submitted notifications to complete, so a
            # shutdown right after a server movement still notifies. What
            # does not finish stays `pending` / unresolved, never sent twice.
            if critical_dispatcher is None:
                return
            with suppress(Exception):
                await critical_dispatcher.alert_once()
            with suppress(Exception):
                await critical_dispatcher.once()
            # Issue #318: a final step refused by storage escalates the
            # recorded but unclaimed criticals it watched; drain once more so
            # they are still attempted (no network wait: the settle below
            # bounds the time spent on their delivery).
            with suppress(Exception):
                await critical_dispatcher.alert_once()
            try:
                unsettled = await run_to_completion(monitoring_runtime.call(
                    monitoring_runtime.settle_notifications,
                    timeline.configuration.dispatch_settle_seconds))
            except Exception:
                unsettled = None
            if unsettled != 0:
                logging.getLogger(__name__).error(Event.CRITICAL_NOTIFICATIONS_UNSETTLED)
            if timeline.unrecorded is not None and timeline.unrecorded.queued:
                # Handed over during a hard stop but never submitted (the
                # service had no room): nothing remembers them after exit.
                logging.getLogger(__name__).error(Event.UNRECORDED_CRITICAL_ALERTS_UNSENT)

        async def settle_camera_offline() -> None:
            # Issue #301 item 2: a camera offline notification submitted by
            # the last monitoring tick still completes and is recorded when
            # the endpoint answers in time. The critical settle above already
            # waits for every pending notification when it ran.
            if camera_offline is None or monitoring_runtime is None or critical_dispatcher is not None:
                return
            try:
                unsettled = await run_to_completion(monitoring_runtime.call(
                    monitoring_runtime.settle_notifications, CAMERA_OFFLINE_SETTLE_SECONDS))
            except Exception:
                unsettled = None
            if unsettled != 0:
                logging.getLogger(__name__).error(Event.CAMERA_OFFLINE_NOTIFICATIONS_UNSETTLED)

        async def settle_calibration_notices() -> None:
            # Like the camera offline settle: a calibration notice submitted
            # just before shutdown still completes and is recorded when the
            # endpoint answers in time. The critical and camera offline
            # settles already wait for every pending notification.
            if (not scene_lifecycle["notified"] or monitoring_runtime is None
                    or critical_dispatcher is not None or camera_offline is not None):
                return
            try:
                unsettled = await run_to_completion(monitoring_runtime.call(
                    monitoring_runtime.settle_notifications, CAMERA_OFFLINE_SETTLE_SECONDS))
            except Exception:
                unsettled = None
            if unsettled != 0:
                logging.getLogger(__name__).error(Event.SCENE_CALIBRATION_NOTICE_UNDELIVERED)

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
            # Registry reads and thread starts must not block the loop.
            try:
                # Cancelling the await never stops the start thread. Even a
                # repeated cancellation waits for it to finish, so the
                # lifespan cleanup's stop() sees, and stops, every worker and
                # descriptor it opened; the cancellation is then re-raised.
                status = await run_to_completion(
                    asyncio.to_thread(local_uvc_runtime.start))
                application.state.local_uvc_state = status.state
            except Exception:
                # Camera capture failure must not take audit/monitoring down.
                application.state.local_uvc_state = LocalUvcRuntimeState.FAILED
                logging.getLogger(__name__).error(Event.LOCAL_UVC_STARTUP_FAILED)

        async def stop_local_uvc() -> None:
            if local_uvc_runtime is None:
                return
            # No retained frame is served while (or after) capture stops.
            local_preview.clear()
            try:
                # Bounded joins; physical capture closes before storage stops.
                # A cancelled shutdown still waits for the stop thread.
                status = await run_to_completion(
                    asyncio.to_thread(local_uvc_runtime.stop))
                application.state.local_uvc_state = status.state
            except Exception:
                application.state.local_uvc_state = LocalUvcRuntimeState.STOP_FAILED
                logging.getLogger(__name__).error(Event.LOCAL_UVC_STOP_FAILED)
            finally:
                local_preview.clear()

        def refresh_monitoring_state() -> None:
            # Snapshots follow the live runtime, e.g. a retried startup open
            # that later succeeds, instead of freezing the first result.
            application.state.monitoring_state = monitoring_runtime.status.state
            application.state.audit_storage_admitted = (
                storage_reservation is not None or runtime_admission.bound
            )
            retry_local_uvc_start()

        def retry_local_uvc_start() -> None:
            deferred = uvc_lifecycle["deferred"]
            if deferred is not None and deferred.done():
                # A finished attempt that ended STORAGE_UNADMITTED again (the
                # admission was refused while pinning) must not block later
                # retries once storage recovers.
                uvc_lifecycle["deferred"] = deferred = None
            if (local_uvc_runtime is not None and not uvc_lifecycle["stopping"]
                    and deferred is None
                    and application.state.local_uvc_state
                    is LocalUvcRuntimeState.STORAGE_UNADMITTED
                    and local_uvc_storage_admitted()):
                # Storage became admitted after a failed startup open or a
                # refused pin: start capture. Shutdown awaits this task
                # before stopping.
                uvc_lifecycle["deferred"] = asyncio.create_task(start_local_uvc())

        async def watch_local_uvc() -> None:
            # The application snapshot follows the live runtime: a worker that
            # later fails polling, dies or cannot persist health turns RUNNING
            # into DEGRADED/FAILED here instead of staying RUNNING until
            # shutdown. It also retries a start refused by storage admission
            # when no monitoring tick drives the retry.
            while True:
                await asyncio.sleep(local_uvc.retry_delay_seconds)
                if uvc_lifecycle["stopping"]:
                    return
                if (application.state.local_uvc_state
                        in (LocalUvcRuntimeState.RUNNING, LocalUvcRuntimeState.DEGRADED)):
                    # Read before the status, so a camera transition the
                    # monitor receives meanwhile is not overwritten by it.
                    versions = camera_offline.version() if camera_offline is not None else None
                    try:
                        status = await asyncio.to_thread(local_uvc_runtime.status)
                    except Exception:
                        status = None
                    if status is not None and versions is not None and not uvc_lifecycle["stopping"]:
                        # A worker that is no longer running is not online.
                        camera_offline.observe_runtime(status.sources, versions)
                    if not uvc_lifecycle["stopping"]:
                        application.state.local_uvc_state = (
                            status.state if status is not None
                            else LocalUvcRuntimeState.DEGRADED
                        )
                retry_local_uvc_start()

        async def shutdown() -> None:
            uvc_lifecycle["stopping"] = True
            if camera_offline is not None:
                # Issue #301 item 2: capture stopping lowers every source; no
                # episode starts and nothing more is notified from here on.
                # An outage that continues is found again by the next start
                # under the same event ID (`MonitoringRuntime`).
                camera_offline.stop()
            if human_task is not None:
                # Requests are denied from here on and run() starts no
                # further step. The check's startup/tick and the expiry sweep
                # run on worker threads that cancelling cannot stop; run()
                # defers the cancellation until the in-flight call returns
                # (bounded by the check's enumeration timeout, plus for a
                # write at most one in-flight monitoring job ahead of it in
                # the storage admission, which has no timeout of its own,
                # plus the SQLite busy timeout), so no verdict or
                # revocation/expiry write lands after the admission below is
                # unbound or the monitoring runtime is stopped.
                human_access.stop()
                human_task.cancel()
                with suppress(asyncio.CancelledError):
                    await human_task
            scene_lifecycle["stopping"] = True
            if scene_calibration_service is not None:
                # Ends an acquisition in flight at once, so the calibration
                # task (and an Owner request) returns without waiting for its
                # deadline; nothing is committed after this.
                scene_calibration_service.close()
                calibration_task = scene_lifecycle["calibration"]
                if calibration_task is not None:
                    calibration_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await calibration_task
                # A notice queued by an attempt that finished just before
                # the close is submitted now, while the monitoring runtime
                # still runs; the calibration settle below waits for it like
                # any other (Claude review proposal 8).
                await deliver_calibration_notices()
                if scene_calibration_service.take_notices():
                    # Not submitted (storage not admitted): in memory only;
                    # the next start re-acquires again and notifies again.
                    logging.getLogger(__name__).error(Event.SCENE_CALIBRATION_NOTICE_UNDELIVERED)
            for name in ("timeline", "watch", "dispatch"):
                # The timeline task first: a deferred start it is running
                # finishes (cancellation is deferred) before stop() below,
                # and it can then create no new watcher. A dispatch step in
                # flight finishes on the monitoring worker first as well.
                task = scene_lifecycle[name]
                if task is not None:
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
            if uvc_watch_task is not None:
                uvc_watch_task.cancel()
                with suppress(asyncio.CancelledError):
                    await uvc_watch_task
            if uvc_lifecycle["deferred"] is not None:
                # start() and stop() serialize on the runtime lock; let a
                # deferred start finish so stop() sees its workers.
                with suppress(Exception):
                    await asyncio.shield(uvc_lifecycle["deferred"])
            await stop_local_uvc()
            # After capture stops, so no frame is offered to a stopped worker;
            # its final pass retries staged critical observations.
            scene_status = await stop_scene_monitoring()
            # After scene stop() returned and while storage is still admitted
            # (the monitoring runtime stops below).
            await finish_timeline(scene_status)
            # Before the monitoring runtime (and its notification service)
            # stops below.
            await settle_critical_dispatch()
            await settle_camera_offline()
            await settle_calibration_notices()
            if cleanup_task is not None:
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

        # Everything below runs under one cleanup guard.
        try:
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
            # Before capture, so the first frames already reach the detector.
            if timeline is None:
                await launch_scene_monitoring()
            else:
                if await open_timeline():
                    await launch_scene_monitoring()
                else:
                    # Not started: every scene conclusion stays unknown until
                    # the timeline task's retried open succeeds.
                    application.state.scene_monitoring_state = SceneRuntimeState.UNAVAILABLE
                    logging.getLogger(__name__).error(Event.SCENE_MONITORING_UNAVAILABLE)
                scene_lifecycle["timeline"] = asyncio.create_task(run_timeline())
                if critical_dispatcher is not None:
                    # Independent of the outbox open: queued critical work
                    # from an earlier process is submitted as soon as the
                    # monitoring runtime admits storage.
                    scene_lifecycle["dispatch"] = asyncio.create_task(critical_dispatcher.run())
            if scene_calibration_service is not None:
                # It waits for scene monitoring to run (a deferred timeline
                # open starts it later); capture starts right below, so the
                # re-acquisition reads the first frames.
                scene_lifecycle["calibration"] = asyncio.create_task(run_scene_calibration())
            await start_local_uvc()
            if local_uvc_runtime is not None:
                uvc_watch_task = asyncio.create_task(watch_local_uvc())
            if human_access is not None:
                # The reservation check starts closed; its startup and
                # periodic checks run here, off the request path.
                human_task = asyncio.create_task(human_access.run())
            application.state.ready = True
            cleanup_task = asyncio.create_task(audit_retention.run())
            logging.getLogger(__name__).info(Event.STARTED)
            yield
        finally:
            # Also reached when startup itself fails or is cancelled after the
            # monitoring worker started, so no capture worker, descriptor,
            # retention task or monitoring worker outlives a failed lifespan.
            # A cancelled shutdown (ASGI shutdown timeout, embedder) does not
            # skip any step: the whole sequence runs to completion first and
            # the cancellation is re-raised afterwards.
            application.state.ready = False
            await run_to_completion(shutdown())

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
    # Internal only: no route exposes local capture state; preview frames reach
    # only the authorized S7 live routes through `human_access.live`.
    application.state.local_uvc = local_uvc_runtime
    application.state.local_uvc_state = (
        LocalUvcRuntimeState.STARTING if local_uvc_runtime is not None
        else LocalUvcRuntimeState.UNCONFIGURED
    )
    application.state.local_preview = local_preview
    # Internal only: no route exposes scene observations; the Owner calibration
    # status route (#205) reads only each source's state and reason code.
    application.state.scene_monitoring = scene_runtime
    application.state.scene_monitoring_state = (
        SceneRuntimeState.CONFIGURED if scene_runtime is not None
        else SceneRuntimeState.UNCONFIGURED
    )
    # Internal only: the presence timeline composition for scene evidence and
    # how its outbox ended at the last shutdown (`TimelineFinish`). No route
    # reads either; Owner status through a reviewed route is a follow-up.
    application.state.scene_timeline = timeline
    application.state.scene_timeline_finish = None
    # The Owner calibration and restart re-acquisition (#205); its status is
    # served only through the Owner routes of the human surface.
    application.state.scene_calibration = scene_calibration_service
    # Internal only: camera offline episodes (Issue #301 item 2).
    application.state.camera_offline = camera_offline
    # Internal only: drives presence critical notifications (Issue #26).
    application.state.critical_dispatcher = critical_dispatcher
    application.state.diagnostic_export_endpoint = diagnostic_export_endpoint
    application.state.human_access = human_access
    # No FastAPI human router is ever included: the surface below answers
    # every HTTP/WebSocket request itself, before any router or error handler.
    if human_access is None:
        application.add_middleware(ClosedHumanSurface)
    else:
        application.add_middleware(HumanSurface, access=human_access)
    if human_access is not None and access_faults is not None:
        # Last, after every check above passed (PR #271 review): a refused
        # create_app leaves the monitor unattached.
        access_faults.attach(human_access)
    return application
