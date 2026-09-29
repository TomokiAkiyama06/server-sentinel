"""Main Server monitoring runtime owned by one serialized worker thread.

`MainStoragePolicy`, `RecordingStore`, `IntegrityStore`, `NotificationService`
and `DailySummaryScheduler` all require every call on the thread that created
them. This runtime creates them on a single dedicated worker thread and runs
startup, the periodic tick and shutdown there; the asyncio lifespan only awaits
that worker. No HTTP route, listener or human surface is added here.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import logging
import math
import threading
import time
from typing import Callable
from uuid import UUID, uuid5

from app.audit.store import DEFAULT_RETENTION, UnboundStorageAdmission
from app.integrity.service import IntegrityService
from app.integrity.store import IntegrityStore, OwnerApproval
from app.logging import Event
from app.media.health.service import HealthResult, HealthState, RecordingHealthService, Stage
from app.media.recording.model import RecordingError, SegmentValidator
from app.media.recording.store import RecordingStore
from app.notifications.schedule import DailySummaryScheduler
from app.notifications.service import DailySummary, NotificationKind, NotificationService
from app.notifications.slack import SlackDelivery
from app.storage.database import Database
from app.storage.policy import MainStoragePolicy, StorageState, StorageTransition
from app.storage.retention import RetentionService, StorageAudit

from .config import MonitoringConfiguration
from .filesystem import IdentifiedRecordingFilesystem
from .store import NotificationEventStore, RecordingHealthStatusStore


# Fixed namespace for deterministic local event IDs, so an at-least-once
# redelivery of one fault maps to one notification row and one Slack message.
EVENT_NAMESPACE = UUID("3b0f6c52-7a1e-5d49-8e2c-0c7d4f1a9b63")
CRITICAL_KINDS = (
    NotificationKind.HARDWARE_INTEGRITY_FAILURE, NotificationKind.RECORDING_HEALTH_FAILURE,
    NotificationKind.SERVER_MOVEMENT, NotificationKind.CAMERA_TAMPER,
)
WARNING_KINDS = (NotificationKind.HARDWARE_INTEGRITY_WARNING,
                 NotificationKind.RECORDING_HEALTH_WARNING)


class RuntimeState(StrEnum):
    # Storage thresholds are not configured: storage admission stays unbound,
    # every audited/metadata write is refused and no monitoring worker runs.
    UNCONFIGURED = "unconfigured"
    STARTING = "starting"
    RUNNING = "running"
    # Startup could not open the expected recording filesystem or database.
    # Writes stay refused; an immediate recording-health alert was attempted.
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass(frozen=True)
class MonitoringStatus:
    """Bounded, value-free runtime state for the dashboard/diagnostics."""

    state: RuntimeState
    storage_state: StorageState | None = None
    storage_audit_failed: bool = False
    recording_filesystem_ok: bool | None = None
    integrity_degraded: bool = False
    recording_health: HealthState | None = None
    recording_health_degraded: bool = False
    retention_degraded: bool = False
    summary_degraded: bool = False
    notification_local_failed: bool = False
    notification_delivery_failed: bool = False


class RefuseUnvalidatedSegments:
    """Default segment validator: refuses every segment.

    No production codec validator is selected yet (#18/#28), so the runtime
    recorder can account, retain and clean up but never admits media bytes it
    cannot validate.
    """

    def validate(self, segment) -> None:
        raise RecordingError("SEGMENT_VALIDATOR_UNAVAILABLE")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class MonitoringDependencies:
    """Injection points for tests and later pipeline integration.

    `integrity_probe` defaults to the read-only `LinuxProbe`; tests always
    inject a synthetic probe. `recorder_probe_factory(recording_store)` returns
    a `RecorderProbe` once the actual capture pipeline exists; without it the
    daily self-test reports an explicit `UNAVAILABLE` verdict.
    """

    integrity_probe: object | None = None
    recorder_probe_factory: Callable[[RecordingStore], object] | None = None
    segment_validator: SegmentValidator | None = None
    slack_opener: object | None = None
    integrity_approval: OwnerApproval | None = None
    utcnow: Callable[[], datetime] = _utcnow
    monotonic: Callable[[], float] = time.monotonic
    tick_seconds: float = 60.0
    retry_seconds: float = 15 * 60.0
    integrity_max_pending_events: int = 64
    notification_queue_capacity: int = 16

    def __post_init__(self):
        for value in (self.tick_seconds, self.retry_seconds):
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError("invalid monitoring interval")


@contextmanager
def _refused():
    raise RecordingError("STORAGE_POLICY_UNAVAILABLE")
    yield


class MonitoringRuntime:
    def __init__(self, configuration: MonitoringConfiguration, database: Database,
                 dependencies: MonitoringDependencies | None = None):
        if not isinstance(configuration, MonitoringConfiguration) or not configuration.storage_configured:
            raise ValueError("monitoring storage configuration required")
        self.configuration = configuration
        self.database = database
        self.dependencies = dependencies or MonitoringDependencies()
        self._executor: ThreadPoolExecutor | None = None
        self._owner: int | None = None
        self._lock = threading.Lock()
        self._status = MonitoringStatus(RuntimeState.STARTING)
        self._policy: MainStoragePolicy | None = None
        self._connection = None
        self._retry_at: dict[str, float] = {}
        self._filesystem_ok = True
        self._started_monotonic = None
        self.notifications: NotificationService | None = None
        self.notification_events: NotificationEventStore | None = None
        self.recordings: RecordingStore | None = None
        self.integrity_store: IntegrityStore | None = None
        self.integrity: IntegrityService | None = None
        self.recording_health: RecordingHealthService | None = None
        self.health_status: RecordingHealthStatusStore | None = None
        self.scheduler: DailySummaryScheduler | None = None
        self.storage_audit: StorageAudit | None = None
        self.filesystem: IdentifiedRecordingFilesystem | None = None

    # -- status -----------------------------------------------------------

    @property
    def status(self) -> MonitoringStatus:
        with self._lock:
            return self._status

    def _set(self, **changes) -> None:
        with self._lock:
            self._status = replace(self._status, **changes)

    @property
    def bound(self) -> bool:
        """True once the storage policy admits writes on the owning worker."""
        return self.status.state == RuntimeState.RUNNING

    # -- worker plumbing --------------------------------------------------

    async def call(self, function, *args):
        """Run `function` on the owning worker and await its result."""
        if self._executor is None:
            raise RuntimeError("monitoring worker unavailable")
        return await asyncio.wrap_future(self._executor.submit(function, *args))

    def _owner_reservation(self):
        return self._policy.control() if self._policy is not None else _refused()

    @contextmanager
    def reservation(self):
        """Storage admission usable from any thread, e.g. audit retention.

        On the owning worker this is `MainStoragePolicy.control()`. From another
        thread the worker takes the reservation and parks, holding it, until
        the caller's write finishes, so the serialized policy still covers that
        write through commit and no second writer overlaps it. A denial raises
        the policy's bounded `RecordingError` and nothing is written.
        """
        if threading.get_ident() == self._owner:
            with self._owner_reservation():
                yield
            return
        executor = self._executor
        if executor is None or self.status.state != RuntimeState.RUNNING:
            with UnboundStorageAdmission()():
                yield
            return
        granted, finished = threading.Event(), threading.Event()
        failure = []

        def hold():
            try:
                context = self._owner_reservation()
                context.__enter__()
            except BaseException as error:
                failure.append(error)
                granted.set()
                return
            granted.set()
            try:
                finished.wait()
            finally:
                context.__exit__(None, None, None)

        future = executor.submit(hold)
        granted.wait()
        if failure:
            future.result()
            raise failure[0]
        try:
            yield
        finally:
            finished.set()
            future.result()

    def _guarded(self, name: str, function, flag: str) -> None:
        """Run one worker step; a failure is visible and retried later.

        Failures record only the fixed flag, never exception text or values.
        """
        now = self.dependencies.monotonic()
        retry = self._retry_at.get(name)
        # A backwards/invalid clock never postpones the retry indefinitely.
        if (retry is not None and math.isfinite(now)
                and retry - self.dependencies.retry_seconds <= now < retry):
            return
        try:
            function()
        except Exception:
            self._retry_at[name] = now + self.dependencies.retry_seconds
            self._set(**{flag: True})
            logging.getLogger(__name__).error(Event.MONITORING_DEGRADED)
        else:
            self._retry_at.pop(name, None)
            self._set(**{flag: False})

    # -- owner-thread construction -----------------------------------------

    def _now_ms(self) -> int:
        return int(self.dependencies.utcnow().timestamp() * 1000)

    def _persist_notification(self, event) -> None:
        self.notification_events.upsert(event)

    def _storage_transition(self, event: StorageTransition) -> None:
        self._set(storage_state=event.current)
        if self.storage_audit is None:
            raise RecordingError("STORAGE_AUDIT_UNAVAILABLE")
        self.storage_audit.append(event)

    def _open(self) -> None:
        self._owner = threading.get_ident()
        self._started_monotonic = self.dependencies.monotonic()
        configuration, dependencies = self.configuration, self.dependencies
        self._connection = connection = self.database.connect()
        self.notification_events = NotificationEventStore(connection, self._owner_reservation)
        slack = (SlackDelivery(configuration.slack, opener=dependencies.slack_opener)
                 if configuration.slack is not None else None)
        self.notifications = NotificationService(
            self._persist_notification, slack,
            queue_capacity=dependencies.notification_queue_capacity,
        )
        try:
            self.filesystem = IdentifiedRecordingFilesystem(
                configuration.recording_filesystem, self.database.path,
            )
            policy = MainStoragePolicy(configuration.storage_limits, self.filesystem.snapshot,
                                       self._now_ms, self._storage_transition)
            self.storage_audit = StorageAudit(connection, reservation=policy.control)
            self._policy = policy
            self.recordings = RecordingStore(
                connection, configuration.recording_filesystem.root, self.filesystem.expected,
                configuration.recording_limits, policy,
                dependencies.segment_validator or RefuseUnvalidatedSegments(),
            )
            policy.bind(self.recordings, RetentionService(self.recordings))
        except Exception:
            self._startup_failed()
            return
        self.health_status = RecordingHealthStatusStore(connection, policy.control)
        self.scheduler = DailySummaryScheduler(
            connection, configuration.time_zone, self.notifications, policy.control,
            hour=configuration.summary_hour, minute=configuration.summary_minute,
        )
        self.integrity_store = IntegrityStore(
            connection, dependencies.integrity_approval, reservation=policy.control,
            max_pending_events=dependencies.integrity_max_pending_events,
        )
        probe = dependencies.integrity_probe
        if probe is None:
            from app.integrity.probes import LinuxProbe
            probe = LinuxProbe()
        self.integrity = IntegrityService(self.integrity_store, probe, self._integrity_sink,
                                          monotonic=dependencies.monotonic,
                                          utcnow=dependencies.utcnow)
        adapter = (dependencies.recorder_probe_factory(self.recordings)
                   if dependencies.recorder_probe_factory is not None else None)
        self.recording_health = RecordingHealthService(
            adapter, self._record_recording_health,
            monotonic=dependencies.monotonic, utcnow=dependencies.utcnow,
        )
        self._set(state=RuntimeState.RUNNING, storage_state=policy.state,
                  recording_filesystem_ok=True)
        # Startup always compares inventory and runs the recording self-test,
        # regardless of when the previous process last did.
        self._storage_tick()
        self._guarded("retention", self._retention_tick, "retention_degraded")
        self._guarded("integrity", self.integrity.startup, "integrity_degraded")
        self._guarded("health", self.recording_health.startup, "recording_health_degraded")
        self._poll()

    def _startup_failed(self) -> None:
        """The expected recording target is unusable: refuse, never fall back."""
        self._set(state=RuntimeState.FAILED, recording_filesystem_ok=False,
                  storage_state=StorageState.HARD_STOP, recording_health=HealthState.FAILED)
        logging.getLogger(__name__).error(Event.MONITORING_STARTUP_FAILED)
        at = self.dependencies.utcnow()
        # Local persistence is refused without a verified policy; Slack, when
        # configured, still receives the fixed-category immediate alert.
        self.notifications.record(
            NotificationKind.RECORDING_HEALTH_FAILURE, at=at,
            event_id=uuid5(EVENT_NAMESPACE, "recording-startup:" + at.isoformat()),
        )
        self._poll()

    # -- bridges -----------------------------------------------------------

    def _integrity_sink(self, row_id: int, at: datetime, immediate: bool, findings) -> None:
        """Durable #23 → #21 bridge; raising keeps the outbox row pending.

        The event ID derives from the outbox row, so redelivery after a crash
        between acceptance and acknowledgement is deduplicated locally and is
        coalesced in-memory while a Slack delivery is still pending.
        """
        event_id = uuid5(EVENT_NAMESPACE, f"integrity-outbox:{int(row_id)}")
        if self.notification_events.get(event_id) is None:
            kind = (NotificationKind.HARDWARE_INTEGRITY_FAILURE if immediate
                    else NotificationKind.HARDWARE_INTEGRITY_WARNING)
            self.notifications.record(kind, at=at, event_id=event_id)
        if self.notification_events.get(event_id) is None:
            raise RecordingError("INTEGRITY_EVENT_NOT_PERSISTED")

    def _record_recording_health(self, result: HealthResult, at: datetime) -> None:
        # Durable local/UI state first; a failure propagates to the service.
        self.health_status.record(result, at)
        self._set(recording_health=result.state)
        kind = {HealthState.FAILED: NotificationKind.RECORDING_HEALTH_FAILURE,
                HealthState.UNAVAILABLE: NotificationKind.RECORDING_HEALTH_WARNING,
                }.get(result.state)
        if kind is not None:
            self.notifications.record(kind, at=at, event_id=uuid5(
                EVENT_NAMESPACE, f"recording-health:{at.isoformat()}:{result.state.value}",
            ))

    # -- periodic work -----------------------------------------------------

    def _storage_tick(self) -> None:
        try:
            self.filesystem.check()
            healthy = True
        except RecordingError:
            healthy = False
        if not healthy and self._filesystem_ok:
            # One immediate alert per mismatch episode; recovery re-arms it.
            at = self.dependencies.utcnow()
            try:
                self.health_status.record(HealthResult(HealthState.FAILED, (Stage.STORAGE,)), at)
            except Exception:
                pass
            self._set(recording_health=HealthState.FAILED)
            self.notifications.record(
                NotificationKind.RECORDING_HEALTH_FAILURE, at=at,
                event_id=uuid5(EVENT_NAMESPACE, "recording-filesystem:" + at.isoformat()),
            )
        self._filesystem_ok = healthy
        try:
            status = self._policy.status()
            self._set(storage_state=status.state, storage_audit_failed=status.audit_delivery_failed,
                      recording_filesystem_ok=healthy)
        except RecordingError:
            self._set(storage_state=self._policy.state,
                      storage_audit_failed=self._policy.audit_delivery_failed,
                      recording_filesystem_ok=healthy)

    def _retention_tick(self) -> None:
        """Expired unstarred recordings, then state-audit and fault history."""
        now = self.dependencies.utcnow()
        now_ms = self._now_ms()
        RetentionService(self.recordings).expired(now_ms, self.configuration.storage_limits.cleanup_batch_size)
        self.storage_audit.expire(now_ms)
        self.notification_events.expire(now, DEFAULT_RETENTION)

    def _summary(self, now: datetime) -> DailySummary:
        since = now - timedelta(days=1)
        since_ms = max(0, int(since.timestamp() * 1000))
        recordings = self._connection.execute(
            "SELECT COUNT(*) FROM recordings WHERE start_ms>=?", (since_ms,),
        ).fetchone()[0]
        status = self.status
        degraded = sum(bool(value) for value in (
            status.integrity_degraded, status.recording_health_degraded, status.retention_degraded,
            status.storage_audit_failed, status.notification_local_failed,
            status.notification_delivery_failed,
        ))
        elapsed = self.dependencies.monotonic() - self._started_monotonic
        monitored = int(min(86400, max(0, elapsed))) if math.isfinite(elapsed) else 0
        return DailySummary(
            monitored, 0, 0, 0, 0, 0, 0, 0, 0,
            self.notification_events.count_since(since, CRITICAL_KINDS), recordings,
            self.notification_events.count_since(since, WARNING_KINDS) + degraded,
            self.recordings.usage_bytes(), self._policy.state, pipeline_available=False,
        )

    def _summary_tick(self) -> None:
        now = self.dependencies.utcnow()
        self.scheduler.tick(now, self._summary(now))

    def _poll(self) -> None:
        if self.notifications is None:
            # The database itself could not be opened; nothing to persist.
            return
        self.notifications.poll()
        self._set(notification_local_failed=self.notifications.local_delivery_failed,
                  notification_delivery_failed=self.notifications.delivery_failed)

    def tick(self) -> None:
        """One owner-thread pass; call only through `call` or the run loop."""
        if threading.get_ident() != self._owner:
            raise RuntimeError("monitoring owner thread required")
        if self.status.state != RuntimeState.RUNNING:
            self._poll()
            return
        self._poll()
        self._storage_tick()
        self._guarded("retention", self._retention_tick, "retention_degraded")
        self._guarded("integrity", self.integrity.tick, "integrity_degraded")
        self._guarded("health", self.recording_health.tick, "recording_health_degraded")
        self._guarded("summary", self._summary_tick, "summary_degraded")
        self._poll()

    def _close(self) -> None:
        if self.notifications is not None:
            self.notifications.close()
        if self.recordings is not None:
            self.recordings.close()
        if self._connection is not None:
            self._connection.close()
        self._set(state=RuntimeState.STOPPED)

    # -- lifespan ----------------------------------------------------------

    async def start(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1,
                                            thread_name_prefix="serversentinel-monitoring")
        try:
            await self.call(self._open)
        except Exception:
            self._set(state=RuntimeState.FAILED)
            logging.getLogger(__name__).error(Event.MONITORING_STARTUP_FAILED)
            return
        if self.status.state == RuntimeState.RUNNING:
            logging.getLogger(__name__).info(Event.MONITORING_STARTED)

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self.dependencies.tick_seconds)
            try:
                await self.call(self.tick)
            except Exception:
                logging.getLogger(__name__).error(Event.MONITORING_DEGRADED)

    async def stop(self) -> None:
        executor = self._executor
        if executor is None:
            return
        try:
            await self.call(self._close)
        except Exception:
            self._set(state=RuntimeState.STOPPED)
        finally:
            # Queued work, including a parked cross-thread reservation, finishes
            # before the worker exits; nothing is abandoned mid-transaction.
            await asyncio.to_thread(executor.shutdown, wait=True)
            self._executor = None
