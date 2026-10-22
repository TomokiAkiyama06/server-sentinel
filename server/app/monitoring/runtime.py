"""Main Server monitoring runtime owned by one serialized worker thread.

`MainStoragePolicy`, `RecordingStore`, `IntegrityStore`, `NotificationService`
and `DailySummaryScheduler` all require every call on the thread that created
them. This runtime creates them on a single dedicated worker thread and runs
startup, the periodic tick and shutdown there; the asyncio lifespan only awaits
that worker. No HTTP route, listener or human surface is added here.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import logging
import math
import os
import sqlite3
import stat
import threading
import time
from typing import Callable
from uuid import UUID, uuid5

from app.audit.model import AuditAction
from app.audit.store import DEFAULT_RETENTION, UnboundStorageAdmission
from app.integrity.service import IntegrityService
from app.integrity.store import IntegrityStore, OwnerApproval
from app.logging import Event
from app.media.health.service import HealthResult, HealthState, RecordingHealthService, Stage
from app.media.recording.model import RecordingError, SegmentValidator
from app.media.recording.store import RecordingStore
from app.notifications.schedule import DailySummaryScheduler
from app.notifications.service import DailySummary, NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from app.storage.database import Database
from app.storage.migrations import Migration, MigrationError, migrate
from app.storage.policy import MainStoragePolicy, StorageState, StorageTransition
from app.storage.retention import RetentionService, StorageAudit

from .access import HOUR_SECONDS, AccessFaultMonitor
from .cameras import CameraOfflineMonitor
from .config import MonitoringConfiguration
from .filesystem import IdentifiedRecordingFilesystem
from .store import NotificationEventStore, RecordingHealthStatusStore


# Fixed namespace for deterministic local event IDs, so an at-least-once
# redelivery of one fault maps to one notification row and one Slack message.
EVENT_NAMESPACE = UUID("3b0f6c52-7a1e-5d49-8e2c-0c7d4f1a9b63")
CRITICAL_KINDS = (
    NotificationKind.HARDWARE_INTEGRITY_FAILURE, NotificationKind.RECORDING_HEALTH_FAILURE,
    NotificationKind.SERVER_MOVEMENT, NotificationKind.CAMERA_TAMPER,
    NotificationKind.HUMAN_ACCESS_FAULT, NotificationKind.CREDENTIAL_FINDING,
)
WARNING_KINDS = (NotificationKind.HARDWARE_INTEGRITY_WARNING,
                 NotificationKind.RECORDING_HEALTH_WARNING)
# The audited credential findings (``AccessStore``); their records are the
# durable evidence a restart recovers an undelivered notification from.
FINDING_AUDIT_ACTIONS = (AuditAction.MARK_PRINCIPAL_CREDENTIAL_INCONSISTENT,
                         AuditAction.DETECT_PRINCIPAL_CREDENTIAL_SIGN_COUNT_REGRESSION)



def admit_state_file(configuration: MonitoringConfiguration, path) -> None:
    """Refuse to open or create a Main state file outside verified storage.

    Before a missing file may be created the declared recording filesystem
    identity is verified, the file's directory must be a private directory on
    that same filesystem and the free space must cover the hard reserve plus
    the write overhead. An existing file must be a regular file on the
    verified filesystem, so a fallback file left under a missing mount is
    never used. Raises `RecordingError("STORAGE_HARD_STOP")` otherwise. Used
    for the database (re-verified by every later policy admission) and for
    the session-binding key (`app.auth.composition`, Codex PR #282).
    """
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    except OSError:
        raise RecordingError("STORAGE_HARD_STOP") from None
    filesystem = IdentifiedRecordingFilesystem(configuration.recording_filesystem, path)
    if existing is not None:
        # An existing file is opened only while the declared filesystem is
        # verified and the file is a regular file on it, so a fallback
        # database left under a missing mount is never opened.
        if not stat.S_ISREG(existing.st_mode) or existing.st_dev != filesystem.expected.device:
            raise RecordingError("STORAGE_HARD_STOP")
        return
    limits = configuration.storage_limits
    try:
        parent = os.stat(path.parent, follow_symlinks=False)
        space = os.statvfs(path.parent)
    except OSError:
        raise RecordingError("STORAGE_HARD_STOP") from None
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_dev != filesystem.expected.device
            or parent.st_uid != os.geteuid() or parent.st_mode & 0o077
            or space.f_flag & os.ST_RDONLY
            or space.f_bavail * space.f_frsize - limits.write_overhead_bytes
            < limits.hard_reserve_bytes):
        raise RecordingError("STORAGE_HARD_STOP")


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
    # Issue #232 item 4: a failing reservation check / human-access
    # composition, and a credential finding within the hold window.
    human_access_degraded: bool = False
    credential_finding_degraded: bool = False
    # Issue #301 item 2: a camera source has stayed not online past the
    # deployment threshold (`camera_offline_notification.after_seconds`).
    camera_offline_degraded: bool = False
    # Whether that Owner notification reaches the Owner outside the local
    # store: False without a configured Slack endpoint (the local row is then
    # `disabled`) or without a camera offline monitor.
    camera_offline_notifications: bool = False


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
    # The composition root's single sink for the reservation check
    # (``sink=``) and the passkey ceremonies (``findings=``) (Issue #232).
    access_faults: AccessFaultMonitor | None = None
    # Issue #301 item 2: per-source offline episodes, drained on every tick.
    # `create_app` builds it for the configured local UVC sources.
    camera_offline: CameraOfflineMonitor | None = None

    def __post_init__(self):
        for value in (self.tick_seconds, self.retry_seconds):
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError("invalid monitoring interval")
        if self.access_faults is not None and not isinstance(self.access_faults, AccessFaultMonitor):
            raise ValueError("invalid access fault monitor")
        if (self.camera_offline is not None
                and not isinstance(self.camera_offline, CameraOfflineMonitor)):
            raise ValueError("invalid camera offline monitor")


@contextmanager
def _refused():
    raise RecordingError("STORAGE_POLICY_UNAVAILABLE")
    yield


class MonitoringRuntime:
    def __init__(self, configuration: MonitoringConfiguration, database: Database,
                 dependencies: MonitoringDependencies | None = None,
                 migrations: tuple[Migration, ...] = ()):
        if not isinstance(configuration, MonitoringConfiguration) or not configuration.storage_configured:
            raise ValueError("monitoring storage configuration required")
        self.configuration = configuration
        self.database = database
        self.dependencies = dependencies or MonitoringDependencies()
        self._executor: ThreadPoolExecutor | None = None
        self._owner: int | None = None
        self._lock = threading.Lock()
        self._status = MonitoringStatus(
            RuntimeState.STARTING,
            camera_offline_notifications=(self.dependencies.camera_offline is not None
                                          and configuration.slack is not None))
        self._policy: MainStoragePolicy | None = None
        self._connection = None
        self._retry_at: dict[str, float] = {}
        self._filesystem_ok = True
        self._started_monotonic = None
        self._startup_alerted = False
        # Pending schema migrations run on the worker inside the verified
        # storage policy's admission, never before the reserve was checked.
        self._migrations = tuple(migrations)
        self._migrated = not self._migrations
        # (state, at) of the last recording-health alert whose local status
        # row could not be persisted, so a denied write does not re-alert on
        # every 15-minute retry of the same failing self-test.
        self._unpersisted_health: tuple[HealthState, datetime] | None = None
        # Issue #232 / Codex PR #271: once per process, a credential finding
        # committed but not yet notified before a restart is recovered from
        # the audit log on the first running access tick.
        self._findings_recovered = False
        # Issue #301 item 2: the camera offline hourly cap is re-seeded from
        # the stored rows once, on the first running tick.
        self._camera_window_restored = False
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

    def _due(self, name: str, now: float) -> bool:
        retry = self._retry_at.get(name)
        # A backwards/invalid clock never postpones the retry indefinitely.
        return not (retry is not None and math.isfinite(now)
                    and retry - self.dependencies.retry_seconds <= now < retry)

    def _guarded(self, name: str, function, flag: str) -> None:
        """Run one worker step; a failure is visible and retried later.

        Failures record only the fixed flag, never exception text or values.
        """
        now = self.dependencies.monotonic()
        if not self._due(name, now):
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
        if self.notification_events is None:
            # The database was not opened yet; Slack still gets the alert.
            raise RecordingError("NOTIFICATION_STORE_UNAVAILABLE")
        self.notification_events.upsert(event, accepted_at=self.dependencies.utcnow())

    def _admit_database_open(self) -> None:
        """Refuse to open or create the database outside verified storage.

        `Database.connect()` creates a missing file; see `admit_state_file`.
        """
        admit_state_file(self.configuration, self.database.path)

    def _storage_transition(self, event: StorageTransition) -> None:
        self._set(storage_state=event.current)
        if self.storage_audit is None:
            raise RecordingError("STORAGE_AUDIT_UNAVAILABLE")
        self.storage_audit.append(event)

    def _open(self) -> None:
        """Open the worker's components; also the retry path while `FAILED`.

        The notification service is created once and reused by a retry, so
        pending Slack deliveries and their in-memory de-duplication survive.
        The database connection is opened only after the declared filesystem
        was verified and is dropped by a failed attempt, so every retry
        reopens it on the filesystem approved at that time. Storage components
        are rebuilt on each attempt and published only once every one of them
        was constructed.
        """
        self._owner = threading.get_ident()
        if self._started_monotonic is None:
            self._started_monotonic = self.dependencies.monotonic()
        configuration, dependencies = self.configuration, self.dependencies
        if self.notifications is None:
            # Created before any database file, so a refused open still sends
            # the immediate alert; local persistence is then refused.
            slack = (SlackDelivery(configuration.slack, opener=dependencies.slack_opener)
                     if configuration.slack is not None else None)
            self.notifications = NotificationService(
                self._persist_notification, slack,
                queue_capacity=dependencies.notification_queue_capacity,
            )
        if self._connection is None:
            connection = None
            try:
                self._admit_database_open()
                connection = self.database.connect()
                events = NotificationEventStore(connection, self._owner_reservation)
            except Exception:
                # A refused creation or a failed open (SQLite I/O error,
                # read-only or permission change) means recording cannot
                # start: raise the immediate alert and keep the retry.
                if connection is not None:
                    with suppress(Exception):
                        connection.close()
                self._startup_failed()
                return
            self._connection, self.notification_events = connection, events
        connection = self._connection
        recordings = None
        try:
            self.filesystem = IdentifiedRecordingFilesystem(
                configuration.recording_filesystem, self.database.path,
            )
            policy = MainStoragePolicy(configuration.storage_limits, self.filesystem.snapshot,
                                       self._now_ms, self._storage_transition)
            if not self._migrated:
                # Schema DDL and its journal are metadata writes: they are
                # admitted only after the expected filesystem identity and the
                # hard reserve were verified. A denial is a startup failure
                # (alert, retry); the tables are not created meanwhile.
                with policy.control():
                    migrate(connection, self._migrations)
                self._migrated = True
            self.storage_audit = StorageAudit(connection, reservation=policy.control)
            # Every admission re-verifies the filesystem identity, so a local
            # fault row may use this policy even when a later step fails.
            self._policy = policy
            recordings = RecordingStore(
                connection, configuration.recording_filesystem.root, self.filesystem.expected,
                configuration.recording_limits, policy,
                dependencies.segment_validator or RefuseUnvalidatedSegments(),
            )
            policy.bind(recordings, RetentionService(recordings))
            health_status = RecordingHealthStatusStore(connection, policy.control)
            scheduler = DailySummaryScheduler(
                connection, configuration.time_zone, self.notifications, policy.control,
                hour=configuration.summary_hour, minute=configuration.summary_minute,
            )
            integrity_store = IntegrityStore(
                connection, dependencies.integrity_approval, reservation=policy.control,
                max_pending_events=dependencies.integrity_max_pending_events,
            )
            probe = dependencies.integrity_probe
            if probe is None:
                from app.integrity.probes import LinuxProbe
                probe = LinuxProbe()
            integrity = IntegrityService(integrity_store, probe, self._integrity_sink,
                                         monotonic=dependencies.monotonic,
                                         utcnow=dependencies.utcnow)
            adapter = (dependencies.recorder_probe_factory(recordings)
                       if dependencies.recorder_probe_factory is not None else None)
            recording_health = RecordingHealthService(
                adapter, self._record_recording_health,
                monotonic=dependencies.monotonic, utcnow=dependencies.utcnow,
            )
        except MigrationError:
            # A future/edited schema history or failed DDL is not a storage
            # fault; the caller decides whether it aborts startup.
            raise
        except Exception:
            if recordings is not None:
                with suppress(Exception):
                    recordings.close()
            # The alert is persisted locally only if this attempt's verified
            # policy admits it; afterwards the connection is dropped so the
            # retry reopens and revalidates the database on the filesystem
            # that is approved then, never reusing one opened meanwhile.
            self._startup_failed()
            self._drop_connection()
            return
        self.recordings, self.health_status, self.scheduler = recordings, health_status, scheduler
        self.integrity_store, self.integrity = integrity_store, integrity
        self.recording_health = recording_health
        self._startup_alerted = False
        self._filesystem_ok = True
        self._retry_at.pop("startup", None)
        self._set(state=RuntimeState.RUNNING, storage_state=policy.state,
                  recording_filesystem_ok=True, recording_health=None)
        # Startup always compares inventory and runs the recording self-test,
        # regardless of when the previous process last did.
        self._storage_tick()
        self._guarded("retention", self._retention_tick, "retention_degraded")
        self._guarded("integrity", self.integrity.startup, "integrity_degraded")
        self._guarded("health", self.recording_health.startup, "recording_health_degraded")
        self._poll()

    def _drop_connection(self) -> None:
        """Forget the database of a failed attempt; the retry reopens it.

        The notification service is kept, so pending Slack deliveries and
        their de-duplication survive; their local persistence stays refused
        (and retried) until a verified reopen.
        """
        connection = self._connection
        self._connection = None
        self.notification_events = None
        self.storage_audit = None
        self._policy = None
        self.filesystem = None
        self._migrated = not self._migrations
        if connection is not None:
            with suppress(Exception):
                connection.close()

    def _startup_failed(self) -> None:
        """The expected recording target is unusable: refuse, never fall back.

        The tick retries the open every `retry_seconds` against the same
        declared identity, so a mount that appears late recovers without a
        restart and integrity/health/summary checks resume. Only the first
        failure of an episode raises the immediate alert.
        """
        self._set(state=RuntimeState.FAILED, recording_filesystem_ok=False,
                  storage_state=StorageState.HARD_STOP, recording_health=HealthState.FAILED)
        self._retry_at["startup"] = (self.dependencies.monotonic()
                                     + self.dependencies.retry_seconds)
        logging.getLogger(__name__).error(Event.MONITORING_STARTUP_FAILED)
        if self._startup_alerted:
            self._poll()
            return
        self._startup_alerted = True
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
        """Persist the verdict, update the live state and alert.

        A refused status write (e.g. `STORAGE_HARD_STOP`) still updates the
        in-memory state and attempts the alert, because storage/write faults
        are exactly when the immediate notification matters; the failure then
        propagates so the service stays degraded and retries. While the write
        keeps failing, the same verdict re-alerts at most once per day.
        """
        try:
            self.health_status.record(result, at)
        except Exception:
            persisted = False
        else:
            persisted = True
        self._set(recording_health=result.state)
        kind = {HealthState.FAILED: NotificationKind.RECORDING_HEALTH_FAILURE,
                HealthState.UNAVAILABLE: NotificationKind.RECORDING_HEALTH_WARNING,
                }.get(result.state)
        previous = self._unpersisted_health
        if kind is not None and (persisted or previous is None or previous[0] != result.state
                                 or not previous[1] <= at < previous[1] + timedelta(days=1)):
            self.notifications.record(kind, at=at, event_id=uuid5(
                EVENT_NAMESPACE, f"recording-health:{at.isoformat()}:{result.state.value}",
            ))
            previous = None if persisted else (result.state, at)
        if persisted or kind is None:
            previous = None
        self._unpersisted_health = previous
        if not persisted:
            raise RecordingError("RECORDING_HEALTH_NOT_PERSISTED")

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
            status.notification_delivery_failed, status.human_access_degraded,
            status.credential_finding_degraded, status.camera_offline_degraded,
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

    def _access_tick(self) -> None:
        """Human-access faults and credential findings (Issue #232 item 4).

        Runs in every runtime state once the notification service exists:
        Slack still receives the immediate alert while local persistence is
        refused. The monitor never raises on its own; an unexpected failure
        marks access degraded and is logged value-free.
        """
        monitor = self.dependencies.access_faults
        if monitor is None or self.notifications is None:
            return
        if not self._findings_recovered and self.status.state == RuntimeState.RUNNING:
            try:
                self._recover_access_state(monitor)
            except Exception:
                # Retried on the next running tick; nothing is lost meanwhile.
                logging.getLogger(__name__).error(Event.MONITORING_DEGRADED)
            else:
                self._findings_recovered = True
        try:
            status = monitor.drain(self.notifications, at=self.dependencies.utcnow(),
                                   monotonic=self.dependencies.monotonic(),
                                   finding_event_id=self._finding_event_id)
        except Exception:
            self._set(human_access_degraded=True)
            logging.getLogger(__name__).error(Event.MONITORING_DEGRADED)
            return
        self._set(human_access_degraded=status.human_access_degraded,
                  credential_finding_degraded=status.credential_finding_degraded)

    def _camera_tick(self) -> None:
        """Camera sources offline past the threshold (Issue #301 item 2).

        Runs in every runtime state once the notification service exists,
        like the access tick: Slack still receives the notification while
        local persistence is refused. The monitor never raises on its own; an
        unexpected failure is logged value-free and retried on the next tick.
        """
        monitor = self.dependencies.camera_offline
        if monitor is None or self.notifications is None:
            return
        running = self.status.state == RuntimeState.RUNNING
        try:
            if running and not self._camera_window_restored:
                # The rolling hour continues across a restart (as Issue #281
                # item 2 for the access budgets).
                monitor.restore_window(self._notification_window(
                    (NotificationKind.CAMERA_OFFLINE,), monitor.hourly_limit,
                    self.dependencies.utcnow()), monotonic=self.dependencies.monotonic())
                self._camera_window_restored = True
            status = monitor.drain(self.notifications, at=self.dependencies.utcnow(),
                                   monotonic=self.dependencies.monotonic(),
                                   durable_id=self._camera_offline_event if running else None,
                                   known=self._notification_known if running else None)
        except Exception:
            logging.getLogger(__name__).error(Event.MONITORING_DEGRADED)
            return
        self._set(camera_offline_degraded=status.offline_sources > 0)

    def _camera_offline_event(self, source_id: UUID) -> UUID | None:
        """The event ID of ``source_id``'s offline episode in progress.

        Named after the source and its registry ``last_seen_at`` (the last
        frame time, unchanged while no frame arrives), so a restarted process
        that finds the same outage computes the same ID. ``None`` (a
        per-process ID) when the source has no registry row.
        """
        row = self._connection.execute(
            "SELECT last_seen_at FROM camera_sources WHERE id=?", (str(source_id),)).fetchone()
        if row is None:
            return None
        return uuid5(EVENT_NAMESPACE, f"camera-offline:{source_id}:{row[0] or 'never'}")

    def _notification_known(self, event_id: UUID) -> bool:
        """Whether a `notification_events` row with ``event_id`` exists (any state).

        A `pending` row is an earlier process's uncertain delivery: it is not
        sent again (no duplicate), as for the presence critical claims.
        """
        return self.notification_events.get(event_id) is not None

    def _latest_finding(self, *, since: datetime | None = None) -> tuple[str, int] | None:
        """``(id, occurred_at_us)`` of the newest finding audit record.

        The newest is the highest rowid: SQLite gives each insert a rowid
        above every existing row, so it orders findings without trusting the
        wall clock. The rowid itself is not a durable name (an emptied table
        reuses it), so the record's immutable ``id`` names the notification
        (Codex PR #271). ``None`` without a finding or without an audit table.
        """
        marks = ",".join("?" for _ in FINDING_AUDIT_ACTIONS)
        bound, values = "", tuple(action.value for action in FINDING_AUDIT_ACTIONS)
        if since is not None:
            epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
            bound = " AND occurred_at_us > ?"
            values += ((since - epoch) // timedelta(microseconds=1),)
        try:
            row = self._connection.execute(
                "SELECT id, occurred_at_us FROM security_admin_audit_records "
                f"WHERE action IN ({marks}){bound} ORDER BY rowid DESC LIMIT 1",
                values,
            ).fetchone()
        except sqlite3.OperationalError:
            # Only a missing audit table means nothing was ever recorded. Any
            # other error (disk I/O, a locked database) re-raises, so the
            # recovery is retried on the next tick instead of being read as
            # "no finding" and marked done (PR #271 review).
            exists = self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='security_admin_audit_records'").fetchone()
            if exists is None:
                return None
            raise
        return None if row is None else (str(row[0]), int(row[1]))

    @staticmethod
    def _finding_event(audit_id: str) -> UUID:
        """The event ID of a notification covering findings through ``audit_id``."""
        return uuid5(EVENT_NAMESPACE, f"credential-finding-through:{audit_id}")

    def _finding_event_id(self) -> UUID | None:
        """Live path: name the notification by the newest finding it covers."""
        if self._connection is None or self.status.state != RuntimeState.RUNNING:
            return None
        latest = self._latest_finding()
        return None if latest is None else self._finding_event(latest[0])

    def _recover_access_state(self, monitor: AccessFaultMonitor) -> None:
        """Restore what a restart took from the in-memory monitor (Codex PR #271).

        Findings: the finding commits with its audit record, but its
        notification was only latched in memory until the next tick. Every
        ``credential_finding`` notification is named after the newest finding
        audit record it covers (``_finding_event``). The newest retained
        finding always restores the degraded hold
        from its age, and is notified again unless that event row exists with
        a final delivery state: a ``pending`` row is a delivery the previous
        process never finished. The audit rowid, never the wall clock, orders
        findings, so a clock rollback cannot hide one. Only the action, time
        and rowid are read, never the principal. Several findings committed
        after the last tick and lost to a crash before the drain are
        recovered as this one notification, not one each; every finding stays
        in the audit log, and the alert and the degraded hold are restored
        (Issue #281 item 4, Owner decision 2026-10-16 in Issue #287).

        Access episode: when the newest ``human_access_fault`` /
        ``human_access_recovered`` row (by rowid) is a fault, the episode
        continues in this process, so recovery is still announced; a fault
        row still ``pending`` is sent again first. A newest recovery row
        still ``pending`` is sent again (under its own ID and time) once a
        check passes, after its episode's fault when that row is pending too.
        Older episodes are superseded and not replayed.

        Rate windows: the accepted access and finding notification rows of
        the last hour re-seed both hourly budgets (``restore_windows``,
        Issue #281 item 2), so a restart does not reset them. This process's
        own rows (accepted while it started in ``FAILED``) are merged by
        event ID, never counted twice (Issue #287).
        """
        now = self.dependencies.utcnow()
        # The whole retained audit history (Codex PR #271): a notification
        # row is stamped after its finding and shares the 90-day retention,
        # so a finding that was notified never outlives its event row.
        latest = self._latest_finding()
        if latest is not None:
            row = self.notification_events.get(self._finding_event(latest[0]))
            delivered = row is not None and row["delivery"] is not DeliveryResult.PENDING
            epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
            age = (now - (epoch + timedelta(microseconds=latest[1]))).total_seconds()
            monitor.recover_finding(age_seconds=age, monotonic=self.dependencies.monotonic(),
                                    notify=not delivered)
        if monitor.attached is not None:
            rows = self._connection.execute(
                "SELECT kind, delivery, event_id, at FROM notification_events WHERE kind IN (?, ?) "
                "ORDER BY rowid DESC LIMIT 2",
                (NotificationKind.HUMAN_ACCESS_FAULT.value,
                 NotificationKind.HUMAN_ACCESS_RECOVERED.value),
            ).fetchall()
            last = rows[0] if rows else None
            pending = last is not None and last[1] == DeliveryResult.PENDING.value
            if (last is not None and last[0] == NotificationKind.HUMAN_ACCESS_RECOVERED.value
                    and pending):
                # A recovery notice the stopped process never delivered; its
                # episode's fault row may be undelivered too (sent first).
                prior = rows[1] if len(rows) > 1 else None
                fault = (prior if prior is not None
                         and prior[0] == NotificationKind.HUMAN_ACCESS_FAULT.value
                         and prior[1] == DeliveryResult.PENDING.value else None)
                monitor.restore_pending_recovery(
                    event_id=UUID(last[2]), at=datetime.fromisoformat(last[3]),
                    fault_event_id=UUID(fault[2]) if fault is not None else None,
                    fault_at=datetime.fromisoformat(fault[3]) if fault is not None else None)
            elif last is not None and last[0] == NotificationKind.HUMAN_ACCESS_FAULT.value:
                delivered = not pending
                monitor.restore_fault_episode(
                    delivered=delivered,
                    # A pending row is retried under its own ID and time.
                    event_id=None if delivered else UUID(last[2]),
                    at=None if delivered else datetime.fromisoformat(last[3]))
        # Issue #281 item 2: the rolling hours of both budgets continue
        # across the restart. Only accepted rows count, as in the process
        # that sent them; a pending row is sent again and counted then.
        monitor.restore_windows(
            access_rows=self._notification_window(
                (NotificationKind.HUMAN_ACCESS_FAULT, NotificationKind.HUMAN_ACCESS_RECOVERED),
                monitor.access_budget, now),
            finding_rows=self._notification_window(
                (NotificationKind.CREDENTIAL_FINDING,), monitor.finding_budget, now),
            monotonic=self.dependencies.monotonic())

    def _notification_window(self, kinds, limit: int, now: datetime) -> list[tuple[UUID, float]]:
        """``(event ID, age)`` of the newest ``limit`` rows of ``kinds`` accepted
        in the hour before ``now`` (Issue #287).

        The age runs from ``accepted_at``, the row's latest write, so a
        notification accepted on a retry long after its event's ``at`` counts
        from the retry; a row written before that column (``NULL``) counts
        from ``at``. Rows are filtered to the hour before they are limited
        and taken newest first by that time, so neither an old row inserted
        late nor a row stamped in the future (the clock moved back) displaces
        a recent one. The text comparison is the time order for the UTC text
        ``NotificationEventStore`` writes, and every row is parsed again here.
        """
        marks = ",".join("?" for _ in kinds)
        rows = self._connection.execute(
            "SELECT event_id, COALESCE(accepted_at, at) AS accepted FROM notification_events "
            f"WHERE kind IN ({marks}) AND delivery != ? AND accepted > ? AND accepted <= ? "
            "ORDER BY accepted DESC",
            (*(kind.value for kind in kinds), DeliveryResult.PENDING.value,
             (now - timedelta(seconds=HOUR_SECONDS)).astimezone(timezone.utc).isoformat(),
             now.astimezone(timezone.utc).isoformat()),
        )
        window = []
        try:
            for event_id, accepted in rows:
                # A row whose ID or time cannot be read is left out (at worst
                # a notification goes out early) rather than raising, which
                # would repeat the whole recovery on every tick.
                try:
                    age = (now - datetime.fromisoformat(accepted)).total_seconds()
                    event = UUID(event_id)
                except (TypeError, ValueError):
                    continue
                if 0 <= age < HOUR_SECONDS:
                    window.append((event, age))
                    if len(window) == limit:
                        break
        finally:
            # An unfinished statement would keep its read lock.
            rows.close()
        return window

    def _poll(self) -> None:
        if self.notifications is None:
            # The database itself could not be opened; nothing to persist.
            return
        self.notifications.poll()
        self._set(notification_local_failed=self.notifications.local_delivery_failed,
                  notification_delivery_failed=self.notifications.delivery_failed)

    # -- presence critical notifications (Issue #26) -------------------------

    def _require_owner(self) -> None:
        if threading.get_ident() != self._owner:
            raise RuntimeError("monitoring owner thread required")

    def dispatch_notifications(self, step: Callable[[], int]) -> int:
        """Run an upstream outbox's dispatch ``step`` on this worker.

        `NotificationService` is owned by this thread, so the presence
        dispatcher submits through it here (``self.call(...)``). Completions
        are polled before the step, freeing queue capacity, and after it, so a
        synchronous outcome reaches the outbox at once rather than on the next
        tick. Raises without a notification service (nothing is submitted).
        """
        self._require_owner()
        if self.notifications is None:
            raise RecordingError("NOTIFICATION_SERVICE_UNAVAILABLE")
        self._poll()
        try:
            return step()
        finally:
            self._poll()

    def notification_outcomes(self, event_ids) -> dict[UUID, DeliveryResult]:
        """Stored delivery results of ``event_ids`` in `notification_events`.

        Used to reconcile an upstream outbox's unconfirmed claims after a
        restart. An event without a row is absent from the result.
        """
        self._require_owner()
        if self.notification_events is None:
            raise RecordingError("NOTIFICATION_STORE_UNAVAILABLE")
        outcomes = {}
        for event_id in event_ids:
            row = self.notification_events.get(event_id)
            if row is not None:
                outcomes[event_id] = row["delivery"]
        return outcomes

    def settle_notifications(self, timeout_seconds: float) -> int:
        """Poll until no immediate delivery is pending or ``timeout_seconds`` pass.

        Shutdown calls it before `stop()`, so a notification submitted just
        before shutdown still completes and is recorded when the endpoint
        answers in time. Returns how many deliveries are still pending; those
        stay `pending` in `notification_events` (uncertain, never resent).
        """
        self._require_owner()
        if self.notifications is None:
            return 0
        deadline = time.monotonic() + timeout_seconds
        self._poll()
        while self.notifications.pending_count and time.monotonic() < deadline:
            time.sleep(0.02)
            self._poll()
        return self.notifications.pending_count

    def tick(self) -> None:
        """One owner-thread pass; call only through `call` or the run loop."""
        if threading.get_ident() != self._owner:
            raise RuntimeError("monitoring owner thread required")
        if self.status.state != RuntimeState.RUNNING:
            if self.notifications is not None:
                self._access_tick()
                self._camera_tick()
                self._poll()
            if (self.status.state == RuntimeState.FAILED
                    and self._due("startup", self.dependencies.monotonic())):
                self._attempt_open()
            return
        self._poll()
        self._storage_tick()
        self._guarded("retention", self._retention_tick, "retention_degraded")
        self._guarded("integrity", self.integrity.tick, "integrity_degraded")
        self._guarded("health", self.recording_health.tick, "recording_health_degraded")
        self._guarded("summary", self._summary_tick, "summary_degraded")
        self._access_tick()
        self._camera_tick()
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

    def _attempt_open(self, initial: bool = False) -> None:
        """Owner-thread `_open()` whose unexpected raise is still rescheduled.

        `_open()` handles storage failures itself. A raise from database
        connect or notification setup (before any alert path exists) must not
        leave the past-due `startup` deadline in place, or every tick would
        retry and log instead of waiting `retry_seconds`.
        """
        try:
            self._open()
        except Exception as error:
            if initial and isinstance(error, MigrationError):
                # An unusable schema aborts application startup, as before.
                raise
            if self.status.state == RuntimeState.RUNNING:
                # Components were published; a later startup step raised.
                logging.getLogger(__name__).error(Event.MONITORING_DEGRADED)
                return
            self._set(state=RuntimeState.FAILED)
            self._drop_connection()
            self._retry_at["startup"] = (self.dependencies.monotonic()
                                         + self.dependencies.retry_seconds)
            logging.getLogger(__name__).error(Event.MONITORING_STARTUP_FAILED)

    async def start(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1,
                                            thread_name_prefix="serversentinel-monitoring")
        # Usually a raise means the database could not be opened; the tick
        # retries it every `retry_seconds`.
        await self.call(self._attempt_open, True)
        if self.status.state == RuntimeState.RUNNING:
            logging.getLogger(__name__).info(Event.MONITORING_STARTED)

    async def run(self, after_tick: Callable[[], None] | None = None) -> None:
        """Tick forever; `after_tick` refreshes lifespan-held status snapshots."""
        while True:
            await asyncio.sleep(self.dependencies.tick_seconds)
            try:
                await self.call(self.tick)
            except Exception:
                logging.getLogger(__name__).error(Event.MONITORING_DEGRADED)
            if after_tick is not None:
                after_tick()

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
