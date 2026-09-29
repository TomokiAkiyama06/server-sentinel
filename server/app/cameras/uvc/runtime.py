"""Backend lifecycle for configured local UVC sources.

The deployment names which registry sources (1 to 4 logical UUIDs) this Main
Server supervises.  Physical identity evidence is never part of that
configuration: it stays in the private approval store and is only ever created
by the audited Owner boundary.  A configured source without a durable Owner
approval stays ``offline`` and never acquires a device.

The runtime owns one ``LocalUvcAdapter`` and one ``LocalUvcSupervisor``.  Camera
health (``online`` / ``offline`` / ``manual_intervention_required``) is written
to the registry per source by the adapter; the runtime's own state reports only
whether the capture service itself is running, so an unplugged camera never
looks like a crashed service and a crashed worker never looks like a healthy
camera.
"""

from collections import deque
from dataclasses import dataclass
from enum import StrEnum
import logging
import threading
import time
from typing import Callable
from uuid import UUID

from app.cameras.registry import (
    CameraRegistry, NotFoundError, SourceHealthState, SourceType,
)
from app.logging import Event
from .capture import MmapCapture
from .config import LocalUvcConfiguration
from .identity import CameraState, HealthEvent
from .registry_adapter import LocalUvcAdapter
from .supervisor import LocalUvcSupervisor, WorkerStopError


MAX_HEALTH_EVENTS = 256
# A camera that keeps failing negotiation flaps between offline and degraded on
# every retry. Log at most one health line per source per interval; the bounded
# event buffer and the registry still record every transition.
HEALTH_LOG_INTERVAL_SECONDS = 10.0


@dataclass(frozen=True)
class LocalUvcDependencies:
    """Injectable discovery/capture seams; tests pass synthetic adapters."""

    discovery: object = None
    capture_factory: Callable = MmapCapture
    health_sink: Callable[[HealthEvent], None] | None = None


class LocalUvcRuntimeState(StrEnum):
    UNCONFIGURED = "unconfigured"
    # Configured, but no admitted storage/migrated schema exists to hold the
    # approval store and source health, so capture never starts.
    STORAGE_UNADMITTED = "storage_unadmitted"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    FAILED = "failed"
    STOPPED = "stopped"
    STOP_FAILED = "stop_failed"


class SourceRuntimeState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    # The configured UUID is not a local UVC registry source.
    REJECTED = "rejected"
    WORKER_FAILED = "worker_failed"
    STOPPED_FOR_APPROVAL = "stopped_for_approval"
    STOPPED = "stopped"


@dataclass(frozen=True)
class LocalUvcSourceStatus:
    """Worker health for one source; camera health lives in the registry."""

    source_id: UUID
    state: SourceRuntimeState
    worker_running: bool
    worker_failures: int
    cleanup_failed: bool
    # The latest in-memory camera transition, delivered even when persisting
    # it was refused; ``None`` before the first transition this lifecycle.
    camera_state: CameraState | None = None
    # False while the latest registry health write for this source was
    # refused (storage admission) or failed: the registry row may be stale.
    health_persisted: bool = True


@dataclass(frozen=True)
class LocalUvcRuntimeStatus:
    state: LocalUvcRuntimeState
    sources: tuple[LocalUvcSourceStatus, ...] = ()
    health_events_dropped: int = 0
    health_sink_failures: int = 0
    health_logs_suppressed: int = 0


class LocalUvcRuntime:
    """Start, stop and reapprove configured local UVC sources.

    Every method is safe to call from any one thread at a time; a runtime lock
    serializes lifecycle operations.  Frame delivery happens on the per-source
    worker threads through ``on_frame``, which must be thread-safe and must not
    block (the preview hub keeps only one bounded latest frame per source).
    """

    def __init__(self, configuration: LocalUvcConfiguration, registry: CameraRegistry, *,
                 on_frame: Callable[[UUID, object], None],
                 health_sink: Callable[[HealthEvent], None] | None = None,
                 discovery=None, capture_factory=MmapCapture,
                 supervisor_factory=LocalUvcSupervisor, adapter_factory=LocalUvcAdapter,
                 max_health_events: int = MAX_HEALTH_EVENTS, monotonic=time.monotonic):
        if not isinstance(configuration, LocalUvcConfiguration):
            raise TypeError("local UVC configuration is required")
        if not callable(on_frame):
            raise TypeError("local UVC frame sink is required")
        if health_sink is not None and not callable(health_sink):
            raise TypeError("local UVC health sink must be callable")
        if type(max_health_events) is not int or not 1 <= max_health_events <= 4096:
            raise ValueError("health event bound is invalid")
        self.configuration = configuration
        self.registry = registry
        self._on_frame = on_frame
        self._health_sink = health_sink
        self._discovery = discovery
        self._capture_factory = capture_factory
        self._supervisor_factory = supervisor_factory
        self._adapter_factory = adapter_factory
        self._lock = threading.RLock()
        self._events_lock = threading.Lock()
        self._events: deque[HealthEvent] = deque(maxlen=max_health_events)
        self._events_dropped = 0
        self._sink_failures = 0
        self._monotonic = monotonic
        self._last_logged: dict[UUID, float] = {}
        self._camera: dict[UUID, CameraState] = {}
        self.health_logs_suppressed = 0
        self._state = LocalUvcRuntimeState.STARTING
        self._sources = {source_id: SourceRuntimeState.PENDING
                         for source_id in configuration.source_ids}
        self._supervisor = None
        self.adapter = None
        self._started = False

    # -- health events -------------------------------------------------
    def _health(self, event: HealthEvent) -> None:
        """Adapter health callback; never raises into the capture worker."""
        now = self._monotonic()
        with self._events_lock:
            if len(self._events) == self._events.maxlen:
                self._events_dropped += 1
            self._events.append(event)
            if event.source_id in self._sources:
                self._camera[event.source_id] = event.state
            last = self._last_logged.get(event.source_id)
            log = (event.state is CameraState.MANUAL or last is None
                   or now - last >= HEALTH_LOG_INTERVAL_SECONDS)
            if log:
                self._last_logged[event.source_id] = now
            else:
                self.health_logs_suppressed += 1
        if log:
            level = (logging.WARNING if event.state in (CameraState.OFFLINE, CameraState.MANUAL)
                     else logging.INFO)
            # The formatter discards all extras; only the fixed event name is
            # logged, never device paths, serials or the source UUID.
            logging.getLogger(__name__).log(level, Event.LOCAL_UVC_SOURCE_HEALTH_CHANGED)
        if self._health_sink is not None:
            try:
                self._health_sink(event)
            except Exception:
                with self._events_lock:
                    self._sink_failures += 1

    def recent_health_events(self) -> tuple[HealthEvent, ...]:
        with self._events_lock:
            return tuple(self._events)

    # -- lifecycle -----------------------------------------------------
    def start(self) -> LocalUvcRuntimeStatus:
        """Validate configured sources and start one worker per valid source.

        Idempotent while running.  A refused storage admission while pinning
        the database returns ``STORAGE_UNADMITTED`` and leaves the runtime
        startable, because nothing was opened yet.  A runtime is single-use:
        after ``stop()`` a new runtime must be constructed so a stale approval handoff or session
        marker can never leak into a new lifecycle.
        """
        with self._lock:
            if self._started:
                if self._state in (LocalUvcRuntimeState.STOPPED, LocalUvcRuntimeState.STOP_FAILED):
                    raise RuntimeError("local UVC runtime cannot restart")
                return self.status()
            pin = getattr(self.registry.database, "pin", None)
            if callable(pin):
                try:
                    # Pin the admitted database file before any worker opens
                    # it; later opens refuse a missing or replaced file.
                    pin(getattr(self.registry, "reservation", None))
                except Exception:
                    # Storage admission was refused (a hard stop began, or the
                    # verified filesystem is gone) before any adapter, worker
                    # or descriptor exists. That is retryable, not a terminal
                    # failure: the runtime stays startable so the lifespan
                    # retries once storage is admitted again.
                    self._state = LocalUvcRuntimeState.STORAGE_UNADMITTED
                    logging.getLogger(__name__).error(Event.LOCAL_UVC_STORAGE_UNADMITTED)
                    return self.status()
            self._started = True
            try:
                self.adapter = self._adapter_factory(
                    self.registry, emit_audit=self._health, on_frame=self._on_frame,
                    discovery=self._discovery, capture_factory=self._capture_factory,
                )
                self._supervisor = self._supervisor_factory(
                    self.adapter, poll_timeout=self.configuration.poll_timeout_seconds,
                    retry_delay=self.configuration.retry_delay_seconds,
                    join_timeout=self.configuration.join_timeout_seconds,
                )
            except Exception:
                self._state = LocalUvcRuntimeState.FAILED
                logging.getLogger(__name__).error(Event.LOCAL_UVC_STARTUP_FAILED)
                return self.status()
            for source_id in self.configuration.source_ids:
                self._sources[source_id] = self._start_source(source_id)
            self._state = self._aggregate()
            if self._state is LocalUvcRuntimeState.RUNNING:
                logging.getLogger(__name__).info(Event.LOCAL_UVC_STARTED)
            else:
                logging.getLogger(__name__).error(Event.LOCAL_UVC_DEGRADED)
            return self.status()

    def _start_source(self, source_id: UUID) -> SourceRuntimeState:
        try:
            source = self.registry.get_source(source_id)
        except NotFoundError:
            return SourceRuntimeState.REJECTED
        except Exception:
            # Storage is transiently unreadable: start the worker anyway. Each
            # poll re-reads the registry, fails visibly (counted) and retries,
            # and nothing is captured until the source validates.
            source = None
        if source is not None and source.source_type != SourceType.LOCAL_UVC:
            # Never attach a local device to a remote-agent source.
            return SourceRuntimeState.REJECTED
        try:
            self._supervisor.start(source_id)
        except Exception:
            self._mark_offline(source_id)
            return SourceRuntimeState.WORKER_FAILED
        return SourceRuntimeState.RUNNING

    def _mark_offline(self, source_id: UUID) -> None:
        # A source whose worker is not running must not keep a stale healthy
        # state from an earlier lifecycle.
        try:
            self.registry.update_source_health(
                source_id, health_state=SourceHealthState.OFFLINE,
                negotiated_capture_profile=None,
            )
        except Exception:
            pass

    def _aggregate(self) -> LocalUvcRuntimeState:
        states = set(self._sources.values())
        if states <= {SourceRuntimeState.RUNNING, SourceRuntimeState.STOPPED_FOR_APPROVAL}:
            worker_problem = False
            if self._supervisor is not None:
                for source_id, state in self._sources.items():
                    if state is not SourceRuntimeState.RUNNING:
                        continue
                    status = self._supervisor.status(source_id)
                    if (status is None or not status.running or status.cleanup_failed
                            or getattr(status, "polling_failed", False)
                            or self._health_unpersisted(source_id)):
                        # A live worker whose health cannot be persisted is
                        # not a healthy service: the registry may be stale.
                        worker_problem = True
            if not worker_problem:
                return LocalUvcRuntimeState.RUNNING
        if SourceRuntimeState.RUNNING not in states:
            return LocalUvcRuntimeState.FAILED
        return LocalUvcRuntimeState.DEGRADED

    def _health_unpersisted(self, source_id: UUID) -> bool:
        check = getattr(self.adapter, "health_unpersisted", None)
        if check is None:
            return False
        try:
            return check(source_id) is True
        except Exception:
            return True

    def stop(self) -> LocalUvcRuntimeStatus:
        """Stop every worker, then close the adapter; idempotent.

        If a worker does not stop within the join bound the adapter is left for
        that worker's own ``finally`` cleanup instead of being closed from this
        thread while a capture poll may still run; the durable active-session
        marker then conservatively requires Owner reapproval at next start.
        """
        with self._lock:
            if self._state in (LocalUvcRuntimeState.STOPPED, LocalUvcRuntimeState.STOP_FAILED):
                return self.status()
            if not self._started or self._supervisor is None:
                self._state = LocalUvcRuntimeState.STOPPED
                self._started = True
                return self.status()
            failed = False
            workers_alive = False
            try:
                self._supervisor.close()
            except WorkerStopError:
                failed = True
                workers_alive = any(
                    (status := self._supervisor.status(source_id)) is not None and status.running
                    for source_id in self.configuration.source_ids
                )
            except Exception:
                failed = True
                workers_alive = True
            if not workers_alive:
                try:
                    self.adapter.close()
                except Exception:
                    failed = True
            release = getattr(self.registry.database, "release", None)
            if callable(release):
                # Drop the held database pin; a worker that outlived the join
                # bound then fails closed instead of reading storage.
                try:
                    release()
                except Exception:
                    failed = True
            for source_id, state in tuple(self._sources.items()):
                if state is not SourceRuntimeState.REJECTED:
                    self._sources[source_id] = SourceRuntimeState.STOPPED
            self._state = (LocalUvcRuntimeState.STOP_FAILED if failed
                           else LocalUvcRuntimeState.STOPPED)
            logging.getLogger(__name__).log(
                logging.ERROR if failed else logging.INFO,
                Event.LOCAL_UVC_STOP_FAILED if failed else Event.LOCAL_UVC_STOPPED,
            )
            return self.status()

    def reapprove(self, owner_administration, actor_context, source_id: UUID, candidate):
        """Run the audited Owner approval with that source's worker stopped.

        The adapter requires a stopped session before an approval so no
        in-memory/physical transition can escape the SQLite rollback.  The
        worker restarts afterwards whether the approval committed or was
        refused, so a denied or failed ceremony never leaves the source
        unsupervised.  A worker that cannot be stopped refuses the approval.
        """
        with self._lock:
            if (self._state not in (LocalUvcRuntimeState.RUNNING, LocalUvcRuntimeState.DEGRADED)
                    or not isinstance(source_id, UUID)
                    or self._sources.get(source_id) not in (
                        SourceRuntimeState.RUNNING, SourceRuntimeState.WORKER_FAILED)):
                raise ValueError("local UVC source is not supervised")
            try:
                self._supervisor.stop(source_id)
            except WorkerStopError:
                status = self._supervisor.status(source_id)
                if status is not None and status.running:
                    self._state = self._aggregate()
                    raise ValueError("local UVC source could not stop for approval") from None
                # The worker exited but its cleanup failed; its durable
                # session marker stays, so the audited path still validates.
            self._sources[source_id] = SourceRuntimeState.STOPPED_FOR_APPROVAL
            try:
                return owner_administration.approve_uvc(
                    actor_context, self.adapter, source_id, candidate,
                )
            finally:
                self._sources[source_id] = self._start_source(source_id)
                self._state = self._aggregate()

    # -- status --------------------------------------------------------
    def status(self) -> LocalUvcRuntimeStatus:
        with self._lock:
            sources = []
            for source_id in self.configuration.source_ids:
                worker = (self._supervisor.status(source_id)
                          if self._supervisor is not None else None)
                with self._events_lock:
                    camera = self._camera.get(source_id)
                sources.append(LocalUvcSourceStatus(
                    source_id, self._sources[source_id],
                    bool(worker and worker.running),
                    worker.failures if worker else 0,
                    bool(worker and worker.cleanup_failed),
                    camera, not self._health_unpersisted(source_id),
                ))
            state = self._state
            if state in (LocalUvcRuntimeState.RUNNING, LocalUvcRuntimeState.DEGRADED):
                # A worker thread that died later is not hidden behind the
                # state computed at start.
                state = self._aggregate()
                self._state = state
        with self._events_lock:
            dropped, sink_failures = self._events_dropped, self._sink_failures
            suppressed = self.health_logs_suppressed
        return LocalUvcRuntimeStatus(state, tuple(sources), dropped, sink_failures, suppressed)
