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
# The optional health sink runs on one delivery thread, never on a capture
# worker or the watchdog. At most this many events wait for it; on overflow
# an older event of a source that has a newer one pending is dropped
# (coalesced), so each source's latest transition is always kept.
HEALTH_SINK_MAX_PENDING = 64
# A sink call running longer than this is reported as a stalled delivery and
# degrades the service state, so a hung sink is never hidden behind
# ``running``.
HEALTH_SINK_STALL_SECONDS = 5.0
# stop() waits at most this long for pending sink deliveries (for example the
# close/offline transitions raised while stopping) before returning.
HEALTH_SINK_SETTLE_SECONDS = 1.0


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
    # Events waiting for the optional health sink, events coalesced away
    # because that bounded queue was full, and whether one sink call has run
    # longer than ``HEALTH_SINK_STALL_SECONDS`` (the service is then
    # ``degraded``).
    health_sink_pending: int = 0
    health_sink_coalesced: int = 0
    health_sink_stalled: bool = False


class _HealthSinkDelivery:
    """Bounded, ordered delivery of health events to an optional sink.

    ``submit`` only appends to a bounded queue and never blocks, so neither a
    capture worker nor the watchdog ever waits for the sink. One daemon
    thread (started on demand, exiting when the queue is empty) calls the
    sink in submission order. A sink that hangs therefore holds only that
    thread; later events wait in the bounded queue, where an older event of a
    source with a newer pending event is coalesced away on overflow, and the
    hang is reported through ``snapshot`` instead of looking healthy.
    """

    def __init__(self, sink, *, max_pending, monotonic, stall_seconds):
        self._sink = sink
        self._max_pending = max_pending
        self._monotonic = monotonic
        self._stall_seconds = stall_seconds
        self._lock = threading.Lock()
        self._pending: deque[HealthEvent] = deque()
        self._running = False
        self._in_flight_since = None
        self._idle = threading.Event()
        self._idle.set()
        self.coalesced = 0
        self.failures = 0

    def _coalesce(self, event):
        # Called with the lock held and the queue full. Drop the oldest event
        # of a source that has a later pending (or the incoming) event; with
        # at most 4 sources and a bound above 4 such an event always exists,
        # so no source ever loses its latest transition.
        superseded = 0
        newer = {event.source_id}
        for index in range(len(self._pending) - 1, -1, -1):
            item = self._pending[index]
            if item.source_id in newer:
                superseded = index
            newer.add(item.source_id)
        del self._pending[superseded]
        self.coalesced += 1

    def submit(self, event):
        with self._lock:
            if len(self._pending) >= self._max_pending:
                self._coalesce(event)
            self._pending.append(event)
            if self._running:
                return
            self._running = True
            self._idle.clear()
        thread = threading.Thread(target=self._drain, daemon=True,
                                  name="serversentinel-local-uvc-health-sink")
        try:
            thread.start()
        except BaseException:
            with self._lock:
                self._running = False
                self._idle.set()
            raise

    def _drain(self):
        while True:
            with self._lock:
                if not self._pending:
                    self._running = False
                    self._idle.set()
                    return
                event = self._pending.popleft()
                self._in_flight_since = self._monotonic()
            try:
                self._sink(event)
            except BaseException:
                # Counted only: exception text may carry private details. Any
                # escape would leave the queue without a delivery thread.
                with self._lock:
                    self.failures += 1
            finally:
                with self._lock:
                    self._in_flight_since = None

    def settle(self, timeout):
        """Wait at most ``timeout`` for every pending event; True when idle."""
        return self._idle.wait(timeout)

    def snapshot(self):
        """(pending, coalesced, failures, stalled) without waiting for the sink."""
        now = self._monotonic()
        with self._lock:
            since = self._in_flight_since
            stalled = since is not None and now - since >= self._stall_seconds
            return len(self._pending), self.coalesced, self.failures, stalled


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
                 on_camera_state: Callable[[HealthEvent], None] | None = None,
                 discovery=None, capture_factory=MmapCapture,
                 supervisor_factory=LocalUvcSupervisor, adapter_factory=LocalUvcAdapter,
                 max_health_events: int = MAX_HEALTH_EVENTS, monotonic=time.monotonic):
        if not isinstance(configuration, LocalUvcConfiguration):
            raise TypeError("local UVC configuration is required")
        if not callable(on_frame):
            raise TypeError("local UVC frame sink is required")
        if health_sink is not None and not callable(health_sink):
            raise TypeError("local UVC health sink must be callable")
        if on_camera_state is not None and not callable(on_camera_state):
            raise TypeError("local UVC camera state listener must be callable")
        if type(max_health_events) is not int or not 1 <= max_health_events <= 4096:
            raise ValueError("health event bound is invalid")
        self.configuration = configuration
        self.registry = registry
        self._on_frame = on_frame
        self._health_sink = health_sink
        # In-memory listener (preview invalidation), called in transition
        # order with the in-memory record, never behind a downstream sink.
        self._on_camera_state = on_camera_state
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
        self._sink_delivery = (
            _HealthSinkDelivery(health_sink, max_pending=HEALTH_SINK_MAX_PENDING,
                                monotonic=monotonic, stall_seconds=HEALTH_SINK_STALL_SECONDS)
            if health_sink is not None else None
        )
        self._camera: dict[UUID, CameraState] = {}
        self.health_logs_suppressed = 0
        self._state = LocalUvcRuntimeState.STARTING
        self._sources = {source_id: SourceRuntimeState.PENDING
                         for source_id in configuration.source_ids}
        self._supervisor = None
        self.adapter = None
        self._started = False
        # Teardown steps a STOP_FAILED stop could not finish yet. A later
        # stop() retries them (for example once a watchdog that outlived the
        # join bound has exited); a worker cleanup failure is not retryable.
        self._adapter_open = False
        self._database_pinned = False
        self._stop_cleanup_failed = False

    # -- health events -------------------------------------------------
    def _health(self, event: HealthEvent) -> None:
        """Record and publish one event (both halves of the adapter callback)."""
        self._record_health(event)
        self._publish_health(event)

    def _record_health(self, event: HealthEvent) -> None:
        """In-memory half, called under the source's transition lock.

        It only updates bounded in-memory state and never blocks, so the
        runtime status follows every transition even while a downstream sink
        is slow.
        """
        with self._events_lock:
            if len(self._events) == self._events.maxlen:
                self._events_dropped += 1
            self._events.append(event)
            if event.source_id in self._sources:
                self._camera[event.source_id] = event.state
        # ``on_camera_state`` must itself be in-memory and non-blocking (the
        # preview hub only flips a flag and drops its retained frame). It runs
        # here, not with the downstream sinks, so a slow or hung optional sink
        # handling an earlier event can never delay a non-online transition
        # from invalidating the preview.
        if self._on_camera_state is not None:
            try:
                self._on_camera_state(event)
            except Exception:
                with self._events_lock:
                    self._sink_failures += 1

    def _publish_health(self, event: HealthEvent) -> None:
        """Downstream half (logging, health sink), called after the source's
        transition lock is released; never raises into the capture worker."""
        now = self._monotonic()
        with self._events_lock:
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
        if self._sink_delivery is not None:
            # Never call the optional sink here: this runs on a capture
            # worker (or a delivery thread the watchdog handed off to), and a
            # slow or hung sink must not stall capture transitions.
            try:
                self._sink_delivery.submit(event)
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
                self._database_pinned = True
            self._started = True
            try:
                self.adapter = self._adapter_factory(
                    self.registry, emit_audit=self._record_health,
                    publish=self._publish_health, on_frame=self._on_frame,
                    discovery=self._discovery, capture_factory=self._capture_factory,
                    frame_stall_seconds=self.configuration.frame_stall_seconds,
                    frame_stall_reopen_seconds=self.configuration.frame_stall_reopen_seconds,
                    presence_scan_seconds=self.configuration.presence_scan_seconds,
                )
                self._supervisor = self._supervisor_factory(
                    self.adapter, poll_timeout=self.configuration.poll_timeout_seconds,
                    retry_delay=self.configuration.retry_delay_seconds,
                    join_timeout=self.configuration.join_timeout_seconds,
                )
                self._adapter_open = True
            except Exception:
                # No worker exists yet; release what was acquired so a
                # contained startup failure never keeps the admitted
                # database descriptor (and its filesystem) busy for the
                # process lifetime.
                self._release_partial_start()
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

    def _release_database(self) -> bool:
        release = getattr(self.registry.database, "release", None)
        if not callable(release):
            self._database_pinned = False
            return True
        try:
            release()
        except Exception:
            return False
        self._database_pinned = False
        return True

    def _release_partial_start(self) -> None:
        adapter, self.adapter, self._supervisor = self.adapter, None, None
        self._adapter_open = False
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                pass
        self._release_database()

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

    def _aggregate(self, sink_stalled: bool | None = None) -> LocalUvcRuntimeState:
        # ``sink_stalled`` lets ``status()`` derive the state and the reported
        # ``health_sink_stalled`` from one sink snapshot, so the two never
        # disagree (e.g. RUNNING next to a stalled sink).
        if sink_stalled is None:
            sink_stalled = self._sink_stalled()
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
            if not worker_problem and not sink_stalled:
                return LocalUvcRuntimeState.RUNNING
        if SourceRuntimeState.RUNNING not in states:
            return LocalUvcRuntimeState.FAILED
        return LocalUvcRuntimeState.DEGRADED

    def _sink_stalled(self) -> bool:
        # A hung optional sink means health notifications are not being
        # delivered: never report that as a healthy service.
        return self._sink_delivery is not None and self._sink_delivery.snapshot()[3]

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
        A frame-progress watchdog still inside a check after its bounded join
        likewise fails the stop and keeps the adapter open under that check.

        Such a ``STOP_FAILED`` stop is retryable: a later ``stop()`` joins the
        supervisor again and, once no worker or watchdog is left that could
        call into the adapter, closes the adapter (and retries a failed
        database release). A worker whose own cleanup failed keeps the stop
        ``STOP_FAILED``. Pending health-sink deliveries get at most
        ``HEALTH_SINK_SETTLE_SECONDS`` after the teardown.
        """
        with self._lock:
            if self._state is LocalUvcRuntimeState.STOPPED:
                return self.status()
            if self._state is LocalUvcRuntimeState.STOP_FAILED and not (
                    self._adapter_open or self._database_pinned):
                return self.status()
            if not self._started or self._supervisor is None:
                # Never started, or startup failed before any worker existed:
                # nothing may keep holding the database pin or an adapter.
                self._release_partial_start()
                self._state = LocalUvcRuntimeState.STOPPED
                self._started = True
                return self.status()
            failed = self._stop_cleanup_failed
            if self._adapter_open:
                workers_alive = False
                try:
                    self._supervisor.close()
                except WorkerStopError:
                    failed = True
                    # A watchdog still inside a frame-progress check may call
                    # into the adapter as well, so it keeps the adapter open
                    # too.
                    workers_alive = self._supervisor.watchdog_running or any(
                        (status := self._supervisor.status(source_id)) is not None
                        and status.running
                        for source_id in self.configuration.source_ids
                    )
                    if not workers_alive:
                        # Every thread is gone, so this was a worker's own
                        # cleanup failure: a retry cannot undo it.
                        self._stop_cleanup_failed = True
                except Exception:
                    failed = True
                    workers_alive = True
                if not workers_alive:
                    self._adapter_open = False
                    try:
                        self.adapter.close()
                    except Exception:
                        failed = True
                        self._stop_cleanup_failed = True
                else:
                    failed = True
            # Drop the held database pin; a worker that outlived the join
            # bound then fails closed instead of reading storage.
            if self._database_pinned and not self._release_database():
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
        if self._sink_delivery is not None:
            # Outside the runtime lock: a hung sink delays only this return.
            self._sink_delivery.settle(HEALTH_SINK_SETTLE_SECONDS)
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
            # One sink snapshot feeds both the aggregate state and the
            # reported sink fields, so they always describe the same moment.
            pending = coalesced = delivery_failures = 0
            stalled = False
            if self._sink_delivery is not None:
                pending, coalesced, delivery_failures, stalled = self._sink_delivery.snapshot()
            state = self._state
            if state in (LocalUvcRuntimeState.RUNNING, LocalUvcRuntimeState.DEGRADED):
                # A worker thread that died later is not hidden behind the
                # state computed at start.
                state = self._aggregate(sink_stalled=stalled)
                self._state = state
        with self._events_lock:
            dropped, sink_failures = self._events_dropped, self._sink_failures
            suppressed = self.health_logs_suppressed
        sink_failures += delivery_failures
        return LocalUvcRuntimeStatus(state, tuple(sources), dropped, sink_failures, suppressed,
                                     pending, coalesced, stalled)
