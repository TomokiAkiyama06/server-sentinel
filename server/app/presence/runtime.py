"""Main-runtime ownership of the presence timeline outbox for scene detection (#205).

`SceneTimeline` builds the reviewed presence pieces the scene runtime hands
its evidence to and owns their lifecycle inside the Main application:

- a `PresenceService` over the application's database, opened only through a
  `PinnedDatabase` pinned under the storage admission, so a lost or replaced
  filesystem after startup is refused rather than written to;
- a `TimelineOutbox` (bounded staging, the single main-host receipt clock and
  the durable outbox session);
- a `CriticalTimelineRecorder`, the scene runtime's durable critical recorder,
  whose `record_undelivered` is the scene runtime's count-only `undelivered`
  sink.

The lifecycle follows the acceptance conditions on Issue #205 (from PR #250,
#224 and #259):

1. the `undelivered` sink is `CriticalTimelineRecorder.record_undelivered`;
   it only adds to an in-memory count (`TimelineOutbox.record_lost`), so it
   never blocks and does no I/O when `stop()` or the delivery thread call it;
2. `open()` must succeed before the scene runtime starts, so no count is ever
   handed to an outbox that is not open;
3. `finish()` runs only after the scene runtime's `stop()` has returned;
4. `finish()` flushes first, so counts handed over at stop reach the durable
   gap marker even when the session is left open;
5. the outbox is closed cleanly (`TimelineOutbox.close()`) only when the
   scene stop ended `STOPPED` and every undelivered count was recorded. After
   `STOP_FAILED`, an unavailable runtime, a stop that raised, or
   `undelivered_recorded is False`, `close()` is never called: the session row
   stays, so the next start records an interrupted gap and Owner status
   reports `timeline_gap` until the Owner clears it.

Confirmed critical observations queue an `evidence` and a `notification`
delivery row in the same write (`PresenceService.record`). `CriticalDispatcher`
drives `PresenceService.dispatch_pending()` for them (Issue #26): the Main
lifespan runs each step on the monitoring worker that owns the #21
`NotificationService`, so a confirmed server movement or camera tamper reaches
the Owner through the same local event store and optional Slack delivery as a
hardware-integrity or recording-health failure. No evidence-preservation port
exists yet (a separate recording decision), so the `evidence` rows are
recorded `unavailable` and that critical path stays reported unavailable.
A confirmed observation whose record storage refuses (`STORAGE_HARD_STOP`)
still attempts its Slack alert (Issue #318): the recorder hands it to
`UnrecordedCriticalAlerts`, which the dispatcher drains on the same worker.

Nothing here registers a route, reads pixels, names a person or infers cause.
Timing policy stays explicit: there is no default source latency bound or
clock trust (see `adapters.py`).
"""

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
import logging
import math
import threading
from typing import Awaitable, Callable, ContextManager
from uuid import UUID

from app.completion import run_to_completion
from app.detection.roi.runtime import SceneRuntimeState
from app.logging import Event
from app.storage.database import Database, PinnedDatabase

from .adapters import CriticalTimelineRecorder, MainClock, OutboxState, TimelineOutbox
from .delivery import ActionResult, NotificationAdapter, UnrecordedCriticalAlerts, notification_result
from .service import PresenceService


# Staging bound for timeline facts. Scene critical observations are recorded
# synchronously and never staged, and loss counts are not facts, so with the
# scene runtime as the only producer this bound is not consumed; it is kept
# small and explicit for producers that are wired later.
DEFAULT_OUTBOX_CAPACITY = 256
# How often the Main runtime writes counted loss to the durable gap marker
# (`TimelineOutbox.flush`) and retries an outbox open that failed.
DEFAULT_FLUSH_INTERVAL_SECONDS = 5.0
DEFAULT_OPEN_RETRY_SECONDS = 15.0
# Rows one scheduled retention batch may delete per presence table; the
# largest limit `PresenceService.expire_history` / `expire_audit` accept.
RETENTION_BATCH = 1000
# Critical delivery rows one dispatch step selects. A full batch is followed
# by the next step at once, so a backlog drains without waiting an interval.
DISPATCH_BATCH = 50
# How soon a confirmed critical observation is submitted to its ports, the
# ceiling of the backoff after a failed step (storage refused, database
# busy), and how long shutdown waits for submitted notifications to finish.
# The 5 s interval is an Owner decision (2026-10-22).
DEFAULT_DISPATCH_INTERVAL_SECONDS = 5.0
DEFAULT_DISPATCH_BACKOFF_SECONDS = 60.0
# The settle wait exceeds the Slack transport timeout (10 s by default), so a
# slow POST still completes. It is bounded to 30 s because the whole shutdown
# (capture and scene stop, outbox finish, this wait, monitoring stop) must end
# within the unit's `TimeoutStopSec=90` (`install.py`), or systemd kills it.
DEFAULT_DISPATCH_SETTLE_SECONDS = 12.0
MAXIMUM_DISPATCH_SETTLE_SECONDS = 30.0


class RetentionClockUntrusted(RuntimeError):
    """Presence expiry refused: the main-host clock is not trusted now.

    A future-skewed clock would move both retention cutoffs forward and
    delete timeline or audit rows early, so nothing is deleted. Raising
    makes the scheduled cleanup report degraded retention and retry on its
    shorter interval, like any other failed cleanup.
    """

    def __init__(self):
        super().__init__("presence retention clock untrusted")


class TimelineNotPinned(RuntimeError):
    """Critical dispatch refused: the timeline database is not pinned yet.

    `SceneTimeline.open()` (or a retention batch) pins it under the storage
    admission; the dispatcher backs off and retries meanwhile.
    """

    def __init__(self):
        super().__init__("presence timeline database not pinned")


class _PresenceRetention:
    """One presence retention operation as an `AuditRetentionRuntime` store.

    The application's scheduled cleanup calls `cleanup_expired_batch()` at
    startup, daily, on the shorter retry interval after a failure, and again
    at once while a batch came back full (`cleanup_batch_size`). The windows
    are the presence service's shared `RetentionPeriods` (20-day recording
    retention for timeline payloads, 90-day audit retention for Owner-control
    audit rows); nothing here chooses its own. A deletion is dated only by a
    trusted main-host clock (`RetentionClockUntrusted` otherwise).
    """

    cleanup_batch_size = RETENTION_BATCH

    def __init__(self, timeline: "SceneTimeline", operation: str):
        self._timeline, self._operation = timeline, operation

    def cleanup_expired_batch(self) -> int:
        timeline = self._timeline
        # Only a trusted, aware main-host time may date a deletion (Codex PR
        # #296); a raising, malformed or untrusted clock deletes nothing.
        try:
            now, trusted = timeline.configuration.clock()
            aware = now.utcoffset() is not None
        except Exception:
            raise RetentionClockUntrusted() from None
        if trusted is not True or not aware:
            raise RetentionClockUntrusted()
        # Expiry is a write like any other: the database is pinned under the
        # storage admission first, never created or opened unpinned.
        timeline._pin()
        expire = getattr(timeline.presence, self._operation)
        return expire(now=now, limit=self.cleanup_batch_size)


@dataclass(frozen=True)
class SceneTimelineConfiguration:
    """Explicit deployment timing for the scene timeline. No value is defaulted
    that changes how evidence is dated or trusted.

    `maximum_source_latency` is the bound past which a critical observation's
    source timing is recorded as untrusted (confirmation is never withdrawn).
    `clock` is the main-host receipt clock port: it returns an aware time and
    whether the deployment trusts it (for example, NTP synchronized).
    The dispatch values bound how soon confirmed critical work is submitted,
    the exponential backoff after a failed dispatch step, and the bounded
    wait at shutdown for submitted notifications (0 waits for none).
    """

    maximum_source_latency: timedelta
    clock: MainClock
    outbox_capacity: int = DEFAULT_OUTBOX_CAPACITY
    flush_interval_seconds: float = DEFAULT_FLUSH_INTERVAL_SECONDS
    open_retry_seconds: float = DEFAULT_OPEN_RETRY_SECONDS
    dispatch_interval_seconds: float = DEFAULT_DISPATCH_INTERVAL_SECONDS
    dispatch_backoff_seconds: float = DEFAULT_DISPATCH_BACKOFF_SECONDS
    dispatch_settle_seconds: float = DEFAULT_DISPATCH_SETTLE_SECONDS

    def __post_init__(self):
        if (not isinstance(self.maximum_source_latency, timedelta)
                or self.maximum_source_latency <= timedelta(0)):
            raise ValueError("explicit positive source latency bound required")
        if not callable(self.clock):
            raise ValueError("explicit main clock required")
        if type(self.outbox_capacity) is not int or not 1 <= self.outbox_capacity <= 10_000:
            raise ValueError("bounded timeline staging required")
        for value in (self.flush_interval_seconds, self.open_retry_seconds,
                      self.dispatch_interval_seconds, self.dispatch_backoff_seconds):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0.01 <= value <= 3600:
                raise ValueError("invalid timeline interval")
        if self.dispatch_backoff_seconds < self.dispatch_interval_seconds:
            raise ValueError("invalid timeline interval")
        settle = self.dispatch_settle_seconds
        if type(settle) not in (int, float) or not math.isfinite(settle) or not 0 <= settle <= MAXIMUM_DISPATCH_SETTLE_SECONDS:
            raise ValueError("invalid timeline interval")


class TimelineFinish(StrEnum):
    # The outbox never opened: nothing was handed to it and nothing is closed.
    NOT_OPENED = "not_opened"
    # Closed cleanly: the session row is gone and staged facts were counted.
    CLOSED = "closed"
    # Left open on purpose (unclean scene stop or unrecorded counts): the
    # session row stays and the next start records an interrupted gap.
    LEFT_OPEN = "left_open"
    # `close()` raised: the outbox keeps or settles its session itself, and
    # a session row that is still in place is recorded as interrupted.
    CLOSE_FAILED = "close_failed"


class SceneTimeline:
    """Presence timeline composition and outbox lifecycle for scene evidence."""

    def __init__(self, configuration: SceneTimelineConfiguration, database: Database,
                 reservation: Callable[[], ContextManager], *,
                 detection: Callable[[], bool] | None = None,
                 notifications: Callable | None = None):
        if not isinstance(configuration, SceneTimelineConfiguration):
            raise TypeError("scene timeline configuration is required")
        if not isinstance(database, Database):
            raise TypeError("application database is required")
        if not callable(reservation):
            raise TypeError("storage admission is required")
        if detection is not None and not callable(detection):
            raise TypeError("invalid detection health probe")
        if notifications is not None and not callable(notifications):
            raise TypeError("invalid notification port")
        self.configuration = configuration
        self._reservation = reservation
        self._pinned = PinnedDatabase(database)
        # The notification port is the #21 `NotificationService` adapter the
        # Main composition passes when a monitoring runtime owns that service;
        # without it the path stays reported unavailable, never armed. No
        # evidence-preservation port exists yet (a separate recording
        # decision), so `critical_evidence` stays unavailable and its rows are
        # recorded `unavailable` by the dispatcher rather than left pending.
        # Issue #318: a confirmed critical whose record, or whose claim, storage
        # refuses (hard stop) still attempts Slack through the same
        # notification service; the dispatcher drains these on the monitoring
        # worker.
        self.unrecorded = (UnrecordedCriticalAlerts(notifications)
                           if isinstance(notifications, NotificationAdapter) else None)
        self.presence = PresenceService(
            self._pinned, reservation=reservation, detection=detection,
            notifications=notifications,
            unrecorded_alerts=self.unrecorded.counts if self.unrecorded is not None else None)
        self._reconciled = False
        self.outbox = TimelineOutbox(self.presence, clock=configuration.clock,
                                     capacity=configuration.outbox_capacity)
        self.recorder = CriticalTimelineRecorder(
            self.outbox, maximum_source_latency=configuration.maximum_source_latency,
            refused=self.unrecorded.refused if self.unrecorded is not None else None,
            recorded=self.unrecorded.recorded if self.unrecorded is not None else None)
        self._lock = threading.Lock()
        self._pin_lock = threading.Lock()
        self._opened = False
        self._finished = False
        self._open_failures = 0

    @property
    def undelivered(self) -> Callable[[int], None]:
        """The scene runtime's `undelivered` sink (Issue #205 condition 1)."""
        return self.recorder.record_undelivered

    def _pin(self) -> None:
        # Pinned once, under the same admission every write takes; a missing
        # database file is refused, never created here. `_pin_lock` is held
        # while the admission waits for the monitoring worker, so this must
        # never run on that worker (see `dispatch()`).
        with self._pin_lock:
            if not self._pinned.pinned:
                self._pinned.pin(self._reservation)

    @property
    def retention_stores(self) -> tuple:
        """Presence timeline and audit expiry for the scheduled retention cleanup."""
        return (_PresenceRetention(self, "expire_history"),
                _PresenceRetention(self, "expire_audit"))

    @property
    def opened(self) -> bool:
        with self._lock:
            return self._opened

    def open(self) -> bool:
        """Pin the database under admission and open the durable outbox session.

        Returns whether the outbox is open. A failure (storage refused, no
        database yet, a clock fault, another live session) is logged
        value-free and retried by the caller; the scene runtime must not
        start until this returned True.
        """
        with self._lock:
            if self._finished:
                return False
            if self._opened:
                return True
        try:
            self._pin()
            self.outbox.open()
        except Exception:
            with self._lock:
                self._open_failures += 1
                failures = self._open_failures
            if failures & (failures - 1) == 0:
                # The first failure of a streak and every doubling, so a
                # retried open that keeps failing stays visible without
                # flooding the log.
                logging.getLogger(__name__).error(Event.TIMELINE_OUTBOX_OPEN_FAILED)
            return False
        with self._lock:
            self._opened = True
            self._open_failures = 0
        logging.getLogger(__name__).info(Event.TIMELINE_OUTBOX_OPENED)
        return True

    def flush(self) -> OutboxState | None:
        """Write counted loss (and any staged fact) through the open session.

        A storage, database or clock failure keeps the counts in memory for
        the next flush; the outbox itself reports and logs the streak.
        """
        if not self.opened:
            return None
        try:
            return self.outbox.flush()
        except Exception:
            # Only a closed outbox raises here; nothing is lost by skipping.
            return None

    def state(self) -> OutboxState:
        return self.outbox.state()

    def dispatch(self, reconcile: Callable[[tuple[UUID, ...]], dict] | None = None) -> int:
        """One critical dispatch step; run it on the notification port's owning thread.

        Returns how many delivery rows the step resolved (`DISPATCH_BATCH`
        means more may wait). It never pins the database itself: it runs on
        the monitoring worker, while `open()` and the retention cleanup pin on
        other threads by holding `_pin_lock` and waiting in the storage
        admission for that same worker, so blocking on `_pin_lock` here would
        deadlock the worker. Until one of them pinned it, `TimelineNotPinned`
        is raised (the dispatcher backs off) and nothing is claimed.

        Before the first step of this process, `notification` claims that an
        earlier process left `submitting`/`queued` are reconciled against the
        notification service's durable event rows: ``reconcile(ids)`` returns
        the stored #21 delivery result per event ID. A final `sent`, `failed`
        or `disabled` row completes that claim (scoped to its generation); a
        row still `pending`, or none at all, proves nothing about the external
        POST, so the claim stays unresolved for an audited Owner requeue and is
        never resent automatically. Raising leaves reconciliation for the
        next step.

        A failing step (for example storage refused) escalates every
        confirmed critical the recorder wrote but no step has claimed yet to
        `UnrecordedCriticalAlerts` (Issue #318); a successful one stops
        watching those whose notification row is no longer `pending` or
        `unavailable`.
        """
        # `PinnedDatabase.pinned` takes only its own short lock, never
        # `_pin_lock`; an unpinned database also refuses every connection.
        if not self._pinned.pinned:
            raise TimelineNotPinned()
        try:
            progressed = self._dispatch(reconcile)
        except Exception:
            # Issue #318: a confirmed critical recorded just before storage
            # was refused cannot be claimed now; attempt its Slack alert.
            if self.unrecorded is not None:
                self.unrecorded.escalate()
            raise
        if self.unrecorded is not None:
            checked = self.unrecorded.awaiting()
            if checked:
                try:
                    keep = self.presence.awaiting_notification(checked)
                except Exception:
                    self.unrecorded.escalate()
                else:
                    self.unrecorded.prune(checked, keep)
        return progressed

    def _dispatch(self, reconcile) -> int:
        if not self._reconciled:
            if reconcile is not None and self.presence.notifications is not None:
                claims = self.presence.unconfirmed_actions("notification")
                outcomes = reconcile(tuple(identifier for identifier, _ in claims)) if claims else {}
                for identifier, generation in claims:
                    result = notification_result(outcomes.get(identifier))
                    if result in (ActionResult.DELIVERED, ActionResult.FAILED,
                                  ActionResult.DISABLED):
                        self.presence.complete_action(identifier, "notification", result,
                                                      generation=generation)
            self._reconciled = True
        return self.presence.dispatch_pending(limit=DISPATCH_BATCH)

    def finish(self, scene_status) -> TimelineFinish:
        """End the outbox after the scene runtime's `stop()` returned.

        ``scene_status`` is the `SceneRuntimeStatus` that `stop()` returned,
        or None when the stop raised (or no scene status exists). Only a
        `STOPPED` status whose undelivered count was recorded (or was zero)
        closes the outbox; anything else leaves the session row in place.
        """
        with self._lock:
            self._finished = True
            opened = self._opened
        if not opened:
            return TimelineFinish.NOT_OPENED
        # Condition 8: write the counts first, so they reach the gap marker
        # even when the session is left open below.
        self.flush()
        clean = (scene_status is not None
                 and getattr(scene_status, "state", None) is SceneRuntimeState.STOPPED
                 and getattr(scene_status, "undelivered_recorded", False) is not False)
        if not clean:
            # Never `close()`: the session row stays, so the next start
            # records an interrupted gap covering anything not delivered.
            logging.getLogger(__name__).error(Event.TIMELINE_OUTBOX_LEFT_OPEN)
            return TimelineFinish.LEFT_OPEN
        try:
            self.outbox.close()
        except Exception:
            logging.getLogger(__name__).error(Event.TIMELINE_OUTBOX_CLOSE_FAILED)
            return TimelineFinish.CLOSE_FAILED
        return TimelineFinish.CLOSED


class CriticalDispatcher:
    """Drives `SceneTimeline.dispatch()` from the Main lifespan (Issue #26).

    ``run_step(function)`` executes ``function`` on the thread that owns the
    notification port (the monitoring worker) and returns its result; the
    loop itself never touches SQLite or the notification service.

    A step that raises (storage refused, the database not openable yet, a
    busy database) is retried after an exponential backoff from the
    dispatch interval up to `dispatch_backoff_seconds`; the failure is
    logged value-free at the first failure of a streak and at every doubling,
    and the recovery once. Nothing is dropped meanwhile: unclaimed rows stay
    `pending` in the database and are submitted by a later step or the next
    process. A full batch is followed by the next step at once.

    Retries never duplicate a notification: a claimed row is never reclaimed
    by `dispatch_pending`, the notification service coalesces a resubmitted
    event ID, the event ID is the observation identity, and only an action the
    port refused to accept (`unavailable`, nothing submitted) is retried.
    """

    def __init__(self, timeline: SceneTimeline,
                 run_step: Callable[[Callable[[], int]], Awaitable[int]],
                 step: Callable[[], int], *, alerts: Callable[[], int] | None = None):
        if not isinstance(timeline, SceneTimeline):
            raise TypeError("scene timeline is required")
        if not callable(run_step) or not callable(step):
            raise TypeError("dispatch step is required")
        if alerts is not None and not callable(alerts):
            raise TypeError("invalid unrecorded alert step")
        self.configuration = timeline.configuration
        self._run_step, self._step = run_step, step
        self._alerts = alerts
        self._failures = 0
        self._alert_failures = 0

    async def alert_once(self) -> None:
        """Attempt the alerts of refused critical records (Issue #318).

        Runs ``alerts`` (`UnrecordedCriticalAlerts.drain`) through the same
        ``run_step`` on the monitoring worker, independently of the dispatch
        step and its backoff: while storage is refused every dispatch step
        fails, and these alerts exist for exactly that time. A failure is
        logged value-free (first of a streak and every doubling) and retried
        at the next interval.
        """
        if self._alerts is None:
            return
        try:
            await run_to_completion(self._run_step(self._alerts))
        except Exception:
            self._alert_failures += 1
            failures = self._alert_failures
            if failures & (failures - 1) == 0:
                logging.getLogger(__name__).error(Event.UNRECORDED_CRITICAL_ALERTS_FAILING)
            return
        self._alert_failures = 0

    @property
    def failing(self) -> bool:
        """Whether the latest step failed; the backlog then waits for a retry."""
        return self._failures > 0

    async def once(self) -> float:
        """Run one step; returns the delay before the next one.

        Cancelling the caller never abandons a step in flight: it finishes
        on its worker first (`run_to_completion`), so shutdown never races a
        claim or a submission it cannot see.
        """
        configuration = self.configuration
        try:
            selected = await run_to_completion(self._run_step(self._step))
        except Exception:
            self._failures += 1
            failures = self._failures
            if failures & (failures - 1) == 0:
                logging.getLogger(__name__).error(Event.CRITICAL_DISPATCH_FAILING)
            return min(configuration.dispatch_backoff_seconds,
                       configuration.dispatch_interval_seconds * 2 ** min(failures, 30))
        if self._failures:
            self._failures = 0
            logging.getLogger(__name__).info(Event.CRITICAL_DISPATCH_RECOVERED)
        if type(selected) is int and selected >= DISPATCH_BATCH:
            return 0.0
        return configuration.dispatch_interval_seconds

    async def run(self) -> None:
        """Dispatch forever; cancel to stop (an in-flight step completes first).

        The unrecorded alerts are attempted at every dispatch interval even
        while the dispatch step itself is backing off.
        """
        interval = self.configuration.dispatch_interval_seconds
        delay = interval
        while True:
            wait = min(delay, interval) if self._alerts is not None else delay
            await asyncio.sleep(wait)
            delay -= wait
            await self.alert_once()
            if delay <= 0:
                delay = await self.once()
