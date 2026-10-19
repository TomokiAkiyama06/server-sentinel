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

Nothing here registers a route, reads pixels, names a person or infers cause.
Timing policy stays explicit: there is no default source latency bound or
clock trust (see `adapters.py`).
"""

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
import logging
import math
import threading
from typing import Callable, ContextManager

from app.detection.roi.runtime import SceneRuntimeState
from app.logging import Event
from app.storage.database import Database, PinnedDatabase

from .adapters import CriticalTimelineRecorder, MainClock, OutboxState, TimelineOutbox
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


@dataclass(frozen=True)
class SceneTimelineConfiguration:
    """Explicit deployment timing for the scene timeline. No value is defaulted
    that changes how evidence is dated or trusted.

    `maximum_source_latency` is the bound past which a critical observation's
    source timing is recorded as untrusted (confirmation is never withdrawn).
    `clock` is the main-host receipt clock port: it returns an aware time and
    whether the deployment trusts it (for example, NTP synchronized).
    """

    maximum_source_latency: timedelta
    clock: MainClock
    outbox_capacity: int = DEFAULT_OUTBOX_CAPACITY
    flush_interval_seconds: float = DEFAULT_FLUSH_INTERVAL_SECONDS
    open_retry_seconds: float = DEFAULT_OPEN_RETRY_SECONDS

    def __post_init__(self):
        if (not isinstance(self.maximum_source_latency, timedelta)
                or self.maximum_source_latency <= timedelta(0)):
            raise ValueError("explicit positive source latency bound required")
        if not callable(self.clock):
            raise ValueError("explicit main clock required")
        if type(self.outbox_capacity) is not int or not 1 <= self.outbox_capacity <= 10_000:
            raise ValueError("bounded timeline staging required")
        for value in (self.flush_interval_seconds, self.open_retry_seconds):
            if type(value) not in (int, float) or not math.isfinite(value) or not 0.01 <= value <= 3600:
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
                 detection: Callable[[], bool] | None = None):
        if not isinstance(configuration, SceneTimelineConfiguration):
            raise TypeError("scene timeline configuration is required")
        if not isinstance(database, Database):
            raise TypeError("application database is required")
        if not callable(reservation):
            raise TypeError("storage admission is required")
        if detection is not None and not callable(detection):
            raise TypeError("invalid detection health probe")
        self.configuration = configuration
        self._reservation = reservation
        self._pinned = PinnedDatabase(database)
        # No evidence or notification port is configured here yet (#21): the
        # Owner status reports those critical paths as unavailable, never
        # armed, and the queued delivery rows stay visibly pending.
        self.presence = PresenceService(self._pinned, reservation=reservation,
                                        detection=detection)
        self.outbox = TimelineOutbox(self.presence, clock=configuration.clock,
                                     capacity=configuration.outbox_capacity)
        self.recorder = CriticalTimelineRecorder(
            self.outbox, maximum_source_latency=configuration.maximum_source_latency)
        self._lock = threading.Lock()
        self._opened = False
        self._finished = False
        self._open_failures = 0

    @property
    def undelivered(self) -> Callable[[int], None]:
        """The scene runtime's `undelivered` sink (Issue #205 condition 1)."""
        return self.recorder.record_undelivered

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
            if not self._pinned.pinned:
                # Pinned once, under the same admission every write takes; a
                # missing database file is refused, never created here.
                self._pinned.pin(self._reservation)
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
