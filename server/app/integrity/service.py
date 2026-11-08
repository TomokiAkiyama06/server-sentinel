"""Explicit startup/24-hour coordinator; call from the owning worker loop."""

from datetime import datetime, timezone
import logging
import math
import time

from app.logging import Event
from app.stop_budget import INTERRUPTED, UNIT_STOP_TIMEOUT_SECONDS, StopInterrupted, never

from .model import Finding, Inventory, Kind, State, compare
from .store import IntegrityOutboxFull, IntegrityStore

# Issue #385 (second PR #389 review): a check in which a probe command ended
# on SIGTERM before the stop began is held this long before it is recorded.
# systemd's stop signals the whole control group before `begin_stop()` runs
# (after the HTTP graceful wait, or after a startup still running), and it
# kills the service once TimeoutStopSec passes, so a service still running
# without a stop that long after was not being stopped: the SIGTERM came from
# something else (an operator's `pkill`, a watchdog) and the check is recorded
# with that probe unavailable, never dropped. The worker is never blocked.
SIGTERM_HOLD_SECONDS = float(UNIT_STOP_TIMEOUT_SECONDS)


class IntegrityService:
    def __init__(self, store: IntegrityStore, probe, sink, *,
                 monotonic=time.monotonic, utcnow=lambda: datetime.now(timezone.utc)):
        self.store = store
        self.probe = probe
        self.sink = sink
        self.monotonic = monotonic
        self.utcnow = utcnow
        self._last_check = None
        # (started, inventory, held at) of a check held after a SIGTERM.
        self._held = None
        # Issue #396: when the Main stop began (`stop_began`), on this
        # service's clock.
        self._stop_at = None

    def startup(self):
        """Always compare on startup, regardless of the previous boot's clock."""
        self._held = None
        return self._check()

    def tick(self):
        now = self.monotonic()
        if not math.isfinite(now):
            raise ValueError("INVALID_MONOTONIC_CLOCK")
        if self._held is not None:
            return self._release_held(now)
        if self._last_check is None or now < self._last_check or now - self._last_check >= 86400:
            return self._check()
        self.store.deliver(self.sink)
        return None

    def _check(self):
        started = self.monotonic()
        if not math.isfinite(started):
            raise ValueError("INVALID_MONOTONIC_CLOCK")
        # Drain pending accepted events before admitting another observation;
        # a previously full outbox must not prevent its own recovery.
        self.store.deliver(self.sink)
        try:
            current = self.probe.collect()
            if not isinstance(current, Inventory):
                raise ValueError("INVALID_INVENTORY")
        except StopInterrupted:
            # Issue #385: the Main shutdown interrupted the probes. The check
            # did not complete: nothing is compared or recorded, so a partial
            # inventory never becomes a hardware change, an unverifiable
            # warning or an Owner notice, and the baseline is untouched. The
            # last completed check stays current; the next start runs the
            # startup check (INTEGRITY-002). `INTERRUPTED` tells the runtime
            # the check proved nothing (PR #389 review).
            logging.getLogger(__name__).warning(Event.MONITORING_CHECK_INTERRUPTED)
            return INTERRUPTED
        except Exception:
            current = Inventory((), frozenset(Kind))
        if getattr(self.probe, "terminated", False):
            # Issue #385: possibly the stop's SIGTERM; decided at a later tick
            # (`_release_held`). The step's flag and retry stay as they were.
            self._held = (started, current, self.monotonic())
            return INTERRUPTED
        return self._record(started, current)

    def stop_began(self) -> None:
        """Issue #396: note when the Main stop began (any thread).

        `abandon_held` decides by this time, not by when the stop reaches
        the close, which can be tens of seconds later.
        """
        if self._stop_at is None:
            self._stop_at = self.monotonic()

    def abandon_held(self):
        """Issue #396: the Main stop decides a check still held after a SIGTERM.

        After `begin_stop()` the tick loop no longer runs this step, so the
        stop decides it here, as `_release_held` would: when the stop began
        within `SIGTERM_HOLD_SECONDS` of the hold the SIGTERM was the stop's
        own, so nothing is recorded and the drop is logged; otherwise (an
        unrelated SIGTERM whose hold had run out, or a backwards clock) the
        check is recorded with the probe unavailable, never dropped (PR #400
        review). Returns the findings recorded, `INTERRUPTED` when it was
        dropped, or None when no check was held.
        """
        if self._held is None:
            return None
        started, current, held_at = self._held
        self._held = None
        stopped = self._stop_at if self._stop_at is not None else self.monotonic()
        if math.isfinite(stopped) and held_at <= stopped < held_at + SIGTERM_HOLD_SECONDS:
            logging.getLogger(__name__).warning(Event.MONITORING_CHECK_INTERRUPTED)
            return INTERRUPTED
        return self._record(started, current)

    def _release_held(self, now: float):
        started, current, held_at = self._held
        # Reached when a tick passed its stop check just before the stop
        # began; otherwise the stop drops the held check (`abandon_held`).
        if getattr(self.probe, "interrupted", never)():
            self._held = None
            logging.getLogger(__name__).warning(Event.MONITORING_CHECK_INTERRUPTED)
            return INTERRUPTED
        if held_at <= now < held_at + SIGTERM_HOLD_SECONDS:
            self.store.deliver(self.sink)
            return INTERRUPTED
        # No stop followed (a backwards clock never holds it longer).
        self._held = None
        return self._record(started, current)

    def _record(self, started: float, current: Inventory):
        try:
            _, baseline = self.store.baseline()
            findings = compare(baseline, current)
        except Exception:
            # Loading or comparing the baseline must never end the check in
            # silence; report the categories as unknown so the Owner still
            # sees a warning (SPECIFICATION 10.2/10.4, INTEGRITY-002/006).
            findings = tuple(Finding(kind, State.UNVERIFIABLE, "COMPARISON_UNAVAILABLE") for kind in Kind)
        try:
            self.store.record(findings, self.utcnow())
        except IntegrityOutboxFull:
            # record committed the warning to durable bounded overflow. Keep
            # its failed-delivery status visible and retry delivery each tick,
            # without rerunning expensive hardware probes on every worker tick.
            pass
        self._last_check = started
        self.store.deliver(self.sink)
        return findings
