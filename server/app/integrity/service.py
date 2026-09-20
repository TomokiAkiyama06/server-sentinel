"""Explicit startup/24-hour coordinator; call from the owning worker loop."""

from datetime import datetime, timezone
import math
import time

from .model import Inventory, Kind, compare
from .store import IntegrityOutboxFull, IntegrityStore


class IntegrityService:
    def __init__(self, store: IntegrityStore, probe, sink, *,
                 monotonic=time.monotonic, utcnow=lambda: datetime.now(timezone.utc)):
        self.store = store
        self.probe = probe
        self.sink = sink
        self.monotonic = monotonic
        self.utcnow = utcnow
        self._last_check = None

    def startup(self):
        """Always compare on startup, regardless of the previous boot's clock."""
        return self._check()

    def tick(self):
        now = self.monotonic()
        if not math.isfinite(now):
            raise ValueError("INVALID_MONOTONIC_CLOCK")
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
        except Exception:
            current = Inventory((), frozenset(Kind))
        _, baseline = self.store.baseline()
        findings = compare(baseline, current)
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
