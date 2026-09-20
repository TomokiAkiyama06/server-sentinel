"""Explicit startup/24-hour coordinator; call from the owning worker loop."""

from datetime import datetime, timezone
import math
import time

from .model import Inventory, Kind, compare
from .store import IntegrityStore


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
        try:
            current = self.probe.collect()
            if not isinstance(current, Inventory):
                raise ValueError("INVALID_INVENTORY")
        except Exception:
            current = Inventory((), frozenset(Kind))
        _, baseline = self.store.baseline()
        findings = compare(baseline, current)
        self.store.record(findings, self.utcnow())
        self._last_check = started
        self.store.deliver(self.sink)
        return findings
