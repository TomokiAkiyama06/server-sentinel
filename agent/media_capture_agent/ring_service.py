"""The Agent's ring in the running service: clock trust and the loss trigger (Issue #16 PR C1).

``ring.DiskRing`` keeps the segments and protected incidents. This module
connects it to the service loop:

* ``ClockTrust`` decides whether the Agent's own clock may time ring writes.
  It is trusted while the last clock exchange with the Main is within the
  configured limits (``health.assess_clock`` is ``online``). While the Main is
  unreachable there is no exchange, yet the T+10 minutes after a loss must be
  recorded with trusted times, so the clock stays trusted for a bounded
  holdover after the last good exchange (``clock_holdover_seconds``), as long
  as wall time keeps advancing with the monotonic clock (no step beyond
  ``clock_step_limit_seconds``). A step, a monotonic regression or the end of
  the holdover makes it untrusted until the next good exchange.
* ``RingMonitor.after_heartbeat`` runs after every heartbeat attempt. It tells
  the ring whether the authenticated session to the Main is up
  (``observe_connection``): a session that was up and is now down starts the
  10 min pre-loss + 10 min post-loss incident. Owner decision 2026-11-26: every
  such loss counts, including a Main Server that stops or restarts on purpose;
  only the Agent's own shutdown is excluded, and the Agent never reports a
  loss while it is stopping. It then runs ``tick`` (incident completion,
  60-day expiry, trimming) and returns the ring's state for the local status.
  A ring that the Owner has not configured yet cannot protect anything; its
  loss observations are skipped and it reports ``not_configured``.
* ``ring_profiles`` turns the deployment's ``ring`` section into the ring's
  ``SegmentProfile`` per source; ``RingMonitor`` reports
  ``ring_reconfiguration_required`` while the ledger's committed profiles
  differ from them (the Owner reconfigures with the local ring command).

The ring keeps its "connected" flag in memory, so a loss that happens while
the Agent itself is restarting is not detected as a loss (documented in
``agent/docs/RING_BUFFER.md``). Ring state goes to the local status line only:
the Main's heartbeat schema is strict, so a ring summary in the heartbeat
waits for the Main side (PR E).
"""
from __future__ import annotations

import threading

from .ring_models import SECOND, RingRefused, SegmentProfile


def ring_profiles(settings):
    """The ``SegmentProfile`` of every configured source, in configuration order."""
    ring = settings.ring
    if ring is None:
        return ()
    return tuple(SegmentProfile(source.source_id, source.maximum_bitrate,
                                source.expected_bitrate, ring.segment_seconds * SECOND,
                                ring.overhead_bytes)
                 for source in ring.sources)


class ClockTrust:
    def __init__(self, *, holdover_seconds, step_limit_seconds):
        if not holdover_seconds > 0 or not step_limit_seconds > 0:
            raise ValueError("clock holdover and step limit must be positive")
        self.holdover_seconds = holdover_seconds
        self.step_limit_seconds = step_limit_seconds
        self._lock = threading.Lock()
        self._good = None  # (utc, monotonic) of the last online assessment

    def observe(self, online, utc, monotonic):
        """Return whether the clock may time ring writes at (``utc``, ``monotonic``).

        ``online`` is the heartbeat's clock assessment; a recorder thread,
        which has none, passes ``False`` and is trusted within the holdover
        of the last good exchange.
        """
        with self._lock:
            return self._observe(online, utc, monotonic)

    def _observe(self, online, utc, monotonic):
        if online:
            self._good = (utc, monotonic)
            return True
        if self._good is None:
            return False
        good_utc, good_monotonic = self._good
        elapsed = monotonic - good_monotonic
        if elapsed < 0 or elapsed > self.holdover_seconds:
            self._good = None
            return False
        if abs((utc - good_utc) - elapsed) > self.step_limit_seconds:
            # The wall clock was stepped since the last good exchange.
            self._good = None
            return False
        return True


class RingMonitor:
    def __init__(self, ring, settings):
        self.ring = ring
        self.profiles = {profile.source_id: profile for profile in ring_profiles(settings)}
        self.clock = ClockTrust(holdover_seconds=settings.ring.clock_holdover_seconds,
                                step_limit_seconds=settings.clock_step_limit_seconds)
        self.last_status = {"state": "degraded", "reason": "not_configured"}

    @property
    def reconfiguration_required(self):
        return self.ring.config is not None and self.ring.profiles != self.profiles

    def clock_trusted(self, online, utc, monotonic):
        return self.clock.observe(online, utc, monotonic)

    def after_heartbeat(self, *, clock_online, authenticated, connected, utc, monotonic):
        """Report the session state to the ring and advance it; never raises a ring refusal."""
        now_us = int(utc * SECOND)
        trusted = self.clock.observe(clock_online, utc, monotonic)
        try:
            if self.ring.config is not None:
                self.ring.observe_connection(authenticated=authenticated, connected=connected,
                                             unexpected=True, now_us=now_us,
                                             clock_trusted=trusted)
            status = self.ring.tick(now_us=now_us, clock_trusted=trusted)
        except RingRefused as exc:
            status = {"state": "degraded", "reason": str(exc)}
        summary = {"state": status.get("state", "degraded"),
                   "reason": status.get("reason", "ring_status_unavailable")}
        if summary["reason"] != "not_configured" and self.reconfiguration_required:
            summary = {"state": "degraded", "reason": "ring_reconfiguration_required"}
        summary["clock_trusted"] = trusted
        self.last_status = summary
        return summary
