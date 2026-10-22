"""Owner notification when a camera source stays offline (Issue #301 item 2).

Owner decision (2026-10-22): a camera source that stays offline for five
minutes notifies the Owner. The time is a deployment setting
(``monitoring.camera_offline_notification.after_seconds``) and a per-hour cap
(``hourly_limit``) keeps a flapping camera from flooding the channel.

``CameraOfflineMonitor`` follows the ``AccessFaultMonitor`` model: the
capture side only latches state under a short lock and never blocks, raises
or touches SQLite or the network; ``drain`` runs on the monitoring worker
(the ``NotificationService`` owner thread) on every monitoring tick and
submits through the same durable ``notification_events`` row and optional
Slack delivery as a hardware-integrity or recording-health failure.

Signals: ``health_sink`` takes the local UVC runtime's ``HealthEvent`` (it is
installed as that runtime's optional health sink, whose delivery thread calls
it); ``observe_runtime`` takes the runtime status the application watcher
already polls, so a worker that is no longer running is not kept ``online``.
``observe`` is the source-type-neutral entry point: a later ``remote_agent``
runtime on Main reports its sources' camera health through it. Only the
deployment-configured source IDs are tracked.

Episodes: a source is "not online" while its camera health is ``offline``,
``degraded`` or ``manual_intervention_required`` (a camera that keeps failing
negotiation flaps between ``offline`` and ``degraded``, and neither delivers
monitored video). Only ``online`` ends an episode. A source the Owner
disabled (``disabled``) or one whose capture service is stopping
(``capture_service_stopping``) is inactive: it ends an episode and starts
none. Every configured source starts not online when the monitor is built, so
a camera that never comes up after a start (missing at boot, capture never
started) is notified too. An episode notifies once, after it lasted
``after_seconds``; an episode that reached the threshold but recovered before
the next drain is still notified once. A recovery is recorded in the episode
(``recovered``) and is not notified (no Owner decision for a recovery
notice).

Event IDs: an episode still in progress is named after the source and its
registry ``last_seen_at`` (the last frame time, which stops changing while no
frame arrives), supplied by the runtime (``durable_id``). A restarted process
that finds the same camera still offline therefore computes the same ID, finds
the row (``known``) and does not notify the same outage again. Without
storage, or for an episode that already recovered, the ID is per process
(never a missed notification, at worst one repeat after a restart).

Cap: at most ``hourly_limit`` notifications per rolling hour for all sources
together, continued across a restart from the accepted rows of the last hour
(``restore_window``). An episode held back by the cap is logged once
(value-free) and notified as soon as the hour allows if the source is still
not online; one that recovered meanwhile is dropped and logged.

Value-free: the notification is the fixed category ``camera_offline`` with no
source name, role, UUID, device path, serial, reason or image (SPECIFICATION
§9 Slack payload); the Owner sees which source is offline in the Web UI.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
import logging
import math
import threading
from typing import Callable, Iterable
from uuid import UUID, uuid4, uuid5

from app.logging import Event
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult

from .config import (
    CAMERA_OFFLINE_HOURLY_LIMIT, CAMERA_OFFLINE_HOURLY_LIMIT_BOUNDS, CAMERA_OFFLINE_SECONDS,
    CAMERA_OFFLINE_SECONDS_BOUNDS,
)


CAMERA_EVENT_NAMESPACE = UUID("6f2b8c41-93d7-5e0a-b4c6-1d8e2a7f9c53")
HOUR_SECONDS = 3600.0
DEFAULT_OFFLINE_SECONDS = CAMERA_OFFLINE_SECONDS
DEFAULT_HOURLY_LIMIT = CAMERA_OFFLINE_HOURLY_LIMIT
# The monitoring tick (60 s by default) drains the monitor, so a shorter
# threshold would not be honoured; a day is the longest useful delay.
OFFLINE_SECONDS_BOUNDS = CAMERA_OFFLINE_SECONDS_BOUNDS
HOURLY_LIMIT_BOUNDS = CAMERA_OFFLINE_HOURLY_LIMIT_BOUNDS
# Camera-health reasons that mean "not expected to capture": no episode.
INACTIVE_REASONS = frozenset({"disabled", "capture_service_stopping"})
_ONLINE = "online"
_NOT_ONLINE = frozenset({"offline", "degraded", "manual_intervention_required"})
MAX_SOURCES = 64


def valid_offline_seconds(value) -> bool:
    low, high = OFFLINE_SECONDS_BOUNDS
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def valid_hourly_limit(value) -> bool:
    low, high = HOURLY_LIMIT_BOUNDS
    return type(value) is int and low <= value <= high


@dataclass
class _Episode:
    since: float
    recovered: float | None = None
    notified: bool = False
    # Logged once when the cap first held it back.
    held: bool = False
    # (at, event ID) of a submission the service could not take yet; the
    # retry reuses both, so it upserts one row.
    attempt: tuple[datetime, UUID] | None = None

    def qualifies(self, now: float, after: float) -> bool:
        end = self.recovered if self.recovered is not None else now
        return not math.isfinite(end) or end - self.since >= after


@dataclass
class _Source:
    active: bool
    online: bool
    # The episode in progress (``recovered is None``) or one that reached the
    # threshold and recovered before it was notified.
    episode: _Episode | None
    # Bumped on every signal, so a runtime status read before a newer event
    # cannot overwrite it (``observe_runtime``).
    version: int = 0


@dataclass(frozen=True)
class CameraOfflineStatus:
    """Bounded, value-free result of one ``drain``."""

    # Sources whose episode in progress has lasted the threshold.
    offline_sources: int
    # Episodes past the threshold that the hourly cap is holding back.
    held: int


class CameraOfflineMonitor:
    """Per-source offline episodes feeding the monitoring runtime."""

    def __init__(self, source_ids: Iterable[UUID], *,
                 after_seconds: float = DEFAULT_OFFLINE_SECONDS,
                 hourly_limit: int = DEFAULT_HOURLY_LIMIT,
                 monotonic: Callable[[], float]):
        ids = tuple(source_ids)
        if (not 1 <= len(ids) <= MAX_SOURCES or len(set(ids)) != len(ids)
                or any(not isinstance(value, UUID) for value in ids)
                or not valid_offline_seconds(after_seconds)
                or not valid_hourly_limit(hourly_limit) or not callable(monotonic)):
            raise ValueError("invalid camera offline monitor setting")
        self.after = float(after_seconds)
        self.hourly_limit = hourly_limit
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._nonce = uuid4()
        self._sequence = 0
        self._stopped = False
        start = monotonic()
        self._sources = {identity: _Source(True, False, _Episode(start)) for identity in ids}
        # (monotonic time, event ID) of the notifications in the rolling hour.
        self._sent: deque[tuple[float, UUID]] = deque()
        # Durable IDs this process already notified: an episode whose
        # ``last_seen_at`` did not move (a refused frame-time write) gets a
        # per-process ID instead of being taken for the earlier one.
        self._used: set[UUID] = set()
        self.recovered = 0
        self.dropped = 0

    @property
    def source_ids(self) -> tuple[UUID, ...]:
        return tuple(self._sources)

    # -- signals (any thread; never block or raise on valid input) ----------

    def observe(self, source_id: UUID, state: str, reason: str = "") -> None:
        """Apply one camera-health signal for ``source_id``.

        ``state`` is the camera health value (``online`` / ``offline`` /
        ``degraded`` / ``manual_intervention_required``); ``reason`` only
        decides whether the source is inactive and is not kept.
        """
        state = getattr(state, "value", state)
        if not isinstance(state, str) or (state != _ONLINE and state not in _NOT_ONLINE):
            return
        now = self._monotonic()
        with self._lock:
            source = self._sources.get(source_id)
            if source is None:
                return
            source.version += 1
            self._apply(source, state == _ONLINE, reason not in INACTIVE_REASONS, now)

    def _apply(self, source: _Source, online: bool, active: bool, now: float) -> None:
        # Called with the lock held.
        episode = source.episode
        ongoing = episode is not None and episode.recovered is None
        if online or not active:
            if ongoing:
                episode.recovered = now
                self.recovered += 1
                if episode.notified or not episode.qualifies(now, self.after):
                    # Notified, or shorter than the threshold: nothing left
                    # to report. The recovery is recorded (``recovered``).
                    source.episode = None
        elif not ongoing and not self._stopped:
            if episode is not None and not episode.notified:
                # A recovered, qualifying episode not yet drained is
                # superseded by the new one; its loss is counted and logged.
                self.dropped += 1
                logging.getLogger(__name__).warning(Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED)
            source.episode = _Episode(now)
        source.online, source.active = online, active

    def health_sink(self, event) -> None:
        """Local UVC ``health_sink``: one ``HealthEvent``; never raises."""
        try:
            self.observe(event.source_id, event.state, getattr(event, "reason", ""))
        except Exception:
            pass

    def version(self) -> dict[UUID, int]:
        """Per-source signal versions, read before a runtime status poll."""
        with self._lock:
            return {identity: source.version for identity, source in self._sources.items()}

    def observe_runtime(self, sources, versions: dict[UUID, int]) -> None:
        """Apply a polled ``LocalUvcRuntimeStatus.sources`` snapshot.

        A source whose worker is not running is not online. A running
        worker's latest in-memory camera state ``online`` ends an episode
        (for example after a worker restart that raised no new transition).
        A source that received an event after ``versions`` was read keeps
        that newer event; an inactive source stays inactive.
        """
        now = self._monotonic()
        with self._lock:
            for item in sources:
                source = self._sources.get(getattr(item, "source_id", None))
                if (source is None or not source.active
                        or source.version != versions.get(item.source_id)):
                    continue
                camera = getattr(getattr(item, "camera_state", None), "value", None)
                if not item.worker_running:
                    if source.online:
                        source.version += 1
                        self._apply(source, False, True, now)
                elif camera == _ONLINE and not source.online:
                    source.version += 1
                    self._apply(source, True, True, now)

    def stop(self) -> None:
        """Shutdown: no new episode and no further notification."""
        with self._lock:
            self._stopped = True

    # -- owner thread --------------------------------------------------------

    def restore_window(self, rows, *, monotonic: float) -> None:
        """Re-seed the rolling hour from accepted rows after a restart.

        ``rows`` are ``(event ID, age seconds)`` of the newest accepted
        ``camera_offline`` rows of the last hour, as for the access budgets
        (Issue #281 item 2). Rows of this process's own notifications are
        merged by event ID, never counted twice.
        """
        rows = tuple(rows)
        if (type(monotonic) not in (int, float) or len(rows) > self.hourly_limit or any(
                type(row) is not tuple or len(row) != 2 or not isinstance(row[0], UUID)
                or type(row[1]) not in (int, float) or not math.isfinite(row[1])
                for row in rows)):
            raise ValueError("invalid restored window")
        if not math.isfinite(monotonic):
            return
        own = {event_id for _time, event_id in self._sent}
        merged = sorted([*self._sent, *((monotonic - age, event_id) for event_id, age in rows
                                         if 0 <= age < HOUR_SECONDS and event_id not in own)],
                        key=lambda entry: entry[0])
        self._sent.clear()
        self._sent.extend(merged[-self.hourly_limit:])

    def _window_open(self, now: float) -> bool:
        if not math.isfinite(now):
            return True
        while self._sent and not (self._sent[0][0] <= now < self._sent[0][0] + HOUR_SECONDS):
            # Expired, or a backwards clock: never postpone indefinitely.
            self._sent.popleft()
        return len(self._sent) < self.hourly_limit

    def _local_id(self, source_id: UUID) -> UUID:
        self._sequence += 1
        return uuid5(CAMERA_EVENT_NAMESPACE,
                     f"camera-offline:{self._nonce}:{self._sequence}:{source_id}")

    def drain(self, notifications: NotificationService, *, at: datetime, monotonic: float,
              durable_id: Callable[[UUID], UUID | None] | None = None,
              known: Callable[[UUID], bool] | None = None) -> CameraOfflineStatus:
        """Notify every episode that reached the threshold, within the cap.

        ``durable_id(source_id)`` names an episode in progress after the
        source's durable last-frame time; ``known(event_id)`` tells whether
        that row already exists (an earlier process notified this outage).
        Either may be absent or fail; the episode then gets a per-process ID.
        """
        with self._lock:
            stopped = self._stopped
            due = sorted(((identity, source.episode) for identity, source in self._sources.items()
                          if source.episode is not None and not source.episode.notified
                          and source.episode.qualifies(monotonic, self.after)),
                         key=lambda item: item[1].since)
        for identity, episode in () if stopped else due:
            ongoing = episode.recovered is None
            if not self._window_open(monotonic):
                with self._lock:
                    if not ongoing:
                        # Recovered while held back: nothing left to report.
                        self._discard(identity, episode)
                        self.dropped += 1
                        logging.getLogger(__name__).warning(
                            Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED)
                    elif not episode.held:
                        episode.held = True
                        logging.getLogger(__name__).warning(
                            Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED)
                continue
            attempt = episode.attempt
            if attempt is None:
                event_id = self._durable(identity, durable_id) if ongoing else None
                if event_id is not None and self._known(event_id, known):
                    # An earlier process already notified this outage.
                    self._used.add(event_id)
                    with self._lock:
                        episode.notified = True
                        if episode.recovered is not None:
                            self._discard(identity, episode)
                    continue
                attempt = (at, event_id or self._local_id(identity))
            if not notifications.can_accept(attempt[1]):
                # Queue full or closed: retried on the next drain.
                episode.attempt = attempt
                continue
            result = notifications.record(NotificationKind.CAMERA_OFFLINE, at=attempt[0],
                                          confirmed=True, event_id=attempt[1])
            if result == DeliveryResult.FAILED and not notifications.retained(attempt[1]):
                episode.attempt = attempt
                continue
            self._used.add(attempt[1])
            if math.isfinite(monotonic):
                self._sent.append((monotonic, attempt[1]))
            with self._lock:
                episode.notified, episode.attempt = True, None
                if episode.recovered is not None:
                    self._discard(identity, episode)
        now = monotonic
        with self._lock:
            offline = sum(1 for source in self._sources.values()
                          if source.episode is not None and source.episode.recovered is None
                          and source.episode.qualifies(now, self.after))
            held = sum(1 for source in self._sources.values()
                       if source.episode is not None and source.episode.held
                       and not source.episode.notified)
        return CameraOfflineStatus(offline_sources=offline, held=held)

    def _discard(self, identity: UUID, episode: _Episode) -> None:
        # Called with the lock held; a newer episode is never removed.
        source = self._sources[identity]
        if source.episode is episode:
            source.episode = None

    def _durable(self, identity, durable_id) -> UUID | None:
        if durable_id is None:
            return None
        try:
            value = durable_id(identity)
        except Exception:
            return None
        if not isinstance(value, UUID) or value in self._used:
            return None
        return value

    @staticmethod
    def _known(event_id, known) -> bool:
        if known is None:
            return False
        try:
            return known(event_id) is True
        except Exception:
            # Unknown: notify rather than risk hiding an outage.
            return False
