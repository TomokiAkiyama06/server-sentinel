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
already polls, so a worker that is no longer running is not kept ``online``
and a health event that never reached the sink cannot hide an outage.
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
the next drain is still notified once. If the source goes offline again
before that drain after a recovery shorter than ``after_seconds``, the
recovery is folded into it (still owed, the count is not restarted); after a
longer recovery the new outage is its own episode and the old one stays owed
under its own time and ID (one owed episode per source). A recovery is recorded in the episode
(``recovered``) and is not notified (no Owner decision for a recovery
notice).

Event IDs: an episode still in progress is named after the source and its
registry ``last_seen_at`` (the last frame time, which stops changing while no
frame arrives), supplied by the runtime (``durable_id``). A restarted process
that finds the same camera still offline therefore computes the same ID, finds
the row (``known``) and does not notify the same outage again. A row of that
name accepted more than 24 h earlier no longer counts (Owner decision
2026-10-22): the runtime then names the outage with the next name of a
deterministic chain and it is notified again; a ``pending`` row is aged by
its event time instead (a resend writes its acceptance again, Issue #342).
Without storage, or for an episode that already recovered, the ID is per
process (never a missed notification, at worst one repeat after a restart),
except each source's initial episode: its name is resolved once on the first
running tick while it is in progress (``name_initial``) and kept, so it still
matches its row after it recovered (Issue #342 D).

Uncertain deliveries (Issue #336): only a final ``sent`` / ``failed`` /
``disabled`` row counts as notified. A row still ``pending`` is a delivery an
earlier process never finished (it exited before the Slack outcome was
stored), which the notifications README forbids treating as confirmed. The
runtime hands the newest such rows whose event time is less than 24 h old to
``restore_pending`` at the first running tick; each is submitted again under
its stored event ID and time whether or not the outage is still in progress
(an episode that reached the threshold is notified once even if it recovered
before the drain; the row does not name its source). An episode or ratio
alert whose durable name is such a row is covered by it, settled when it is
named, before the cap is consulted. Only each source's initial episode (in
progress since this process started) and a ratio alert can be covered; a
later outage that reuses a restored name gets a per-process ID; a pending row found only by ``known`` /
``flapping_id`` is submitted again the same way. For such a restored row or
one found by name, if the earlier POST did reach Slack the Owner sees the
alert twice, never not at all. A pending row beyond ``hourly_limit`` that is
left out of the restore (``unrestored``) and that no outage in progress maps
to by name (its outage recovered) is not sent again. An initial episode this
process already notified under a per-process ID while the runtime was not
running (no names without storage) is matched by the name resolved on the
first running tick: the restored row of that name is not sent again
(``covered``), it stays ``pending`` and keeps its slot (Issue #342 E; see
``name_initial`` for the one later resend it may still get).

Cap: at most ``hourly_limit`` notifications per rolling hour for all sources
together, continued across a restart from the confirmed ``camera_offline``
rows accepted in the last hour, ``pending`` included (``restore_window``).
The cap is absolute (Owner decision, PR #339): a resend takes a slot like any
notification, a pending row that still holds a slot of the restored hour
waits until that slot expires (up to about an hour late), and live alerts
are sent before restored rows. An episode held back by the cap is logged once
(value-free) and notified as soon as the hour allows, also when it recovered
meanwhile (Owner decision 2026-10-24, Issue #349: an episode that reached the
threshold is notified once, as one that recovered before its drain is). An
alert sent after its episode recovered (or its ratio period closed) carries
the fixed text suffix ``(already recovered)``; a restored row's does not (the
row does not name its source). Such late notices go after every outage and
ratio period still in progress. One whose outage ended a window and one bin
(window/``DOWN_BINS``) or longer before it was sent opens no alerted period,
and while it waits it does not keep the ratio rule from evaluating its
source, so current flapping gets its own (in progress, first) ratio alert
(Issue #349 review, Codex PR #359 P2).

Intermittent outages (Owner decision 2026-10-22, Refs #301): short outages
that repeat notify too. A source that was not online for
``flapping_offline_seconds`` (default 300 s) in total within the last
``flapping_window_seconds`` (default 900 s), over at least two separate
not-online periods (a single outage is the continuous rule's), is notified
once as the same ``camera_offline`` kind under the same cap. Every
notification of a source that was sent (either rule), or that an earlier
process already sent, opens that source's *alerted period*, which closes only
after the source stayed online (or inactive) for a whole window; one dropped
under the cap opens none. While it is open the ratio rule does not notify
that source again. In a period a ratio alert opened (Owner decision
2026-10-23, PR #335) the flapping continues to belong to that alert: the
outage in progress at the alert and every outage that begins after an online
shorter than ``after_seconds`` are *flapping episodes*; the first of them
that stays offline for ``after_seconds`` (the one in progress counting from
the alert) is notified once by the continuous rule and later ones are not,
so one flapping period yields at most two notifications. Which period a
flapping episode belongs to is its generation (``period_seq``), not how long
ago it recovered: a late notice of a flapping episode of the period still
open is that period's continuous notification, or is skipped after it
(Claude re-review PR #359 重要 1). Sending one flapping episode settles any
other unsent one of the same generation without a notice, also after the
period closed (PR #335 takes precedence over Issue #349 inside a flapping
period); every skipped or settled flapping episode is counted
(``suppressed``) and logged value-free at INFO
(``camera_offline_notification_suppressed``). An outage that
begins after an online of at least ``after_seconds`` is an ordinary episode
(one notification per episode, as before). A period opened by a continuous
notification leaves the continuous rule as it was. Not-online time is kept
per source in at most ``DOWN_BINS`` + 2 time bins of window/``DOWN_BINS``
holding the actual not-online seconds; the oldest bin may straddle the window
start and is counted whole, so the total can exceed the true one by at most
that bin's not-online seconds, never fall short of it. A ratio alert is named
after the source and the wall-clock window bucket of its trigger
(``flapping_id``), so a restarted process that triggers again within a window
of a stored alert of that source sends nothing twice. A ratio alert held back
by the cap is sent when the hour allows while its period is still open. Once
its period closed it is dropped (logged) before the cap is consulted, also
when the hour has room again by the next drain (Issue #338 item 2): a ratio
alert exists only from the drain that triggers it, so an ended one without a
pending attempt was held for a whole quiet window. One the cap allowed but
the queue refused is retried under its time and ID like a refused continuous
episode, also after its period closed, and held by the cap like a recovered
episode (Issue #349) rather than dropped; it waits apart (``late_flaps``),
so no number of them blocks a new ratio period of the source, and the alert
of a period in progress goes before them (Codex PR #359 P2). At most
``LATE_FLAPS_PER_SOURCE`` (4) wait per source; beyond that the oldest is
dropped (counted in ``dropped``, logged as
``camera_offline_notification_dropped``). After a restart the in-memory period is
gone; a continuous episode that is due while its source has no period looks
up the source's recent ratio alert once (``flapping_id``) and, when an
earlier process stored one within the window, restores the period as
ratio-opened with this episode as its flapping episode (Issue #338 item 1):
the episode is still notified once (whether the stopped process already sent
the period's continuous notification is not stored) and later flapping
episodes of the period are not.

Value-free: the notification is the fixed category ``camera_offline`` with no
source name, role, UUID, device path, serial, reason or image (SPECIFICATION
§9 Slack payload); the Owner sees which source is offline in the Web UI.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
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
    CAMERA_FLAPPING_OFFLINE_SECONDS, CAMERA_FLAPPING_WINDOW_SECONDS,
    CAMERA_OFFLINE_HOURLY_LIMIT, CAMERA_OFFLINE_HOURLY_LIMIT_BOUNDS, CAMERA_OFFLINE_SECONDS,
    CAMERA_OFFLINE_SECONDS_BOUNDS, valid_flapping,
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
# Time bins per window holding a source's not-online seconds (ratio rule).
DOWN_BINS = 128
DEFAULT_FLAPPING_WINDOW = CAMERA_FLAPPING_WINDOW_SECONDS
DEFAULT_FLAPPING_OFFLINE = CAMERA_FLAPPING_OFFLINE_SECONDS
# Refused ratio alerts whose period closed, kept per source while they wait
# (``late_flaps``). Each needs a flapping period and a whole quiet window
# under a refusing queue; beyond this the oldest is dropped (counted and
# logged as ``camera_offline_notification_dropped``).
LATE_FLAPS_PER_SOURCE = 4
# Who opened a source's alerted period.
_BY_CONTINUOUS = "continuous"
_BY_RATIO = "ratio"


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
    # Set when a ratio alert covered this episode while it was in progress:
    # the continuous threshold then counts again from that alert (Owner
    # decision 2026-10-23, PR #335).
    counted_from: float | None = None
    # Part of a ratio-opened flapping period: in progress at its alert, or
    # begun after an online shorter than ``after_seconds`` inside it.
    flapping: bool = False
    # The source's ``period_seq`` of that ratio-opened period: a flapping
    # episode belongs to the period of this generation only, however long
    # ago it recovered (Claude re-review PR #359 重要 1).
    period_seq: int | None = None
    # The episode every source starts with: in progress since this process
    # started, so the only one that can be an earlier process's outage that
    # a restored pending row reported (PR #339, Codex P2).
    initial: bool = False
    # The initial episode's durable name, resolved once on the first running
    # tick while it was still in progress (``name_initial``, Issue #342 D/E).
    name: UUID | None = None
    # The recent ratio alert of the source was looked up once for this
    # episode from the continuous path (Issue #338 item 1).
    ratio_checked: bool = False

    def qualifies(self, now: float, after: float) -> bool:
        end = self.recovered if self.recovered is not None else now
        start = self.since if self.counted_from is None else self.counted_from
        return not math.isfinite(end) or end - start >= after


@dataclass
class _Flap:
    """A ratio alert of one flapping period, until it is notified."""

    since: float
    notified: bool = False
    held: bool = False
    attempt: tuple[datetime, UUID] | None = None
    # The period closed before the alert was notified.
    ended: bool = False
    # ``(event ID, notified)`` of an earlier process's ratio alert found from
    # the continuous path (Issue #338 item 1): the name is not looked up again.
    name: tuple[UUID, bool | datetime] | None = None


@dataclass
class _Resend:
    """A ``pending`` row an earlier process left (Issue #336).

    Its Slack outcome was never stored, so it is not confirmed delivery
    (notifications README): it is submitted again under its stored event ID
    and time. The row does not name its source, so it is never dropped as
    recovered and opens no alerted period.
    """

    attempt: tuple[datetime, UUID] | None
    notified: bool = False
    held: bool = False
    # The stored row's ID (``attempt`` is cleared once it is sent).
    event_id: UUID | None = None

    def __post_init__(self):
        self.event_id = self.attempt[1]


class _DownTime:
    """Bounded not-online seconds of one source within the ratio window.

    ``bins`` holds ``[index, seconds]`` for time bins of ``width`` (window /
    ``DOWN_BINS``) in increasing index, at most ``DOWN_BINS`` + 2 of them;
    ``ends`` the end times of the last two closed not-online periods and
    ``since`` the start of the one in progress. Called with the lock held.
    """

    __slots__ = ("width", "window", "bins", "ends", "since", "last")

    def __init__(self, window: float, start: float | None = None):
        self.window = window
        self.width = window / DOWN_BINS
        self.bins: deque[list] = deque()
        self.ends: deque[float] = deque(maxlen=2)
        self.since = start
        self.last = start

    def clear(self) -> None:
        self.bins.clear()
        self.ends.clear()

    def _clock(self, now: float) -> float | None:
        """``now`` as this record uses it; ``None`` when it is not finite.

        The runtime reads the monotonic clock before it drains, outside the
        lock, so a health event observed meanwhile can carry a slightly later
        time (PR #335 re-review 提案 1). A step back of at most one bin width
        is such a race: the later time already seen is used. Only a larger
        step back is a backwards clock: the kept time cannot be placed
        against it, so the count starts again (the continuous rule is
        unaffected; a ratio alert is at most one window later).
        """
        if not math.isfinite(now):
            return None
        if self.last is not None and now < self.last:
            if self.last - now <= self.width:
                return self.last
            self.clear()
            if self.since is not None:
                self.since = now
        self.last = now
        return now

    def start(self, now: float) -> None:
        self.since = self._clock(now)

    def stop(self, now: float) -> None:
        since, self.since = self.since, None
        now = self._clock(now)
        if since is None or now is None or now <= since:
            # Unknown or zero length: no not-online time to count.
            return
        self.ends.append(now)
        self._add(max(since, now - self.window - self.width), now)
        self.trim(now)

    def _add(self, begin: float, end: float) -> None:
        width = self.width
        index = math.floor(begin / width)
        while begin < end:
            stop = min(end, (index + 1) * width)
            if stop > begin:
                if self.bins and self.bins[-1][0] == index:
                    self.bins[-1][1] += stop - begin
                else:
                    self.bins.append([index, stop - begin])
            begin, index = stop, index + 1

    def trim(self, now: float) -> None:
        if not math.isfinite(now):
            return
        first = math.floor((now - self.window) / self.width)
        while self.bins and self.bins[0][0] < first:
            self.bins.popleft()

    def flapping(self, now: float, offline: float) -> bool:
        """``offline`` seconds or more, over two or more periods, in the window."""
        now = self._clock(now)
        if now is None:
            return False
        self.trim(now)
        start = now - self.window
        total = sum(seconds for _index, seconds in self.bins)
        periods = sum(1 for end in self.ends if end > start)
        if self.since is not None:
            total += now - max(self.since, start)
            periods += 1
        return periods >= 2 and total >= offline


@dataclass
class _Source:
    active: bool
    online: bool
    # The episode in progress (``recovered is None``) or one that reached the
    # threshold and recovered before it was notified.
    episode: _Episode | None
    # A recovered episode that reached the threshold, still owed its
    # notification, set aside when a later outage began after it had stayed
    # recovered for at least the threshold (a new outage, not a blip).
    owed: _Episode | None = None
    # Bumped on every signal, so a runtime status read before a newer event
    # cannot overwrite it (``observe_runtime``).
    version: int = 0
    # Not-online time of the ratio rule.
    down: _DownTime | None = None
    # Since when the source has been online or inactive; None while not.
    quiet_since: float | None = None
    # Who opened the alerted period (``_BY_CONTINUOUS`` / ``_BY_RATIO``).
    period: str | None = None
    # The ratio alert of the current period, while it is not notified.
    flap: _Flap | None = None
    # Refused ratio alerts whose period closed, still owed (each has an
    # attempt), oldest first: set aside so none of them blocks a new ratio
    # period of the source (Issue #349 review 提案 3, Codex PR #359 P2). At
    # most ``LATE_FLAPS_PER_SOURCE``.
    late_flaps: deque[_Flap] = field(default_factory=deque)
    # A ratio-opened period already sent its one continuous notification.
    continuous_sent: bool = False
    # Generation of the ratio-opened periods, bumped each time one opens.
    period_seq: int = 0


@dataclass(frozen=True)
class CameraOfflineStatus:
    """Bounded, value-free result of one ``drain``."""

    # Sources whose episode in progress has lasted the threshold.
    offline_sources: int
    # Episodes past the threshold that the hourly cap is holding back.
    held: int
    # Sources in an alerted period opened by the ratio rule.
    flapping_sources: int = 0


class CameraOfflineMonitor:
    """Per-source offline episodes feeding the monitoring runtime."""

    def __init__(self, source_ids: Iterable[UUID], *,
                 after_seconds: float = DEFAULT_OFFLINE_SECONDS,
                 hourly_limit: int = DEFAULT_HOURLY_LIMIT,
                 flapping_window_seconds: float = DEFAULT_FLAPPING_WINDOW,
                 flapping_offline_seconds: float = DEFAULT_FLAPPING_OFFLINE,
                 monotonic: Callable[[], float]):
        ids = tuple(source_ids)
        if (not 1 <= len(ids) <= MAX_SOURCES or len(set(ids)) != len(ids)
                or any(not isinstance(value, UUID) for value in ids)
                or not valid_offline_seconds(after_seconds)
                or not valid_hourly_limit(hourly_limit) or not callable(monotonic)
                or not valid_flapping(flapping_window_seconds, flapping_offline_seconds)
                or not all(map(math.isfinite, (flapping_window_seconds,
                                               flapping_offline_seconds)))):
            raise ValueError("invalid camera offline monitor setting")
        self.after = float(after_seconds)
        self.window = float(flapping_window_seconds)
        self.flapping_offline = float(flapping_offline_seconds)
        self.hourly_limit = hourly_limit
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._nonce = uuid4()
        self._sequence = 0
        self._stopped = False
        start = monotonic()
        self._sources = {
            identity: _Source(True, False, _Episode(start, initial=True),
                              down=_DownTime(self.window, start if math.isfinite(start) else None))
            for identity in ids}
        # (monotonic time, event ID) of the notifications in the rolling hour.
        self._sent: deque[tuple[float, UUID]] = deque()
        # Durable IDs this process already notified: an episode whose
        # ``last_seen_at`` did not move (a refused frame-time write) gets a
        # per-process ID instead of being taken for the earlier one.
        self._used: set[UUID] = set()
        # Restored ``pending`` rows still to be sent again (``restore_pending``)
        # and their IDs while unsent.
        self._resend: list[_Resend] = []
        self._restored: set[UUID] = set()
        # Restored IDs whose resend was sent (moved out of ``_restored``).
        self._resent: set[UUID] = set()
        self.recovered = 0
        self.dropped = 0
        # Flapping episodes settled without a notice because their ratio
        # period already had its continuous notification (PR #335).
        self.suppressed = 0
        # Pending rows left out of ``restore_pending`` (beyond the cap).
        self.unrestored = 0
        # Restored rows not sent again because this process had already
        # notified the same outage (``name_initial``, Issue #342 E).
        self.covered = 0

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
        self._close_period(source, now)
        was_down = source.active and not source.online
        down = active and not online
        # How long the source was online (or inactive) before this outage,
        # taken before the quiet start is cleared (PR #335 review 重大 1).
        quiet = source.quiet_since
        short_online = (quiet is not None and math.isfinite(now) and math.isfinite(quiet)
                        and now - quiet < self.after)
        if down and not was_down:
            source.quiet_since = None
            source.down.start(now)
        elif was_down and not down:
            source.down.stop(now)
            # An unknown time counts as long ago: the period may close.
            source.quiet_since = now if math.isfinite(now) else -math.inf
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
            if (episode is not None and not episode.notified
                    and now - episode.recovered < self.after):
                # A recovered episode that reached the threshold and is still
                # owed its notification: a recovery shorter than the
                # threshold is folded into it, so the outage that already
                # lasted the threshold is notified on the next drain instead
                # of restarting the count (PR #320 review 重要 1).
                episode.recovered = None
            else:
                if episode is not None and not episode.notified:
                    # Recovered for at least the threshold: the new outage is
                    # its own episode (own time and ID); the old one stays
                    # owed. Only one is kept per source; an older owed one
                    # that is still unsent is counted and logged as dropped.
                    if source.owed is not None:
                        self.dropped += 1
                        logging.getLogger(__name__).warning(
                            Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED)
                    source.owed = episode
                # Inside a ratio-opened period, an outage after a short
                # online continues the flapping; after a longer one it is an
                # ordinary episode.
                flapping = source.period == _BY_RATIO and short_online
                source.episode = _Episode(
                    now, flapping=flapping,
                    period_seq=source.period_seq if flapping else None)
        source.online, source.active = online, active

    def _close_period(self, source: _Source, now: float) -> None:
        """Close the alerted period once the source stayed quiet a window."""
        if source.period is None or source.quiet_since is None or not math.isfinite(now):
            return
        if now < source.quiet_since:
            # A backwards clock: count the quiet time again from now.
            source.quiet_since = now
        if now - source.quiet_since < self.window:
            return
        source.period, source.continuous_sent = None, False
        # Every not-online period ended before the quiet window began.
        source.down.clear()
        if source.flap is not None:
            # Still unsent (a notified one is removed at once).
            source.flap.ended = True

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
        worker's latest in-memory camera state decides otherwise: ``online``
        ends an episode (for example after a worker restart that raised no
        new transition), and any other known state starts one, so a health
        event that never reached the sink cannot hide an outage. A source
        that received an event after ``versions`` was read keeps that newer
        event; an inactive source (disabled, stopping) stays inactive.
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
                elif camera in _NOT_ONLINE and source.online:
                    source.version += 1
                    self._apply(source, False, True, now)

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

    def restore_pending(self, rows, *, unrestored: int = 0) -> None:
        """Send again the ``pending`` rows an earlier process left (Issue #336).

        ``rows`` are ``(event ID, stored event time)`` of confirmed
        ``camera_offline`` rows still ``pending`` whose event time is less
        than 24 h old, newest first, at most ``hourly_limit``. A process exit
        before the Slack outcome was stored leaves such a row, and
        ``pending`` is not confirmed delivery (notifications README). Each is
        submitted again under its own ID and stored time, whether or not the
        outage is still in progress: an episode that reached the threshold is
        notified once even if it recovered before the drain, and the row
        does not name its source.

        The hourly cap stays absolute (PR #339): a resend takes a slot like
        any notification, and one whose row still holds a slot of the
        restored hour (its uncertain delivery) waits until that slot expires,
        so it can be up to about an hour late. Live alerts go first; restored
        rows follow by their stored time. A resend is never dropped. An
        episode or ratio alert of this process whose durable name is such a
        row is covered by it and sends nothing twice. Only the outage in
        progress since this process started (each source's initial episode)
        and a ratio alert, whose name already holds only within its window,
        can be the earlier process's outage. Any later episode of this
        process that maps to a restored name (its online last-frame write was
        refused), before or after the resend was sent, is a new outage and
        gets a per-process ID (Codex PR #339 P2). The ID leaves the set of
        unsent resends as soon as its resend is sent; a resend is never
        dropped, and a refused submission keeps waiting. For such a restored row,
        if the earlier POST did reach Slack, the Owner sees the alert twice,
        never not at all.

        ``unrestored`` counts the older pending rows left out (more than
        ``hourly_limit``): they are not resent on their own, only when an
        outage still in progress or a ratio alert maps to one by name (then
        as above under its ID and time); one whose outage already recovered
        is not sent again. They are counted in ``unrestored`` (not
        ``dropped``) and logged once as
        ``camera_offline_notification_unrestored``.

        The runtime calls ``name_initial`` right after this, so each
        source's initial episode is matched to these rows by name even once
        it recovered or after it was sent while not running (Issue #342).
        """
        rows = tuple(rows)
        if (len(rows) > self.hourly_limit or type(unrestored) is not int or unrestored < 0
                or any(type(row) is not tuple or len(row) != 2 or not isinstance(row[0], UUID)
                       or not _aware(row[1]) for row in rows)):
            raise ValueError("invalid restored pending rows")
        with self._lock:
            for event_id, at in rows:
                # This process's own rows are its deliveries, not a restart's.
                if event_id in self._used or self._is_restored(event_id):
                    continue
                self._restored.add(event_id)
                self._resend.append(_Resend((at, event_id)))
        if unrestored:
            self.unrestored += unrestored
            logging.getLogger(__name__).warning(Event.CAMERA_OFFLINE_NOTIFICATION_UNRESTORED)

    def name_initial(self, durable_id: Callable[[UUID], UUID | None] | None) -> None:
        """Resolve each source's initial-episode durable name once (Issue #342 D/E).

        The runtime calls this on the first running tick, right after
        ``restore_pending``. A source whose initial episode (in progress
        since this process started) is still in progress then gets its
        durable name remembered, so the episode is matched to a restored
        ``pending`` row of that name even when it is no longer named live:

        - D: it reached the threshold and recovered before the drain that
          would have named it. It is covered by the restored row's resend
          (or, for a row found only by ``known``, settled or resent under
          that name) instead of being sent again under a per-process ID.
        - E: it was already sent under a per-process ID while the runtime
          was not running (no names without storage). The restored row of
          that name reported the same outage, so its resend is not sent:
          the Owner already received this process's notification of it.
          The row stays ``pending`` (there is no truthful final state to
          write for a POST whose outcome is unknown); it keeps its slot of
          the restored hour and a later restart within 24 h of its event
          time may send it once more (SPECIFICATION §9). A per-process
          submission of the episode the queue has not taken yet is
          discarded and the episode is named, so the resend covers it.

        A name that cannot be resolved (no registry row, a failing lookup)
        leaves the episode as before. An episode that already recovered is
        not named here: its last-frame time may have moved.
        """
        if durable_id is None:
            return
        with self._lock:
            candidates = [(identity, source.episode) for identity, source in self._sources.items()
                          if source.episode is not None and source.episode.initial
                          and source.episode.recovered is None and source.episode.name is None]
        names = [(identity, episode, self._durable(identity, durable_id))
                 for identity, episode in candidates]
        with self._lock:
            for identity, episode, name in names:
                if (name is None or self._sources[identity].episode is not episode
                        or episode.recovered is not None):
                    continue
                episode.name = name
                if name not in self._restored:
                    continue
                if episode.notified:
                    # E: this process's own notification covered the outage.
                    self._resend = [item for item in self._resend if item.event_id != name]
                    self._restored.discard(name)
                    self._used.add(name)
                    self.covered += 1
                elif episode.attempt is not None:
                    # Never accepted (queue full or the write refused): it is
                    # named on the next drain and covered by the resend.
                    episode.attempt = None

    def _is_restored(self, event_id: UUID) -> bool:
        """Whether ``event_id`` is a restored row's ID, sent again or not."""
        return event_id in self._restored or event_id in self._resent

    def _counted(self, event_id: UUID) -> bool:
        """Whether ``event_id`` already holds a slot of the rolling hour."""
        return any(entry == event_id for _time, entry in self._sent)

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
              known: Callable[[UUID], bool] | None = None,
              flapping_id: Callable[[UUID], tuple[UUID, bool] | None] | None = None,
              ) -> CameraOfflineStatus:
        """Notify every episode or flapping period that qualified, within the cap.

        ``durable_id(source_id)`` names an episode in progress after the
        source's durable last-frame time; ``known(event_id)`` tells whether
        that row already exists (an earlier process notified this outage).
        ``flapping_id(source_id)`` names a ratio alert: ``(event ID,
        notified)``, ``notified`` when an earlier process stored a ratio
        alert of that source within the window. Any of them may be absent or
        fail; the alert then gets a per-process ID. A stored row still
        ``pending`` is not confirmed (Issue #336): ``known`` (or ``notified``)
        then gives its stored time instead of ``True``, and the alert is
        submitted again under that ID and time; only ``True`` (a final
        ``sent`` / ``failed`` / ``disabled`` row) settles it as notified.
        ``flapping_id`` is also asked once for a continuous episode that is
        due while its source has no alerted period (Issue #338 item 1): a
        stored ratio alert then restores that period.
        """
        now = monotonic
        check = []
        with self._lock:
            stopped = self._stopped
            if not stopped:
                for identity, source in self._sources.items():
                    self._close_period(source, now)
                    source.down.trim(now)
                    flap = source.flap
                    if flap is not None and flap.ended and flap.attempt is not None:
                        # Refused, then its period closed: still sent under
                        # its time and ID, apart from a new period's alert,
                        # however many are already waiting (Codex PR #359
                        # P2). Bounded: the oldest beyond the bound is
                        # dropped (the queue never accepted it: nothing sent).
                        source.flap = None
                        source.late_flaps.append(flap)
                        while len(source.late_flaps) > LATE_FLAPS_PER_SOURCE:
                            source.late_flaps.popleft().notified = True
                            self.dropped += 1
                            logging.getLogger(__name__).warning(
                                Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED)
                    if (source.period is None and source.flap is None
                            and not self._continuous_due(source, now)
                            and source.down.flapping(now, self.flapping_offline)):
                        # One alert for this flapping period. The outage in
                        # progress belongs to it; it is notified by the
                        # continuous rule only if it lasts `after_seconds`
                        # more (Owner decision 2026-10-23, PR #335).
                        source.period, source.flap = _BY_RATIO, _Flap(now)
                        source.continuous_sent = False
                        source.period_seq += 1
                        episode = source.episode
                        if episode is not None and episode.recovered is None:
                            episode.counted_from, episode.flapping = now, True
                            episode.period_seq = source.period_seq
                    episode = source.episode
                    if (flapping_id is not None and source.period is None
                            and source.flap is None and episode is not None
                            and episode.recovered is None and not episode.notified
                            and not episode.ratio_checked and episode.attempt is None
                            and episode.qualifies(now, self.after)):
                        check.append((identity, episode))
        # Issue #338 item 1 (Codex PR #335 P2): a continuous episode that is
        # due keeps the ratio rule from evaluating its source, so a restart
        # during a flapping period an earlier process's ratio alert opened
        # would otherwise lose that period. Its recent ratio alert of the
        # source is looked up once per episode, before the episode is named.
        found = [(identity, episode, self._flapping_name(identity, flapping_id))
                 for identity, episode in check]
        with self._lock:
            for identity, episode, (event_id, earlier) in found:
                source = self._sources[identity]
                if source.episode is episode and episode.recovered is None:
                    # Checked only once the result met the episode still in
                    # progress (Issue #353, Codex PR #348 P2): one that
                    # recovered during the lookup discards the result, and a
                    # recovery folded back into it later looks up again.
                    episode.ratio_checked = True
                if (stopped or event_id is None or earlier is False
                        or source.period is not None or source.flap is not None
                        or source.episode is not episode or episode.recovered is not None):
                    continue
                # Found: the period is restored as ratio-opened and this
                # episode is its flapping episode. Its one continuous
                # notification is still sent (whether the stopped process
                # sent it is not stored); later flapping episodes are not.
                # The found alert is settled through the loop below (final:
                # nothing; pending: covered by a restored resend or sent
                # again under its ID and time).
                source.period, source.continuous_sent = _BY_RATIO, False
                source.period_seq += 1
                source.flap = _Flap(now, name=(event_id, earlier))
                episode.flapping, episode.period_seq = True, source.period_seq
            # Outages and ratio periods in progress first, by their start;
            # then recovered episodes and ended ratio alerts, by their start;
            # restored rows last, by their stored time. An outage in progress
            # is never held back behind an earlier process's uncertain
            # delivery (PR #339 重要 3) or a late notice of an outage that
            # already recovered (Issue #349 review 重要 1).
            due = sorted([*((identity, item) for identity, source in self._sources.items()
                            for item in (source.owed, source.episode, source.flap,
                                         *source.late_flaps)
                            if item is not None and not item.notified
                            and (isinstance(item, _Flap) or item.qualifies(now, self.after))),
                          *((None, item) for item in self._resend)],
                         key=_due_order)
        for identity, item in () if stopped else due:
            flap = isinstance(item, _Flap)
            resend = isinstance(item, _Resend)
            with self._lock:
                if item.notified:
                    # Settled earlier in this drain (a flapping episode of a
                    # period whose continuous notification just went out).
                    continue
                # A restored row is never dropped: its source is not known.
                ongoing = _ongoing(item)
                source = None if resend else self._sources[identity]
                if (not flap and not resend and _of_period(source, item)
                        and source.continuous_sent):
                    # A ratio-opened period yields at most one continuous
                    # notification after its ratio alert (at most two). The
                    # period is told by its generation, not by time: a
                    # flapping episode of the period still open is skipped
                    # however long ago it recovered; one of an earlier
                    # period is still sent (Claude re-review PR #359 重要 1).
                    self._finish(identity, item)
                    self._suppressed()
                    continue
                if flap and item.ended and item.attempt is None:
                    # Issue #338 item 2 (Codex PR #335 P2): the period
                    # closed before its alert went out. A ratio alert exists
                    # only from the drain that triggers it, so one without a
                    # pending attempt ended while held by the cap for a
                    # whole quiet window: dropped whether or not the hour
                    # has room by now (never a stale alert after a delayed
                    # drain). Not sent: no alerted period. One the cap
                    # allowed but the queue refused keeps its attempt and is
                    # sent once the queue takes it, as a refused continuous
                    # episode is (PR #348 review 提案 1); like a recovered
                    # episode, it waits for the cap if it is closed by then
                    # (Issue #349). The Owner decision of Issue #349 is the
                    # continuous rule's: an outage that lasted the threshold
                    # is one event worth one notice. A ratio alert the cap
                    # never allowed reports flapping in progress, and its
                    # period closing means it ended a whole window ago.
                    self._finish(identity, item, sent=False)
                    self.dropped += 1
                    logging.getLogger(__name__).warning(
                        Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED)
                    continue
            attempt, event_id = item.attempt, None
            if attempt is None:
                # Named before the cap (PR #339 重要 1): an alert an earlier
                # process notified, or whose pending row a restored resend
                # covers, is settled now whatever the hour allows, so it is
                # never held, dropped or left claiming that row.
                if flap:
                    event_id, earlier = item.name or self._flapping_name(identity, flapping_id)
                else:
                    event_id = self._durable(identity, durable_id) if ongoing else None
                    earlier = False
                    name = item.name
                    if (name is not None and name != event_id and self._usable(name)
                            and (self._is_restored(name)
                                 or (event_id is None and self._known(name, known) is not False))):
                        # Issue #342 D: the initial episode's name resolved on
                        # the first running tick, used when the episode is no
                        # longer named live (it recovered before this drain)
                        # and its row exists, or when it is a restored row.
                        event_id = name
                if event_id is not None and self._is_restored(event_id):
                    if flap or item.initial:
                        # The earlier process's pending row of this name is
                        # (or was) sent again by ``restore_pending``: that
                        # covers the outage in progress since this process
                        # started, or a ratio alert within its window.
                        earlier = True
                    else:
                        # A later outage of this process that reuses the name
                        # (its online last-frame write was refused) is a new
                        # outage: its own per-process ID (Codex PR #339 P2).
                        event_id, earlier = None, False
                elif not flap and event_id is not None:
                    earlier = self._known(event_id, known)
                if isinstance(earlier, datetime):
                    # A pending row: submitted again under its ID and time.
                    attempt, earlier = (earlier, event_id), False
                if earlier:
                    # An earlier process already notified this outage.
                    self._used.add(event_id)
                    with self._lock:
                        self._finish(identity, item)
                    continue
            # The cap is absolute (Owner decision, PR #339 重要 2): every
            # submission takes a slot, and a pending row whose uncertain
            # delivery still holds a slot of the hour waits until that slot
            # has expired, so a restart loop never sends it more than once
            # an hour.
            if not self._window_open(now) or (attempt is not None
                                              and self._counted(attempt[1])):
                # Held until the hour allows, also once it recovered (Owner
                # decision 2026-10-24, Issue #349): an episode that reached
                # the threshold is notified once, as one that recovered
                # before its drain is (PR #320), and so is a ratio alert the
                # cap had allowed before its period closed.
                with self._lock:
                    if not item.held:
                        item.held = True
                        logging.getLogger(__name__).warning(
                            Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED)
                continue
            if attempt is None:
                attempt = (at, event_id or self._local_id(identity))
            if not notifications.can_accept(attempt[1]):
                # Queue full or closed: retried on the next drain.
                item.attempt = attempt
                continue
            # One that recovered (or whose period closed) says so in the
            # fixed text; a restored row's source is not known.
            result = notifications.record(NotificationKind.CAMERA_OFFLINE, at=attempt[0],
                                          confirmed=True, event_id=attempt[1],
                                          recovered=not ongoing)
            if result == DeliveryResult.FAILED and not notifications.retained(attempt[1]):
                item.attempt = attempt
                continue
            self._used.add(attempt[1])
            if math.isfinite(now):
                self._sent.append((now, attempt[1]))
            with self._lock:
                item.attempt = None
                self._finish(identity, item, now=now)
        with self._lock:
            offline = sum(1 for source in self._sources.values()
                          if source.episode is not None and source.episode.recovered is None
                          and source.episode.qualifies(now, self.after))
            held = sum(1 for source in self._sources.values()
                       for item in (source.owed, source.episode, source.flap,
                                    *source.late_flaps)
                       if item is not None and item.held and not item.notified) + sum(
                           1 for item in self._resend if item.held)
            flapping = sum(1 for source in self._sources.values()
                           if source.period == _BY_RATIO)
        return CameraOfflineStatus(offline_sources=offline, held=held,
                                   flapping_sources=flapping)

    def _continuous_due(self, source: _Source, now: float) -> bool:
        # A qualifying continuous episode is the continuous rule's to report.
        # A stale one (its outage left the ratio window) is not the current
        # flapping: it never keeps the ratio rule from evaluating the source
        # (Codex PR #359 P2).
        return any(item is not None and not item.notified and item.qualifies(now, self.after)
                   and not self._stale(item, now)
                   for item in (source.owed, source.episode))

    def _stale(self, item: _Episode, now: float | None) -> bool:
        """Recovered a window and one bin or longer ago: out of the ratio window.

        ``trim`` then has removed every bin of its not-online time and its
        end time precedes the window, so the ratio rule cannot count it.
        """
        return (item.recovered is not None and now is not None and math.isfinite(now)
                and math.isfinite(item.recovered)
                and now - item.recovered >= self.window + self.window / DOWN_BINS)

    def _finish(self, identity: UUID, item, *, sent: bool = True,
                now: float | None = None) -> None:
        """Notified, found notified, covered, or dropped: settled for good.

        Called with the lock held; a newer episode is never removed. A
        continuous episode that was sent (or an earlier process sent) opens
        the alerted period when none is open, so the ratio rule does not
        report the same outage again; a dropped one (``sent=False``) opens
        none, since the Owner was never told. Nor does a late notice of an
        outage that recovered a window and one bin or longer before it was
        sent (``now``, ``_stale``, Issue #349 review 提案 2): none of its
        not-online time is left in the ratio window, so a camera flapping by
        then still gets its ratio alert. Whether a sent episode is the one
        continuous notification of a ratio-opened period is decided by the
        period's generation (``_of_period``), not by time: a flapping
        episode of the period still open counts however long ago it
        recovered, and one of an earlier period (or none) never does.
        """
        item.notified = True
        if isinstance(item, _Resend):
            if item in self._resend:
                self._resend.remove(item)
            # Sent: the ID no longer waits (Codex PR #339 P2); it still covers
            # the source's initial episode and a ratio alert (``drain``).
            self._restored.discard(item.event_id)
            self._resent.add(item.event_id)
            return
        source = self._sources[identity]
        if isinstance(item, _Flap):
            if source.flap is item:
                source.flap = None
            # By identity: two alerts may hold equal fields.
            source.late_flaps = deque(flap for flap in source.late_flaps
                                      if flap is not item)
            return
        if sent:
            if source.period is None:
                if not self._stale(item, now):
                    source.period = _BY_CONTINUOUS
            elif _of_period(source, item):
                source.continuous_sent = True
            if item.flapping and item.period_seq is not None:
                # Its period's one continuous notification: any other
                # unsent flapping episode of the same generation (the other
                # of owed / episode) is settled without a notice, also once
                # the period has closed meanwhile (Owner decision PR #335
                # over Issue #349 inside one flapping period; Claude
                # re-review PR #359 重要 1). Later episodes of a period still
                # open are covered by ``continuous_sent``.
                for other in (source.owed, source.episode):
                    if (other is not None and other is not item and not other.notified
                            and other.flapping and other.period_seq == item.period_seq):
                        other.notified = True
                        self._drop_recovered(source, other)
                        self._suppressed()
        self._drop_recovered(source, item)

    @staticmethod
    def _drop_recovered(source: _Source, item: _Episode) -> None:
        if item.recovered is not None:
            if source.episode is item:
                source.episode = None
            if source.owed is item:
                source.owed = None

    def _suppressed(self) -> None:
        """One flapping episode settled without a notice (value-free log)."""
        self.suppressed += 1
        logging.getLogger(__name__).info(Event.CAMERA_OFFLINE_NOTIFICATION_SUPPRESSED)

    def _flapping_name(self, identity, flapping_id) -> tuple[UUID | None, bool]:
        if flapping_id is None:
            return None, False
        try:
            value = flapping_id(identity)
        except Exception:
            return None, False
        if (type(value) is not tuple or len(value) != 2 or not isinstance(value[0], UUID)
                or not (type(value[1]) is bool or _aware(value[1]))
                or not self._usable(value[0])):
            return None, False
        return value

    def _durable(self, identity, durable_id) -> UUID | None:
        if durable_id is None:
            return None
        try:
            value = durable_id(identity)
        except Exception:
            return None
        if not isinstance(value, UUID) or not self._usable(value):
            return None
        return value

    def _usable(self, event_id: UUID) -> bool:
        """A durable name this process has not used, or a restored row's."""
        return event_id not in self._used or self._is_restored(event_id)

    @staticmethod
    def _known(event_id, known) -> bool | datetime:
        """``True`` (final row), a pending row's stored time, or ``False``."""
        if known is None:
            return False
        try:
            value = known(event_id)
        except Exception:
            # Unknown: notify rather than risk hiding an outage.
            return False
        return value if value is True or _aware(value) else False


def _ongoing(item) -> bool:
    """An outage or ratio period still in progress (a restored row counts)."""
    if isinstance(item, _Resend):
        return True
    if isinstance(item, _Flap):
        return not item.ended
    return item.recovered is None


def _of_period(source: _Source, item: _Episode) -> bool:
    """A flapping episode of the source's ratio-opened period still open."""
    return (source.period == _BY_RATIO and item.flapping
            and item.period_seq == source.period_seq)


def _due_order(entry):
    """In progress, then recovered or ended, by their start; restored rows last."""
    item = entry[1]
    if isinstance(item, _Resend):
        return (2, item.attempt[0].timestamp())
    return (0 if _ongoing(item) else 1, item.since)


def _aware(value) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None
