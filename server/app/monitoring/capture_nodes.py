"""Owner notices for capture-node health and the ingest listener (Issue #14).

Owner decision 2026-11-12. The inputs are the capture ingest listener's state
word and the in-memory node health of its registry
(``app.cameras.remote_agent.node_health``), read through a provider the
composition root builds (``app.main``). ``drain`` runs on the monitoring
worker on every monitoring tick, like the camera offline monitor, and submits
through the same ``NotificationService`` (durable row, optional Slack).

Notices, by the reason words of a node's latest heartbeat (degraded only):

* ``storage_unavailable`` -> ``capture_node_storage_failure`` at the next
  tick (the Agent cannot write its ring buffer);
* ``storage_device_numbers_stale`` -> ``capture_node_device_numbers_changed``
  once it lasted ``NOTICE_AFTER_SECONDS`` (5 min; Issue #324, the Agent
  counterpart of Main's ``recording_device_numbers_changed``);
* any ``clock_*`` reason -> ``capture_node_clock_degraded`` after the same
  5 min;
* ``capture_unconfigured`` and ``other`` are never notified (the Agent
  reports ``capture_unconfigured`` until its capture adapter is wired).

Each episode (one node and one notice kind, from the first heartbeat that
showed the reason to the first heartbeat without it) notifies once; a
recovery is not notified. While a node is offline (no heartbeat within the
idle timeout) its episodes neither end nor become due, and only observed
time counts towards the 5 min: the episode's start moves forward by the time
it was not observed (heartbeat loss is #397). A revoked node is forgotten by
the registry, and its episodes with it.

At most ``HOURLY_LIMIT`` (4) node notices per node per rolling hour. An
episode that reached its delay while observed is owed: the cap holds it
(also while the node is offline) and it is sent once the cap frees, saying
so if it already recovered. Per node and kind at most one owed episode that
already recovered is kept beside the current one; a further one replaces the
older (bounded, as the camera offline monitor's hold limit). After a Main
restart the hour is re-seeded from the node notices accepted in the last
hour (``restore_window``): their rows name no node, so they count against
every node (conservative), and a restart loop cannot exceed the cap.

The listener: configured (state ``starting`` or ``unavailable``: material
unreadable, bind being retried) but not ``running`` for 5 min sends one
``capture_ingest_unavailable`` per episode. ``disabled`` (no deployment
section) and ``stopped`` (the stop) start none.

Event IDs are deterministic per episode (the node, the kind and the UTC time
the episode began), and the first attempt's time is kept for every retry. A
full or closed queue (``can_accept``) and an unrecorded result leave the
notice owed; a result kept for the local write retry (``retained``) counts as
recorded. Node health lives in memory, so a Main restart starts new episodes:
a node still degraded after a restart is notified again once (within the
restored cap). Notices are value-free: the kind word only, never a node UUID,
address or reason text.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
import math
from typing import Callable, Iterable
from uuid import UUID, uuid5

from app.notifications.service import DeliveryResult, NotificationKind, NotificationService


NOTICE_AFTER_SECONDS = 300.0
# The node notice kinds whose accepted rows re-seed the hourly cap.
NODE_NOTICE_KINDS = (
    NotificationKind.CAPTURE_NODE_STORAGE_FAILURE,
    NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED,
    NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED,
)
HOURLY_LIMIT = 4
_HOUR = 3600.0
_NAMESPACE = UUID("7b0c55a4-4f3e-5d4b-9c55-2f1a8e5d0c14")
_LISTENER = "listener"
# (kind, delay, matches the reasons of a degraded heartbeat)
_NODE_NOTICES: tuple[tuple[NotificationKind, float, Callable[[tuple[str, ...]], bool]], ...] = (
    (NotificationKind.CAPTURE_NODE_STORAGE_FAILURE, 0.0,
     lambda reasons: "storage_unavailable" in reasons),
    (NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED, NOTICE_AFTER_SECONDS,
     lambda reasons: "storage_device_numbers_stale" in reasons),
    (NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED, NOTICE_AFTER_SECONDS,
     lambda reasons: any(reason.startswith("clock_") for reason in reasons)),
)
_LISTENER_PENDING = frozenset({"starting", "unavailable"})


@dataclass(frozen=True)
class CaptureNodeView:
    """One known node as the registry sees it (``CaptureNodeHealthRegistry.nodes``)."""

    node_id: UUID
    state: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CaptureHealthStatus:
    """Value-free counts for the runtime status and the daily summary."""

    online_nodes: int = 0
    degraded_nodes: int = 0
    offline_nodes: int = 0
    # Degraded for a reason that is notified (not `capture_unconfigured` or
    # `other` alone): what the daily summary counts as degraded.
    notable_degraded_nodes: int = 0
    # A configured listener that is not running yet or any more.
    listener_unavailable: bool = False
    # Owed node notices not recorded yet (cap, full queue, refused write).
    held_notices: int = 0


@dataclass
class _Episode:
    kind: NotificationKind
    delay: float
    started: float
    event_id: UUID
    notified: bool = False
    recovered: bool = False
    # Observed with its reason on this drain (False while the node is
    # offline: its episode then neither ends nor becomes due).
    observed: bool = True
    # Reached its delay while observed: owed from then on.
    reached: bool = False
    paused_at: float | None = None
    # The first attempt's time, kept for every retry of the same row.
    at: datetime | None = None

    def pause(self, now: float) -> None:
        if self.observed:
            self.observed = False
            self.paused_at = now

    def resume(self, now: float) -> None:
        if not self.observed:
            if self.paused_at is not None:
                # Only observed time counts towards the delay.
                self.started += max(0.0, now - self.paused_at)
            self.observed = True
            self.paused_at = None

    def check(self, now: float) -> None:
        if self.observed and now - self.started >= self.delay:
            self.reached = True

    def due(self) -> bool:
        return not self.notified and (self.recovered or self.reached)


class CaptureNodeHealthMonitor:
    def __init__(self, provider: Callable[[], tuple[str, Iterable[CaptureNodeView]]], *,
                 after_seconds: float = NOTICE_AFTER_SECONDS, hourly_limit: int = HOURLY_LIMIT):
        if (not callable(provider) or type(after_seconds) not in (int, float)
                or not math.isfinite(after_seconds) or after_seconds < 0
                or type(hourly_limit) is not int or hourly_limit <= 0):
            raise ValueError("invalid capture node health monitor")
        self._provider = provider
        self._after = float(after_seconds)
        self.hourly_limit = hourly_limit
        # Current episodes, and owed ones that already recovered.
        self._episodes: dict[tuple[object, NotificationKind], _Episode] = {}
        self._held: dict[tuple[object, NotificationKind], _Episode] = {}
        self._sent: dict[UUID, deque[float]] = {}
        # Restored node notices of an earlier process (any node).
        self._restored: deque[float] = deque()
        # This process's own notices (bounded; only the restore reads it).
        self._own: deque[UUID] = deque(maxlen=256)

    def restore_window(self, rows, *, monotonic: float) -> None:
        """Re-seed the hour from ``(event ID, age seconds)`` of accepted node notice rows.

        The rows name no node, so each counts against every node. Rows of
        this process's own notices are not counted twice.
        """
        rows = tuple(rows)
        if (type(monotonic) not in (int, float) or any(
                type(row) is not tuple or len(row) != 2 or not isinstance(row[0], UUID)
                or type(row[1]) not in (int, float) or not math.isfinite(row[1])
                for row in rows)):
            raise ValueError("invalid restored window")
        if not math.isfinite(monotonic):
            return
        self._restored = deque(sorted(monotonic - age for event_id, age in rows
                                      if 0 <= age < _HOUR and event_id not in self._own))

    def drain(self, notifications: NotificationService, *, at: datetime,
              monotonic: float) -> CaptureHealthStatus:
        """Observe the provider once, then record every owed notice the cap allows."""
        state, nodes = self._provider()
        nodes = tuple(nodes)
        self._observe_listener(state, at, monotonic)
        self._observe_nodes(nodes, at, monotonic)
        while self._restored and monotonic - self._restored[0] >= _HOUR:
            self._restored.popleft()
        held = 0
        owed = [(key, episode, self._held) for key, episode in self._held.items()]
        owed += [(key, episode, self._episodes) for key, episode in self._episodes.items()]
        for key, episode, table in sorted(owed, key=lambda item: item[1].started):
            if not episode.due():
                continue
            node = key[0]
            window = None if node == _LISTENER else self._window(node, monotonic)
            if window is not None and len(window) + len(self._restored) >= self.hourly_limit:
                held += 1
                continue
            if episode.at is None:
                episode.at = at
            if not notifications.can_accept(episode.event_id):
                # Queue full or closed: retried on the next drain.
                held += 1
                continue
            result = notifications.record(episode.kind, at=episode.at, confirmed=True,
                                          event_id=episode.event_id,
                                          recovered=episode.recovered)
            if (result is DeliveryResult.FAILED
                    and not notifications.retained(episode.event_id)):
                # Not recorded (local write refused, retry buffer full):
                # still owed, tried again on the next tick.
                held += 1
                continue
            episode.notified = True
            self._own.append(episode.event_id)
            if window is not None:
                window.append(monotonic)
            if table is self._held:
                del self._held[key]
        return CaptureHealthStatus(
            online_nodes=sum(node.state == "online" for node in nodes),
            degraded_nodes=sum(node.state == "degraded" for node in nodes),
            offline_nodes=sum(node.state == "offline" for node in nodes),
            notable_degraded_nodes=sum(
                node.state == "degraded"
                and any(matches(node.reasons) for _kind, _delay, matches in _NODE_NOTICES)
                for node in nodes),
            listener_unavailable=state in _LISTENER_PENDING,
            held_notices=held)

    # -- observation ---------------------------------------------------------

    def _window(self, node: UUID, now: float) -> deque[float]:
        window = self._sent.setdefault(node, deque())
        while window and now - window[0] >= _HOUR:
            window.popleft()
        return window

    def _begin(self, key, kind: NotificationKind, delay: float, at: datetime,
               now: float) -> None:
        current = self._episodes.get(key)
        if current is None:
            current = self._episodes[key] = _Episode(
                kind, delay, now, uuid5(_NAMESPACE, f"{kind.value}:{key[0]}:{at.isoformat()}"))
        current.resume(now)
        current.check(now)

    def _recovered(self, key, now: float) -> None:
        """End the current episode of ``key``; keep it if it is owed."""
        episode = self._episodes.pop(key, None)
        if episode is None:
            return
        episode.check(now)
        if not episode.notified and episode.reached:
            # It reached its delay while observed (the cap held it, or it
            # was reached since the last drain): still sent once, saying it
            # already recovered. A newer owed one replaces an older.
            episode.recovered = True
            self._held[key] = episode

    def _observe_listener(self, state: str, at: datetime, now: float) -> None:
        key = (_LISTENER, NotificationKind.CAPTURE_INGEST_UNAVAILABLE)
        if state in _LISTENER_PENDING:
            self._begin(key, NotificationKind.CAPTURE_INGEST_UNAVAILABLE, self._after, at, now)
        else:
            # Running again, or no listener at all: no recovery notice, and a
            # notice not yet sent is not owed (the listener has no hourly cap).
            self._episodes.pop(key, None)

    def _observe_nodes(self, nodes: tuple[CaptureNodeView, ...], at: datetime,
                       now: float) -> None:
        known = set()
        for node in nodes:
            known.add(node.node_id)
            if node.state == "offline":
                for kind, _delay, _matches in _NODE_NOTICES:
                    episode = self._episodes.get((node.node_id, kind))
                    if episode is not None:
                        episode.check(now)
                        episode.pause(now)
                continue
            reasons = node.reasons if node.state == "degraded" else ()
            for kind, delay, matches in _NODE_NOTICES:
                key = (node.node_id, kind)
                # Only the storage failure is immediate; the others wait
                # `after_seconds` (5 min by the Owner decision).
                delay = 0.0 if delay == 0 else self._after
                if matches(reasons):
                    self._begin(key, kind, delay, at, now)
                else:
                    self._recovered(key, now)
        for table in (self._episodes, self._held):
            for key in [key for key in table if key[0] != _LISTENER and key[0] not in known]:
                # Forgotten by the registry (revoked, or dropped for room).
                del table[key]
        active = known | {key[0] for key in self._episodes} | {key[0] for key in self._held}
        for node in [node for node in self._sent if node not in active]:
            del self._sent[node]
