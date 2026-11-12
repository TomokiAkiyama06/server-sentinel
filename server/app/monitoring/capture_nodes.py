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
idle timeout) its episodes neither end nor become due: heartbeat loss is
#397. A revoked node is forgotten by the registry, and its episodes with it.
At most ``HOURLY_LIMIT`` (4) node notices per node per rolling hour; one held
by the cap is sent once the cap frees, saying so if it already recovered.

The listener: configured (state ``starting`` or ``unavailable``: material
unreadable, bind being retried) but not ``running`` for 5 min sends one
``capture_ingest_unavailable`` per episode. ``disabled`` (no deployment
section) and ``stopped`` (the stop) start none.

Event IDs are deterministic per episode (the node, the kind and the UTC time
the episode began). Node health lives in memory, so a Main restart starts new
episodes: a node still degraded after a restart is notified again once, and
the hourly window starts empty. Notices are value-free: the kind word only,
never a node UUID, address or reason text.
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
    # A configured listener that is not running yet or any more.
    listener_unavailable: bool = False
    # Node episodes past their delay whose notice is not recorded yet.
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
    # Became due on a drain (so a recovery after an offline gap still owes it).
    reached: bool = False

    def due(self, now: float) -> bool:
        return not self.notified and (
            self.recovered or self.observed and now - self.started >= self.delay)


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
        self._episodes: dict[tuple[object, NotificationKind], _Episode] = {}
        self._sent: dict[UUID, deque[float]] = {}

    def drain(self, notifications: NotificationService, *, at: datetime,
              monotonic: float) -> CaptureHealthStatus:
        """Observe the provider once, then record every due notice the cap allows."""
        state, nodes = self._provider()
        nodes = tuple(nodes)
        self._observe_listener(state, at, monotonic)
        self._observe_nodes(nodes, at, monotonic)
        held = 0
        for key, episode in sorted(self._episodes.items(), key=lambda item: item[1].started):
            if not episode.due(monotonic):
                continue
            # Due while observed: owed even if the node goes offline before
            # it recovers (a held notice keeps it).
            episode.reached = True
            node = key[0]
            window = None if node == _LISTENER else self._window(node, monotonic)
            if window is not None and len(window) >= self.hourly_limit:
                held += 1
                continue
            result = notifications.record(episode.kind, at=at, confirmed=True,
                                          event_id=episode.event_id,
                                          recovered=episode.recovered)
            if result is DeliveryResult.FAILED:
                # Not recorded (local write refused, retry buffer full):
                # still owed, tried again on the next tick.
                held += 1
                continue
            episode.notified = True
            if window is not None:
                window.append(monotonic)
            if episode.recovered:
                del self._episodes[key]
        return CaptureHealthStatus(
            online_nodes=sum(node.state == "online" for node in nodes),
            degraded_nodes=sum(node.state == "degraded" for node in nodes),
            offline_nodes=sum(node.state == "offline" for node in nodes),
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
        if current is not None and not current.recovered:
            current.observed = True
            return
        # A held notice of an episode that recovered is replaced by the new
        # episode (one per node and kind, so the table stays bounded).
        self._episodes[key] = _Episode(
            kind, delay, now, uuid5(_NAMESPACE, f"{kind.value}:{key[0]}:{at.isoformat()}"))

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
                    if episode is not None and not episode.recovered:
                        episode.observed = False
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
                    episode = self._episodes.get(key)
                    if episode is not None and not episode.recovered:
                        if not episode.notified and (episode.reached or episode.observed and (
                                now - episode.started >= episode.delay)):
                            # It reached its delay while observed degraded (the
                            # cap held it, or it was reached since the last
                            # drain): still sent once, saying it already
                            # recovered. Time offline does not count.
                            episode.recovered = True
                        else:
                            del self._episodes[key]
        for key in [key for key in self._episodes
                    if key[0] != _LISTENER and key[0] not in known]:
            # Forgotten by the registry (revoked, or dropped for room).
            del self._episodes[key]
        for node in [node for node in self._sent if node not in known]:
            del self._sent[node]
