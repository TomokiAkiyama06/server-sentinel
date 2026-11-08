"""Capture-node health from authenticated heartbeats (SPECIFICATION §5.8, #14).

Memory only and hard-bounded: one entry per node that held an admitted ingest
session in this process, at most ``maximum_nodes``. Node health is separate
from camera health and from media-flow continuity (``continuity.py``); a
heartbeat never makes a camera ``online``.

States (§5.8): ``online`` and ``degraded`` come from the latest heartbeat of a
connected node; ``offline`` is a known node without a heartbeat within
``stale_after_seconds`` (also after its session closed). A revoked node is
forgotten (``forget``), so it is not counted at all. A process restart starts
empty: a node is known again once it connects.

``snapshot`` is value-free: counts and fixed reason words, never a node UUID,
address or byte count.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from threading import Lock
import time
from typing import Callable
from uuid import UUID

from .ingest_wire import NodeHeartbeat


@dataclass
class _Node:
    generation: int
    connected: bool
    last_heartbeat: float | None = None
    heartbeat: NodeHeartbeat | None = None


@dataclass(frozen=True)
class CaptureNodeHealthSnapshot:
    known_nodes: int
    connected_nodes: int
    online_nodes: int
    degraded_nodes: int
    offline_nodes: int
    storage_degraded_nodes: int
    # Sorted fixed words from ``ingest_wire.KNOWN_NODE_REASONS`` (or ``other``).
    reasons: tuple[str, ...]


class CaptureNodeHealthRegistry:
    def __init__(self, *, maximum_nodes: int = 64, stale_after_seconds: float = 10.0,
                 monotonic: Callable[[], float] = time.monotonic):
        if type(maximum_nodes) is not int or maximum_nodes <= 0:
            raise ValueError("invalid node limit")
        if (type(stale_after_seconds) not in (int, float) or not math.isfinite(stale_after_seconds)
                or stale_after_seconds <= 0):
            raise ValueError("invalid stale bound")
        if not callable(monotonic):
            raise ValueError("invalid clock")
        self._maximum = maximum_nodes
        self._stale = float(stale_after_seconds)
        self._monotonic = monotonic
        self._nodes: dict[UUID, _Node] = {}
        self._lock = Lock()

    def connected(self, node_id: UUID, generation: int) -> bool:
        """Record a newly admitted session; False when the table is full.

        A node already known is admitted when ``generation`` is newer than
        the one it holds (its newer session replaces the older); an older or
        equal generation is refused, so a late registration can never
        replace a newer session (PR #401 review). A new node needs room, made
        by dropping the oldest entry that is not connected, or it is refused
        (fail closed, bounded).
        """
        with self._lock:
            entry = self._nodes.get(node_id)
            if entry is not None and generation <= entry.generation:
                return False
            if entry is None:
                if len(self._nodes) >= self._maximum:
                    idle = next((node for node, item in self._nodes.items()
                                 if not item.connected), None)
                    if idle is None:
                        return False
                    del self._nodes[idle]
                self._nodes[node_id] = _Node(generation, True)
            else:
                entry.generation = generation
                entry.connected = True
            return True

    def heartbeat(self, generation: int, heartbeat: NodeHeartbeat) -> bool:
        """Keep a heartbeat of the current session; False for a superseded one."""
        with self._lock:
            entry = self._nodes.get(heartbeat.node_id)
            if entry is None or entry.generation != generation or not entry.connected:
                return False
            entry.heartbeat = heartbeat
            entry.last_heartbeat = self._monotonic()
            return True

    def disconnected(self, node_id: UUID, generation: int) -> None:
        with self._lock:
            entry = self._nodes.get(node_id)
            if entry is not None and entry.generation == generation:
                entry.connected = False

    def forget(self, node_id: UUID) -> None:
        with self._lock:
            self._nodes.pop(node_id, None)

    def state(self, node_id: UUID) -> str | None:
        """The node's §5.8 state, or None for an unknown (or revoked) node."""
        with self._lock:
            entry = self._nodes.get(node_id)
            return None if entry is None else self._state(entry, self._monotonic())

    def _state(self, entry: _Node, now: float) -> str:
        if (not entry.connected or entry.heartbeat is None or entry.last_heartbeat is None
                or not 0 <= now - entry.last_heartbeat <= self._stale):
            return "offline"
        return entry.heartbeat.node_state

    def snapshot(self) -> CaptureNodeHealthSnapshot:
        with self._lock:
            now = self._monotonic()
            states = [(self._state(entry, now), entry) for entry in self._nodes.values()]
        reasons = sorted({reason for state, entry in states if state == "degraded"
                          for reason in entry.heartbeat.reasons})
        return CaptureNodeHealthSnapshot(
            known_nodes=len(states),
            connected_nodes=sum(entry.connected for _, entry in states),
            online_nodes=sum(state == "online" for state, _ in states),
            degraded_nodes=sum(state == "degraded" for state, _ in states),
            offline_nodes=sum(state == "offline" for state, _ in states),
            storage_degraded_nodes=sum(state != "offline" and entry.heartbeat.storage_state
                                       != "online" for state, entry in states),
            reasons=tuple(reasons),
        )
