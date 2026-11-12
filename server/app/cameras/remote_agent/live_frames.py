"""Authorization and rate budget of capture ingest live frames (Issue #14).

Owner decision 2026-11-12 ("option A"): an Agent sends ``LIVE_FRAME``s
(``ingest_wire``) of each approved camera, at most 5 per second per source,
and the Main keeps only the newest one per source in memory for the live view
(``app.media.live.remote_preview``). The listener (``ingest_server``) applies,
per frame and in this order, after the frame's size (from its header) and the
pairing ledger's current record:

1. ``LiveFrameBudget.charge``: its own budget, separate from the heartbeat
   budget, of at most 6 frames per source and 24 per node per second, and at
   most 4 sources per node at once; anything beyond is ``rate_limited``;
2. ``RegistryLiveSources``: the camera registry must hold an enabled source
   of type ``remote_agent`` with that identity whose ``capture_node_id`` is
   the session's node; otherwise ``source_not_authorized``.

Identity (checked for this PR). The session's node is the pairing ledger's
``node_id``: the URI of its mTLS client certificate, checked against the
ledger's active record (``ingest_tls``). The registry's ``capture_nodes.id``
and ``camera_sources.capture_node_id`` are separate columns with no foreign
key to the ledger, and the registry's ``create_capture_node`` draws its own
UUID. The contract here is that a ``remote_agent`` source's
``capture_node_id`` **is** the ledger ``node_id`` of the node that captures
it (the registry row of a paired node is created with that UUID): a source
whose ``capture_node_id`` is any other value is never authorized, so a
registry node created with an unrelated UUID authorizes nothing (fail
closed). A registry node marked ``revoked`` authorizes nothing either.
The ``source UUID`` on the wire is the Main registry's ``camera_sources.id``.
"""

from __future__ import annotations

from contextlib import closing
import threading
import time
from typing import Callable
from uuid import UUID


LIVE_FRAMES_PER_SOURCE_PER_SECOND = 6
LIVE_FRAMES_PER_NODE_PER_SECOND = 24
MAXIMUM_LIVE_SOURCES_PER_NODE = 4
_WINDOW_NS = 1_000_000_000


class LiveFrameBudget:
    """Fixed one-second windows per node and per (node, source); thread-safe.

    Bounded: at most ``maximum_nodes`` nodes and ``maximum_sources_per_node``
    source windows per node are tracked; an expired window is reclaimed when
    room is needed. Over either bound, or over a window's count, ``charge``
    refuses. A clock that runs backwards refuses too (fail closed).
    """

    def __init__(self, *, maximum_nodes: int,
                 per_source: int = LIVE_FRAMES_PER_SOURCE_PER_SECOND,
                 per_node: int = LIVE_FRAMES_PER_NODE_PER_SECOND,
                 maximum_sources_per_node: int = MAXIMUM_LIVE_SOURCES_PER_NODE,
                 clock_ns: Callable[[], int] = time.monotonic_ns) -> None:
        if (any(type(value) is not int or value <= 0
                for value in (maximum_nodes, per_source, per_node, maximum_sources_per_node))
                or not callable(clock_ns)):
            raise ValueError("invalid live frame budget")
        self._maximum_nodes = maximum_nodes
        self._per_source = per_source
        self._per_node = per_node
        self._per_node_sources = maximum_sources_per_node
        self._clock_ns = clock_ns
        self._lock = threading.Lock()
        # node -> [window start, count, {source: [window start, count]}]
        self._nodes: dict[UUID, list] = {}

    @staticmethod
    def _expired(start: int, now: int) -> bool:
        return now >= start and now - start >= _WINDOW_NS

    def charge(self, node_id: UUID, source_id: UUID) -> bool:
        """Charge one live frame; False when it is over a bound."""
        if not isinstance(node_id, UUID) or not isinstance(source_id, UUID):
            return False
        now = self._clock_ns()
        if type(now) is not int or now < 0:
            return False
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                if len(self._nodes) >= self._maximum_nodes:
                    for key in [key for key, value in self._nodes.items()
                                if self._expired(value[0], now)
                                and all(self._expired(window[0], now)
                                        for window in value[2].values())]:
                        del self._nodes[key]
                if len(self._nodes) >= self._maximum_nodes:
                    return False
                node = self._nodes[node_id] = [now, 0, {}]
            if now < node[0]:
                return False
            if self._expired(node[0], now):
                node[0], node[1] = now, 0
            sources = node[2]
            window = sources.get(source_id)
            if window is None:
                if len(sources) >= self._per_node_sources:
                    for key in [key for key, value in sources.items()
                                if self._expired(value[0], now)]:
                        del sources[key]
                if len(sources) >= self._per_node_sources:
                    return False
                window = sources[source_id] = [now, 0]
            if now < window[0]:
                return False
            if self._expired(window[0], now):
                window[0], window[1] = now, 0
            if node[1] >= self._per_node or window[1] >= self._per_source:
                return False
            node[1] += 1
            window[1] += 1
            return True

    @property
    def tracked_nodes(self) -> int:
        with self._lock:
            return len(self._nodes)


class RegistryLiveSources:
    """``(node_id, source_id) -> bool`` from the camera registry, read-only.

    One read-only transaction per frame on a connection that never creates
    the database (``Database.connect_read_only``); any failure denies.
    """

    _QUERY = (
        "SELECT 1 FROM camera_sources s JOIN capture_nodes n ON n.id = s.capture_node_id"
        " WHERE s.id = ? AND s.source_type = 'remote_agent' AND s.enabled = 1"
        " AND s.capture_node_id = ? AND n.health_state != 'revoked'")

    def __init__(self, database) -> None:
        if not callable(getattr(database, "connect_read_only", None)):
            raise ValueError("registry database is required")
        self._database = database

    def __call__(self, node_id: UUID, source_id: UUID) -> bool:
        if not isinstance(node_id, UUID) or not isinstance(source_id, UUID):
            return False
        try:
            with closing(self._database.connect_read_only()) as connection:
                connection.execute("BEGIN")
                row = connection.execute(self._QUERY, (str(source_id), str(node_id))).fetchone()
                connection.execute("COMMIT")
        except Exception:
            return False
        return row is not None
