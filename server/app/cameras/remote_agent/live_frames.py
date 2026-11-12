"""Authorization and rate budget of capture ingest live frames (Issue #14).

Owner decision 2026-11-12 ("option A"): an Agent sends ``LIVE_FRAME``s
(``ingest_wire``) of every camera it approved, at most 5 per second per
source, and the Main keeps only the newest one per source in memory for the
live view (``app.media.live.remote_preview``). The listener
(``ingest_server``) applies, per frame and in this order, after the frame's
size (from its header) and the pairing ledger's current record:

1. the body's form (``live_frame_invalid`` closes the session);
2. ``LiveFrameBudget.flooding``: per-node flood bounds, of ten times the node
   refill rate in frames (240 per second, burst 1200) and of 16 MB per second
   (burst 80 MB, about 5 s) in body bytes, twice the ordinary 8 MB/s of four
   sources at 5 fps with 0.4 MB frames (PR #416 review: a node sending 1 MiB
   frames at line rate stays far below the frame bound); only a node beyond
   either is closed (``rate_limited``);
3. ``CachedLiveSources``: the camera registry must hold an enabled source of
   type ``remote_agent`` with that identity whose ``capture_node_id`` is the
   session's node (``RegistryLiveSources``), cached per (node, source) for
   1 s; otherwise the frame is **dropped and counted**, the session stays
   open. An Agent sends every camera it approved, so a source the Owner has
   not created on the Main yet, or disabled, is an ordinary state (PR #416
   review);
4. ``LiveFrameBudget.charge``: token buckets separate from the heartbeat
   budget, per source (refill 6 per second, burst 30) and per node (refill 24
   per second, burst 120), at most 4 sources per node at once; a frame beyond
   them is **dropped and counted**. The bursts absorb the frames an Agent
   sends at once after a pause of the Main or the network.

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

from .ingest_wire import MAXIMUM_LIVE_FRAME_BODY_BYTES


SOURCE_REFILL_PER_SECOND = 6
SOURCE_BURST = 30
NODE_REFILL_PER_SECOND = 24
NODE_BURST = 120
# Closing needs a node to sustain more than ten times its refill rate.
FLOOD_FACTOR = 10
# ... or more body bytes than twice what a node may send within the contract
# (its refill rate of maximum-size frames, about 25 MB/s; PR #416 review: a
# conforming Agent with 4 cameras at 5 fps and large frames must never be
# closed), with a 5 s burst. A node at 1 Gbit/s line rate is still closed.
FLOOD_BYTES_PER_SECOND = 2 * NODE_REFILL_PER_SECOND * MAXIMUM_LIVE_FRAME_BODY_BYTES
FLOOD_BYTES_BURST = 5 * FLOOD_BYTES_PER_SECOND
MAXIMUM_LIVE_SOURCES_PER_NODE = 4
AUTHORIZATION_CACHE_SECONDS = 1.0
# Distinct sources a node may have looked up in the registry at once (each
# cached for AUTHORIZATION_CACHE_SECONDS): bounds the registry reads of a node
# that sends many unknown source identities.
MAXIMUM_LOOKUPS_PER_NODE = 8
_NS = 1_000_000_000


class _Bucket:
    """A token bucket on an integer nanosecond clock; never refills backwards."""

    __slots__ = ("tokens", "last")

    def __init__(self, burst: float, now: int):
        self.tokens = float(burst)
        self.last = now

    def refill(self, now: int, rate: float, burst: float) -> None:
        if now > self.last:
            self.tokens = min(float(burst), self.tokens + (now - self.last) * rate / _NS)
            self.last = now

    def full(self, now: int, rate: float, burst: float) -> bool:
        self.refill(now, rate, burst)
        return self.tokens >= burst


class LiveFrameBudget:
    """Per-node and per-(node, source) token buckets plus a per-node flood bound.

    Thread-safe and bounded: at most ``maximum_nodes`` nodes and
    ``maximum_sources_per_node`` source buckets per node are tracked; a bucket
    that refilled completely is reclaimed when room is needed (a full bucket
    carries no state). A clock that runs backwards refills nothing.
    """

    def __init__(self, *, maximum_nodes: int,
                 source_refill: float = SOURCE_REFILL_PER_SECOND, source_burst: int = SOURCE_BURST,
                 node_refill: float = NODE_REFILL_PER_SECOND, node_burst: int = NODE_BURST,
                 flood_factor: int = FLOOD_FACTOR,
                 flood_bytes_per_second: int = FLOOD_BYTES_PER_SECOND,
                 flood_bytes_burst: int = FLOOD_BYTES_BURST,
                 maximum_sources_per_node: int = MAXIMUM_LIVE_SOURCES_PER_NODE,
                 clock_ns: Callable[[], int] = time.monotonic_ns) -> None:
        if (any(type(value) is not int or value <= 0
                for value in (maximum_nodes, source_burst, node_burst, flood_factor,
                              flood_bytes_per_second, flood_bytes_burst,
                              maximum_sources_per_node))
                or any(isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
                       for value in (source_refill, node_refill))
                or not callable(clock_ns)):
            raise ValueError("invalid live frame budget")
        self._maximum_nodes = maximum_nodes
        self._source = (float(source_refill), source_burst)
        self._node = (float(node_refill), node_burst)
        self._flood = (float(node_refill) * flood_factor, node_burst * flood_factor)
        self._flood_bytes = (float(flood_bytes_per_second), flood_bytes_burst)
        self._per_node_sources = maximum_sources_per_node
        self._clock_ns = clock_ns
        self._lock = threading.Lock()
        # node -> (flood bucket, node bucket, {source: bucket}, flood byte bucket)
        self._nodes: dict[UUID, tuple[_Bucket, _Bucket, dict[UUID, _Bucket], _Bucket]] = {}

    def _now(self) -> int | None:
        now = self._clock_ns()
        return now if type(now) is int and now >= 0 else None

    def _node_locked(self, node_id: UUID, now: int):
        entry = self._nodes.get(node_id)
        if entry is None:
            if len(self._nodes) >= self._maximum_nodes:
                for key in [key for key, (flood, node, sources, volume) in self._nodes.items()
                            if flood.full(now, *self._flood) and node.full(now, *self._node)
                            and volume.full(now, *self._flood_bytes)
                            and all(bucket.full(now, *self._source)
                                    for bucket in sources.values())]:
                    del self._nodes[key]
            if len(self._nodes) >= self._maximum_nodes:
                return None
            entry = self._nodes[node_id] = (_Bucket(self._flood[1], now),
                                            _Bucket(self._node[1], now), {},
                                            _Bucket(self._flood_bytes[1], now))
        return entry

    def flooding(self, node_id: UUID, size: int = 0) -> bool:
        """Charge one live frame attempt of ``size`` body bytes to the flood bounds; True closes.

        Every attempt is charged, whatever happens to the frame later. A node
        floods only beyond ten times the node bucket's refill rate and burst
        in frames, or beyond ``FLOOD_BYTES_PER_SECOND`` (burst
        ``FLOOD_BYTES_BURST``) in body bytes.
        """
        if not isinstance(node_id, UUID) or type(size) is not int or size < 0:
            return True
        now = self._now()
        if now is None:
            return True
        with self._lock:
            entry = self._node_locked(node_id, now)
            if entry is None:
                # The node table is full of nodes that are all still active:
                # nothing is tracked for this one, so it is not charged; its
                # frames are dropped by `charge` below.
                return False
            flood, volume = entry[0], entry[3]
            flood.refill(now, *self._flood)
            volume.refill(now, *self._flood_bytes)
            if flood.tokens < 1 or volume.tokens < size:
                return True
            flood.tokens -= 1
            volume.tokens -= size
            return False

    def charge(self, node_id: UUID, source_id: UUID) -> bool:
        """Take one token from the source's and the node's bucket; False drops the frame."""
        if not isinstance(node_id, UUID) or not isinstance(source_id, UUID):
            return False
        now = self._now()
        if now is None:
            return False
        with self._lock:
            entry = self._node_locked(node_id, now)
            if entry is None:
                return False
            _, node, sources, _ = entry
            bucket = sources.get(source_id)
            if bucket is None:
                if len(sources) >= self._per_node_sources:
                    for key in [key for key, value in sources.items()
                                if value.full(now, *self._source)]:
                        del sources[key]
                if len(sources) >= self._per_node_sources:
                    return False
                bucket = sources[source_id] = _Bucket(self._source[1], now)
            node.refill(now, *self._node)
            bucket.refill(now, *self._source)
            if node.tokens < 1 or bucket.tokens < 1:
                return False
            node.tokens -= 1
            bucket.tokens -= 1
            return True

    @property
    def tracked_nodes(self) -> int:
        with self._lock:
            return len(self._nodes)


class RegistryLiveSources:
    """``(node_id, source_id) -> bool`` from the camera registry, read-only.

    One read-only transaction on a connection that never creates the
    database (``Database.connect_read_only``); any failure denies.
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


class CachedLiveSources:
    """A short-lived cache of an authorizer's answer per (node, source).

    An answer (allowed or denied) is reused for ``ttl_seconds`` (1 s), so a
    disabled source stops being shown within about a second and a node's
    frames cost at most one registry read per source per second. At most
    ``maximum_per_node`` sources of a node are cached at once; a further
    unknown source while they are all current is denied without a read, so a
    node cycling through source identities cannot drive registry reads. An
    authorizer that raises denies and is not cached. ``forget`` drops a node.
    """

    def __init__(self, authorizer: Callable[[UUID, UUID], bool], *,
                 maximum_nodes: int, ttl_seconds: float = AUTHORIZATION_CACHE_SECONDS,
                 maximum_per_node: int = MAXIMUM_LOOKUPS_PER_NODE,
                 clock_ns: Callable[[], int] = time.monotonic_ns) -> None:
        if (not callable(authorizer) or type(maximum_nodes) is not int or maximum_nodes <= 0
                or type(maximum_per_node) is not int or maximum_per_node <= 0
                or isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float))
                or not 0 < ttl_seconds <= 60 or not callable(clock_ns)):
            raise ValueError("invalid live source cache")
        self._authorizer = authorizer
        self._maximum_nodes = maximum_nodes
        self._ttl = int(ttl_seconds * _NS)
        self._per_node = maximum_per_node
        self._clock_ns = clock_ns
        self._lock = threading.Lock()
        # node -> {source: (answer, read at)}
        self._entries: dict[UUID, dict[UUID, tuple[bool, int]]] = {}

    def _current(self, read_at: int, now: int) -> bool:
        return read_at <= now < read_at + self._ttl

    def __call__(self, node_id: UUID, source_id: UUID) -> bool:
        if not isinstance(node_id, UUID) or not isinstance(source_id, UUID):
            return False
        now = self._clock_ns()
        if type(now) is not int:
            return False
        with self._lock:
            node = self._entries.get(node_id, {})
            cached = node.get(source_id)
            if cached is not None and self._current(cached[1], now):
                return cached[0]
            for key in [key for key, (_, at) in node.items() if not self._current(at, now)]:
                del node[key]
            if len(node) >= self._per_node:
                return False
        # The registry read runs outside the lock (other nodes' frames go on).
        try:
            answer = self._authorizer(node_id, source_id) is True
        except Exception:
            return False
        with self._lock:
            node = self._entries.get(node_id)
            if node is None:
                if len(self._entries) >= self._maximum_nodes:
                    for key in [key for key, values in self._entries.items()
                                if all(not self._current(at, now) for _, at in values.values())]:
                        del self._entries[key]
                if len(self._entries) >= self._maximum_nodes:
                    return answer
                node = self._entries[node_id] = {}
            if source_id in node or len(node) < self._per_node:
                node[source_id] = (answer, now)
        return answer

    def forget(self, node_id: UUID) -> None:
        with self._lock:
            self._entries.pop(node_id, None)
