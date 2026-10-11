"""Bounded per-source rate limiting for the pre-credential human routes (Issue #181).

The authentication ceremony runs before any credential exists, so anyone who
can reach the human listener can call it. ``begin_authentication`` stores a
challenge inside the session gate, so a flood would make the reservation
check's close wait for the gate lock (``threading.Lock`` is not fair). The
limiter runs before the ceremony, outside every gate and SQLite lock.

Source key: the backend sees every human request from the loopback proxy, so
the transport peer names no viewer, and client-controlled ``Forwarded`` /
``X-Forwarded-For`` values are never trusted (ADR-0003). The only source
attribute the backend can rely on is the verified trusted-proxy identity, so
that is the key. In the shared-Tailscale-account deployment every person
presents the same login, so the per-source bucket is shared by the room: a
holder of the shared login who floods the route can delay sign-in for the
others (availability), never gain access (an Owner-reviewable trade-off, see
``server/app/auth/README.md``). A global bucket bounds the total rate across
all sources.

Memory is bounded: at most ``max_sources`` buckets, keyed by a SHA-256 digest of
the identity rather than the identity itself. When the table is full, the
least recently used bucket is evicted only if it has refilled completely (an
evicted full bucket behaves exactly like an absent one); otherwise the new
source is refused, which fails closed instead of growing.

Logging is value-free: a limited request writes at most one
``human_request_rate_limited`` event per ``log_interval_seconds``, with no
identity, digest, path or count.

Invitation redemption (Issue #10 phase 2 S2, Owner decision D4) uses its own,
stricter instance (``redemption_rate_limiter``): per source a burst of 5 and
one more every 12 seconds, and a global bucket of 10 refilled every 6 seconds.
It is a separate object with separate buckets, so a redemption flood never
spends the sign-in buckets and a sign-in flood never spends the redemption
ones. It comes on top of the per-code attempt bound
(``store.MAX_REDEMPTION_ATTEMPTS``).
"""

from __future__ import annotations

from collections import OrderedDict
import hashlib
import logging
import math
import threading
import time
from typing import Callable

from app.logging import Event


def _positive(value) -> bool:
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and value > 0)


class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, updated: float):
        self.tokens = tokens
        self.updated = updated


class SourceRateLimiter:
    """Token buckets per source plus one global bucket; thread safe."""

    def __init__(self, *, per_source_capacity: int = 20, per_source_refill_seconds: float = 3.0,
                 global_capacity: int = 120, global_refill_seconds: float = 0.5,
                 max_sources: int = 256, log_interval_seconds: float = 60.0,
                 monotonic: Callable[[], float] = time.monotonic):
        for value in (per_source_capacity, global_capacity, max_sources):
            if type(value) is not int or value < 1:
                raise ValueError("rate limit configuration is invalid")
        for value in (per_source_refill_seconds, global_refill_seconds, log_interval_seconds):
            if not _positive(value):
                raise ValueError("rate limit configuration is invalid")
        if not callable(monotonic):
            raise ValueError("rate limit configuration is invalid")
        self.per_source_capacity = per_source_capacity
        self.per_source_refill_seconds = float(per_source_refill_seconds)
        self.global_capacity = global_capacity
        self.global_refill_seconds = float(global_refill_seconds)
        self.max_sources = max_sources
        self.log_interval_seconds = float(log_interval_seconds)
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._sources: OrderedDict[bytes, _Bucket] = OrderedDict()
        self._global: _Bucket | None = None
        self._last_logged: float | None = None
        # Bounded health only: how many requests were refused.
        self.limited = 0

    @staticmethod
    def _refill(bucket: _Bucket, now: float, capacity: int, period: float) -> None:
        if now < bucket.updated:
            # A clock that moved backwards never adds tokens.
            bucket.updated = now
            return
        bucket.tokens = min(float(capacity), bucket.tokens + (now - bucket.updated) / period)
        bucket.updated = now

    def _now(self) -> float | None:
        try:
            now = self._monotonic()
        except Exception:
            return None
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            return None
        return float(now)

    def sources(self) -> int:
        with self._lock:
            return len(self._sources)

    def allow(self, source: str) -> bool:
        """Consume one token for ``source`` and the global bucket, or refuse.

        A refusal consumes nothing. An unusable source key or clock refuses.
        """
        if not isinstance(source, str) or not source:
            return self._refuse(None)
        key = hashlib.sha256(source.encode("utf-8", "surrogatepass")).digest()
        with self._lock:
            now = self._now()
            if now is None:
                return self._refuse_locked(None)
            if self._global is None:
                self._global = _Bucket(float(self.global_capacity), now)
            self._refill(self._global, now, self.global_capacity, self.global_refill_seconds)
            bucket = self._sources.get(key)
            if bucket is None:
                if len(self._sources) >= self.max_sources:
                    oldest_key, oldest = next(iter(self._sources.items()))
                    self._refill(oldest, now, self.per_source_capacity, self.per_source_refill_seconds)
                    if oldest.tokens < self.per_source_capacity:
                        # Every bucket is still in use: refuse rather than grow
                        # or forget a source that is being limited.
                        return self._refuse_locked(now)
                    del self._sources[oldest_key]
                bucket = _Bucket(float(self.per_source_capacity), now)
                self._sources[key] = bucket
            else:
                self._sources.move_to_end(key)
                self._refill(bucket, now, self.per_source_capacity, self.per_source_refill_seconds)
            if bucket.tokens < 1 or self._global.tokens < 1:
                return self._refuse_locked(now)
            bucket.tokens -= 1
            self._global.tokens -= 1
            return True

    def _refuse(self, now: float | None) -> bool:
        with self._lock:
            return self._refuse_locked(now if now is not None else self._now())

    def _refuse_locked(self, now: float | None) -> bool:
        self.limited += 1
        if now is None or self._last_logged is None or now < self._last_logged \
                or now - self._last_logged >= self.log_interval_seconds:
            self._last_logged = now
            # Value-free: no identity, digest, path or count.
            logging.getLogger(__name__).warning(Event.HUMAN_REQUEST_RATE_LIMITED)
        return False


# Owner decision D4 (2026-10-11): per source burst 5, one per 12 seconds.
REDEMPTION_PER_SOURCE_CAPACITY = 5
REDEMPTION_PER_SOURCE_REFILL_SECONDS = 12.0
# Global cap across every source (implementation bound): burst 10, then one
# every 6 seconds (at most 10 per minute sustained).
REDEMPTION_GLOBAL_CAPACITY = 10
REDEMPTION_GLOBAL_REFILL_SECONDS = 6.0


def redemption_rate_limiter(*, max_sources: int = 256,
                            monotonic: Callable[[], float] = time.monotonic) -> SourceRateLimiter:
    """The separate, stricter limiter for invitation redemption (D4)."""
    return SourceRateLimiter(per_source_capacity=REDEMPTION_PER_SOURCE_CAPACITY,
                             per_source_refill_seconds=REDEMPTION_PER_SOURCE_REFILL_SECONDS,
                             global_capacity=REDEMPTION_GLOBAL_CAPACITY,
                             global_refill_seconds=REDEMPTION_GLOBAL_REFILL_SECONDS,
                             max_sources=max_sources, monotonic=monotonic)
