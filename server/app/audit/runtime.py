"""Main Server audit retention lifecycle."""

import asyncio
from datetime import datetime, timezone


class AuditRetentionHealth:
    NOT_STARTED = "not_started"
    HEALTHY = "healthy"
    DEGRADED = "degraded"


class AuditRetentionRuntime:
    """Owns the 90-day audit cleanup schedule and its bounded health.

    Retention is never abandoned: a degraded run is retried sooner than the
    ordinary interval so a transient storage or database fault cannot delay
    the deletion of expired audit rows by a whole day.
    """

    def __init__(self, store, *, interval_seconds=24 * 60 * 60,
                 retry_seconds=15 * 60):
        if (type(interval_seconds) not in (int, float)
                or interval_seconds <= 0
                or type(retry_seconds) not in (int, float)
                or retry_seconds <= 0):
            raise ValueError("invalid audit cleanup interval")
        self.store = store
        self.interval_seconds = interval_seconds
        self.retry_seconds = min(retry_seconds, interval_seconds)
        self.health = AuditRetentionHealth.NOT_STARTED
        self.total_failures = 0
        self.consecutive_failures = 0
        self.last_attempt_at = None
        self.last_success_at = None
        self.last_deleted_count = None

    def _attempt(self):
        self.last_attempt_at = datetime.now(timezone.utc)
        try:
            deleted = self.store.cleanup_expired()
        except Exception:
            # Store only bounded health, never exception text/database values.
            self.health = AuditRetentionHealth.DEGRADED
            self.total_failures += 1
            self.consecutive_failures += 1
            raise
        self.health = AuditRetentionHealth.HEALTHY
        self.consecutive_failures = 0
        self.last_success_at = self.last_attempt_at
        self.last_deleted_count = deleted
        return deleted

    def startup_cleanup(self):
        """Run one cleanup before serving; the caller reports a failure."""
        return self._attempt()

    async def run(self):
        while True:
            # A degraded run, including a failed startup run, is retried on the
            # shorter interval; it never ends retry scheduling.
            degraded = self.health == AuditRetentionHealth.DEGRADED
            await asyncio.sleep(self.retry_seconds if degraded else self.interval_seconds)
            try:
                self._attempt()
            except Exception:
                continue
