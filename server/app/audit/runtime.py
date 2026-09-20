"""Main Server audit retention lifecycle."""

import asyncio


class AuditRetentionRuntime:
    def __init__(self, store, *, interval_seconds=24 * 60 * 60):
        if (type(interval_seconds) not in (int, float)
                or interval_seconds <= 0):
            raise ValueError("invalid audit cleanup interval")
        self.store = store
        self.interval_seconds = interval_seconds

    def startup_cleanup(self):
        return self.store.cleanup_expired()

    async def run(self):
        while True:
            await asyncio.sleep(self.interval_seconds)
            self.store.cleanup_expired()
