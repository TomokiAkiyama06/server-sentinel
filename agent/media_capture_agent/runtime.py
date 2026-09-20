"""Dependency-injected outbound agent loop; unconfigured production fails closed."""

from dataclasses import asdict
import os
import time
from typing import Protocol

from .health import ClockExchange, SourceHealth, assess_clock
from .storage import StorageRefused, open_directory


class Capture(Protocol):
    """Adapters must validate UVC identity and capture video only before online."""

    def poll(self) -> tuple[SourceHealth, ...]: ...
    def close(self) -> None: ...


class OutboundSession(Protocol):
    """Issue #13 supplies an already authenticated, revocable node-only session.

    Implementations initiate the Main connection; this process never listens or
    accesses human/admin API routes. Missing identity never falls back to plaintext.
    """

    @property
    def authenticated(self) -> bool: ...
    def exchange_clock(self) -> ClockExchange | None: ...
    def send_heartbeat(self, heartbeat: dict) -> None: ...
    def close(self) -> None: ...


class UnconfiguredCapture:
    def poll(self):
        return ()

    def close(self):
        pass


class UnpairedSession:
    authenticated = False

    def exchange_clock(self):
        return None

    def send_heartbeat(self, heartbeat):
        raise ConnectionError("pairing_required")

    def close(self):
        pass


class Agent:
    def __init__(self, settings, store, *, capture=None, session=None,
                 utc=time.time, monotonic=time.monotonic):
        if os.geteuid() == 0 or os.geteuid() != settings.service_uid:
            raise StorageRefused("dedicated_nonroot_account_required")
        runtime = open_directory(settings.runtime_root)
        try:
            info = os.fstat(runtime)
            if info.st_uid != settings.service_uid or info.st_mode & 0o077:
                raise StorageRefused("runtime_root_ownership")
            if not info.st_mode & 0o200 or not info.st_mode & 0o100:
                raise StorageRefused("runtime_root_not_writable")
        finally:
            os.close(runtime)
        self.settings = settings
        self.store = store
        self.capture = capture or UnconfiguredCapture()
        self.session = session or UnpairedSession()
        self.utc = utc
        self.monotonic = monotonic
        self.sequence = 0

    def tick(self):
        self.sequence += 1
        reasons = []
        try:
            free = self.store.check()
            storage = {"state": "online", "available_bytes": free,
                       "safety_reserve_bytes": self.settings.safety_reserve_bytes}
        except StorageRefused as exc:
            reasons.append("storage_unavailable")
            storage = {"state": "failed", "reason": str(exc)}
        # Capture adapters report individual source failures; a programming error
        # is not swallowed and must reach the service supervisor as a failure.
        sources = self.capture.poll()
        if not isinstance(sources, tuple) or any(not isinstance(source, SourceHealth)
                                                 for source in sources):
            raise ValueError("invalid source health collection")
        if len({source.source_id for source in sources}) != len(sources):
            raise ValueError("duplicate source health identity")
        if isinstance(self.capture, UnconfiguredCapture):
            reasons.append("capture_unconfigured")
        exchange = None
        if not self.session.authenticated:
            reasons.append("pairing_required")
        else:
            try:
                exchange = self.session.exchange_clock()
            except (ConnectionError, TimeoutError, OSError):
                reasons.append("main_unavailable")
        clock = assess_clock(exchange, self.settings)
        if clock.state != "online":
            reasons.append(clock.reason)
        heartbeat = {
            "schema_version": 1, "node_id": str(self.settings.node_id),
            "sequence": self.sequence, "utc_seconds": self.utc(),
            "monotonic_seconds": self.monotonic(),
            "node_state": "degraded" if reasons else "online",
            "node_reasons": reasons, "clock": asdict(clock), "storage": storage,
            "sources": [source.public() for source in sources],
        }
        if self.session.authenticated:
            try:
                self.session.send_heartbeat(heartbeat)
            except (ConnectionError, TimeoutError, OSError):
                heartbeat["node_state"] = "degraded"
                if "main_unavailable" not in reasons:
                    reasons.append("main_unavailable")
        return heartbeat

    def close(self):
        try:
            self.capture.close()
        finally:
            try:
                self.session.close()
            finally:
                self.store.close()
