"""Bounded per-source workers for the synchronous local UVC adapter."""

from dataclasses import dataclass
import threading
import time
from uuid import UUID


class WorkerStopError(RuntimeError):
    """A capture worker did not stop cleanly within its configured bound."""


@dataclass(frozen=True)
class WorkerStatus:
    running: bool
    failures: int
    cleanup_failed: bool


@dataclass
class _Worker:
    stop: threading.Event
    thread: threading.Thread | None = None
    failures: int = 0
    cleanup_failed: bool = False


class LocalUvcSupervisor:
    """Run one serialized blocking capture loop per logical local source.

    Different sources have independent threads, so a disconnected or blocked
    source cannot make another source stop polling.  A worker owns every
    ``poll_source`` and ``stop_source`` call for its source.  Callers must stop
    a source before an Owner reapproval ceremony mutates that source's session.

    Ordinary adapter failures are contained and retried after a bounded delay.
    Status intentionally records only a count, never exception text that might
    contain deployment-private device information.
    """

    def __init__(self, adapter, *, poll_timeout=1.0, retry_delay=0.1,
                 join_timeout=3.0, clock=time.monotonic):
        if not callable(getattr(adapter, "poll_source", None)):
            raise TypeError("local UVC adapter is required")
        if not callable(getattr(adapter, "stop_source", None)):
            raise TypeError("local UVC adapter cannot stop a source")
        for value in (poll_timeout, retry_delay, join_timeout):
            if type(value) not in (int, float) or value <= 0:
                raise ValueError("worker timing must be positive")
        self._adapter = adapter
        self._poll_timeout = float(poll_timeout)
        self._retry_delay = float(retry_delay)
        self._join_timeout = float(join_timeout)
        self._clock = clock
        self._lock = threading.Lock()
        self._workers: dict[UUID, _Worker] = {}
        self._closed = False

    @staticmethod
    def _identity(source_id):
        if not isinstance(source_id, UUID):
            raise ValueError("invalid source identity")
        return source_id

    def start(self, source_id):
        """Start a source worker; repeated starts are idempotent."""
        source_id = self._identity(source_id)
        with self._lock:
            if self._closed:
                raise WorkerStopError("local UVC supervisor is closed")
            existing = self._workers.get(source_id)
            if existing is not None and existing.thread is not None and existing.thread.is_alive():
                return False
            if existing is not None and existing.cleanup_failed:
                raise WorkerStopError("previous local UVC worker cleanup failed")
            worker = _Worker(threading.Event())
            thread = threading.Thread(
                target=self._run, args=(source_id, worker),
                name=f"serversentinel-local-uvc-{source_id}", daemon=True,
            )
            worker.thread = thread
            self._workers[source_id] = worker
            try:
                thread.start()
            except BaseException:
                del self._workers[source_id]
                raise
        return True

    def _failed(self, worker, *, cleanup=False):
        with self._lock:
            worker.failures += 1
            worker.cleanup_failed = worker.cleanup_failed or cleanup

    def _run(self, source_id, worker):
        try:
            while not worker.stop.is_set():
                try:
                    delivered = self._adapter.poll_source(
                        source_id, timeout=self._poll_timeout,
                    )
                except Exception:
                    self._failed(worker)
                    delivered = False
                if not delivered:
                    worker.stop.wait(self._retry_delay)
        finally:
            try:
                self._adapter.stop_source(source_id)
            except BaseException:
                # Keep the worker stoppable, but make failed durable cleanup
                # observable to its lifecycle owner.
                self._failed(worker, cleanup=True)

    def status(self, source_id):
        source_id = self._identity(source_id)
        with self._lock:
            worker = self._workers.get(source_id)
            if worker is None:
                return None
            return WorkerStatus(
                worker.thread is not None and worker.thread.is_alive(),
                worker.failures, worker.cleanup_failed,
            )

    def stop(self, source_id):
        """Stop and join one source before returning to its lifecycle owner."""
        source_id = self._identity(source_id)
        with self._lock:
            worker = self._workers.get(source_id)
            if worker is None:
                return False
            thread = worker.thread
            if thread is threading.current_thread():
                raise WorkerStopError("capture worker cannot join itself")
            worker.stop.set()
        thread.join(self._join_timeout)
        if thread.is_alive():
            raise WorkerStopError("local UVC worker did not stop")
        with self._lock:
            # A concurrent start may have replaced this completed worker while
            # stop() was outside the lock joining it.  Never discard that new
            # live lifecycle from the supervisor's registry.
            if self._workers.get(source_id) is worker:
                self._workers.pop(source_id)
            cleanup_failed = worker.cleanup_failed
        if cleanup_failed:
            raise WorkerStopError("local UVC worker cleanup failed")
        return True

    def close(self):
        """Stop all sources within one total join deadline."""
        with self._lock:
            if self._closed and not self._workers:
                return
            self._closed = True
            workers = tuple(self._workers.items())
            for _source_id, worker in workers:
                worker.stop.set()
        deadline = self._clock() + self._join_timeout
        for _source_id, worker in workers:
            remaining = max(0.0, deadline - self._clock())
            worker.thread.join(remaining)
        alive = [source_id for source_id, worker in workers if worker.thread.is_alive()]
        cleanup_failed = [
            source_id for source_id, worker in workers if worker.cleanup_failed
        ]
        with self._lock:
            for source_id, worker in workers:
                if not worker.thread.is_alive():
                    self._workers.pop(source_id, None)
        if alive:
            raise WorkerStopError("local UVC workers did not stop")
        if cleanup_failed:
            raise WorkerStopError("local UVC worker cleanup failed")
