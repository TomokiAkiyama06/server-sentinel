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
    # The most recent poll raised (storage/registry fault, not an ordinary
    # camera offline, which polls report by returning False). Cleared by the
    # next poll that completes.
    polling_failed: bool = False


@dataclass
class _Worker:
    stop: threading.Event
    thread: threading.Thread | None = None
    failures: int = 0
    cleanup_failed: bool = False
    polling_failed: bool = False


class LocalUvcSupervisor:
    """Run one serialized blocking capture loop per logical local source.

    Different sources have independent threads, so a disconnected or blocked
    source cannot make another source stop polling.  A worker owns every
    ``poll_source`` and ``stop_source`` call for its source.  Callers must stop
    a source before an Owner reapproval ceremony mutates that source's session.

    Ordinary adapter failures are contained and retried after a bounded delay.
    Status intentionally records only a count, never exception text that might
    contain deployment-private device information.

    When the adapter exposes ``check_frame_progress(source_id)``, one
    watchdog thread calls it for every registered source whose worker thread
    is still alive (including one whose stop timed out) each
    ``watchdog_interval``. This is the single deliberate exception to "one
    thread per source": the check is read-mostly, never opens, closes or
    rebinds a device, and only lowers an ``online`` claim for a source whose
    worker has stopped delivering frames (for example while that worker is
    blocked in a kernel or storage call). Its failures are counted, never
    logged with text.
    """

    # close() gives the watchdog join at least this long even when joining
    # the workers used up the shared deadline. A frame-progress check is
    # in-memory work under a non-blocking lock (its health write runs on a
    # background writer), so it normally finishes well within this bound. A
    # watchdog still alive after it makes close() fail, so a successful
    # close() always returns with the watchdog stopped.
    WATCHDOG_JOIN_MINIMUM_SECONDS = 1.0

    def __init__(self, adapter, *, poll_timeout=1.0, retry_delay=0.1,
                 join_timeout=10.0, clock=time.monotonic, watchdog_interval=0.25):
        if not callable(getattr(adapter, "poll_source", None)):
            raise TypeError("local UVC adapter is required")
        if not callable(getattr(adapter, "stop_source", None)):
            raise TypeError("local UVC adapter cannot stop a source")
        for value in (poll_timeout, retry_delay, join_timeout, watchdog_interval):
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
        check = getattr(adapter, "check_frame_progress", None)
        self._check = check if callable(check) else None
        self._watchdog_interval = float(watchdog_interval)
        self._watchdog_stop = threading.Event()
        self._watchdog = None
        self.watchdog_failures = 0

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
            self._start_watchdog()
        return True

    def _start_watchdog(self):
        # Called with self._lock held.
        if self._check is None or (self._watchdog is not None and self._watchdog.is_alive()):
            return
        watchdog = threading.Thread(target=self._watch, name="serversentinel-local-uvc-watchdog",
                                    daemon=True)
        watchdog.start()
        self._watchdog = watchdog

    @property
    def watchdog_running(self):
        return self._watchdog is not None and self._watchdog.is_alive()

    def _watch(self):
        while not self._watchdog_stop.wait(self._watchdog_interval):
            # A requested stop is not an exit: a worker blocked in a kernel
            # call past a timed-out stop() or close() stays registered, and
            # its source is still reported by that worker's last state. Keep
            # checking it until the thread has actually exited or was removed.
            with self._lock:
                sources = [(source_id, worker) for source_id, worker in self._workers.items()
                           if worker.thread is not None and worker.thread.is_alive()]
                if self._closed and not sources:
                    # close() left this watchdog running for workers that
                    # outlived its join bound; all of them have now exited.
                    return
            for source_id, worker in sources:
                if self._watchdog_stop.is_set():
                    return
                with self._lock:
                    if (self._workers.get(source_id) is not worker
                            or not worker.thread.is_alive()):
                        continue
                try:
                    self._check(source_id)
                except Exception:
                    # Counted only: exception text may carry private details.
                    with self._lock:
                        self.watchdog_failures += 1

    def _failed(self, worker, *, cleanup=False):
        with self._lock:
            worker.failures += 1
            worker.cleanup_failed = worker.cleanup_failed or cleanup
            if not cleanup:
                worker.polling_failed = True

    def _polled(self, worker):
        with self._lock:
            worker.polling_failed = False

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
                else:
                    self._polled(worker)
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
                worker.failures, worker.cleanup_failed, worker.polling_failed,
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
        """Stop all sources within one total join deadline.

        The watchdog keeps running until every worker has been joined. A
        worker blocked in a kernel call past the deadline stays registered
        and watched, so its source cannot keep an ``online`` claim while it
        delivers no frames; the watchdog exits on its own once such workers
        have exited, or a later ``close()`` that joins them stops it.

        Success means no worker and no watchdog thread is left that could
        still call into the adapter. A watchdog still inside a check after its
        own bounded join makes ``close()`` fail, so the owner does not tear
        the adapter down under that check; a later ``close()`` joins it again.
        """
        with self._lock:
            if (self._closed and not self._workers
                    and not (self._watchdog is not None and self._watchdog.is_alive())):
                return
            self._closed = True
            watchdog = self._watchdog
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
            if not alive:
                # Only now is no source left that the watchdog must report.
                self._watchdog_stop.set()
        if not alive and watchdog is not None:
            # The watchdog only ever lowers a health claim under the source's
            # transition lock, so a check still finishing a storage write after
            # this bound cannot race capture cleanup into a wrong state.
            # The remaining shared deadline may already be zero after a slow
            # worker join, so the watchdog gets a minimum bound of its own.
            watchdog.join(max(self.WATCHDOG_JOIN_MINIMUM_SECONDS, deadline - self._clock()))
        if alive:
            raise WorkerStopError("local UVC workers did not stop")
        if watchdog is not None and watchdog.is_alive():
            # A check still running may call into the adapter: never report a
            # clean close, or the owner would close the adapter under it.
            raise WorkerStopError("local UVC watchdog did not stop")
        if cleanup_failed:
            raise WorkerStopError("local UVC worker cleanup failed")
