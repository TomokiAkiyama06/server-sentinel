"""One bounded daemon delivery worker; no SQLite or local event callbacks here."""

from queue import Empty, Full, Queue
import threading

from app.notifications.slack import DeliveryResult


class DeliveryWorker:
    """Hands completions to the owning thread without losing one or a wake-up.

    One capacity budget covers an accepted delivery from submission until the
    owner drains its completion, so queued work plus unacknowledged completions
    never exceed it and the completion queue cannot be full when the delivery
    thread publishes. A completion is therefore never dropped or retried, and
    the thread never exits on backpressure; a lost completion would strand the
    event as pending forever and silently lose a critical alert's outcome.

    The thread publishes a completion and raises `ready` under the same lock the
    owner uses to drain, and the owner lowers `ready` only after observing the
    completion queue empty under that lock, so a queued completion can never be
    acknowledged by a flag that was already lowered.
    """

    def __init__(self, transport, capacity: int):
        self._transport = transport
        self._work = Queue(maxsize=capacity)
        self._results = Queue(maxsize=capacity)
        self._budget = threading.Semaphore(capacity)
        self._stop = threading.Event()
        self._handoff = threading.Lock()
        self.ready = threading.Event()
        self._thread = None

    def submit(self, identifier, text: str) -> None:
        if self._stop.is_set():
            raise RuntimeError('notification worker closed')
        # Holding the budget until the owner drains the completion keeps both
        # queues bounded while delivery outruns persistence.
        if not self._budget.acquire(blocking=False):
            raise Full
        try:
            self._work.put_nowait((identifier, text))
        except BaseException:
            self._budget.release()
            raise
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name='serversentinel-notifications', daemon=True)
            self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                identifier, text = self._work.get(timeout=0.1)
            except Empty:
                continue
            try:
                result = self._transport.send(text)
                if result not in {DeliveryResult.SENT, DeliveryResult.FAILED, DeliveryResult.DISABLED}:
                    result = DeliveryResult.FAILED
            except Exception:
                result = DeliveryResult.FAILED
            # This delivery still holds its budget slot, so the completion queue
            # has room for it even after close; no finished delivery is lost.
            with self._handoff:
                self._results.put_nowait((identifier, result))
                self.ready.set()

    def results(self):
        while True:
            with self._handoff:
                try:
                    completion = self._results.get_nowait()
                except Empty:
                    self.ready.clear()
                    return
            self._budget.release()
            yield completion

    def close(self) -> None:
        # Never join a possibly stuck DNS/transport call on the recorder thread.
        # Undelivered/in-flight entries remain durably pending; no false success.
        self._stop.set()
