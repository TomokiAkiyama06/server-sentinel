"""One bounded daemon delivery worker; no SQLite or local event callbacks here."""

from queue import Empty, Full, Queue
import threading

from app.notifications.slack import DeliveryResult


class DeliveryWorker:
    """Hands completions to the owning thread without losing one or a wake-up.

    The delivery thread publishes a completion and raises `ready` under the same
    lock the owner uses to drain, and the owner lowers `ready` only after it has
    observed the completion queue empty under that lock. A completion can
    therefore never be acknowledged by a flag that was already lowered. The
    thread also survives a transiently full completion queue: dropping a
    completion, or letting the thread exit, would strand the event as pending
    forever and silently lose a critical alert's outcome.
    """

    def __init__(self, transport, capacity: int):
        self._transport = transport
        self._work = Queue(maxsize=capacity)
        self._results = Queue(maxsize=capacity)
        self._stop = threading.Event()
        self._handoff = threading.Condition()
        self.ready = threading.Event()
        self._thread = None

    def submit(self, identifier, text: str) -> None:
        if self._stop.is_set():
            raise RuntimeError('notification worker closed')
        # The owner also caps unacknowledged completions, preventing growth of
        # either queue while delivery outruns persistence.
        self._work.put_nowait((identifier, text))
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
            self._complete(identifier, result)

    def _complete(self, identifier, result) -> None:
        # A finished delivery is always offered, including after close, so the
        # owner can persist its real outcome instead of a stranded pending row.
        with self._handoff:
            while True:
                try:
                    self._results.put_nowait((identifier, result))
                except Full:
                    # A close never joins this daemon. Keep the finished result
                    # until the owner drains a slot instead of silently losing it.
                    self.ready.set()
                    self._handoff.wait()
                    continue
                self.ready.set()
                return

    def results(self):
        while True:
            with self._handoff:
                try:
                    completion = self._results.get_nowait()
                except Empty:
                    self.ready.clear()
                    return
                self._handoff.notify()
            yield completion

    def close(self) -> None:
        # Never join a possibly stuck DNS/transport call on the recorder thread.
        # Undelivered/in-flight entries remain durably pending; no false success.
        self._stop.set()
