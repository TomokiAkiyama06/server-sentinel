"""One bounded daemon delivery worker; no SQLite or local event callbacks here."""

from queue import Empty, Queue
import threading

from app.notifications.slack import DeliveryResult


class DeliveryWorker:
    def __init__(self, transport, capacity: int):
        self._transport = transport
        self._work = Queue(maxsize=capacity)
        self._results = Queue(maxsize=capacity)
        self._stop = threading.Event()
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
            self._results.put_nowait((identifier, result))
            self.ready.set()

    def results(self):
        self.ready.clear()
        while True:
            try:
                yield self._results.get_nowait()
            except Empty:
                return

    def close(self) -> None:
        # Never join a possibly stuck DNS/transport call on the recorder thread.
        # Undelivered/in-flight entries remain durably pending; no false success.
        self._stop.set()
