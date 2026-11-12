"""The latest compressed frame of every capturing source, for the live preview (Issue #14).

Owner decision 2026-11-12 (option A): the Agent sends the Main a live preview
of each approved camera (JPEG frames as captured, a few per second) before
any recording is wired. ``PreviewTap`` is the consumer of every source's
bounded ``FrameQueue`` (``uvc_capture.UvcCapture.frames``): one daemon thread
per source takes each frame as it arrives and keeps only the newest one, so
the queue never overflows (no drop is reported because nobody reads it) and
memory stays bounded to one frame per source. The ingest session sender reads
``latest`` (PR 2). Frames are kept in memory only and never written to disk
or logs; the Agent's ring buffer is wired separately later.

``close`` stops the threads; each wakes within ``POLL_SECONDS``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Callable, Iterable
from uuid import UUID


POLL_SECONDS = 0.25


@dataclass(frozen=True)
class PreviewFrame:
    """One JPEG frame; bytes never appear in repr or logs."""

    source_id: UUID
    data: bytes = field(repr=False)
    sequence: int
    received_monotonic: float


class PreviewTap:
    def __init__(self, queues: Iterable[tuple[UUID, object]], *,
                 clock: Callable[[], float] = time.monotonic):
        queues = tuple(queues)
        if any(not isinstance(source, UUID) or not callable(getattr(queue, "get", None))
               for source, queue in queues):
            raise ValueError("invalid preview queues")
        self._clock = clock
        self._lock = threading.Lock()
        self._latest: dict[UUID, PreviewFrame] = {}
        self._stopping = threading.Event()
        self._threads = [threading.Thread(target=self._drain, args=(source, queue), daemon=True,
                                          name="media-capture-agent-preview")
                         for source, queue in queues]
        for thread in self._threads:
            thread.start()

    def latest(self, source_id: UUID) -> PreviewFrame | None:
        with self._lock:
            return self._latest.get(source_id)

    def sources(self) -> tuple[UUID, ...]:
        with self._lock:
            return tuple(self._latest)

    def _drain(self, source: UUID, queue) -> None:
        while not self._stopping.is_set():
            try:
                frame = queue.get(POLL_SECONDS)
            except Exception:
                # A queue error is the capture adapter's to report; wait and retry.
                self._stopping.wait(POLL_SECONDS)
                continue
            if frame is None:
                # A closed queue returns at once; do not spin on it.
                self._stopping.wait(0.05)
                continue
            data = getattr(frame, "data", None)
            sequence = getattr(frame, "sequence", None)
            if not isinstance(data, bytes) or not data or type(sequence) is not int:
                continue
            kept = PreviewFrame(source, data, sequence, self._clock())
            with self._lock:
                self._latest[source] = kept

    def close(self, timeout: float = 2.0) -> None:
        self._stopping.set()
        deadline = time.monotonic() + timeout
        for thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        with self._lock:
            self._latest.clear()
