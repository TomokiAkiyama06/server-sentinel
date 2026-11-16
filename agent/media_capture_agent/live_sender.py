"""Send each source's newest JPEG to the Main for the live view (Issue #14).

Owner decision 2026-11-12 (option A): up to ``FRAMES_PER_SECOND`` (5) frames
per source, the frames as the camera produced them (the Agent is stdlib-only
and does not resize). One daemon thread reads ``PreviewTap.latest`` and sends
a frame only when it is newer than the last one sent for that source, through
``IngestSession.send_live_frame``: it never connects (the heartbeat owns the
connection and its back-off), so while the Main is unreachable nothing is
queued or retried and memory stays bounded to the preview's one frame per
source. The Main keeps the frame in memory only and sends no reply.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Iterable
from uuid import UUID


FRAMES_PER_SECOND = 5


class LiveSender:
    def __init__(self, session, preview, sources: Iterable[UUID], *,
                 frames_per_second: int = FRAMES_PER_SECOND,
                 clock: Callable[[], float] = time.monotonic):
        sources = tuple(sources)
        if (not callable(getattr(session, "send_live_frame", None))
                or not callable(getattr(preview, "latest", None))
                or not sources or any(not isinstance(source, UUID) for source in sources)
                or type(frames_per_second) is not int or not 1 <= frames_per_second <= 30):
            raise ValueError("invalid live sender")
        self._session = session
        self._preview = preview
        self._sources = sources
        self._period = 1.0 / frames_per_second
        self._clock = clock
        self._sent: dict[UUID, tuple[int, int]] = {}
        # Value-free counters for diagnostics and tests.
        self.frames_sent = 0
        self.frames_not_sent = 0
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="media-capture-agent-live-sender")
        self._thread.start()

    def _run(self) -> None:
        while not self._stopping.is_set():
            started = self._clock()
            for source in self._sources:
                if self._stopping.is_set():
                    return
                frame = self._preview.latest(source)
                # A restarted pipeline numbers its frames from 1 again, so a
                # frame is identified by its generation and sequence.
                identity = (getattr(frame, "generation", 0), getattr(frame, "sequence", None))
                if frame is None or self._sent.get(source) == identity:
                    continue
                if self._session.send_live_frame(source, frame.data):
                    self._sent[source] = identity
                    self.frames_sent += 1
                else:
                    self.frames_not_sent += 1
            # One pass per period: at most `frames_per_second` per source.
            self._stopping.wait(max(0.0, self._period - (self._clock() - started)))

    def close(self, timeout: float = 2.0) -> None:
        self._stopping.set()
        self._thread.join(timeout)
