"""Camera frames to H.264 ring segments, one recorder per source (Issue #16 PR C2).

``PreviewTap`` hands every frame of a source to its ``SegmentRecorder``
(``offer``, never blocking: a bounded queue drops the oldest frame and counts
it). The recorder thread turns frames into fixed-duration segments:

* **Grid.** Segment boundaries are multiples of the segment duration in UTC.
  The monotonic clock is mapped to UTC once (at start and after every
  interruption); each segment's pictures are placed on a slot grid that starts
  exactly at its boundary (``frame_pacer``), so a segment always has
  ``fps × segment_seconds`` pictures. A late frame repeats the previous one, a
  surplus frame is dropped, and no frame newer than ``MAX_HOLD_US`` old is
  stretched over an interruption: that is a gap.
* **Encoder.** Each segment gets its own OpenH264 child
  (``h264_encoder``), so it starts with an IDR picture and an encoder fault
  costs at most one segment. The next segment's child is started one
  segment early (a spare) so that its start-up does not delay frames.
* **Finish.** After the segment's last picture the encoder's input is closed;
  a finisher thread reads the Annex B stream to its end, checks it
  (``validate_segment``: exactly the expected access units, IDR first),
  writes one fragmented MP4 (``fmp4``) and appends it to the ring with the
  segment's UTC interval and whether the clock is trusted
  (``RingMonitor.clock_trusted``).
* **Refusals.** A gap, an encoder failure, a stream that fails validation,
  output beyond the profile's segment bound or a ring refusal drops only
  that segment, counted under a fixed reason word; the ring then sees the
  missing interval as a gap. Nothing is recorded while the Owner has not
  configured the ring or its committed profiles differ from the deployment
  (no encoder runs then), and the mapping to UTC is re-established when the
  wall clock departs from it by more than ``clock_step_limit_seconds``; a
  finished segment whose mapping no longer holds is not stored. An encoder
  whose process group cannot be reaped is kept and retried, and no new
  encoder starts until it is gone (as ``UvcCapture`` does for capture).

No frame bytes are logged; counters and reason words are the only output.
"""
from __future__ import annotations

from collections import Counter, deque
import threading
import time

from .fmp4 import Fmp4Error, write_segment
from .frame_pacer import FramePacer, PacedFrame, PacedGap
from .h264_annexb import AccessUnitSplitter, AnnexBError, validate_segment
from .h264_encoder import EncoderProfile
from .ring_models import SECOND, RingRefused
from .uvc_pipeline import MjpegProfile, PipelineError


TIMESCALE = 90000
QUEUE_SECONDS = 2          # frames buffered between the capture and the recorder
MAX_HOLD_US = SECOND       # one picture may fill slots for at most this long
LATENCY_US = 250_000       # a frame captured this long ago may still be queued
WRITE_TIMEOUT_SECONDS = 2.0
FINISH_TIMEOUT_SECONDS = 15.0
STOP_TIMEOUT_SECONDS = 5.0
# Segments waiting for the finisher (each holds an encoder, its pipes and its
# output). A slower finisher drops further segments instead of piling them up
# (PR #434 review).
MAX_PENDING_SEGMENTS = 3
POLL_SECONDS = 0.05
READ_BYTES = 65536


class _Output:
    """Reads one encoder's stdout to its end; keeps at most ``limit`` bytes."""

    def __init__(self, process, limit):
        self.process, self.limit = process, limit
        self.data = bytearray()
        self.overflow = False
        self.thread = threading.Thread(target=self._read, daemon=True,
                                       name="media-capture-agent-encoder-output")
        self.thread.start()

    def _read(self):
        while True:
            chunk = self.process.read(READ_BYTES)
            if not chunk:
                return
            if len(self.data) + len(chunk) > self.limit:
                # Keep draining so the child never blocks on a full pipe.
                self.overflow = True
                continue
            self.data += chunk


class _Encoder:
    def __init__(self, process, limit):
        self.process = process
        self.output = _Output(process, limit)


class _Segment:
    def __init__(self, index, start_utc_us, start_mono_us, duration_us, frames, pacer):
        self.index = index
        self.start_utc_us, self.start_mono_us = start_utc_us, start_mono_us
        self.end_utc_us = start_utc_us + duration_us
        self.end_mono_us = start_mono_us + duration_us
        self.frames, self.pacer = frames, pacer
        self.encoder = None
        self.written = 0
        self.failure = None
        self.anchor = None  # the (utc_us, mono_us) mapping its times come from


class SegmentRecorder:
    def __init__(self, source_id, capture, setting, *, segment_seconds, ring, monitor,
                 launcher, step_limit_seconds, utc=time.time, monotonic=time.monotonic,
                 start=True, finish_inline=False):
        if not isinstance(capture, MjpegProfile) or capture.fps_denominator != 1:
            raise ValueError("an integer-rate MJPEG capture profile is required")
        if TIMESCALE % capture.fps_numerator:
            raise ValueError("the capture rate must divide the MP4 timescale")
        self.source_id = source_id
        self.fps = capture.fps_numerator
        self.frames_per_segment = self.fps * segment_seconds
        self.segment_us = segment_seconds * SECOND
        self.period_us = self.segment_us // self.frames_per_segment
        self.sample_duration = TIMESCALE // self.fps
        self.encoder_profile = EncoderProfile(capture, setting.target_bitrate,
                                              setting.maximum_bitrate, setting.gop_frames)
        self.ring, self.monitor, self.launcher = ring, monitor, launcher
        self.step_limit_us = int(step_limit_seconds * SECOND)
        self.utc, self.monotonic = utc, monotonic
        self.stats = Counter()
        self._stats_lock = threading.Lock()
        self._queue = deque()
        self._queue_limit = self.fps * QUEUE_SECONDS
        self._wake = threading.Condition()
        self._stopping = False
        # Set only after the recorder thread stopped: the finisher drains
        # until then, so no segment is enqueued after it left (PR #434 review).
        self._producer_done = False
        self._anchor = None        # (utc_us, mono_us)
        self._next = None          # (index, start_utc_us, start_mono_us) of the first segment
        self._segment = None
        self._last = None          # (captured_mono_us, data) of the newest frame
        self._spare = None
        # Encoders whose process group could not be reaped yet (PR #434
        # review): retried, and no new encoder starts while one remains.
        self._stuck = []
        self._stuck_lock = threading.Lock()
        self._finish_inline = finish_inline
        self._finishing = deque()
        self._finisher = None
        self._thread = None
        if start:
            self._finisher = threading.Thread(target=self._finish_loop, daemon=True,
                                              name="media-capture-agent-segment-finisher")
            self._finisher.start()
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="media-capture-agent-recorder")
            self._thread.start()

    def _count(self, key, amount=1):
        with self._stats_lock:
            self.stats[key] += amount  # the only writer

    # -- frames in ---------------------------------------------------------

    def offer(self, frame):
        """Queue one capture frame; never blocks (PreviewTap listener)."""
        data = getattr(frame, "data", None)
        captured = getattr(frame, "received_monotonic", None)
        if not isinstance(data, bytes) or not data or type(captured) not in (int, float):
            return
        with self._wake:
            if len(self._queue) >= self._queue_limit:
                self._queue.popleft()
                self._count("frames_dropped_queue")
            self._queue.append((int(captured * SECOND), data))
            self._wake.notify()

    def _run(self):
        while True:
            with self._wake:
                if not self._queue and not self._stopping:
                    self._wake.wait(POLL_SECONDS)
                if self._stopping:
                    return
                frames = list(self._queue)
                self._queue.clear()
            try:
                for captured, data in frames:
                    self.feed(captured, data)
                self.poll(int(self.monotonic() * SECOND))
            except Exception:  # noqa: BLE001 - a fixed counter, never exception text
                self._count("recorder_error")
                self._abandon("recorder_error")

    # -- the state machine (synchronous; tests drive it directly) ----------

    def feed(self, captured_us, data):
        if self._last is not None and captured_us < self._last[0]:
            self._count("frames_out_of_order")
            return
        self._advance_to(captured_us)
        if self._segment is not None and self._segment.start_mono_us <= captured_us:
            self._handle(self._segment.pacer.offer(captured_us, data))
        self._last = (captured_us, data)

    def poll(self, now_mono_us):
        self._advance_to(now_mono_us - LATENCY_US, deciding=True)

    def _advance_to(self, limit_us, *, deciding=False):
        if self._next is None and self._segment is None:
            self._anchor_at(int(self.utc() * SECOND), int(self.monotonic() * SECOND))
        while True:
            segment = self._segment
            if segment is None:
                index, start_utc, start_mono = self._next
                if limit_us < start_mono:
                    return
                self._begin(index, start_utc, start_mono)
                continue
            if limit_us < segment.end_mono_us:
                if deciding and limit_us >= segment.start_mono_us:
                    self._handle(segment.pacer.advance(limit_us))
                return
            self._handle(segment.pacer.advance(segment.end_mono_us - 1))
            self._end(segment)
            self._next = (segment.index + 1, segment.end_utc_us, segment.end_mono_us)
            self._segment = None

    def _anchor_at(self, utc_us, mono_us):
        """Map monotonic to UTC; the first segment starts at the next boundary."""
        self._anchor = (utc_us, mono_us)
        index = -(-utc_us // self.segment_us)
        start_utc = index * self.segment_us
        self._next = (index, start_utc, mono_us + (start_utc - utc_us))

    def _begin(self, index, start_utc, start_mono):
        utc_us, mono_us = int(self.utc() * SECOND), int(self.monotonic() * SECOND)
        anchor_utc, anchor_mono = self._anchor
        if abs((utc_us - anchor_utc) - (mono_us - anchor_mono)) > self.step_limit_us:
            # The wall clock moved away from the mapping: map again and start
            # at the next boundary of the new mapping (this interval is a gap).
            self._count("segment_dropped_clock_remapped")
            self._anchor_at(utc_us, mono_us)
            index, start_utc, start_mono = self._next
        pacer = FramePacer(origin_us=start_mono, period_us=self.period_us,
                           max_hold_us=MAX_HOLD_US)
        segment = _Segment(index, start_utc, start_mono, self.segment_us,
                           self.frames_per_segment, pacer)
        segment.anchor = self._anchor
        self._segment = segment
        if not self._ring_ready():
            segment.failure = "ring_not_ready"
            self._discard_spare()
        elif not self._reap_stuck():
            segment.failure = "encoder_cleanup_pending"
            self._discard_spare()
        else:
            try:
                segment.encoder = self._take_encoder()
            except PipelineError:
                segment.failure = "encoder_unavailable"
        if self._last is not None:
            # The newest frame before the boundary may fill its first slots.
            self._handle(pacer.offer(*self._last))

    def _ring_ready(self):
        return self.ring.config is not None and not self.monitor.reconfiguration_required

    def _take_encoder(self):
        spare, self._spare = self._spare, None
        encoder = spare or self._launch()
        try:
            self._spare = self._launch()
        except PipelineError:
            self._count("encoder_spare_unavailable")
        return encoder

    def _launch(self):
        limit = self.ring.profiles[self.source_id].segment_bytes()
        return _Encoder(self.launcher.launch(self.encoder_profile), limit)

    def _discard_spare(self):
        spare, self._spare = self._spare, None
        if spare is not None:
            self._dispose(spare)

    def _dispose(self, encoder, timeout=STOP_TIMEOUT_SECONDS):
        """Stop an encoder; one that cannot be reaped is kept for retries."""
        if encoder.process.stop(timeout):
            encoder.process.close()
            return
        self._count("encoder_cleanup_pending")
        with self._stuck_lock:
            self._stuck.append(encoder)

    def _reap_stuck(self):
        """Retry the unreaped encoders; True when none remains."""
        with self._stuck_lock:
            stuck, self._stuck = self._stuck, []
        remaining = []
        for encoder in stuck:
            if encoder.process.stop(0.1, wait=False):
                encoder.process.close()
            else:
                remaining.append(encoder)
        with self._stuck_lock:
            self._stuck = remaining + self._stuck
            return not self._stuck

    def _handle(self, outcomes):
        segment = self._segment
        for outcome in outcomes:
            if isinstance(outcome, PacedGap):
                self._count("frame_gap_slots", outcome.stop - outcome.start)
                self._fail(segment, "frame_gap")
                continue
            if not isinstance(outcome, PacedFrame) or outcome.index >= segment.frames:
                continue
            if outcome.repeated:
                self._count("frames_repeated")
            if segment.failure is not None:
                continue
            try:
                segment.encoder.process.write(outcome.item, WRITE_TIMEOUT_SECONDS)
            except PipelineError:
                self._fail(segment, "encoder_failed")
                continue
            segment.written += 1

    def _fail(self, segment, reason):
        if segment.failure is None:
            segment.failure = reason
            if segment.encoder is not None:
                self._dispose(segment.encoder)
                segment.encoder = None

    def _end(self, segment):
        if segment.failure is None and segment.written != segment.frames:
            self._fail(segment, "frame_gap")
        if segment.failure is not None:
            if segment.failure not in ("ring_not_ready", "encoder_cleanup_pending"):
                self._count("segment_dropped_" + segment.failure)
            return
        if self._finish_inline:
            segment.encoder.process.close_input()
            self._finish(segment)
            return
        with self._wake:
            backlog = len(self._finishing) >= MAX_PENDING_SEGMENTS
            if not backlog:
                segment.encoder.process.close_input()
                self._finishing.append(segment)
                self._wake.notify_all()
        if backlog:
            self._count("segment_dropped_finish_backlog")
            self._dispose(segment.encoder)
            segment.encoder = None

    def _abandon(self, reason):
        segment, self._segment = self._segment, None
        if segment is not None:
            self._fail(segment, reason)
        self._discard_spare()
        self._next = None
        self._last = None

    # -- finishing ---------------------------------------------------------

    def _finish_loop(self):
        while True:
            with self._wake:
                while not self._finishing and not self._producer_done:
                    self._wake.wait()
                if not self._finishing:
                    return
                segment = self._finishing.popleft()
            try:
                self._finish(segment)
            except Exception:  # noqa: BLE001 - a fixed counter, never exception text
                self._count("segment_dropped_finish_error")

    def _finish(self, segment):
        encoder = segment.encoder
        encoder.output.thread.join(FINISH_TIMEOUT_SECONDS)
        reason = None
        if encoder.output.thread.is_alive():
            reason = "encoder_stalled"
        elif encoder.output.overflow:
            reason = "segment_bound_exceeded"
        try:
            if encoder.process.process.wait(FINISH_TIMEOUT_SECONDS) != 0 and reason is None:
                reason = "encoder_failed"
        except Exception:  # noqa: BLE001
            reason = reason or "encoder_stalled"
        self._dispose(encoder)
        if reason is not None:
            self._count("segment_dropped_" + reason)
            return
        try:
            splitter = AccessUnitSplitter(max_nal_bytes=encoder.output.limit,
                                          max_access_unit_bytes=encoder.output.limit)
            units = splitter.feed(bytes(encoder.output.data)) + splitter.flush()
            stream = validate_segment(units, expected_count=segment.frames)
            data = write_segment(
                stream, timescale=TIMESCALE, sample_duration=self.sample_duration,
                sequence_number=segment.index % 0xFFFFFFFF + 1,
                base_decode_time=(segment.index * segment.frames * self.sample_duration)
                % (1 << 64))
        except (AnnexBError, Fmp4Error):
            self._count("segment_dropped_invalid_stream")
            return
        # The ring refuses a segment that ends after "now"; the wall clock may
        # trail the mapping by up to the step limit, so wait for it (bounded)
        # rather than report a time that has not come.
        deadline = time.monotonic() + self.step_limit_us / SECOND + 1
        while int(self.utc() * SECOND) < segment.end_utc_us and time.monotonic() < deadline:
            time.sleep(0.05)
        utc, monotonic = self.utc(), self.monotonic()
        anchor_utc, anchor_mono = segment.anchor
        if (abs((int(utc * SECOND) - anchor_utc) - (int(monotonic * SECOND) - anchor_mono))
                > self.step_limit_us):
            # The wall clock moved away from the mapping this segment's times
            # come from: they may be wrong, so the segment is not stored even
            # if the clock is trusted again now (PR #434 review).
            self._count("segment_dropped_clock_remapped")
            return
        try:
            self.ring.append(self.source_id, segment.start_utc_us, segment.end_utc_us, data,
                             now_us=int(utc * SECOND),
                             clock_trusted=self.monitor.clock_trusted(utc, monotonic))
        except RingRefused as exc:
            self._count("segment_refused_" + str(exc))
            return
        self._count("segments_stored")

    # -- status and shutdown ------------------------------------------------

    def status(self):
        with self._stats_lock:
            return dict(self.stats)

    def close(self):
        with self._wake:
            self._stopping = True
            self._wake.notify_all()
        if self._thread is not None:
            self._thread.join(STOP_TIMEOUT_SECONDS + 1)
        segment, self._segment = self._segment, None
        if segment is not None and segment.encoder is not None:
            self._dispose(segment.encoder)
        self._discard_spare()
        with self._wake:
            self._producer_done = True
            self._wake.notify_all()
        if self._finisher is not None:
            self._finisher.join(FINISH_TIMEOUT_SECONDS * 2 + 1)
        # Whatever is still queued (no finisher, or one that did not finish in
        # time) is cleaned up, never left with a running encoder.
        with self._wake:
            leftover = list(self._finishing)
            self._finishing.clear()
        for segment in leftover:
            self._count("segment_dropped_shutdown")
            if segment.encoder is not None:
                self._dispose(segment.encoder)
        self._reap_stuck()
