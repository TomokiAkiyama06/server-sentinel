"""One source's capture lifecycle, with injected frame and negotiated-profile sinks."""

import threading
import time

from .capture import CaptureError, FrameTimeout, MmapCapture, profile_satisfies
from .discovery import ProbeError


# The stall window is never shorter than this many negotiated frame intervals,
# so a slow profile (or a dark scene that legitimately lowers the delivered
# rate) cannot flap between online and degraded.
STALL_FRAME_INTERVALS = 10


class CaptureSession:
    """A caller drives step() in its worker; failures do not exit the service.

    Frame delivery stays in memory and is video-only. There is no preview HTTP
    route here; the eventual authorized viewer pipeline consumes this sink.
    Each session has its own capture descriptor and controller.

    Frame progress: an open capture that delivers no frame for the stall
    window (``frame_stall_seconds``, widened to at least
    ``STALL_FRAME_INTERVALS`` negotiated frame intervals, which scales the
    reopen bound by the same factor) is reported
    ``degraded`` (``video_frame_stalled``) without closing the descriptor, so a
    transient stall neither churns the USB device nor ends a live weak
    binding. Only a delivered frame returns it to ``online``. A stall lasting
    ``frame_stall_reopen_seconds`` closes the capture (``offline``) and the
    next step reopens it through the normal identity path. Any other capture
    error still closes immediately. ``check_frame_progress()`` repeats the
    stall check from a second thread, so a worker blocked inside a kernel or
    storage call cannot leave an ``online`` claim standing.

    Presence: while a capture is open, the full discovery scan (which opens
    every video node) runs at most every ``presence_scan_seconds``; a real
    unplug surfaces through the open descriptor. A scan with probe failures
    that no longer lists the bound device is inconclusive and does not tear
    down the live descriptor. A closed capture always rescans before binding,
    and the identity re-verification after opening is unchanged.
    """

    def __init__(self, controller, discovery, profile, *, on_frame, on_profile,
                 capture_factory=MmapCapture, frame_stall_seconds=1.0,
                 frame_stall_reopen_seconds=5.0, presence_scan_seconds=1.0,
                 clock=time.monotonic):
        for value in (frame_stall_seconds, frame_stall_reopen_seconds, presence_scan_seconds):
            if type(value) not in (int, float) or not 0 < value < float("inf"):
                raise ValueError("capture session timing must be positive")
        if frame_stall_reopen_seconds < frame_stall_seconds:
            raise ValueError("stall reopen must not precede the stall report")
        self.controller = controller
        self.discovery = discovery
        self.profile = profile
        self.on_frame, self.on_profile = on_frame, on_profile
        self.capture_factory = capture_factory
        self.frame_stall_seconds = float(frame_stall_seconds)
        self.frame_stall_reopen_seconds = float(frame_stall_reopen_seconds)
        self.presence_scan_seconds = float(presence_scan_seconds)
        self.clock = clock
        self.capture = None
        self._last_scan = None
        # Shared with check_frame_progress(): (candidate, stall window, reopen
        # bound) of the open, profile-accepted capture, and the monotonic time
        # of its last frame (or of opening, before the first frame).
        self._progress_lock = threading.Lock()
        self._live = None
        self._last_progress = None

    def close(self):
        with self._progress_lock:
            self._live = None
            self._last_progress = None
        self._last_scan = None
        try:
            if self.capture is not None:
                self.capture.close()
        finally:
            self.capture = None
            self.controller.capture_closed()

    @property
    def stopped(self):
        return self.capture is None and self.controller.bound is None

    def supersede_stopped_session(self):
        if not self.stopped:
            raise ValueError("capture session must stop before reapproval")
        self.controller.supersede_stopped_session()

    def configure(self, *, enabled, profile):
        if enabled != self.controller.enabled or profile != self.profile:
            self.close()
            self.controller.set_enabled(enabled)
            self.profile = profile

    def _verify(self, candidate):
        current = self.discovery.scan()
        if current.failures:
            return False
        return self.controller.reconcile(current.devices) == candidate

    def _windows(self, negotiated):
        interval = 1.0 / negotiated.fps
        window = max(self.frame_stall_seconds, STALL_FRAME_INTERVALS * interval)
        # A slow profile widens both bounds by the same factor, so a stall is
        # always reported for a while before the capture is reopened.
        scale = window / self.frame_stall_seconds
        return window, self.frame_stall_reopen_seconds * scale

    def _presence(self):
        """Return the candidate to capture from, or None after a teardown."""
        now = self.clock()
        live = self.capture is not None and self.controller.bound is not None
        if live and self._last_scan is not None and now - self._last_scan < self.presence_scan_seconds:
            return self.controller.bound
        scan = self.discovery.scan()
        self._last_scan = now
        if self.capture is not None and self.controller.bound not in scan.devices:
            if scan.failures and self.controller.bound is not None:
                # A failed probe can hide the bound node; the open descriptor
                # still reports a real unplug, so keep it and rescan later.
                return self.controller.bound
            self.close()
            self.controller.disconnected()
            return None
        return self.controller.reconcile(scan.devices)

    def _stalled(self, candidate):
        with self._progress_lock:
            live, last = self._live, self._last_progress
        if live is None or last is None:
            return False
        _candidate, window, reopen = live
        age = self.clock() - last
        if age >= reopen:
            # A stall this long is treated as capture loss: reopen through
            # the identity path (a weak binding then needs the Owner again).
            self.close()
            self.controller.capture_failed()
        elif age >= window:
            self.controller.frame_stalled(candidate)
        return False

    def check_frame_progress(self):
        """Off-worker check: lower an ``online`` claim when frames stopped.

        Safe to call from a thread other than the source worker. It never
        closes, opens or rebinds anything; it only reports an open capture
        whose last frame is older than its stall window as ``degraded``.
        Returns True when it reported the stall.
        """
        with self._progress_lock:
            live, last = self._live, self._last_progress
        if live is None or last is None:
            return False
        candidate, window, _reopen = live
        if self.clock() - last < window:
            return False
        return self.controller.frame_stalled(candidate, only_online=True, blocking=False)

    def step(self, *, timeout=1.0):
        """Deliver at most one frame, returning False on offline/manual/failure."""
        if self.profile is None:
            self.close()
            if self.controller.requires_approval:
                # A missing profile must not hide a durable Owner action. This
                # needs no physical discovery and the transition is deduplicated.
                self.controller.reconcile(())
            return False
        if not self.controller.enabled or self.controller.requires_approval:
            # Neither state depends on physical discovery; skip the rescan.
            self.close()
            self.controller.reconcile(())
            return False
        try:
            candidate = self._presence()
            if candidate is None:
                if self.capture is not None or not self.controller.profile_unavailable:
                    self.close()
                return False
            if self.capture is None:
                self.capture = self.capture_factory(candidate, self.profile, verify_identity=self._verify)
                negotiated = self.capture.open()
                if not profile_satisfies(self.profile, negotiated.profile):
                    # The driver silently adjusted an unsupported request.
                    # Record what it negotiated, but never report the source
                    # online for a profile the Owner did not configure.
                    capture, self.capture = self.capture, None
                    try:
                        capture.close()
                    finally:
                        self.controller.capture_profile_unavailable(candidate)
                    self.on_profile(negotiated)
                    return False
                window, reopen = self._windows(negotiated.profile)
                with self._progress_lock:
                    self._live = (candidate, window, reopen)
                    self._last_progress = self.clock()
                self.on_profile(negotiated)
            with self._progress_lock:
                window = self._live[1] if self._live is not None else self.frame_stall_seconds
            try:
                frame = self.capture.read_frame(min(timeout, window))
            except FrameTimeout:
                return self._stalled(candidate)
            with self._progress_lock:
                self._last_progress = self.clock()
            self.controller.capture_ready(candidate)
            self.on_frame(frame)
            return True
        except (CaptureError, ProbeError, OSError):
            self.close()
            self.controller.capture_failed()
            return False
