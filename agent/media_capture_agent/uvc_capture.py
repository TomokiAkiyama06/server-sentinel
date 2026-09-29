"""Agent runtime ``Capture`` for 1-4 locally attached UVC cameras (video only).

Each poll rescans V4L2 evidence, reconciles every source against its durable
Owner approval, supervises one bounded pipeline per bound source and reports
per-source health. Camera loss, pipeline crashes and stalls change only that
source; they never raise into the Agent loop or make the node unhealthy.
Fail-closed rules:

- discovery that cannot enumerate every node never binds a camera;
- identity is re-verified after the device descriptor is opened, and the
  pipeline receives that exact descriptor (never a ``/dev/videoN`` path);
- a source is ``online`` only while frames actually arrive; dropped frames,
  startup/stall timeouts and malformed streams are visible;
- a pipeline that cannot be reaped blocks relaunch for that source and keeps
  the restart-recovery marker armed;
- device probing (V4L2 discovery ioctls, opening the capture node) runs off the
  Agent tick thread under a bound, so a hung camera/driver becomes a per-source
  ``discovery_failed``/``capture_failed`` and never stops the node heartbeat;
- queue drops stay latched until a ``degraded`` snapshot has reported them.

Frames go to a bounded per-source ``FrameQueue``. Transport/ring integration
(#15/#16) and the Owner approval route (#13/#14) are not wired here.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import threading
import time
from uuid import UUID

from .health import SourceHealth
from .uvc_approvals import ApprovalStorageError, ApprovalStore
from .uvc_discovery import DiscoveryResult, LinuxDiscovery, ProbeError
from .uvc_identity import CameraState, DeviceEvidence, ReconnectController
from .uvc_pipeline import (MAX_FRAME_BYTES, MAX_QUEUE_FRAMES, READ_CHUNK_BYTES, Frame,
                           FrameError, FrameQueue, MjpegFrameParser, MjpegProfile,
                           PipelineError)


MAX_SOURCES = 4
MJPEG = "MJPG"
_AMBIGUOUS = frozenset({"duplicate_identity", "identity_not_unique"})


class CaptureRefused(RuntimeError):
    """A fixed safe reason; never carries device paths, serials or OS text."""


class CaptureCleanupError(RuntimeError):
    """At least one pipeline could not be reaped or state could not be released."""


def _positive(value, maximum):
    return type(value) in (int, float) and 0 < value <= maximum


@dataclass(frozen=True)
class CaptureLimits:
    max_frame_bytes: int = 8 * 1024 * 1024
    queue_frames: int = 8
    startup_timeout: float = 10.0
    stall_timeout: float = 5.0
    stop_timeout: float = 3.0
    # Bound for one discovery scan or capture-node open on the tick thread.
    device_timeout: float = 2.0
    backoff_initial: float = 1.0
    backoff_max: float = 60.0

    def __post_init__(self):
        if type(self.max_frame_bytes) is not int or not 64 <= self.max_frame_bytes <= MAX_FRAME_BYTES:
            raise ValueError("invalid frame bound")
        if type(self.queue_frames) is not int or not 1 <= self.queue_frames <= MAX_QUEUE_FRAMES:
            raise ValueError("invalid frame queue bound")
        for value in (self.startup_timeout, self.stall_timeout, self.stop_timeout):
            if not _positive(value, 300):
                raise ValueError("invalid capture timeout")
        if not _positive(self.device_timeout, 60):
            raise ValueError("invalid capture timeout")
        if not _positive(self.backoff_initial, 3600) or not _positive(self.backoff_max, 3600):
            raise ValueError("invalid capture backoff")
        if self.backoff_initial > self.backoff_max:
            raise ValueError("invalid capture backoff")


@dataclass(frozen=True)
class UvcSourceConfig:
    source_id: UUID
    profile: MjpegProfile

    def __post_init__(self):
        if not isinstance(self.source_id, UUID) or not isinstance(self.profile, MjpegProfile):
            raise ValueError("invalid UVC source configuration")


def open_video_device(candidate):
    """Open exactly the discovered character device; no symlink or path substitution."""
    path = Path(candidate.device_path)
    if path.parent != Path("/dev") or not re.fullmatch(r"video[0-9]+", path.name):
        raise CaptureRefused("invalid video capture node")
    if candidate.device_number is None:
        raise CaptureRefused("video device number is unavailable")
    descriptor = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != candidate.device_number:
            raise CaptureRefused("video capture node changed")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


class _Call:
    """One blocking call in a worker; a result arriving after abandon is discarded."""

    def __init__(self, discard):
        self.done = threading.Event()
        self._lock = threading.Lock()
        self._discard = discard
        self._abandoned = False
        self._value = None
        self._error = None

    def execute(self, function):
        value = error = None
        try:
            value = function()
        except BaseException as exc:  # Re-raised in the caller, never in the worker.
            error = exc
        with self._lock:
            abandoned = self._abandoned
            if not abandoned:
                self._value, self._error = value, error
            self.done.set()
        if abandoned and error is None:
            self._release(value)

    def abandon(self):
        with self._lock:
            self._abandoned = True
            late = self.done.is_set() and self._error is None
            value, self._value = self._value, None
        if late:
            # Finished between the timed-out wait and this abandon: still unused.
            self._release(value)

    def _release(self, value):
        if self._discard is not None and value is not None:
            try:
                self._discard(value)
            except Exception:
                pass

    def result(self):
        if self._error is not None:
            raise self._error
        return self._value


class _BoundedCall:
    """Run a potentially blocking device call off the Agent tick thread.

    At most one call is outstanding: while an earlier call is still blocked
    (e.g. an ioctl on a hung UVC driver) new requests fail at once, so the
    number of stuck threads never grows. A timed-out call's late result is
    passed to ``discard`` (e.g. close a descriptor) and never used.
    """

    def __init__(self, name, discard=None):
        self._name = name
        self._discard = discard
        self._pending = None

    @property
    def blocked(self):
        return self._pending is not None and not self._pending.done.is_set()

    def run(self, function, timeout):
        if self.blocked:
            raise TimeoutError("device call still blocked")
        call = _Call(self._discard)
        thread = threading.Thread(target=call.execute, args=(function,), name=self._name,
                                  daemon=True)
        try:
            thread.start()
        except RuntimeError:
            raise TimeoutError("device call could not start") from None
        if not call.done.wait(timeout):
            self._pending = call
            call.abandon()
            raise TimeoutError("device call exceeded bound")
        self._pending = None
        return call.result()


class _Active:
    """One running pipeline plus its reader thread; frames only via the queue."""

    def __init__(self, candidate, process, parser, queue, generation, clock, started):
        self.candidate = candidate
        self.process = process
        self.parser = parser
        self.queue = queue
        self.generation = generation
        self.clock = clock
        self.started = started
        self.first_frame = None
        self.last_frame = None
        self.frames = 0
        self.eof = False
        self.error = None
        self._lock = threading.Lock()
        self.thread = threading.Thread(target=self._read, name="media-capture-agent-uvc",
                                       daemon=True)

    def _read(self):
        try:
            while True:
                data = self.process.read(READ_CHUNK_BYTES)
                if not data:
                    if self.parser.partial:
                        self.error = "stream_truncated"
                    self.eof = True
                    return
                for image in self.parser.feed(data):
                    now = self.clock()
                    with self._lock:
                        self.frames += 1
                        if self.first_frame is None:
                            self.first_frame = now
                        self.last_frame = now
                        sequence = self.frames
                    self.queue.put(Frame(image, sequence, self.generation, now))
        except FrameError:
            self.error = "stream_invalid"
        except Exception:  # A dead reader must be visible, never a silent stall.
            self.error = "reader_failed"

    def timing(self):
        with self._lock:
            return self.first_frame, self.last_frame


class _Source:
    def __init__(self, config, controller, limits, clock):
        self.config = config
        self.controller = controller
        self.queue = FrameQueue(limits.queue_frames, clock=clock)
        self.active = None
        self.stuck = []
        self.generation = 0
        self.backoff = limits.backoff_initial
        self.retry_at = 0.0
        self.discovery_blocked = False
        self.storage_failed = False
        # Queue drops already surfaced in a degraded snapshot.
        self.reported_drops = 0
        # Last capture failure while no pipeline runs; cleared by real frames.
        self.failure = None


class UvcCapture:
    """Implements ``runtime.Capture`` for approved local UVC sources."""

    def __init__(self, settings, sources, *, launcher, store=None, discovery=None,
                 limits=None, open_device=open_video_device, close_device=os.close,
                 clock=time.monotonic, geteuid=os.geteuid):
        if geteuid() == 0:
            raise CaptureRefused("dedicated_nonroot_account_required")
        sources = tuple(sources)
        if not 1 <= len(sources) <= MAX_SOURCES or any(
                not isinstance(source, UvcSourceConfig) for source in sources):
            raise ValueError("between one and four UVC sources are required")
        if len({source.source_id for source in sources}) != len(sources):
            raise ValueError("duplicate UVC source identity")
        if not callable(getattr(launcher, "launch", None)):
            raise TypeError("a capture pipeline launcher is required")
        self.limits = limits or CaptureLimits()
        if not isinstance(self.limits, CaptureLimits):
            raise TypeError("invalid capture limits")
        self.launcher = launcher
        self.discovery = discovery or LinuxDiscovery()
        self.open_device, self.close_device, self.clock = open_device, close_device, clock
        self._discovery_call = _BoundedCall("media-capture-agent-uvc-discovery")
        # Inside poll(): one stop bound shared by every teardown of that tick.
        self._teardown_deadline = None
        self._owns_store = store is None
        self.store = ApprovalStore(settings) if store is None else store
        self._lock = threading.RLock()
        self._closed = False
        self._sources = {}
        try:
            for config in sources:
                controller = ReconnectController(config.source_id, self.store)
                source = _Source(config, controller, self.limits, clock)
                source.open_call = _BoundedCall("media-capture-agent-uvc-open",
                                                discard=self._close_quietly)
                self._sources[config.source_id] = source
        except BaseException:
            if self._owns_store:
                self.store.close()
            raise

    # -- discovery ---------------------------------------------------------
    def _close_quietly(self, descriptor):
        try:
            self.close_device(descriptor)
        except OSError:
            pass

    def _scan(self):
        # A timed-out or still-blocked scan (TimeoutError is an OSError) proves
        # neither absence nor uniqueness: it counts as a failed node.
        try:
            result = self._discovery_call.run(self.discovery.scan, self.limits.device_timeout)
        except (OSError, ValueError, ProbeError):
            return DiscoveryResult((), 1)
        if not isinstance(result, DiscoveryResult) or any(
                not isinstance(device, DeviceEvidence) for device in result.devices):
            raise TypeError("invalid discovery result")
        return result

    # -- lifecycle ---------------------------------------------------------
    def _schedule_retry(self, source, now):
        source.retry_at = now + source.backoff
        source.backoff = min(self.limits.backoff_max, source.backoff * 2)

    def _teardown(self, source):
        active, source.active = source.active, None
        if active is None:
            return
        if not self._reap(active):
            source.stuck.append(active)

    def _stop_bound(self):
        if self._teardown_deadline is None:
            return self.limits.stop_timeout
        return max(0.0, min(self.limits.stop_timeout,
                            self._teardown_deadline - time.monotonic()))

    def _reap(self, active, timeout=None):
        # In poll() all teardowns share one stop bound, so several cameras
        # failing together (e.g. a USB hub fault) cannot multiply the delay
        # before the heartbeat; an unfinished one is retried as stuck.
        timeout = self._stop_bound() if timeout is None else timeout
        stopped = active.process.stop(timeout)
        if active.thread.ident is not None:
            active.thread.join(min(timeout, self._stop_bound()))
        if not stopped or active.thread.is_alive():
            return False
        active.process.close()
        return True

    def _retry_stuck(self, source):
        # Already waited the full bound once at teardown. A process stuck in
        # uninterruptible sleep must not stall every poll (and so the node
        # heartbeat); later attempts re-signal and only check without waiting.
        source.stuck = [active for active in source.stuck if not self._reap(active, 0.0)]

    def _storage_failure(self, source):
        self._teardown(source)
        source.storage_failed = True
        source.controller.bound = None

    def _reconcile(self, source, scan):
        controller, active = source.controller, source.active
        present = active is not None and scan.devices.count(active.candidate) == 1
        if scan.failures and not present:
            # An unreadable node could be the approved camera or a duplicate;
            # neither absence nor uniqueness is proven.
            source.discovery_blocked = True
            if active is not None:
                self._teardown(source)
                controller.capture_closed("discovery_failed")
            return
        source.discovery_blocked = False
        try:
            bound = controller.reconcile(scan.devices)
        except ApprovalStorageError:
            self._storage_failure(source)
            return
        if active is not None and bound != active.candidate:
            self._teardown(source)
            if controller.state != CameraState.MANUAL:
                controller.capture_closed()

    def _supervise(self, source, now):
        active, controller = source.active, source.controller
        if active is None:
            return
        first, last = active.timing()
        failed = (active.error is not None or active.eof or active.process.exited()
                  or first is None and now - active.started > self.limits.startup_timeout
                  or last is not None and now - last > self.limits.stall_timeout)
        if failed:
            self._teardown(source)
            controller.capture_failed()
            source.failure = "capture_failed"
            self._schedule_retry(source, now)
        elif first is not None and controller.state != CameraState.ONLINE:
            controller.capture_ready(active.candidate)
            source.failure = None
            source.backoff = self.limits.backoff_initial

    def _resolve_conflicts(self):
        by_device = {}
        for source in self._sources.values():
            bound = source.controller.bound
            if bound is not None and bound.device_number is not None:
                by_device.setdefault(bound.device_number, []).append(source)
        for sharing in by_device.values():
            if len(sharing) < 2:
                continue
            for source in sharing:
                self._teardown(source)
                try:
                    source.controller.require_approval("identity_not_unique")
                except ApprovalStorageError:
                    self._storage_failure(source)

    def _launch(self, source, now):
        controller = source.controller
        candidate = controller.bound
        if MJPEG not in candidate.formats:
            controller.capture_failed()
            source.failure = "capture_unsupported"
            self._schedule_retry(source, now)
            return
        descriptor = None
        process = None
        try:
            descriptor = source.open_call.run(lambda: self.open_device(candidate),
                                              self.limits.device_timeout)
            # Re-verify after opening: the descriptor must belong to the same,
            # still unique physical evidence the controller would bind now.
            fresh = self._scan()
            if (fresh.failures or fresh.devices.count(candidate) != 1
                    or controller.reconcile(fresh.devices) != candidate):
                raise CaptureRefused("video capture identity changed")
            process = self.launcher.launch(descriptor, source.config.profile)
        except ApprovalStorageError:
            self._storage_failure(source)
            return
        except (CaptureRefused, PipelineError, OSError, ValueError):
            if not controller.requires_approval:
                controller.capture_failed()
                source.failure = "capture_failed"
            self._schedule_retry(source, now)
            return
        finally:
            if descriptor is not None:
                try:
                    self.close_device(descriptor)
                except OSError:
                    pass
        source.generation += 1
        parser = MjpegFrameParser(self.limits.max_frame_bytes)
        active = _Active(candidate, process, parser, source.queue, source.generation,
                         self.clock, now)
        source.active = active
        try:
            active.thread.start()
        except RuntimeError:
            self._teardown(source)
            controller.capture_failed()
            source.failure = "capture_failed"
            self._schedule_retry(source, now)

    # -- health --------------------------------------------------------------
    def _health(self, source, now):
        controller = source.controller
        source_id = source.config.source_id
        if source.storage_failed:
            return SourceHealth(source_id, "manual_intervention_required", "approval_state_unavailable")
        if controller.state == CameraState.MANUAL or controller.requires_approval:
            reason = "identity_ambiguous" if controller.reason in _AMBIGUOUS else "owner_approval_required"
            return SourceHealth(source_id, "manual_intervention_required", reason)
        if source.stuck:
            return SourceHealth(source_id, "offline", "capture_cleanup_failed")
        if source.discovery_blocked:
            return SourceHealth(source_id, "offline", "discovery_failed")
        if controller.state == CameraState.ONLINE and source.active is not None:
            dropped, drop = source.queue.drop_stats()
            # A drop between polls (or older than the window when polls are
            # slower than stall_timeout) is still reported once before recovery.
            if (dropped != source.reported_drops
                    or drop is not None and now - drop <= self.limits.stall_timeout):
                source.reported_drops = dropped
                return SourceHealth(source_id, "degraded", "capture_overloaded")
            return SourceHealth(source_id, "online", "video_ready")
        if controller.state == CameraState.DEGRADED and source.active is not None:
            return SourceHealth(source_id, "degraded", "capture_starting")
        if source.failure is not None and controller.reason != "approved_device_absent":
            # Waiting for a bounded retry is not a starting camera.
            return SourceHealth(source_id, "offline", source.failure)
        if controller.state == CameraState.DEGRADED:
            return SourceHealth(source_id, "degraded", "capture_starting")
        if controller.reason in ("approved_device_absent", "video_capture_closed"):
            return SourceHealth(source_id, "offline", "camera_missing")
        return SourceHealth(source_id, "offline", "capture_failed")

    # -- Capture protocol ----------------------------------------------------
    def poll(self):
        with self._lock:
            if self._closed:
                raise CaptureRefused("capture is closed")
            scan = self._scan()
            # Sample after the bounded scan so timeouts use the current time.
            now = self.clock()
            self._teardown_deadline = time.monotonic() + self.limits.stop_timeout
            try:
                for source in self._sources.values():
                    self._retry_stuck(source)
                    if not source.storage_failed:
                        self._reconcile(source, scan)
                for source in self._sources.values():
                    self._supervise(source, now)
                self._resolve_conflicts()
            finally:
                self._teardown_deadline = None
            for source in self._sources.values():
                controller = source.controller
                if (source.active is None and not source.stuck and not source.storage_failed
                        and not source.discovery_blocked and controller.bound is not None
                        and not controller.requires_approval and now >= source.retry_at):
                    self._launch(source, now)
            return tuple(self._health(source, now) for source in self._sources.values())

    def frames(self, source_id):
        """Bounded compressed-frame queue for a later ring/transport consumer."""
        return self._sources[source_id].queue

    def candidates(self, source_id):
        """Current Owner-selectable evidence; private, for the Owner boundary only."""
        with self._lock:
            if source_id not in self._sources:
                raise KeyError("unknown source")
            scan = self._scan()
            if scan.failures:
                raise CaptureRefused("discovery_failed")
            return scan.devices

    def approve(self, source_id, candidate):
        """Owner-authorized re-approval of an exact current candidate.

        This is an internal boundary. The Owner route that authenticates and
        audits the decision is supplied by the approval flow (#13/#14).
        """
        with self._lock:
            if self._closed:
                raise CaptureRefused("capture is closed")
            source = self._sources[source_id]
            if not isinstance(candidate, DeviceEvidence):
                raise CaptureRefused("invalid candidate")
            if source.stuck or source.storage_failed:
                raise CaptureRefused("source requires local recovery")
            scan = self._scan()
            if scan.failures:
                raise CaptureRefused("discovery_failed")
            if any(other is not source and other.controller.bound is not None
                   and other.controller.bound.device_number == candidate.device_number
                   for other in self._sources.values()):
                raise CaptureRefused("candidate is bound to another source")
            self._teardown(source)
            if source.stuck:
                raise CaptureRefused("source requires local recovery")
            source.controller.capture_closed()
            try:
                source.controller.approve(candidate, scan.devices)
            except ApprovalStorageError:
                self._storage_failure(source)
                raise CaptureRefused("approval_state_unavailable") from None
            source.retry_at = 0.0
            source.failure = None
            source.backoff = self.limits.backoff_initial

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            failed = False
            for source in self._sources.values():
                self._teardown(source)
                # Shutdown grants every stuck pipeline one more full bound.
                source.stuck = [active for active in source.stuck if not self._reap(active)]
                source.queue.close()
                source.controller.capture_closed()
                if source.stuck or source.storage_failed:
                    # Keep the recovery marker armed: restart requires re-approval.
                    failed = True
                    continue
                try:
                    source.controller.shutdown()
                except (ApprovalStorageError, ValueError):
                    failed = True
            if self._owns_store:
                self.store.close()
            if failed:
                raise CaptureCleanupError("UVC capture did not shut down cleanly")
