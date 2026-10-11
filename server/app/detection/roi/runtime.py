"""Main-runtime wiring of calibrated scene detection (Issue #205).

`SceneMonitoringRuntime` connects capture frame callbacks to one
`SceneDetector` per configured source, behind that source's own
detector-specific quality gates, and hands every confirmed critical
observation to the injected durable `CriticalRecorder` (in the Main runtime,
`app.presence.adapters.CriticalTimelineRecorder`) through bounded critical
staging. The recorder is only ever called on a dedicated delivery thread, so a
stalled recorder (for example on stalled storage) never blocks sampling or
detection: staging fills, new confirmations are refused as explicit
backpressure, and a call in flight longer than the stall bound is reported.

Capture threads only take a cheap, non-blocking sample decision: at most one
pending sample per source is held (a newer one replaces it and the replacement
is counted), so a slow evaluation never blocks or buffers capture. Decoding,
quality assessment and detection run on one bounded worker thread, which
isolates each source: a failure in one source makes that source `unknown` and
leaves the others running.

The runtime fails closed throughout. Without a durable critical recorder no
detector runs. Without a stored calibration whose reference frame can be
re-bound (the Owner calibration route is Issue #10), a source stays inactive
and `unknown`; no baseline is fabricated from live frames. Poor or unknown
quality, an undecodable frame, a sampling gap, critical backpressure or an
evaluation failure is `unknown`, never "no movement" or "no tamper". Results
are neutral scene observations; they never name a person or assert a cause.
No frame or pixel is retained after evaluation, and nothing is persisted here.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import logging
import math
import sqlite3
import threading
import time
from contextlib import closing
from typing import Callable, Protocol
from uuid import UUID, uuid4

from app.cameras.registry.models import SourceType
from app.detection.foundation import GrayFrame, Observation
from app.detection.quality import DetectorQualityPolicy, Execution, QualityGate
from app.logging import Event
from .calibration import CalibrationArchive, CalibrationRecord
from .contracts import Calibration, CriticalObservation
from .delivery import MAXIMUM_BATCH, CriticalRecorder
from .detector import SceneDetector
from .mjpg import MjpgFrameRejected, MjpgLumaLayout


MAXIMUM_SOURCES = 4
# Conservative default: one evaluated sample per second per source. A
# calibration whose `maximum_gap_ns` does not exceed the configured interval
# is refused, because every sample would then be a sampling discontinuity.
DEFAULT_SAMPLE_INTERVAL_NS = 1_000_000_000
DEFAULT_CRITICAL_CAPACITY = 4 * MAXIMUM_BATCH * MAXIMUM_SOURCES
CALIBRATION_RETRY_NS = 60 * 1_000_000_000
# `SceneDetector.source_lost` confirms at most one CAMERA_TAMPER observation.
LOSS_BATCH = 1
# Producer stream identities a decoded-sample source has replaced. Frames from
# one of them are stale imagery and are refused on the capture side. The set
# is never evicted from: once it is full a further replacement stream is
# refused (the source reports `stream_history_exhausted`) instead of
# forgetting a retired identity.
RETIRED_PRODUCER_LIMIT = 1024
MINIMUM_TICK_SECONDS = 0.01
MAXIMUM_TICK_SECONDS = 60.0
# A recorder call in flight longer than this is reported as stalled.
DEFAULT_RECORDER_STALL_NS = 5 * 1_000_000_000
# Bound on closing an already started delivery thread when the worker thread
# cannot be started.
START_ROLLBACK_TIMEOUT_SECONDS = 5.0
PACKED_FORMATS = {"GREY": 1, "YUYV": 2}


class CalibrationUnavailable(Exception):
    """A calibration provider's fixed, value-free reason for no calibration."""

    REASONS = frozenset({
        "calibration_missing", "calibration_reference_unavailable",
        "calibration_unavailable", "calibration_unreadable", "calibration_integrity_failed",
    })

    def __init__(self, reason: str):
        if reason not in self.REASONS:
            reason = "calibration_unavailable"
        super().__init__(reason)
        self.reason = reason


class CalibrationProvider(Protocol):
    def __call__(self, binding: "SceneSourceBinding") -> Calibration:
        """Return the bound calibration or raise `CalibrationUnavailable`."""
        ...


class ArchiveCalibrationProvider:
    """Resolve the latest archived calibration and re-bind its reference.

    The archive keeps provenance only, never a reference image. `references`
    is the deployment's Owner-controlled port that supplies the transient
    reference frame again (Issue #10); without it, or when it has none, a
    stored calibration stays unusable rather than being re-based on a live
    frame. `connect` opens a fresh connection on the calling (worker) thread.
    """

    def __init__(self, connect: Callable[[], sqlite3.Connection], *,
                 references: Callable[[CalibrationRecord], GrayFrame | None] | None = None):
        if not callable(connect) or references is not None and not callable(references):
            raise ValueError("invalid calibration provider")
        self.connect, self.references = connect, references

    def __call__(self, binding: "SceneSourceBinding") -> Calibration:
        try:
            with closing(self.connect()) as connection:
                record = CalibrationArchive(connection).load(binding.source_id, binding.profile_id)
        except ValueError:
            raise CalibrationUnavailable("calibration_unreadable") from None
        except Exception:
            raise CalibrationUnavailable("calibration_unavailable") from None
        if record is None:
            raise CalibrationUnavailable("calibration_missing")
        if self.references is None:
            raise CalibrationUnavailable("calibration_reference_unavailable")
        try:
            reference = self.references(record)
        except Exception:
            reference = None
        if reference is None:
            raise CalibrationUnavailable("calibration_reference_unavailable")
        try:
            return record.rehydrate(reference)
        except Exception:
            raise CalibrationUnavailable("calibration_integrity_failed") from None


@dataclass(frozen=True)
class PackedLumaLayout:
    """Exact uncompressed capture layout whose luma plane can be sampled.

    Only packed `GREY` and `YUYV` are read here: their luma is read by byte
    slicing with no image library. `MJPG` uses the reviewed decoder in
    `MjpgLumaLayout` (Issue #217); any other compressed format is refused.
    Frames whose length does not match this exact unpadded layout are refused
    per frame.
    """

    width: int
    height: int
    pixel_format: str

    def __post_init__(self):
        for value in (self.width, self.height):
            if type(value) is not int or not 1 <= value <= 16384:
                raise ValueError("invalid capture dimensions")
        if self.pixel_format not in PACKED_FORMATS:
            raise ValueError("capture pixel format has no reviewed luma reader")

    def available(self) -> bool:
        return True

    def compatible(self, width: int, height: int) -> bool:
        return self.width % width == 0 and self.height % height == 0

    def luma(self, data, width: int, height: int) -> bytes:
        """Nearest-sample decimation of the luma plane to `width` x `height`."""
        if not self.compatible(width, height):
            raise ValueError("capture layout does not decimate to the reference")
        buffer = data if type(data) is bytes else bytes(memoryview(data).cast("B"))
        step = PACKED_FORMATS[self.pixel_format]
        line = self.width * step
        if len(buffer) != line * self.height:
            raise ValueError("frame does not match the capture layout")
        fx, fy = self.width // width, self.height // height
        output = bytearray()
        for row in range(height):
            start = row * fy * line
            output += buffer[start:start + line:step * fx]
        return bytes(output)


CAPTURE_LAYOUTS = (PackedLumaLayout, MjpgLumaLayout)


def capture_luma_layout(width: int, height: int, pixel_format: str):
    """The reviewed luma reader for a negotiated local UVC format.

    Pass the driver-negotiated profile, never the requested one. A format with
    no reviewed reader raises `ValueError`, so that source cannot be bound.
    """
    if pixel_format == MjpgLumaLayout.pixel_format:
        return MjpgLumaLayout(width, height)
    return PackedLumaLayout(width, height, pixel_format)


def _policy(value, detector):
    if not isinstance(value, DetectorQualityPolicy) or value.detector != detector:
        raise ValueError("a detector-specific quality policy is required")
    return value


@dataclass(frozen=True)
class SceneSourceBinding:
    source_id: UUID
    source_type: SourceType
    profile_id: UUID
    # Independent prerequisites: a frame may be unusable for one and usable
    # for the other. Neither is supplied by default.
    movement_quality: DetectorQualityPolicy = field(repr=False)
    tamper_quality: DetectorQualityPolicy = field(repr=False)
    # Required for raw local UVC frames (packed luma or reviewed MJPG
    # decoding, see `capture_luma_layout`); None for producers that already
    # supply decoded grayscale samples (`offer_luma`).
    layout: PackedLumaLayout | MjpgLumaLayout | None = None
    sample_interval_ns: int = DEFAULT_SAMPLE_INTERVAL_NS

    def __post_init__(self):
        if not isinstance(self.source_id, UUID) or not isinstance(self.profile_id, UUID):
            raise ValueError("scene binding identities must be UUIDs")
        if not isinstance(self.source_type, SourceType):
            raise ValueError("invalid scene source type")
        _policy(self.movement_quality, "server_roi")
        _policy(self.tamper_quality, "camera_tamper")
        if self.layout is not None and not isinstance(self.layout, CAPTURE_LAYOUTS):
            raise ValueError("invalid capture layout")
        if self.source_type is SourceType.LOCAL_UVC and self.layout is None:
            raise ValueError("local UVC scene detection requires its capture layout")
        if self.source_type is SourceType.REMOTE_AGENT and self.layout is not None:
            raise ValueError("remote agent samples arrive decoded")
        if type(self.sample_interval_ns) is not int or self.sample_interval_ns <= 0:
            raise ValueError("invalid scene sample interval")


@dataclass(frozen=True)
class SceneMonitoringConfiguration:
    bindings: tuple[SceneSourceBinding, ...] = field(repr=False)
    critical_capacity: int = DEFAULT_CRITICAL_CAPACITY

    def __post_init__(self):
        if (type(self.bindings) is not tuple or not 1 <= len(self.bindings) <= MAXIMUM_SOURCES
                or any(not isinstance(item, SceneSourceBinding) for item in self.bindings)
                or len({item.source_id for item in self.bindings}) != len(self.bindings)):
            raise ValueError("scene monitoring needs 1 to 4 distinct source bindings")
        if type(self.critical_capacity) is not int or not MAXIMUM_BATCH <= self.critical_capacity <= 4096:
            raise ValueError("invalid critical staging capacity")

    @property
    def source_ids(self) -> tuple[UUID, ...]:
        return tuple(item.source_id for item in self.bindings)


def _utcnow():
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SceneMonitoringDependencies:
    """Injected ports. Without `recorder` no detector runs; without
    `calibrations` every source stays inactive and unknown."""

    recorder: CriticalRecorder | None = None
    calibrations: CalibrationProvider | None = None
    monotonic_ns: Callable[[], int] = time.monotonic_ns
    utcnow: Callable[[], datetime] = _utcnow
    tick_seconds: float = 0.5
    calibration_retry_ns: int = CALIBRATION_RETRY_NS
    recorder_stall_ns: int = DEFAULT_RECORDER_STALL_NS

    def __post_init__(self):
        tick = self.tick_seconds
        if (type(tick) not in (int, float) or not math.isfinite(tick)
                or not MINIMUM_TICK_SECONDS <= tick <= MAXIMUM_TICK_SECONDS):
            # A zero, negative or tiny tick would spin the worker and delivery
            # threads; a huge one would hide state changes for too long.
            raise ValueError("invalid scene monitoring tick")
        for value in (self.calibration_retry_ns, self.recorder_stall_ns):
            if type(value) is not int or value <= 0:
                raise ValueError("invalid scene monitoring interval")
        if not callable(self.monotonic_ns) or not callable(self.utcnow):
            raise ValueError("invalid scene monitoring clock")


class SceneRuntimeState(StrEnum):
    # Reported by the Main application when no scene configuration exists.
    UNCONFIGURED = "unconfigured"
    CONFIGURED = "configured"
    RUNNING = "running"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    STOPPED = "stopped"
    STOP_FAILED = "stop_failed"


class SceneSourceState(StrEnum):
    INACTIVE = "inactive"
    ACTIVE = "active"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class SceneSourceStatus:
    source_id: UUID
    source_type: SourceType
    state: SceneSourceState
    reason: str
    movement: Observation
    tamper: Observation
    movement_reason: str
    tamper_reason: str
    calibration_version: int | None
    accepted: int
    sampled_out: int
    replaced: int
    evaluated: int
    unusable: int
    backpressured: int
    failures: int
    # Decoded samples refused because their producer stream was already
    # replaced (stale imagery) or the retired-stream history is full, and
    # pending samples discarded because their producer stream was retired
    # (or found stale at history exhaustion) before they were evaluated.
    stale_rejected: int = 0
    # Pending samples captured before a calibration refresh request, discarded
    # instead of becoming the first sample of the refreshed detector.
    refresh_discarded: int = 0
    # A calibration refresh was requested and has not run yet. It is deferred
    # while a camera loss is still to be handed to the current detector, so
    # under sustained losses it can stay pending; this makes that visible.
    refresh_pending: bool = False


@dataclass(frozen=True)
class SceneRuntimeStatus:
    state: SceneRuntimeState
    sources: tuple[SceneSourceStatus, ...]
    critical_pending: int
    critical_accepted: int
    worker_running: bool
    # Camera losses waiting for critical staging room. After `stop()` this is
    # how many could not be handed to their detector (in memory only, never
    # persisted), alongside `critical_pending`.
    losses_held: int = 0
    # Camera losses that could not be handed to their detector because the
    # source faulted or a shutdown drain failed (logged and counted here).
    losses_failed: int = 0
    # A recorder call is in progress on the delivery thread, and whether it
    # has been in flight longer than `recorder_stall_ns`.
    critical_in_flight: bool = False
    recorder_stalled: bool = False
    delivery_running: bool = False
    # Confirmed observations a worker that outlived its stop bound tried to
    # stage after staging closed (in memory only, logged, never delivered).
    critical_refused: int = 0


@dataclass
class _Sample:
    stream_id: UUID
    sequence: int
    monotonic_ns: int
    observed_at: datetime
    data: object
    width: int | None = None
    height: int | None = None
    # The producer stream the sample came from (None for local UVC capture).
    producer: UUID | None = None


@dataclass
class _Loss:
    monotonic_ns: int
    observed_at: datetime
    trusted: bool


@dataclass
class _Slot:
    """Capture-side state, guarded by the runtime lock."""

    binding: SceneSourceBinding
    sample: _Sample | None = None
    loss: _Loss | None = None
    stream_id: UUID | None = None
    # The producer stream the current runtime stream was minted for, and
    # whether an interruption requires a new one for the next sample.
    minted_for: UUID | None = None
    new_stream: bool = True
    sequence: int = -1
    last_accepted_ns: int | None = None
    last_uvc_sequence: int | None = None
    retired_producers: set = field(default_factory=set)
    history_exhausted: bool = False
    # When the history was exhausted: a camera loss timestamped at or after
    # it is handed to the detector as untrusted (Owner decision 2026-10-11).
    exhausted_ns: int | None = None
    accepted: int = 0
    sampled_out: int = 0
    replaced: int = 0
    stale_rejected: int = 0


@dataclass
class _Published:
    """Worker results, guarded by the runtime lock."""

    state: SceneSourceState = SceneSourceState.INACTIVE
    reason: str = "not_started"
    movement: Observation = Observation.UNKNOWN
    tamper: Observation = Observation.UNKNOWN
    movement_reason: str = "unavailable"
    tamper_reason: str = "unavailable"
    calibration_version: int | None = None
    evaluated_ns: int | None = None
    # When the source last became active (calibration bound), so a source
    # that never receives a sample is also lowered once the gap elapses.
    active_since_ns: int | None = None
    maximum_gap_ns: int | None = None
    evaluated: int = 0
    unusable: int = 0
    backpressured: int = 0
    failures: int = 0
    refresh_discarded: int = 0


class _Context:
    """Worker-only detector state for one source."""

    def __init__(self, binding):
        self.binding = binding
        self.calibration = None
        self.detector = None
        self.movement_gate = self.tamper_gate = None
        self.resolved_ns = None
        self.refresh = True
        # Monotonic time of the latest refresh request: a pending sample
        # captured at or before it is never evaluated by the refreshed
        # detector (it may show the scene before the new calibration).
        self.refresh_ns = None
        # A trusted or untrusted loss that could not be handed to the detector
        # because critical staging had no room. It is kept (not converted to
        # a failure) until staging drains, so a loss correlated with a scene
        # shift is never dropped as evidence.
        self.held_loss = None
        # A loss taken from the capture slot (merged with a held one) that has
        # not yet been handed to the detector and staged. A fault while it is
        # set means that loss is lost, and it is counted.
        self.unprocessed_loss = None


@dataclass(frozen=True)
class _PumpSnapshot:
    pending: int
    accepted: int
    # Observations refused because staging was already closed (shutdown).
    refused: int
    in_flight_since: int | None
    call: int
    running: bool


class _CriticalPump:
    """Bounded in-memory critical staging, delivered off the scene worker.

    `submit()` never calls the recorder on a threaded pump: it only stages a
    whole batch (or raises `BufferError`, which callers avoid by checking
    `remaining` first). The delivery thread calls the recorder one observation
    at a time and records when each call started, so a call that does not
    return is visible as in flight instead of wedging detection. An item stays
    staged and counted until the recorder accepts it. After `close()` no
    further recorder call starts and `submit()` refuses (a worker that outlived
    its stop bound cannot stage into a pump nobody delivers from; refused
    observations are counted and logged); a call already in flight is
    reported, never waited on without bound. An unthreaded pump (tests driving
    `step()`) delivers on the caller instead.
    """

    def __init__(self, *, capacity, recorder, clock, tick_seconds, threaded):
        self.capacity, self.recorder, self.clock = capacity, recorder, clock
        self.tick_seconds, self.threaded = tick_seconds, threaded
        self._lock = threading.Lock()
        self._wake = threading.Condition(self._lock)
        self._pending = {}
        self._accepted = 0
        self._refused = 0
        # Serial of the most recent recorder call, so each distinct call that
        # stalls is reported once even when the clock repeats a value.
        self._call = 0
        self._in_flight_since = None
        self._stopping = self._closed = False
        self._thread = None

    def start(self):
        if self.threaded:
            thread = threading.Thread(target=self._run, name="scene-critical-delivery",
                                      daemon=True)
            # Retained only once started: a thread that could not be started
            # is never joined (`close()`) nor reported as a dead thread.
            thread.start()
            with self._lock:
                self._thread = thread

    @property
    def remaining(self):
        with self._lock:
            return self.capacity - len(self._pending)

    def snapshot(self):
        with self._lock:
            thread = self._thread
            return _PumpSnapshot(len(self._pending), self._accepted, self._refused,
                                 self._in_flight_since, self._call,
                                 thread is not None and thread.is_alive())

    def submit(self, observations):
        """Stage a whole batch. Returns False (counted, logged) after close."""
        if any(not isinstance(item, CriticalObservation) or not item.confirmed
               for item in observations):
            raise ValueError("only confirmed critical observations may be submitted")
        new = {item.identifier: item for item in observations}
        with self._lock:
            closed = self._closed
            if closed:
                self._refused += len(new)
            elif len(set(new) - set(self._pending)) > self.capacity - len(self._pending):
                raise BufferError("critical staging is full")
            else:
                self._pending.update(new)
                self._wake.notify_all()
        if closed:
            logging.getLogger(__name__).error(Event.SCENE_CRITICAL_UNDELIVERED)
            return False
        self.kick()
        return True

    def kick(self):
        """Deliver now on an unthreaded pump; a threaded pump delivers on its
        own thread after every submit and retries refusals on its tick."""
        if not self.threaded:
            self.deliver()

    def deliver(self):
        """Offer every staged observation to the recorder once.

        Returns True when the recorder refused one (retry after a tick).
        """
        if self.recorder is None:
            return False
        with self._lock:
            items = tuple(self._pending.items())
        refused = False
        for identifier, observation in items:
            with self._lock:
                if self._closed:
                    return refused
                if identifier not in self._pending:
                    continue
                self._call += 1
                self._in_flight_since = self.clock()
            try:
                self.recorder(observation)
                accepted = True
            except Exception:
                accepted = False
            with self._lock:
                self._in_flight_since = None
                if accepted:
                    if self._pending.pop(identifier, None) is not None:
                        self._accepted += 1
                else:
                    refused = True
        return refused

    def _run(self):
        retry_wait = False
        try:
            while True:
                with self._lock:
                    if self._closed:
                        return
                    final = self._stopping
                    if not final and (not self._pending or retry_wait):
                        retry_wait = False
                        self._wake.wait(self.tick_seconds)
                        continue
                retry_wait = self.deliver()
                if final:
                    return
        except Exception:
            # Staged items stay counted; the dead thread is visible in status.
            logging.getLogger(__name__).error(Event.SCENE_CRITICAL_UNDELIVERED)

    def close(self, timeout):
        """Final bounded delivery pass, then no further recorder call.

        Returns the start (monotonic ns) of a recorder call still in flight,
        or None.
        """
        with self._lock:
            self._stopping = True
            self._wake.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(timeout)
        elif not self.threaded:
            self.deliver()
        with self._lock:
            self._closed = True
            return self._in_flight_since


class SceneMonitoringRuntime:
    """Bounded, per-source isolated scene detection for the Main runtime."""

    def __init__(self, configuration: SceneMonitoringConfiguration,
                 dependencies: SceneMonitoringDependencies | None = None, *,
                 threaded: bool = True):
        if not isinstance(configuration, SceneMonitoringConfiguration):
            raise TypeError("scene monitoring configuration is required")
        dependencies = dependencies or SceneMonitoringDependencies()
        if not isinstance(dependencies, SceneMonitoringDependencies):
            raise TypeError("invalid scene monitoring dependencies")
        if dependencies.recorder is not None and not callable(dependencies.recorder):
            raise TypeError("critical recorder must be callable")
        if dependencies.calibrations is not None and not callable(dependencies.calibrations):
            raise TypeError("calibration provider must be callable")
        self.configuration = configuration
        self._deps = dependencies
        self._threaded = threaded
        self._lock = threading.Lock()
        self._wake = threading.Condition(self._lock)
        self._slots = {item.source_id: _Slot(item) for item in configuration.bindings}
        self._published = {item.source_id: _Published() for item in configuration.bindings}
        self._contexts = {item.source_id: _Context(item) for item in configuration.bindings}
        self._pump = _CriticalPump(capacity=configuration.critical_capacity,
                                   recorder=dependencies.recorder,
                                   clock=dependencies.monotonic_ns,
                                   tick_seconds=dependencies.tick_seconds, threaded=threaded)
        self._losses_failed = 0
        # Serial of the last recorder call reported as stalled.
        self._stall_logged_call = None
        # Set by `stop()` once every source is withdrawn: a worker that
        # outlived its stop bound can no longer republish a conclusion or
        # change the lifecycle state.
        self._withdrawn = False
        # Lifecycle only (CONFIGURED/RUNNING/UNAVAILABLE/STOPPED/STOP_FAILED);
        # `status()` derives DEGRADED from the live conditions.
        self._accepting = False
        self._stopping = False
        # SCENE_MONITORING_UNAVAILABLE is logged once, by the runtime, whether
        # the worker failed or `status()` found a thread gone.
        self._unavailable_logged = False
        self._state = SceneRuntimeState.CONFIGURED
        self._thread = None

    @property
    def source_ids(self) -> tuple[UUID, ...]:
        return self.configuration.source_ids

    @property
    def refresh_interval_seconds(self) -> float:
        """How often an embedder should re-read `status()` (worker tick)."""
        return self._deps.tick_seconds

    # -- lifecycle -----------------------------------------------------
    def start(self) -> SceneRuntimeStatus:
        with self._lock:
            if self._state is not SceneRuntimeState.CONFIGURED:
                raise RuntimeError("scene monitoring runtime cannot be restarted")
            if self._deps.recorder is None:
                # Confirmed evidence would have nowhere durable to go. The
                # caller reports this result (the app logs it from the
                # returned state), so `status()` does not log it again.
                self._state = SceneRuntimeState.UNAVAILABLE
                self._unavailable_logged = True
                for published in self._published.values():
                    published.reason = "critical_recorder_unavailable"
                return self._status_locked()
            # Both threads are started before RUNNING becomes visible, so
            # `status()` never reads a not-yet-started thread as dead.
            failed = False
            try:
                self._pump.start()
                if self._threaded:
                    thread = threading.Thread(target=self._run, name="scene-monitoring",
                                              daemon=True)
                    thread.start()
                    # Retained only once started, so `stop()` never joins an
                    # unstarted thread.
                    self._thread = thread
            except Exception:
                # Partial start: nothing evaluates and nothing is current. The
                # caller reports the startup failure.
                failed = True
                self._state = SceneRuntimeState.UNAVAILABLE
                self._unavailable_logged = True
                for published in self._published.values():
                    published.state = SceneSourceState.INACTIVE
                    published.reason = "worker_start_failed"
                    self._withdraw(published, "worker_start_failed")
            else:
                self._state = SceneRuntimeState.RUNNING
                self._accepting = True
        if failed:
            # A delivery thread that did start is closed within a bounded
            # wait (it has nothing staged), so it is not left running.
            self._pump.close(START_ROLLBACK_TIMEOUT_SECONDS)
            raise RuntimeError("scene monitoring threads could not be started")
        return self.status()

    def stop(self, timeout: float = 5.0) -> SceneRuntimeStatus:
        """Stop the worker, then the delivery thread, each bounded by `timeout`.

        A worker or recorder call still running after its bound is reported
        as `STOP_FAILED` (with `critical_in_flight`), never waited on; the
        delivery thread then starts no further recorder call. A delivery
        thread that had already died before `stop()` has no call in flight,
        so the runtime ends `STOPPED`; whatever it left staged stays counted
        in `critical_pending` and `scene_critical_undelivered` is logged.
        """
        with self._lock:
            self._accepting = False
            self._stopping = True
            # A loss queued just before shutdown (possibly correlated with a
            # scene shift) stays in its slot: the final worker pass
            # (`_finish`) hands it to the detector before slots are cleared.
            self._wake.notify_all()
            thread = self._thread
        worker_alive = False
        if thread is not None:
            thread.join(timeout)
            worker_alive = thread.is_alive()
        elif self._state is SceneRuntimeState.RUNNING:
            self._finish()
        # The final worker pass has staged what it could; one bounded final
        # delivery pass follows.
        since = self._pump.close(timeout)
        in_flight = since is not None
        stalled = in_flight and (
            self._deps.monotonic_ns() - since >= self._deps.recorder_stall_ns)
        log = logging.getLogger(__name__)
        with self._lock:
            self._withdrawn = True
            for slot in self._slots.values():
                if slot.sample is not None:
                    slot.sample.data = None
                slot.sample = slot.loss = None
            if worker_alive or in_flight:
                self._state = SceneRuntimeState.STOP_FAILED
            elif self._state is not SceneRuntimeState.UNAVAILABLE:
                self._state = SceneRuntimeState.STOPPED
            for published in self._published.values():
                # Nothing is current after stop; a worker failure keeps its reason.
                if published.reason != "worker_failed":
                    published.state, published.reason = SceneSourceState.INACTIVE, "stopped"
                self._withdraw(published, "stopped")
            status = self._status_locked()
        if stalled:
            # Only a call that actually exceeded `recorder_stall_ns`.
            log.error(Event.SCENE_CRITICAL_RECORDER_STALLED)
        elif in_flight:
            log.error(Event.SCENE_CRITICAL_IN_FLIGHT_AT_STOP)
        if worker_alive or in_flight:
            log.error(Event.SCENE_MONITORING_STOP_FAILED)
        if (status.critical_pending or status.critical_refused or status.losses_held
                or status.losses_failed):
            # Staging is in memory only; the counts stay visible in status.
            log.error(Event.SCENE_CRITICAL_UNDELIVERED)
        return status

    def step(self) -> None:
        """Run one worker pass on the calling thread (unthreaded runtimes)."""
        if self._threaded:
            raise RuntimeError("threaded runtime is driven by its worker")
        with self._lock:
            if not self._accepting:
                return
        self._cycle()

    def request_calibration_refresh(self, source_id: UUID | None = None) -> None:
        """Re-resolve calibration on the worker (after an Owner save, #10)."""
        now = self._deps.monotonic_ns()
        with self._lock:
            for key, context in self._contexts.items():
                if source_id is None or key == source_id:
                    context.refresh = True
                    context.refresh_ns = now
            self._wake.notify_all()

    # -- capture-side producers (never block, never raise) ---------------
    def on_uvc_frame(self, source_id: UUID, frame) -> None:
        """`LocalUvcRuntime` frame sink; holds at most one raw frame per source."""
        try:
            slot = self._slots.get(source_id) if isinstance(source_id, UUID) else None
            if slot is None or slot.binding.layout is None:
                return
            data, sequence = frame.data, frame.sequence
            if not isinstance(data, (bytes, bytearray, memoryview)) or type(sequence) is not int:
                return
            now, observed_at = self._deps.monotonic_ns(), self._deps.utcnow()
            with self._lock:
                if slot.last_uvc_sequence is not None and sequence <= slot.last_uvc_sequence:
                    # A capture reopen restarts the driver sequence.
                    slot.new_stream = True
                slot.last_uvc_sequence = sequence
                self._accept_locked(slot, now, observed_at, data, None, None, None)
        except Exception:
            return

    def offer_luma(self, source_id: UUID, *, stream_id: UUID, width: int, height: int,
                   pixels: bytes) -> bool:
        """Decoded grayscale sample from a producer without a raw layout.

        This is the same interface for any source whose frames are decoded
        elsewhere, such as a future remote-agent decoder; no such producer
        exists on Main yet, so those sources stay `unknown`.
        """
        try:
            slot = self._slots.get(source_id) if isinstance(source_id, UUID) else None
            if (slot is None or slot.binding.layout is not None or not isinstance(stream_id, UUID)
                    or type(pixels) is not bytes):
                return False
            now, observed_at = self._deps.monotonic_ns(), self._deps.utcnow()
            with self._lock:
                return self._accept_locked(slot, now, observed_at, pixels, stream_id, width, height)
        except Exception:
            return False

    def source_unavailable(self, source_id: UUID, *, trusted: bool) -> None:
        """A source-health loss; trusted loss may correlate with a scene shift."""
        try:
            slot = self._slots.get(source_id) if isinstance(source_id, UUID) else None
            if slot is None or type(trusted) is not bool:
                return
            now, observed_at = self._deps.monotonic_ns(), self._deps.utcnow()
            with self._lock:
                # The next sample begins a new stream: capture was interrupted.
                slot.new_stream = True
                slot.last_uvc_sequence = None
                if not self._accepting:
                    return
                if slot.exhausted_ns is not None and now >= slot.exhausted_ns:
                    # After history exhaustion the detector never sees the
                    # refused stream restart, so its scene-shift state may be
                    # from a stream it can no longer place: a later loss only
                    # ends confirmation, never confirms tamper. A loss
                    # timestamped before exhaustion keeps its trust.
                    trusted = False
                # Keep the first trusted loss since the last worker pass.
                if slot.loss is None or trusted and not slot.loss.trusted:
                    slot.loss = _Loss(now, observed_at, trusted)
                self._wake.notify_all()
        except Exception:
            return

    def on_uvc_health(self, event) -> None:
        """`LocalUvcRuntime` camera-state listener."""
        try:
            state = getattr(getattr(event, "state", None), "value", None)
            source_id = getattr(event, "source_id", None)
            slot = self._slots.get(source_id) if isinstance(source_id, UUID) else None
            if slot is None or slot.binding.source_type is not SourceType.LOCAL_UVC:
                return
            if state == "online":
                with self._lock:
                    slot.new_stream = True
                    slot.last_uvc_sequence = None
                return
            # A local disconnect or manual-intervention state is observed by
            # this process; degraded/unknown states only end confirmation.
            self.source_unavailable(source_id, trusted=state in ("offline",
                                                                 "manual_intervention_required"))
        except Exception:
            return

    def _accept_locked(self, slot, now, observed_at, data, producer_stream, width, height):
        if not self._accepting:
            return False
        if slot.history_exhausted:
            # Terminal until restart: the refused replacement showed that the
            # current producer stream is stale too, so no further sample of
            # this source is admitted.
            slot.stale_rejected += 1
            return False
        replacing = producer_stream != slot.minted_for
        if replacing and producer_stream in slot.retired_producers:
            # A producer stream this source already replaced: its frames are
            # stale imagery. Minting it a fresh runtime identity would defeat
            # the detector's retired-stream refusal, so it is refused here,
            # before it can displace a live sample or move the sampling clock.
            slot.stale_rejected += 1
            return False
        if replacing and slot.minted_for is not None and (
                len(slot.retired_producers) >= RETIRED_PRODUCER_LIMIT):
            # Admitting another stream would mean forgetting a retired one.
            # The arrival of a replacement also means the current stream is
            # stale: its pending sample is dropped and nothing more of this
            # source is admitted until the runtime is restarted.
            slot.history_exhausted, slot.exhausted_ns = True, now
            slot.stale_rejected += 1
            if slot.sample is not None:
                slot.sample.data, slot.sample = None, None
                slot.stale_rejected += 1
            return False
        # The stream transition is recorded before the sampling decision: a
        # replacement stream's first frame retires the old stream even when
        # it is itself sampled out, so delayed frames of the old stream are
        # refused afterwards instead of being accepted as continuous.
        if replacing and slot.minted_for is not None:
            slot.retired_producers.add(slot.minted_for)
            if slot.sample is not None and slot.sample.producer in slot.retired_producers:
                # A sample of the stream just replaced, still pending (worker
                # slow): stale imagery that must not complete a temporal
                # confirmation after the switch, even when the replacement's
                # first frame is itself sampled out.
                slot.sample.data, slot.sample = None, None
                slot.stale_rejected += 1
        if slot.new_stream or replacing:
            # Runtime-minted stream identity, never a calibration reference
            # stream, so a producer cannot resume a pre-calibration sequence.
            slot.stream_id, slot.sequence = uuid4(), -1
            slot.minted_for, slot.new_stream = producer_stream, False
        if (slot.last_accepted_ns is not None
                and now - slot.last_accepted_ns < slot.binding.sample_interval_ns):
            slot.sampled_out += 1
            return False
        if slot.sample is not None:
            slot.replaced += 1
        # Consecutive per accepted sample: a sample replaced before evaluation
        # leaves a sequence gap, which restarts quality recovery.
        slot.sequence += 1
        slot.last_accepted_ns = now
        slot.accepted += 1
        slot.sample = _Sample(slot.stream_id, slot.sequence, now, observed_at, data, width, height,
                              producer_stream)
        self._wake.notify_all()
        return True

    # -- worker ----------------------------------------------------------
    def _run(self):
        try:
            while True:
                with self._lock:
                    if self._stopping:
                        break
                self._cycle()
                with self._lock:
                    if self._stopping:
                        break
                    if not any(slot.sample or slot.loss for slot in self._slots.values()):
                        self._wake.wait(self._deps.tick_seconds)
        except Exception:
            # The worker itself failed: no conclusion stays published and no
            # more samples are accepted, so nothing reads as current.
            with self._lock:
                self._accepting = False
                # After stop() the lifecycle is final (STOPPED/STOP_FAILED):
                # the late failure is logged as a failure, not as a transition.
                log = not self._unavailable_logged and not self._withdrawn
                if log:
                    self._unavailable_logged = True
                if not self._withdrawn:
                    self._state = SceneRuntimeState.UNAVAILABLE
                    for published in self._published.values():
                        published.state = SceneSourceState.INACTIVE
                        published.reason = "worker_failed"
                        self._withdraw(published, "worker_failed")
            logging.getLogger(__name__).error(
                Event.SCENE_MONITORING_UNAVAILABLE if log else Event.SCENE_SOURCE_FAILED)
        finally:
            self._finish()

    def _kick(self):
        """Let staging progress (inline when unthreaded) and report each
        distinct recorder call that has stalled in flight, once."""
        try:
            self._pump.kick()
        except Exception:
            pass
        snapshot = self._pump.snapshot()
        since = snapshot.in_flight_since
        stalled = since is not None and (
            self._deps.monotonic_ns() - since >= self._deps.recorder_stall_ns)
        if stalled and snapshot.call != self._stall_logged_call:
            self._stall_logged_call = snapshot.call
            logging.getLogger(__name__).error(Event.SCENE_CRITICAL_RECORDER_STALLED)

    def _finish(self):
        # Also runs after a worker failure: evidence for a loss queued before
        # the failure is still handed to its detector and staged.
        self._process_queued_losses()
        self._drain_held_losses()
        self._kick()
        with self._lock:
            if self._state is SceneRuntimeState.UNAVAILABLE and not self._withdrawn:
                # The final pass may have published results; a failed worker
                # still reports nothing as current.
                for published in self._published.values():
                    published.state, published.reason = SceneSourceState.INACTIVE, "worker_failed"
                    self._withdraw(published, "worker_failed")

    def _process_queued_losses(self):
        """Final pass over losses still queued in capture slots at shutdown.

        Bounded: at most one loss and one earlier sample per source. A sample
        captured before the loss is evaluated first, exactly as a normal pass
        would, so it can still end an episode instead of being skipped; a
        sample after the loss (or with no loss) is dropped. A loss lost to a
        per-source fault is counted in `losses_failed`.
        """
        for source_id, context in self._contexts.items():
            with self._lock:
                slot = self._slots[source_id]
                sample, loss = slot.sample, slot.loss
                slot.sample = slot.loss = None
            if sample is not None and (loss is None or sample.monotonic_ns > loss.monotonic_ns):
                sample.data, sample = None, None
            if loss is None:
                continue
            context.unprocessed_loss = loss
            try:
                self._process(context, sample, loss)
            except Exception:
                self._fault(context)

    def _cycle(self):
        now = self._deps.monotonic_ns()
        for source_id, context in self._contexts.items():
            with self._lock:
                slot = self._slots[source_id]
                sample, loss = slot.sample, slot.loss
                slot.sample = slot.loss = None
                # A calibration refresh would discard the detector's scene
                # shift state, so it waits until a held loss and a loss just
                # taken from the slot are processed (the next pass at the
                # latest for the latter).
                # Under sustained losses it can stay deferred; `status()`
                # reports it as `refresh_pending`.
                refresh = context.refresh and context.held_loss is None and loss is None
                if refresh:
                    context.refresh = False
                    if (sample is not None and context.refresh_ns is not None
                            and sample.monotonic_ns <= context.refresh_ns):
                        # Captured before the refresh request: it may show
                        # the scene before the new calibration, so it never
                        # becomes a temporal-confirmation sample of the
                        # refreshed detector.
                        sample.data, sample = None, None
                        self._target_locked(source_id).refresh_discarded += 1
            context.unprocessed_loss = loss
            try:
                if refresh or context.detector is None and (
                        context.resolved_ns is None
                        or now - context.resolved_ns >= self._deps.calibration_retry_ns):
                    self._bind(context, now)
                self._process(context, sample, loss)
            except Exception:
                # Per-source isolation: this source becomes unknown and its
                # episode ends; other sources keep running.
                self._fault(context)
        self._kick()

    def _bind(self, context, now):
        context.resolved_ns = now
        context.detector = context.calibration = None
        binding = context.binding
        reason, calibration, detector = None, None, None
        if self._deps.calibrations is None:
            reason = "calibration_provider_unconfigured"
        else:
            try:
                calibration = self._deps.calibrations(binding)
            except CalibrationUnavailable as error:
                reason = error.reason
            except Exception:
                reason = "calibration_unavailable"
        if reason is None:
            reference = getattr(calibration, "reference", None)
            if (not isinstance(calibration, Calibration) or calibration.source_id != binding.source_id
                    or calibration.source_type is not binding.source_type
                    or calibration.profile_id != binding.profile_id):
                reason = "calibration_mismatch"
            elif binding.sample_interval_ns >= calibration.policy.maximum_gap_ns:
                reason = "sampling_exceeds_gap"
            elif reference.width * reference.height > min(
                    binding.movement_quality.maximum_pixels, binding.tamper_quality.maximum_pixels):
                reason = "quality_budget_exceeded"
            elif binding.layout is not None and not binding.layout.compatible(
                    reference.width, reference.height):
                reason = "capture_layout_incompatible"
            elif binding.layout is not None and not binding.layout.available():
                # The reviewed MJPG decoder (exact simplejpeg / numpy pins) is
                # not installed: nothing can be decoded, so nothing is bound.
                reason = "frame_decoder_unavailable"
            else:
                try:
                    detector = SceneDetector(calibration)
                except Exception:
                    reason = "calibration_refused"
        with self._lock:
            published = self._target_locked(binding.source_id)
            if reason is not None:
                published.state, published.reason = SceneSourceState.INACTIVE, reason
                published.calibration_version = published.maximum_gap_ns = None
                published.active_since_ns = None
                self._withdraw(published, reason)
                return
            context.calibration, context.detector = calibration, detector
            context.movement_gate = QualityGate(binding.source_id, binding.movement_quality)
            context.tamper_gate = QualityGate(binding.source_id, binding.tamper_quality)
            published.state, published.reason = SceneSourceState.ACTIVE, "awaiting_sample"
            published.calibration_version = calibration.version
            published.maximum_gap_ns = calibration.policy.maximum_gap_ns
            published.active_since_ns = now
            self._withdraw(published, "awaiting_sample")

    @staticmethod
    def _merge_loss(held, loss):
        # Same rule as the capture side: keep the first trusted loss.
        if held is None or loss is None:
            return held or loss
        return loss if loss.trusted and not held.trusted else held

    def _loss_admissible(self):
        self._kick()
        return self._pump.remaining >= LOSS_BATCH

    def _process(self, context, sample, loss):
        detector = context.detector
        if detector is None:
            # Inactive source: there is no tracked scene to correlate with.
            context.held_loss = context.unprocessed_loss = None
            return
        held, context.held_loss = context.held_loss, None
        merged = self._merge_loss(held, loss)
        context.unprocessed_loss = merged
        items = [item for item in (merged, sample) if item is not None]
        items.sort(key=lambda item: item.monotonic_ns)
        for item in items:
            if context.held_loss is not None:
                # A sample after a held loss is never evaluated ahead of it:
                # it would end the episode and move the detector's clock past
                # the loss, so the correlation could no longer be confirmed.
                item.data = None
                self._backpressure(context)
            elif isinstance(item, _Loss):
                if not self._loss_admissible():
                    # Explicit backpressure: the loss is held, never turned
                    # into a per-source fault that would discard the detector.
                    context.held_loss, context.unprocessed_loss = item, None
                    self._backpressure(context, count=item is not held)
                    continue
                result = context.detector.source_lost(monotonic_ns=item.monotonic_ns,
                                                      observed_at=item.observed_at,
                                                      health_signal_trusted=item.trusted)
                self._handle(context, result, item.monotonic_ns, reason="source_unavailable")
                context.unprocessed_loss = None
            else:
                self._evaluate(context, item)

    def _backpressure(self, context, *, count=True):
        with self._lock:
            published = self._target_locked(context.binding.source_id)
            if count:
                published.backpressured += 1
            published.state, published.reason = SceneSourceState.DEGRADED, "critical_backpressure"
            self._withdraw(published, "critical_backpressure")

    def _drain_held_losses(self):
        """Hand held losses to their detectors at shutdown when room allows.

        A loss that still has no room stays held (counted in `losses_held`);
        one whose detector fails is counted in `losses_failed` and logged.
        Both are in memory only, like staging.
        """
        for context in self._contexts.values():
            loss = context.held_loss
            if loss is None:
                continue
            try:
                if context.detector is None or not self._loss_admissible():
                    continue
                context.held_loss = None
                result = context.detector.source_lost(monotonic_ns=loss.monotonic_ns,
                                                      observed_at=loss.observed_at,
                                                      health_signal_trusted=loss.trusted)
                if result.critical:
                    self._submit(result.critical)
            except Exception:
                context.held_loss = None
                logging.getLogger(__name__).error(Event.SCENE_SOURCE_FAILED)
                with self._lock:
                    self._losses_failed += 1

    def _submit(self, critical):
        self._pump.submit(critical)

    def _end_episode(self, context, item, reason, counter):
        # A sample this runtime could not evaluate still ends the episode, so
        # no later confirmation spans it. Untrusted loss never confirms.
        context.detector.source_lost(monotonic_ns=item.monotonic_ns, observed_at=item.observed_at,
                                     health_signal_trusted=False)
        with self._lock:
            published = self._target_locked(context.binding.source_id)
            setattr(published, counter, getattr(published, counter) + 1)
            published.state, published.reason = SceneSourceState.DEGRADED, reason
            self._withdraw(published, reason)

    def _evaluate(self, context, item):
        reference = context.calibration.reference
        self._kick()
        if self._pump.remaining < MAXIMUM_BATCH:
            # Undelivered evidence fills staging: do not evaluate (and risk
            # a confirmation that could not be staged); report backpressure.
            self._end_episode(context, item, "critical_backpressure", "backpressured")
            return
        try:
            if context.binding.layout is not None:
                pixels = context.binding.layout.luma(item.data, reference.width, reference.height)
                width, height = reference.width, reference.height
            else:
                pixels, width, height = item.data, item.width, item.height
            frame = GrayFrame(context.binding.source_id, item.stream_id, item.sequence,
                              width, height, pixels)
        except MjpgFrameRejected:
            # Pre-check refusal, decoder error or warning, post-check
            # mismatch, undecoded band or slow decode: unknown, never "no
            # movement" / "no tamper".
            self._end_episode(context, item, "frame_undecodable", "unusable")
            return
        except Exception:
            self._end_episode(context, item, "frame_unusable", "unusable")
            return
        finally:
            item.data = None
        movement = context.movement_gate.assess(frame, execution=Execution.READY)
        tamper = context.tamper_gate.assess(frame, execution=Execution.READY)
        # No occlusion mask producer exists, so no explicit occlusion signal
        # is passed; temporal confirmation and ROI matching still apply.
        result = context.detector.inspect(frame, monotonic_ns=item.monotonic_ns,
                                          observed_at=item.observed_at,
                                          movement_quality=movement.quality,
                                          tamper_quality=tamper.quality, roi_occluded=None)
        self._handle(context, result, item.monotonic_ns, reason="evaluated")

    def _handle(self, context, result, monotonic_ns, *, reason):
        if result.critical:
            self._submit(result.critical)
        exhausted = result.movement_reason == "stream_history_exhausted"
        if exhausted:
            # The detector latched; a fresh detector from the same trusted
            # calibration resumes, as the detector contract requires.
            context.detector = SceneDetector(context.calibration)
        with self._lock:
            published = self._target_locked(context.binding.source_id)
            if reason == "evaluated":
                published.evaluated += 1
            # A camera loss lowers the source until a new evaluated sample
            # establishes recovery; it is never presented as healthy.
            published.state = (SceneSourceState.ACTIVE if reason == "evaluated"
                               else SceneSourceState.DEGRADED)
            published.reason = reason
            published.movement, published.tamper = result.movement, result.tamper
            published.movement_reason = result.movement_reason
            published.tamper_reason = result.tamper_reason
            published.evaluated_ns = monotonic_ns

    def _fault(self, context):
        logging.getLogger(__name__).error(Event.SCENE_SOURCE_FAILED)
        # Rebind from the trusted provider after the retry interval, so a
        # deterministic fault cannot repeat (and log) on every sample.
        lost = context.held_loss is not None or context.unprocessed_loss is not None
        context.detector = context.held_loss = context.unprocessed_loss = None
        context.resolved_ns = self._deps.monotonic_ns()
        with self._lock:
            if lost:
                # The loss (possibly correlated with a scene shift) can no
                # longer reach a detector: counted, never silently dropped.
                self._losses_failed += 1
            published = self._target_locked(context.binding.source_id)
            published.failures += 1
            published.state, published.reason = SceneSourceState.DEGRADED, "scene_evaluation_failed"
            self._withdraw(published, "scene_evaluation_failed")

    def _target_locked(self, source_id):
        """Where the worker publishes a source result: its live record, or a
        discarded scratch record once `stop()` withdrew every source."""
        if self._withdrawn:
            return _Published()
        return self._published[source_id]

    @staticmethod
    def _withdraw(published, reason):
        published.movement = published.tamper = Observation.UNKNOWN
        published.movement_reason = published.tamper_reason = reason
        published.evaluated_ns = None

    # -- status ------------------------------------------------------------
    def status(self) -> SceneRuntimeStatus:
        with self._lock:
            status = self._status_locked()
            log = (status.state is SceneRuntimeState.UNAVAILABLE
                   and not self._unavailable_logged)
            if log:
                self._unavailable_logged = True
        if log:
            # A thread found gone while running: reported once, by the runtime.
            logging.getLogger(__name__).error(Event.SCENE_MONITORING_UNAVAILABLE)
        return status

    def _status_locked(self):
        now = self._deps.monotonic_ns()
        thread = self._thread
        snapshot = self._pump.snapshot()
        worker_running = thread is not None and thread.is_alive()
        delivery_running = snapshot.running
        lost = None
        if (self._state is SceneRuntimeState.RUNNING and self._threaded and not self._stopping
                and not (worker_running and delivery_running)):
            # A worker or delivery thread that is gone evaluates or delivers
            # nothing: never reported as running or merely degraded, and no
            # published conclusion is presented as current (fail closed; the
            # stored results are not changed). During `stop()` both threads
            # end by design and are not read as lost.
            lost = "worker_unavailable" if not worker_running else "delivery_unavailable"
        sources = []
        for source_id, slot in self._slots.items():
            published, context = self._published[source_id], self._contexts[source_id]
            movement, tamper = published.movement, published.tamper
            movement_reason, tamper_reason = published.movement_reason, published.tamper_reason
            stale = (published.evaluated_ns is None or published.maximum_gap_ns is None
                     or now - published.evaluated_ns > published.maximum_gap_ns)
            if stale and published.evaluated_ns is not None:
                # A conclusion older than the calibrated sampling gap (worker
                # stalled, frames stopped) is no longer current: unknown.
                movement = tamper = Observation.UNKNOWN
                movement_reason = tamper_reason = "observation_stale"
            state, reason = published.state, published.reason
            fresh_ns = (published.evaluated_ns if published.evaluated_ns is not None
                        else published.active_since_ns)
            if (self._state is SceneRuntimeState.RUNNING and state is SceneSourceState.ACTIVE
                    and fresh_ns is not None and published.maximum_gap_ns is not None
                    and now - fresh_ns > published.maximum_gap_ns):
                # No sample evaluated within the calibrated gap (frames
                # stopped, worker stalled): the source is lowered, not only
                # its conclusions, until a fresh evaluated sample recovers it.
                state, reason = SceneSourceState.DEGRADED, "observation_stale"
            if slot.history_exhausted:
                # No sample of this source is admitted any more, so nothing it
                # concluded is current; the source is lowered while running.
                movement = tamper = Observation.UNKNOWN
                movement_reason = tamper_reason = "stream_history_exhausted"
                if self._state is SceneRuntimeState.RUNNING:
                    state, reason = SceneSourceState.DEGRADED, "stream_history_exhausted"
            if lost is not None:
                state, reason = SceneSourceState.INACTIVE, lost
                movement = tamper = Observation.UNKNOWN
                movement_reason = tamper_reason = lost
            sources.append(SceneSourceStatus(
                source_id, slot.binding.source_type, state, reason,
                movement, tamper, movement_reason, tamper_reason,
                published.calibration_version, slot.accepted, slot.sampled_out, slot.replaced,
                published.evaluated, published.unusable, published.backpressured,
                published.failures, slot.stale_rejected, published.refresh_discarded,
                # An explicitly requested refresh not yet run (the initial
                # bind is not a request).
                context.refresh and context.refresh_ns is not None,
            ))
        # A reference read of worker-owned state; a snapshot, never a decision.
        held = sum(context.held_loss is not None for context in self._contexts.values())
        pending, since = snapshot.pending, snapshot.in_flight_since
        stalled = since is not None and now - since >= self._deps.recorder_stall_ns
        state = SceneRuntimeState.UNAVAILABLE if lost is not None else self._state
        if state is SceneRuntimeState.RUNNING and (
                pending or held or stalled
                or any(item.state is SceneSourceState.DEGRADED for item in sources)):
            # Undelivered evidence, a held loss, a stalled recorder call or a
            # lowered source (camera loss, unusable frame, backpressure,
            # fault) is never reported as healthy.
            state = SceneRuntimeState.DEGRADED
        return SceneRuntimeStatus(state, tuple(sources), pending, snapshot.accepted,
                                  worker_running, held, self._losses_failed,
                                  since is not None, stalled, delivery_running,
                                  snapshot.refused)
