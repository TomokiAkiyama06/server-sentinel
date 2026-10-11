"""Main-runtime wiring of calibrated scene detection (Issue #205).

`SceneMonitoringRuntime` connects capture frame callbacks to one
`SceneDetector` per configured source, behind that source's own
detector-specific quality gates, and hands every confirmed critical
observation to the injected durable `CriticalRecorder` (in the Main runtime,
`app.presence.adapters.CriticalTimelineRecorder`) through bounded
`CriticalDelivery` staging.

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
from .contracts import Calibration
from .delivery import MAXIMUM_BATCH, CriticalDelivery, CriticalRecorder
from .detector import SceneDetector


MAXIMUM_SOURCES = 4
# Conservative default: one evaluated sample per second per source. A
# calibration whose `maximum_gap_ns` does not exceed the configured interval
# is refused, because every sample would then be a sampling discontinuity.
DEFAULT_SAMPLE_INTERVAL_NS = 1_000_000_000
DEFAULT_CRITICAL_CAPACITY = 4 * MAXIMUM_BATCH * MAXIMUM_SOURCES
CALIBRATION_RETRY_NS = 60 * 1_000_000_000
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

    Only packed `GREY` and `YUYV` are reviewed here: their luma is read by
    byte slicing with no image library. A compressed format (for example
    `MJPG`) needs a reviewed decoder and is refused. Frames whose length does
    not match this exact unpadded layout are refused per frame.
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
    # Required for raw local UVC frames; None for producers that already
    # supply decoded grayscale samples (`offer_luma`).
    layout: PackedLumaLayout | None = None
    sample_interval_ns: int = DEFAULT_SAMPLE_INTERVAL_NS

    def __post_init__(self):
        if not isinstance(self.source_id, UUID) or not isinstance(self.profile_id, UUID):
            raise ValueError("scene binding identities must be UUIDs")
        if not isinstance(self.source_type, SourceType):
            raise ValueError("invalid scene source type")
        _policy(self.movement_quality, "server_roi")
        _policy(self.tamper_quality, "camera_tamper")
        if self.layout is not None and not isinstance(self.layout, PackedLumaLayout):
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


@dataclass(frozen=True)
class SceneRuntimeStatus:
    state: SceneRuntimeState
    sources: tuple[SceneSourceStatus, ...]
    critical_pending: int
    critical_accepted: int
    worker_running: bool


@dataclass
class _Sample:
    stream_id: UUID
    sequence: int
    monotonic_ns: int
    observed_at: datetime
    data: object
    width: int | None = None
    height: int | None = None


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
    accepted: int = 0
    sampled_out: int = 0
    replaced: int = 0


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
    maximum_gap_ns: int | None = None
    evaluated: int = 0
    unusable: int = 0
    backpressured: int = 0
    failures: int = 0


class _Context:
    """Worker-only detector state for one source."""

    def __init__(self, binding):
        self.binding = binding
        self.calibration = None
        self.detector = None
        self.movement_gate = self.tamper_gate = None
        self.resolved_ns = None
        self.refresh = True


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
        self._delivery = CriticalDelivery(capacity=configuration.critical_capacity,
                                          recorder=dependencies.recorder)
        self._pending_critical = 0
        self._accepted_critical = 0
        self._accepting = False
        self._stopping = False
        self._state = SceneRuntimeState.CONFIGURED
        self._thread = None

    @property
    def source_ids(self) -> tuple[UUID, ...]:
        return self.configuration.source_ids

    # -- lifecycle -----------------------------------------------------
    def start(self) -> SceneRuntimeStatus:
        with self._lock:
            if self._state is not SceneRuntimeState.CONFIGURED:
                raise RuntimeError("scene monitoring runtime cannot be restarted")
            if self._deps.recorder is None:
                # Confirmed evidence would have nowhere durable to go.
                self._state = SceneRuntimeState.UNAVAILABLE
                for published in self._published.values():
                    published.reason = "critical_recorder_unavailable"
                return self._status_locked()
            self._state = SceneRuntimeState.RUNNING
            self._accepting = True
        if self._threaded:
            thread = threading.Thread(target=self._run, name="scene-monitoring", daemon=True)
            self._thread = thread
            thread.start()
        return self.status()

    def stop(self, timeout: float = 5.0) -> SceneRuntimeStatus:
        with self._lock:
            self._accepting = False
            self._stopping = True
            for slot in self._slots.values():
                slot.sample = slot.loss = None
            self._wake.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():
                with self._lock:
                    self._state = SceneRuntimeState.STOP_FAILED
                    for published in self._published.values():
                        self._withdraw(published, "stopped")
                logging.getLogger(__name__).error(Event.SCENE_MONITORING_STOP_FAILED)
                return self.status()
        elif self._state in (SceneRuntimeState.RUNNING, SceneRuntimeState.DEGRADED):
            self._finish()
        with self._lock:
            if self._state is not SceneRuntimeState.UNAVAILABLE:
                self._state = SceneRuntimeState.STOPPED
            for published in self._published.values():
                self._withdraw(published, "stopped")
        return self.status()

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
        with self._lock:
            for key, context in self._contexts.items():
                if source_id is None or key == source_id:
                    context.refresh = True
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
        if (slot.last_accepted_ns is not None
                and now - slot.last_accepted_ns < slot.binding.sample_interval_ns):
            slot.sampled_out += 1
            return False
        if slot.new_stream or producer_stream != slot.minted_for:
            # Runtime-minted stream identity, never a calibration reference
            # stream, so a producer cannot resume a pre-calibration sequence.
            slot.stream_id, slot.sequence = uuid4(), -1
            slot.minted_for, slot.new_stream = producer_stream, False
        if slot.sample is not None:
            slot.replaced += 1
        # Consecutive per accepted sample: a sample replaced before evaluation
        # leaves a sequence gap, which restarts quality recovery.
        slot.sequence += 1
        slot.last_accepted_ns = now
        slot.accepted += 1
        slot.sample = _Sample(slot.stream_id, slot.sequence, now, observed_at, data, width, height)
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
                self._state = SceneRuntimeState.UNAVAILABLE
                for published in self._published.values():
                    published.state, published.reason = SceneSourceState.INACTIVE, "worker_failed"
                    self._withdraw(published, "worker_failed")
            logging.getLogger(__name__).error(Event.SCENE_MONITORING_UNAVAILABLE)
        finally:
            self._finish()

    def _retry(self):
        try:
            state = self._delivery.retry()
        except Exception:
            state = None
        with self._lock:
            self._sync_delivery(state)
            return self._pending_critical

    def _finish(self):
        if self._retry():
            # Staging is in memory only; the count stays visible in status.
            logging.getLogger(__name__).error(Event.SCENE_CRITICAL_UNDELIVERED)

    def _cycle(self):
        now = self._deps.monotonic_ns()
        for source_id, context in self._contexts.items():
            with self._lock:
                slot = self._slots[source_id]
                sample, loss = slot.sample, slot.loss
                slot.sample = slot.loss = None
                refresh = context.refresh
                context.refresh = False
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
        self._retry()

    def _sync_delivery(self, state):
        if state is not None:
            self._accepted_critical += len(state.accepted)
        self._pending_critical = self._delivery.capacity - self._delivery.remaining
        if self._state in (SceneRuntimeState.RUNNING, SceneRuntimeState.DEGRADED):
            self._state = (SceneRuntimeState.DEGRADED if self._pending_critical
                           else SceneRuntimeState.RUNNING)

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
            else:
                try:
                    detector = SceneDetector(calibration)
                except Exception:
                    reason = "calibration_refused"
        with self._lock:
            published = self._published[binding.source_id]
            if reason is not None:
                published.state, published.reason = SceneSourceState.INACTIVE, reason
                published.calibration_version = published.maximum_gap_ns = None
                self._withdraw(published, reason)
                return
            context.calibration, context.detector = calibration, detector
            context.movement_gate = QualityGate(binding.source_id, binding.movement_quality)
            context.tamper_gate = QualityGate(binding.source_id, binding.tamper_quality)
            published.state, published.reason = SceneSourceState.ACTIVE, "awaiting_sample"
            published.calibration_version = calibration.version
            published.maximum_gap_ns = calibration.policy.maximum_gap_ns
            self._withdraw(published, "awaiting_sample")

    def _process(self, context, sample, loss):
        detector = context.detector
        if detector is None:
            return
        items = [item for item in (loss, sample) if item is not None]
        items.sort(key=lambda item: item.monotonic_ns)
        for item in items:
            if isinstance(item, _Loss):
                result = detector.source_lost(monotonic_ns=item.monotonic_ns,
                                              observed_at=item.observed_at,
                                              health_signal_trusted=item.trusted)
                self._handle(context, result, item.monotonic_ns, reason="source_unavailable")
            else:
                self._evaluate(context, item)

    def _end_episode(self, context, item, reason, counter):
        # A sample this runtime could not evaluate still ends the episode, so
        # no later confirmation spans it. Untrusted loss never confirms.
        context.detector.source_lost(monotonic_ns=item.monotonic_ns, observed_at=item.observed_at,
                                     health_signal_trusted=False)
        with self._lock:
            published = self._published[context.binding.source_id]
            setattr(published, counter, getattr(published, counter) + 1)
            published.state, published.reason = SceneSourceState.DEGRADED, reason
            self._withdraw(published, reason)

    def _evaluate(self, context, item):
        reference = context.calibration.reference
        self._retry()
        if self._delivery.remaining < MAXIMUM_BATCH:
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
            self._delivery.submit(result.critical)
        exhausted = result.movement_reason == "stream_history_exhausted"
        if exhausted:
            # The detector latched; a fresh detector from the same trusted
            # calibration resumes, as the detector contract requires.
            context.detector = SceneDetector(context.calibration)
        with self._lock:
            published = self._published[context.binding.source_id]
            if reason == "evaluated":
                published.evaluated += 1
            published.state, published.reason = SceneSourceState.ACTIVE, reason
            published.movement, published.tamper = result.movement, result.tamper
            published.movement_reason = result.movement_reason
            published.tamper_reason = result.tamper_reason
            published.evaluated_ns = monotonic_ns

    def _fault(self, context):
        logging.getLogger(__name__).error(Event.SCENE_SOURCE_FAILED)
        # Rebind from the trusted provider after the retry interval, so a
        # deterministic fault cannot repeat (and log) on every sample.
        context.detector = None
        context.resolved_ns = self._deps.monotonic_ns()
        with self._lock:
            published = self._published[context.binding.source_id]
            published.failures += 1
            published.state, published.reason = SceneSourceState.DEGRADED, "scene_evaluation_failed"
            self._withdraw(published, "scene_evaluation_failed")

    @staticmethod
    def _withdraw(published, reason):
        published.movement = published.tamper = Observation.UNKNOWN
        published.movement_reason = published.tamper_reason = reason
        published.evaluated_ns = None

    # -- status ------------------------------------------------------------
    def status(self) -> SceneRuntimeStatus:
        with self._lock:
            return self._status_locked()

    def _status_locked(self):
        now = self._deps.monotonic_ns()
        sources = []
        for source_id, slot in self._slots.items():
            published = self._published[source_id]
            movement, tamper = published.movement, published.tamper
            movement_reason, tamper_reason = published.movement_reason, published.tamper_reason
            stale = (published.evaluated_ns is None or published.maximum_gap_ns is None
                     or now - published.evaluated_ns > published.maximum_gap_ns)
            if stale and published.evaluated_ns is not None:
                # A conclusion older than the calibrated sampling gap (worker
                # stalled, frames stopped) is no longer current: unknown.
                movement = tamper = Observation.UNKNOWN
                movement_reason = tamper_reason = "observation_stale"
            sources.append(SceneSourceStatus(
                source_id, slot.binding.source_type, published.state, published.reason,
                movement, tamper, movement_reason, tamper_reason,
                published.calibration_version, slot.accepted, slot.sampled_out, slot.replaced,
                published.evaluated, published.unusable, published.backpressured,
                published.failures,
            ))
        thread = self._thread
        return SceneRuntimeStatus(self._state, tuple(sources), self._pending_critical,
                                  self._accepted_critical,
                                  thread is not None and thread.is_alive())
