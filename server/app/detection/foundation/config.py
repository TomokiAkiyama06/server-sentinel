"""Explicit deployment schema for detector bindings; fail-closed when unset.

The deployment's optional `detection` object names, per source, one reviewed
detector implementation/version, its evaluation parameters, the inference
cadence/resource policy and the isolated-worker limits. Nothing here chooses
a model, threshold, cadence or limit: every value is required. Only the
detectors reviewed in this repository can be named; an unknown
implementation, version or model digest is rejected instead of switched to.

Without the object there is no inference runtime: `build_inference()` refuses,
and callers must publish `unknown/model_unavailable` for every source, never
`absent`. Validation messages never contain supplied values.
"""

from dataclasses import dataclass, field, fields
import math
from pathlib import PurePosixPath
from typing import Callable
from uuid import UUID

from app.settings import ConfigurationError

from .contracts import DetectorKind, Reason
from .isolation import IsolatedDetector, WorkerLimits, WorkerSpec, WorkerStatus
from .motion import MotionBaseline
from .person import MODEL_REVISION, MODEL_SHA256, RtDetrPersonDetector
from .scheduler import InferenceScheduler, SourcePolicy

MAXIMUM_SOURCES = 4
DETECTION_KEYS = frozenset({"bindings"})
BINDING_KEYS = frozenset({"source_id", "detector", "cadence", "worker"})
CADENCE_KEYS = frozenset(item.name for item in fields(SourcePolicy))
# maximum_frame_bytes is derived from the cadence pixel cap (<= 3 channels).
WORKER_KEYS = frozenset(item.name for item in fields(WorkerLimits)) - {"maximum_frame_bytes"}
MOTION_KEYS = frozenset({"kind", "implementation", "version", "pixel_delta", "changed_fraction"})
PERSON_KEYS = frozenset({"kind", "implementation", "version", "artifact", "artifact_sha256",
                         "score_threshold", "intra_op_threads"})


def create_motion(pixel_delta: int, changed_fraction: float) -> MotionBaseline:
    """Worker-side factory for the reviewed CPU motion baseline."""
    return MotionBaseline(pixel_delta=pixel_delta, changed_fraction=changed_fraction)


def create_person(artifact: str, score_threshold: float,
                  intra_op_threads: int) -> RtDetrPersonDetector:
    """Worker-side factory; the adapter re-verifies the artifact digest."""
    from pathlib import Path
    return RtDetrPersonDetector(Path(artifact), score_threshold=score_threshold,
                                intra_op_threads=intra_op_threads)


@dataclass(frozen=True)
class DetectorBinding:
    source_id: UUID
    kind: DetectorKind
    policy: SourcePolicy = field(repr=False)
    limits: WorkerLimits = field(repr=False)
    spec: WorkerSpec = field(repr=False)


@dataclass(frozen=True)
class DetectionConfiguration:
    bindings: tuple[DetectorBinding, ...] = field(repr=False)

    def kinds(self) -> tuple[DetectorKind, ...]:
        return tuple(kind for kind in DetectorKind
                     if any(item.kind is kind for item in self.bindings))


@dataclass(frozen=True)
class InferenceRuntime:
    """One separately budgeted scheduler per detector kind."""

    schedulers: dict[DetectorKind, InferenceScheduler] = field(repr=False)
    detectors: dict[tuple[DetectorKind, UUID], IsolatedDetector] = field(repr=False)

    def maintain(self) -> dict[tuple[DetectorKind, UUID], WorkerStatus]:
        """Restart workers when permitted; call on the inference worker thread.

        A binding without a running worker is invalidated at once, so a child
        that died while idle cannot leave an earlier conclusion published
        until its observation age expires.
        """
        statuses = {}
        for (kind, source_id), detector in self.detectors.items():
            status = detector.maintain()
            if status.state != "running":
                self.schedulers[kind].invalidate(
                    source_id, reason=status.last_failure or Reason.WORKER_UNAVAILABLE)
            statuses[(kind, source_id)] = status
        return statuses

    def close(self) -> bool:
        """Stop every worker; True only when all children are reaped."""
        return all([detector.close() for detector in self.detectors.values()])


def _invalid() -> ConfigurationError:
    return ConfigurationError("invalid detection configuration")


def _object(value: object, keys: frozenset[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise _invalid()
    return value


def _positive(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise _invalid()
    return value


def _fraction(value: object, *, inclusive_upper: bool) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise _invalid()
    if not 0 < value < 1 and not (inclusive_upper and value == 1):
        raise _invalid()
    return value


def _detector(value: object) -> tuple[DetectorKind, WorkerSpec]:
    if type(value) is not dict:
        raise _invalid()
    kind = value.get("kind")
    if kind == DetectorKind.MOTION.value:
        value = _object(value, MOTION_KEYS)
        if (value["implementation"], value["version"]) != (
                MotionBaseline.implementation, MotionBaseline.version):
            raise _invalid()
        pixel_delta = _positive(value["pixel_delta"])
        if pixel_delta > 255:
            raise _invalid()
        changed = _fraction(value["changed_fraction"], inclusive_upper=True)
        return DetectorKind.MOTION, WorkerSpec(
            DetectorKind.MOTION, MotionBaseline.implementation, MotionBaseline.version,
            create_motion, {"pixel_delta": pixel_delta, "changed_fraction": changed})
    if kind == DetectorKind.PERSON.value:
        value = _object(value, PERSON_KEYS)
        # Naming the digest makes the Owner's approval of this exact artifact
        # explicit; the adapter independently verifies bytes and size.
        if (value["implementation"], value["version"], value["artifact_sha256"]) != (
                RtDetrPersonDetector.implementation, MODEL_REVISION, MODEL_SHA256):
            raise _invalid()
        artifact = value["artifact"]
        if (type(artifact) is not str or "\0" in artifact
                or not PurePosixPath(artifact).is_absolute()):
            raise _invalid()
        threshold = _fraction(value["score_threshold"], inclusive_upper=False)
        threads = _positive(value["intra_op_threads"])
        if threads > 64:
            raise _invalid()
        return DetectorKind.PERSON, WorkerSpec(
            DetectorKind.PERSON, RtDetrPersonDetector.implementation, MODEL_REVISION,
            create_person, {"artifact": artifact, "score_threshold": threshold,
                            "intra_op_threads": threads})
    raise _invalid()


def parse_detection(value: object) -> DetectionConfiguration:
    value = _object(value, DETECTION_KEYS)
    bindings = value["bindings"]
    if type(bindings) is not list or not bindings:
        raise _invalid()
    parsed: list[DetectorBinding] = []
    seen: set[tuple[DetectorKind, UUID]] = set()
    for item in bindings:
        item = _object(item, BINDING_KEYS)
        try:
            if type(item["source_id"]) is not str:
                raise ValueError()
            source_id = UUID(item["source_id"])
            if str(source_id) != item["source_id"]:
                raise ValueError()
        except ValueError:
            raise _invalid() from None
        kind, spec = _detector(item["detector"])
        cadence = _object(item["cadence"], CADENCE_KEYS)
        worker = _object(item["worker"], WORKER_KEYS)
        try:
            policy = SourcePolicy(**{key: _positive(cadence[key]) for key in CADENCE_KEYS})
            limits = WorkerLimits(
                maximum_frame_bytes=policy.maximum_pixels * 3,
                **{key: _positive(worker[key]) for key in WORKER_KEYS})
        except ValueError:
            raise _invalid() from None
        # A watchdog shorter than the evaluation budget would kill evaluations
        # the scheduler still accepts as within budget.
        if limits.evaluation_timeout_ns < policy.maximum_evaluation_ns:
            raise _invalid()
        if (kind, source_id) in seen:
            raise _invalid()
        seen.add((kind, source_id))
        parsed.append(DetectorBinding(source_id, kind, policy, limits, spec))
    if len({item.source_id for item in parsed}) > MAXIMUM_SOURCES:
        raise _invalid()
    return DetectionConfiguration(tuple(parsed))


def build_inference(configuration: DetectionConfiguration | None, *,
                    clock_ns: Callable[[], int] | None = None) -> InferenceRuntime:
    """Construct schedulers and (unstarted) isolated workers, or refuse.

    Workers are started by the inference worker thread via `maintain()`.
    """
    if not isinstance(configuration, DetectionConfiguration) or not configuration.bindings:
        raise ConfigurationError("detector configuration is required for inference")
    options = {} if clock_ns is None else {"clock_ns": clock_ns}
    schedulers = {kind: InferenceScheduler(maximum_sources=MAXIMUM_SOURCES, **options)
                  for kind in configuration.kinds()}
    detectors: dict[tuple[DetectorKind, UUID], IsolatedDetector] = {}
    for binding in configuration.bindings:
        detector = IsolatedDetector(binding.spec, binding.limits, **options)
        schedulers[binding.kind].register(binding.source_id, detector, binding.policy)
        detectors[(binding.kind, binding.source_id)] = detector
    return InferenceRuntime(schedulers, detectors)
