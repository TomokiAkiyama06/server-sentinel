"""Detector isolation: owner-verifier and person-detector failures fail unknown.

Frames are generated textures and geometric shapes only; no real person,
face, room or media file is read. Every scenario drives production cores:
``InferenceScheduler`` + ``MotionBaseline`` (motion), ``SceneDetector`` +
``CriticalDelivery`` (calibrated ROI movement / tamper), ``QualityGate``,
``OwnerVerificationService`` with an ``OwnerTemplateStore`` in a private
temporary directory, and ``IsolatedDetector`` worker processes built from the
synthetic top-level factories below. The per-frame loop that calls them in
sequence is test composition: the Main inference runtime that will own it is
not implemented yet. This is not model accuracy or hardware acceptance.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import time
import unittest
from uuid import UUID, uuid4

from app.detection.foundation import (
    Detection, DetectorKind, GrayFrame, Health, InferenceScheduler, IsolatedDetector,
    MotionBaseline, Observation, Quality, Reason, SourcePolicy,
    UnavailablePersonDetector, WorkerLimits, WorkerSpec,
)
from app.detection.owner.contracts import (
    Comparison, FaceCandidate, ModelProvenance, Verdict, VerificationReason,
)
from app.detection.owner.service import OwnerVerificationService
from app.detection.owner.store import OwnerTemplateStore
from app.detection.quality import (
    DetectorQualityPolicy, Execution, FrameIdentity, Metric, MetricRule, QualityContext,
    QualityGate,
)
from app.detection.roi import Calibration, CriticalDelivery, CriticalKind, Policy, SceneDetector
from app.presence.models import InvalidObservation, Kind, Observation as TimelineObservation
from app.presence.models import Quality as TimelineQuality, Value

from tests.e2e.harness import MixedSourceTopology, NetworkGuard, SyntheticClock


NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
SCENE = 12
POLYGON = ((4, 4), (7, 4), (7, 7), (4, 7))
SECOND = 1_000_000_000
PROVENANCE = ModelProvenance(
    "generated-test-adapter", "fixture-1", "Apache-2.0", "Apache-2.0",
    "https://example.invalid/generated-fixture", "a" * 64, "b" * 64, UUID(int=99))


# ------------------------------------------------------------ synthetic media

def texture():
    """Non-symmetric generated grayscale texture; not a real scene."""
    return bytes((x * 29 + y * 47 + x * y * 11) % 251 + 2
                 for y in range(SCENE) for x in range(SCENE))


def shifted_roi(source, dx=1, region=(4, 4, 8, 7)):
    """Move only the calibrated region right by ``dx`` pixels."""
    output = bytearray(source)
    for y in range(SCENE):
        for x in range(SCENE):
            if region[0] <= x <= region[2] and region[1] <= y <= region[3]:
                previous = x - dx
                output[y * SCENE + x] = source[y * SCENE + previous] if 0 <= previous < SCENE else 0
    return bytes(output)


def geometric_person(source, stream, sequence, *, dark=False, size=16):
    """Head/torso/legs rectangles on a checkerboard; never a real person."""
    pixels = []
    for y in range(size):
        for x in range(size):
            head = 6 <= x <= 9 and 2 <= y <= 5
            torso = 4 <= x <= 11 and 6 <= y <= 11
            legs = (4 <= x <= 6 or 9 <= x <= 11) and y >= 12
            value = 210 if head or torso or legs else (64 if (x + y) % 2 else 192)
            pixels.append(value // 64 if dark else value)
    return GrayFrame(source, stream, sequence, size, size, bytes(pixels))


def quality_policy(detector):
    # Synthetic calibration for this test only; no production default.
    return DetectorQualityPolicy(detector, 1, (
        MetricRule(Metric.LUMINANCE, .1, .2, .8, .95),
        MetricRule(Metric.SHARPNESS, .001, .01, 1, 1),
        MetricRule(Metric.SATURATION, 0, 0, .1, .4),
        MetricRule(Metric.WIDTH, 8, 8, 64, 64),
        MetricRule(Metric.HEIGHT, 8, 8, 64, 64),
        MetricRule(Metric.TARGET_WIDTH, 4, 6, 64, 64),
        MetricRule(Metric.TARGET_HEIGHT, 4, 6, 64, 64),
        MetricRule(Metric.OCCLUSION, 0, 0, .1, .4),
    ), 2, 4096)


def quality_context(frame):
    return QualityContext(FrameIdentity.from_frame(frame), target_width=10, target_height=10,
                          occlusion_fraction=0.0)


def roi_policy():
    return Policy(
        global_search_pixels=2, roi_search_pixels=2,
        global_quarter_turns=(0,), roi_quarter_turns=(0,),
        maximum_match_error=.01, minimum_match_margin=.001, minimum_coverage=.8,
        minimum_background_variance=.002, minimum_roi_variance=.002,
        movement_pixels=1, camera_shift_pixels=1,
        dark_pixel_ceiling=5, camera_dark_fraction=.9,
        confirmation_frames=2, confirmation_ns=10,
        maximum_gap_ns=100, loss_correlation_ns=30,
        maximum_pixels=256, maximum_comparisons=100_000,
    )


def scheduler_policy():
    return SourcePolicy(cadence_ns=1, maximum_cadence_ns=8, maximum_queue_age_ns=10 * SECOND,
                        maximum_evaluation_ns=10 * SECOND, maximum_observation_age_ns=10 * SECOND,
                        maximum_pixels=4096)


# ------------------------------------------- synthetic detectors / verifiers

class RaisingPerson:
    kind, implementation, version = DetectorKind.PERSON, "synthetic-raising-person", "1"

    def reset(self):
        pass

    def evaluate(self, frame):
        raise RuntimeError("synthetic plugin failure /private/model")


class MalformedPerson(RaisingPerson):
    implementation = "synthetic-malformed-person"

    def evaluate(self, frame):
        return "absent"


class NegativePerson(RaisingPerson):
    """Would report no person for every frame it is allowed to see."""

    implementation = "synthetic-negative-person"

    def __init__(self):
        self.calls = 0

    def evaluate(self, frame):
        self.calls += 1
        return Detection(Observation.ABSENT, Reason.EVALUATED)


class _WorkerPerson(RaisingPerson):
    implementation = "synthetic-worker-person"

    def __init__(self, behaviour):
        self.behaviour = behaviour

    def evaluate(self, frame):
        if self.behaviour == "crash":
            os._exit(9)
        if self.behaviour == "hang":
            time.sleep(3600)
        return Detection(Observation.ABSENT, Reason.EVALUATED)


def worker_person(behaviour):
    """Importable top-level factory for the spawned worker process."""
    return _WorkerPerson(behaviour)


class Verifier:
    """Local synthetic 1:1 verifier; ``failure`` selects a fault mode."""

    def __init__(self, failure=None):
        self.failure = failure
        self.compares = 0

    @property
    def provenance(self):
        if self.failure == "provenance":
            raise RuntimeError("synthetic provenance failure")
        return PROVENANCE

    def enroll(self, crop):
        return b"synthetic-owner-template-v1"

    def compare(self, crop, template):
        self.compares += 1
        if self.failure == "raise":
            raise RuntimeError("synthetic verifier crash")
        if self.failure == "malformed":
            return None
        return Comparison(Verdict.MATCH, .99)

    def forget_candidate(self):
        if self.failure == "cleanup":
            raise RuntimeError("synthetic cleanup failure")


class Owner:
    def require_owner(self, operation):
        return UUID(int=123)


# ---------------------------------------------------------------- scenarios

class DetectionIsolationScenarios(unittest.TestCase):
    def setUp(self):
        self.network = NetworkGuard().__enter__()
        self.addCleanup(self.network.__exit__)
        self.addCleanup(lambda: self.assertEqual([], self.network.attempts))
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.source = self.topology.sources[1]
        self.stream = uuid4()
        self.now = [0]

    def monotonic_ns(self):
        return self.now[0]

    def scene(self, sequence, data=None):
        return GrayFrame(self.source.source_id, self.stream, sequence, SCENE, SCENE,
                         texture() if data is None else data)

    # -- owner verification ---------------------------------------------

    def owner_service(self, verifier):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "private"
        root.mkdir(mode=0o700)

        @contextmanager
        def reservation():
            yield

        store = OwnerTemplateStore(root, max_template_bytes=1024, reservation=reservation,
                                   authorizer=Owner())
        self.addCleanup(store.close)
        gate = QualityGate(self.source.source_id, quality_policy("owner_verification"))
        enrolling = OwnerVerificationService(store, Verifier())
        candidate, decision = self.face(enrolling, gate, 0)
        enrolling.enroll(candidate, gate, decision, expected_generation=store.status().generation,
                         at=NOW)
        self.assertTrue(store.status().enrolled)
        return OwnerVerificationService(store, verifier), gate

    def face(self, service, gate, sequence):
        """Two consecutive good crops, so the gate authorizes the second."""
        stream = UUID(int=900)
        for offset in (0, 1):
            crop = geometric_person(self.source.source_id, stream, 2 * sequence + offset)
            candidate = FaceCandidate(uuid4(), crop)
            decision = service.assess(candidate, gate, context=quality_context(crop))
        return candidate, decision

    def test_owner_verifier_failure_never_stops_motion_or_roi_critical_output(self):
        for failure in ("raise", "malformed", "provenance", "cleanup", "unavailable"):
            with self.subTest(failure=failure):
                self.stream = uuid4()
                verifier = None if failure == "unavailable" else Verifier(failure)
                owner, gate = self.owner_service(verifier)
                self.run_monitoring_with_failing_owner(owner, gate, verifier)

    def run_monitoring_with_failing_owner(self, owner, gate, verifier):
        motion = InferenceScheduler(clock_ns=self.monotonic_ns)
        motion.register(self.source.source_id,
                        MotionBaseline(pixel_delta=1, changed_fraction=.01), scheduler_policy())
        roi = SceneDetector(Calibration(
            UUID(int=401), self.source.source_id, self.source.source_type, UUID(int=302), 1, NOW,
            POLYGON, self.scene(0), roi_policy()))
        delivered = []
        delivery = CriticalDelivery(capacity=8, recorder=delivered.append)
        moved = shifted_roi(texture())
        motion_results, verdicts = [], []
        for index, data in enumerate((texture(), texture(), moved, moved)):
            self.now[0] += 10
            frame = self.scene(index + 1, data)
            # Owner verification runs first in each tick and fails.
            candidate, decision = self.face(owner, gate, index + 1)
            verdicts.append(owner.verify(candidate, gate, decision))
            motion.offer(frame, quality=Quality.SUFFICIENT)
            motion_results.append(motion.run_one().result)
            scene = roi.inspect(frame, monotonic_ns=self.now[0], observed_at=NOW,
                                movement_quality=Quality.SUFFICIENT,
                                tamper_quality=Quality.SUFFICIENT, roi_occluded=None)
            if scene.critical:
                state = delivery.submit(scene.critical)
                self.assertTrue(state.available)
        # Every owner result is unknown: never a match or a no-match.
        for verification in verdicts:
            self.assertEqual(Verdict.UNKNOWN, verification.verdict)
            self.assertIsNone(verification.confidence)
            self.assertNotEqual(VerificationReason.EVALUATED, verification.reason)
        self.assertIn(verdicts[0].reason, (VerificationReason.FAILURE,
                                           VerificationReason.VERIFIER_UNAVAILABLE))
        if verifier is not None and verifier.failure != "provenance":
            self.assertGreater(verifier.compares, 0)
        # Motion kept evaluating, including the change at the moved frame.
        self.assertEqual(Reason.WARMUP, motion_results[0].reason)
        self.assertEqual(Observation.ABSENT, motion_results[1].observation)
        self.assertEqual(Observation.PRESENT, motion_results[2].observation)
        # The calibrated ROI movement was confirmed and durably handed over.
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], [item.kind for item in delivered])
        self.assertTrue(delivered[0].confirmed)
        self.assertEqual(self.source.source_id, delivered[0].source_id)

    # -- person detector failure is never "no person" --------------------

    def person_scheduler(self, detector, *, gate=True):
        scheduler = InferenceScheduler(clock_ns=self.monotonic_ns)
        scheduler.register(self.source.source_id, detector, scheduler_policy())
        quality = (QualityGate(self.source.source_id, quality_policy("person"), results=scheduler)
                   if gate else None)
        return scheduler, quality

    def person_tick(self, scheduler, gate, sequence, *, dark=False):
        self.now[0] += 10
        frame = geometric_person(self.source.source_id, self.stream, sequence, dark=dark)
        decision = gate.assess(frame, execution=Execution.READY, context=quality_context(frame))
        scheduler.offer(frame, quality=decision.quality)
        snapshot = scheduler.run_one() or scheduler.snapshot(self.source.source_id)
        return decision, snapshot

    def assertUnknownPerson(self, snapshot, reason):
        self.assertEqual(Detection(Observation.UNKNOWN, reason), snapshot.result)
        self.assertEqual(Health.UNAVAILABLE, snapshot.health)
        self.assertNotEqual(Observation.ABSENT, snapshot.result.observation)

    def test_failing_or_missing_person_detector_is_unknown_while_motion_continues(self):
        motion = InferenceScheduler(clock_ns=self.monotonic_ns)
        motion_source = self.topology.sources[0]
        motion.register(motion_source.source_id,
                        MotionBaseline(pixel_delta=1, changed_fraction=.01), scheduler_policy())
        cases = ((RaisingPerson(), Reason.FAILURE), (MalformedPerson(), Reason.FAILURE),
                 (UnavailablePersonDetector(), Reason.MODEL_UNAVAILABLE))
        motion_stream = uuid4()
        sequence = 0
        for detector, reason in cases:
            with self.subTest(detector=detector.implementation):
                self.stream = uuid4()
                person, gate = self.person_scheduler(detector)
                for index in range(3):
                    _decision, snapshot = self.person_tick(person, gate, index)
                    sequence += 1
                    motion.offer(GrayFrame(motion_source.source_id, motion_stream, sequence,
                                           SCENE, SCENE,
                                           texture() if sequence % 2 else shifted_roi(texture())),
                                 quality=Quality.SUFFICIENT)
                    motion_snapshot = motion.run_one()
                self.assertUnknownPerson(snapshot, reason)
                # The other source's motion detector still reaches conclusions.
                self.assertEqual(Reason.EVALUATED, motion_snapshot.result.reason)
                self.assertEqual(Health.HEALTHY, motion.snapshot(motion_source.source_id).health)

    def test_low_light_revokes_a_published_negative_and_never_reports_no_person(self):
        detector = NegativePerson()
        person, gate = self.person_scheduler(detector)
        for sequence in range(3):
            decision, snapshot = self.person_tick(person, gate, sequence)
        self.assertEqual(Observation.ABSENT, snapshot.result.observation)
        calls = detector.calls
        decision, snapshot = self.person_tick(person, gate, 3, dark=True)
        self.assertEqual(Quality.INSUFFICIENT, decision.quality)
        # The earlier "absent" is revoked at once and the dark frame never
        # reaches the detector.
        self.assertUnknownPerson(snapshot, Reason.QUALITY)
        self.assertEqual(calls, detector.calls)
        for observation in (Observation.ABSENT, Observation.PRESENT):
            guarded = gate.guard_result(decision, Detection(observation, Reason.EVALUATED),
                                        execution=Execution.SUCCEEDED,
                                        frame=decision.frame)
            self.assertEqual(Observation.UNKNOWN, guarded.observation)
        # One good frame is not recovery: the gate needs consecutive good frames.
        decision, snapshot = self.person_tick(person, gate, 4)
        self.assertNotEqual(Observation.ABSENT, snapshot.result.observation)
        # The timeline refuses an unreliable person result recorded as "not observed".
        with self.assertRaises(InvalidObservation):
            TimelineObservation(Kind.PERSON, NOW, NOW, value=Value.NOT_OBSERVED,
                                source_id=self.source.source_id,
                                quality=TimelineQuality.INSUFFICIENT)
        accepted = TimelineObservation(Kind.PERSON, NOW, NOW, value=Value.UNKNOWN,
                                       source_id=self.source.source_id,
                                       quality=TimelineQuality.INSUFFICIENT)
        self.assertEqual(Value.UNKNOWN, accepted.value)

    def test_crashed_or_hung_isolated_worker_is_unknown_not_no_person(self):
        limits = WorkerLimits(evaluation_timeout_ns=SECOND // 2, start_timeout_ns=30 * SECOND,
                              restart_backoff_ns=10 * SECOND, maximum_consecutive_failures=3,
                              address_space_bytes=1 << 31, open_files=64,
                              maximum_frame_bytes=1024)
        for behaviour, reason in (("crash", Reason.WORKER_CRASHED),
                                  ("hang", Reason.WORKER_TIMEOUT)):
            with self.subTest(behaviour=behaviour):
                self.stream = uuid4()
                worker = IsolatedDetector(
                    WorkerSpec(DetectorKind.PERSON, "synthetic-worker-person", "1",
                               worker_person, {"behaviour": behaviour}),
                    limits, clock_ns=self.monotonic_ns)
                self.addCleanup(worker.close)
                self.assertEqual("running", worker.maintain().state)
                person, _gate = self.person_scheduler(worker, gate=False)
                self.now[0] += 10
                person.offer(geometric_person(self.source.source_id, self.stream, 0),
                             quality=Quality.SUFFICIENT)
                snapshot = person.run_one()
                self.assertUnknownPerson(snapshot, reason)
                self.assertNotEqual("running", worker.status().state)
                # Without a running worker the next frame is still unknown.
                self.now[0] += 10
                person.offer(geometric_person(self.source.source_id, self.stream, 1),
                             quality=Quality.SUFFICIENT)
                self.assertUnknownPerson(person.run_one(), Reason.WORKER_UNAVAILABLE)
                self.assertTrue(worker.close())


if __name__ == "__main__":
    unittest.main()
