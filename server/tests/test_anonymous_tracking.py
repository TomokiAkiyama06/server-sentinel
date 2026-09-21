"""Generated geometric observations only, no faces or cross-camera profiles."""

from dataclasses import asdict, replace
from datetime import datetime, timezone
from unittest import TestCase
from uuid import UUID, uuid4
import json

from app.detection.foundation import Quality
from app.detection.owner.contracts import FaceCandidate, Verdict, Verification, VerificationReason
from app.detection.owner.service import OwnerVerificationService
from app.detection.quality import Execution, FrameIdentity, QualityGate
from app.detection.tracking.entrance import (AnonymousEntranceTracker, CrossingKind, EntranceLine,
                                             PersonPoint, Point, TrackingPolicy)
from tests.test_detector_quality import SOURCE, STREAM, assess, calibrated_policy, context, synthetic_person
from tests import test_owner_verification as owner_fixtures


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
LINE = EntranceLine(Point(.5, .2), Point(.5, .8), -1, .05)
POLICY = TrackingPolicy(max_tracks=4, max_gap_ms=500, max_distance=.5)


class TrackingTests(TestCase):
    def setUp(self):
        self.gate = QualityGate(SOURCE, calibrated_policy("entrance_crossing"))
        assess(self.gate, synthetic_person(0))
        self.tracker = AnonymousEntranceTracker(SOURCE, POLICY, LINE)
        self.sequence = 0

    def update(self, points, *, condition="clear", stream=STREAM, millis=None, sequence=None,
               owner_results=(), owner_verifier=None, clock_trusted=True):
        self.sequence = self.sequence + 1 if sequence is None else sequence
        sample = synthetic_person(self.sequence, condition=condition, stream=stream)
        decision = assess(self.gate, sample)
        return self.tracker.update(FrameIdentity.from_frame(sample),
                                   tuple(PersonPoint(uuid4(), Point(*point)) for point in points),
                                   gate=self.gate, decision=decision,
                                   observed_ms=self.sequence * 10 if millis is None else millis,
                                   occurred_at=NOW, received_at=NOW, clock_trusted=clock_trusted,
                                   uncertainty_us=0, owner_results=owner_results, owner_verifier=owner_verifier)

    def test_directed_crossings_emit_observations_without_track_identifiers(self):
        first = self.update(((.3, .5),))
        entered = self.update(((.7, .5),))
        exited = self.update(((.3, .5),))
        self.assertEqual(entered.quality, Quality.SUFFICIENT)
        self.assertEqual([event.kind for event in entered.crossings], [CrossingKind.ANONYMOUS_ENTRY])
        self.assertEqual([event.kind for event in exited.crossings], [CrossingKind.ANONYMOUS_EXIT])
        self.assertEqual(first.assignments[0][1], entered.assignments[0][1])
        event = asdict(entered.crossings[0])
        self.assertFalse(event["confirmed"])
        self.assertIsNone(event["confidence"])
        self.assertNotIn("track", str(event))
        self.assertNotIn("session", str(event))
        self.assertNotIn(str(first.assignments[0][1]), json.dumps(event, default=str))

    def test_hysteresis_prevents_line_jitter_and_emits_once_per_settled_crossing(self):
        events = []
        for x in (.3, .49, .51, .49, .51, .54, .56, .57):
            events.extend(self.update(((x, .5),)).crossings)
        self.assertEqual([event.kind for event in events], [CrossingKind.ANONYMOUS_ENTRY])

    def test_walking_around_finite_endpoint_does_not_count_as_crossing(self):
        self.update(((.3, .1),))
        self.assertEqual(self.update(((.7, .1),)).crossings, ())
        self.assertEqual(self.update(((.7, .4),)).crossings, ())

    def test_reverse_inside_hysteresis_cancels_old_finite_line_crossing(self):
        self.tracker = AnonymousEntranceTracker(SOURCE, POLICY, EntranceLine(Point(.4, .5), Point(.6, .5), 1, .1))
        events = []
        for point in ((.5, .3), (.5, .51), (.5, .49), (.8, .49), (.8, .7)):
            events.extend(self.update((point,)).crossings)
        self.assertEqual(events, [])

    def test_entry_direction_is_explicit_and_reversible(self):
        self.tracker = AnonymousEntranceTracker(SOURCE, POLICY, replace(LINE, entry_direction=1))
        self.update(((.3, .5),))
        self.assertEqual(self.update(((.7, .5),)).crossings[0].kind, CrossingKind.ANONYMOUS_EXIT)

    def test_occlusion_gap_and_dropped_sequence_never_infer_crossing(self):
        first = self.update(((.3, .5),))
        self.update(())
        after_occlusion = self.update(((.7, .5),))
        self.assertEqual(after_occlusion.crossings, ())
        self.assertNotEqual(first.assignments[0][1], after_occlusion.assignments[0][1])
        self.assertEqual(self.update(((.3, .5),), sequence=8).crossings, ())
        self.assertEqual(self.update(((.7, .5),), millis=1000).crossings, ())

    def test_quality_failure_is_unknown_and_resets_crossing_continuity(self):
        first = self.update(((.3, .5),))
        unknown = self.update(((.7, .5),), condition="dark")
        self.assertEqual(unknown.quality, Quality.UNKNOWN)
        self.assertEqual(unknown.assignments, ())
        self.assertEqual(self.update(((.7, .5),)).quality, Quality.UNKNOWN)
        recovered = self.update(((.7, .5),))
        self.assertEqual(recovered.crossings, ())
        self.assertNotEqual(first.assignments[0][1], recovered.assignments[0][1])

    def test_ambiguous_association_starts_new_tracks_without_crossing(self):
        first = self.update(((.3, .4), (.3, .6)))
        second = self.update(((.7, .4), (.7, .6)))
        self.assertEqual(second.crossings, ())
        self.assertTrue({track for _, track in first.assignments}.isdisjoint(track for _, track in second.assignments))

    def test_stream_restart_and_session_close_forget_identity(self):
        first = self.update(((.3, .5),))
        stream = uuid4()
        self.assertEqual(self.update(((.7, .5),), stream=stream).quality, Quality.UNKNOWN)
        restarted = self.update(((.7, .5),), stream=stream)
        self.assertEqual(restarted.crossings, ())
        self.assertNotEqual(first.assignments[0][1], restarted.assignments[0][1])
        self.tracker.close()
        closed = self.update(((.3, .5),), stream=stream)
        self.assertEqual(closed.crossings, ())
        self.assertNotEqual(restarted.assignments[0][1], closed.assignments[0][1])

    def test_same_candidate_on_different_cameras_never_shares_track(self):
        point = PersonPoint(UUID(int=55), Point(.3, .5))
        tracks = []
        for source in (SOURCE, UUID(int=222)):
            gate = QualityGate(source, calibrated_policy("entrance_crossing"))
            tracker = AnonymousEntranceTracker(source, POLICY, LINE)
            assess(gate, replace(synthetic_person(0), source_id=source))
            sample = replace(synthetic_person(1), source_id=source)
            result = tracker.update(FrameIdentity.from_frame(sample), (point,), gate=gate, decision=assess(gate, sample),
                                    observed_ms=10, occurred_at=NOW, received_at=NOW, clock_trusted=True, uncertainty_us=0)
            tracks.append(result.assignments[0][1])
        self.assertNotEqual(*tracks)

    def test_bad_timestamps_limits_and_foreign_source_cannot_keep_hidden_state(self):
        self.update(((.3, .5),))
        self.assertEqual(self.update(((.7, .5),), millis=1).quality, Quality.UNKNOWN)
        with self.assertRaisesRegex(ValueError, "RESOURCE_LIMIT"):
            self.update(tuple((.1, .1) for _ in range(5)))
        self.assertEqual(self.tracker._tracks, {})
        for value in (float("nan"), float("inf"), -1):
            with self.assertRaises(ValueError):
                Point(value, .5)
        with self.assertRaises(AttributeError):
            self.tracker.source_id = UUID(int=999)


class OwnerCrossingTests(TestCase):
    setUp = owner_fixtures.OwnerTests.setUp
    reservation = owner_fixtures.OwnerTests.reservation
    open_store = owner_fixtures.OwnerTests.open_store
    enroll = owner_fixtures.OwnerTests.enroll

    def test_owner_crossing_requires_current_same_frame_candidate_receipt(self):
        self.enroll()
        tracker = AnonymousEntranceTracker(SOURCE, POLICY, LINE)
        gate = QualityGate(SOURCE, calibrated_policy("entrance_crossing"))
        owner_gate = QualityGate(SOURCE, calibrated_policy("owner_verification"))
        assess(gate, synthetic_person(0))
        assess(owner_gate, synthetic_person(0))
        for sequence, x in ((1, .3), (2, .7)):
            sample = synthetic_person(sequence)
            candidate = FaceCandidate(uuid4(), sample)
            owner_decision = self.service.assess(candidate, owner_gate, context=context(sample))
            owner = self.service.verify(candidate, owner_gate, owner_decision)
            result = tracker.update(FrameIdentity.from_frame(sample), (PersonPoint(candidate.identifier, Point(x, .5)),),
                                    gate=gate, decision=assess(gate, sample), observed_ms=sequence * 10,
                                    occurred_at=NOW, received_at=NOW, clock_trusted=True, uncertainty_us=0,
                                    owner_results=(owner,), owner_verifier=self.service)
        self.assertEqual(result.crossings[0].kind, CrossingKind.OWNER_ENTRY)
        self.assertTrue(result.crossings[0].confirmed)

    def test_forged_stale_or_other_candidate_owner_receipt_stays_anonymous(self):
        self.enroll()
        for mode in ("forged", "other-candidate", "deleted", "other-session", "quality-stopped"):
            tracker = AnonymousEntranceTracker(SOURCE, POLICY, LINE)
            gate = QualityGate(SOURCE, calibrated_policy("entrance_crossing"))
            owner_gate = QualityGate(SOURCE, calibrated_policy("owner_verification"))
            assess(gate, synthetic_person(0))
            assess(owner_gate, synthetic_person(0))
            for sequence, x in ((1, .3), (2, .7)):
                sample = synthetic_person(sequence)
                candidate = FaceCandidate(uuid4(), sample)
                owner = self.service.verify(candidate, owner_gate,
                                             self.service.assess(candidate, owner_gate, context=context(sample)))
                verifier = self.service
                if mode == "forged":
                    owner = Verification(candidate.identifier, FrameIdentity.from_frame(sample), 1, Verdict.MATCH,
                                         .99, VerificationReason.EVALUATED)
                elif mode == "other-candidate":
                    candidate = FaceCandidate(uuid4(), sample)
                elif mode == "deleted" and sequence == 2:
                    self.store.delete(expected_generation=self.store.status().generation, at=NOW)
                elif mode == "other-session":
                    verifier = OwnerVerificationService(self.store, self.verifier)
                elif mode == "quality-stopped":
                    owner_gate.invalidate(execution=Execution.STOPPED)
                result = tracker.update(FrameIdentity.from_frame(sample), (PersonPoint(candidate.identifier, Point(x, .5)),),
                                        gate=gate, decision=assess(gate, sample), observed_ms=sequence * 10,
                                        occurred_at=NOW, received_at=NOW, clock_trusted=True, uncertainty_us=0,
                                        owner_results=(owner,), owner_verifier=verifier)
            self.assertEqual(result.crossings[0].kind, CrossingKind.ANONYMOUS_ENTRY, mode)
            if not self.store.status().enrolled:
                self.enroll()
