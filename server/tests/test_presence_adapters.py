"""Synthetic producer-to-timeline adapters; generated geometry and mock ports only."""

from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from uuid import UUID, uuid4

from app.cameras.registry.models import NodeHealthState, SourceHealthState, SourceType
from app.cameras.uvc.identity import CameraState, HealthEvent
from app.detection.foundation import Quality as DetectionQuality
from app.detection.owner.contracts import FaceCandidate
from app.detection.quality import Execution, FrameIdentity, QualityGate
from app.detection.roi.contracts import CriticalKind, CriticalObservation
from app.detection.roi.delivery import CriticalDelivery
from app.detection.tracking.entrance import (AnonymousEntranceTracker, Crossing, CrossingKind, EntranceLine,
                                             PersonPoint, Point, TrackingPolicy, TrackUpdate)
from app.media.health.service import HealthResult, HealthState
from app.presence.access import AccessDenied
from app.presence.adapters import (CriticalTimelineRecorder, EntranceObservationAdapter, HealthTimeline,
                                   TimelineOutbox)
from app.presence.delivery import ActionResult
from app.presence.models import Kind, PresenceState, Quality, Value
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.policy import StorageState, StorageTransition
from app.storage.schema import APPLICATION_MIGRATIONS
from tests import test_owner_verification as owner_fixtures
from tests.test_detector_quality import SOURCE, assess, calibrated_policy, context, synthetic_person


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
NODE, OWNER = UUID(int=402), UUID(int=403)
LINE = EntranceLine(Point(.5, .2), Point(.5, .8), -1, .05)
POLICY = TrackingPolicy(max_tracks=4, max_gap_ms=500, max_distance=.5)
# Synthetic timing policy; no deployment default is implied.
VALIDITY, LATENCY = timedelta(hours=1), timedelta(seconds=2)
FORBIDDEN = ("culprit", "attacker", "guilt", "guilty", "suspect", "intruder", "thief", "perpetrator",
             "caused", "because")
PAYLOAD_KEYS = {"id", "kind", "value", "label", "occurred_at", "received_at", "source_id", "node_id",
                "confidence", "quality", "clock_trusted", "uncertainty_us", "confirmed", "presence_state",
                "sequence"}


class MockAccess:
    """Test fixture only, not an authentication/session implementation."""
    def require_owner(self, context):
        if context != "owner":
            raise AccessDenied()
        return OWNER

    def require_recordings(self, context):
        if context not in {"owner", "recordings"}:
            raise AccessDenied()


class Clock:
    def __init__(self, at=NOW, trusted=True):
        self.at, self.trusted = at, trusted

    def __call__(self):
        return self.at, self.trusted


class PresenceFixture:
    def make_presence(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as db:
            migrate(db, APPLICATION_MIGRATIONS)
        self.refuse = False
        self.evidence, self.notifications = [], []

        @contextmanager
        def reservation():
            if self.refuse:
                raise RuntimeError("STORAGE_HARD_STOP")
            yield

        def evidence(item, complete):
            self.evidence.append(item)
            return ActionResult.DELIVERED

        def notifications(item, complete):
            self.notifications.append(item)
            return ActionResult.DELIVERED

        self.presence = PresenceService(self.database, access=MockAccess(), evidence=evidence,
                                        notifications=notifications, reservation=reservation,
                                        detection=lambda: True, storage_status=lambda: True)
        self.outbox = TimelineOutbox(self.presence, capacity=8)
        self.clock = Clock()

    def history(self, context="recordings"):
        return self.presence.history(context, received_from=NOW - timedelta(days=1),
                                     received_to=NOW + timedelta(days=1))

    def assertNeutral(self, page):
        text = json.dumps(page).lower()
        for word in FORBIDDEN:
            self.assertNotIn(word, text)
        self.assertEqual(page["causality"], "not_inferred")
        for item in page["items"]:
            self.assertEqual(set(item), PAYLOAD_KEYS)


def crossing(kind, *, received=NOW, occurred=None, confidence=None, trusted=True, confirmed=None,
             uncertainty_us=0, source=SOURCE):
    owner = kind in (CrossingKind.OWNER_ENTRY, CrossingKind.OWNER_EXIT)
    return Crossing(uuid4(), kind, source, occurred or received, received,
                    confidence if confidence is not None else (.97 if owner else None), trusted,
                    uncertainty_us, owner and trusted if confirmed is None else confirmed)


def critical(kind=CriticalKind.SERVER_MOVEMENT, *, at=NOW, quality=DetectionQuality.SUFFICIENT,
             confirmed=True, source=SOURCE):
    return CriticalObservation(uuid4(), kind, source, SourceType.LOCAL_UVC, uuid4(), 1, at, 1, uuid4(), 1,
                               NOW - timedelta(days=1), "0" * 64, .9, quality, "synthetic", confirmed)


class EntranceAdapterTests(PresenceFixture, TestCase):
    def setUp(self):
        self.make_presence()
        self.adapter = EntranceObservationAdapter(self.outbox, owner_presence_validity=VALIDITY,
                                                  maximum_source_latency=LATENCY)

    def submit(self, *crossings, quality=DetectionQuality.SUFFICIENT):
        self.assertTrue(self.adapter.submit(TrackUpdate((), crossings, quality)))
        return self.outbox.flush()

    def state(self, now=NOW):
        return self.presence.snapshot(now=now, clock_trusted=True)["state"]

    def test_timing_policy_has_no_default(self):
        for values in ({}, {"owner_presence_validity": VALIDITY}, {"maximum_source_latency": LATENCY},
                       {"owner_presence_validity": timedelta(0), "maximum_source_latency": LATENCY}):
            with self.assertRaises((TypeError, ValueError)):
                EntranceObservationAdapter(self.outbox, **values)

    def test_confirmed_owner_entry_and_exit_project_presence(self):
        self.submit(crossing(CrossingKind.OWNER_ENTRY))
        self.assertEqual(self.state(), "PRESENT")
        later = NOW + timedelta(minutes=1)
        self.submit(crossing(CrossingKind.OWNER_EXIT, received=later))
        self.assertEqual(self.state(later), "ABSENT")
        self.assertEqual(self.state(later + VALIDITY + timedelta(seconds=1)), "UNKNOWN")

    def test_untrusted_or_late_owner_crossing_makes_presence_unknown(self):
        for index, variant in enumerate(({"trusted": False},
                                         {"occurred": None, "late": True},
                                         {"uncertainty_us": 3_000_000})):
            received = NOW + timedelta(minutes=10 * index)
            self.submit(crossing(CrossingKind.OWNER_ENTRY, received=received))
            self.assertEqual(self.state(received), "PRESENT")
            later = received + timedelta(minutes=1)
            options = dict(variant)
            if options.pop("late", False):
                options["occurred"] = later - timedelta(seconds=30)
            self.submit(crossing(CrossingKind.OWNER_ENTRY, received=later, **options))
            self.assertEqual(self.state(later), "UNKNOWN", variant)
            item = self.history()["items"][-1]
            self.assertFalse(item["confirmed"])
            self.assertFalse(item["clock_trusted"])

    def test_anonymous_crossing_never_affects_presence_or_carries_identity(self):
        self.submit(crossing(CrossingKind.OWNER_ENTRY))
        later = NOW + timedelta(minutes=1)
        self.submit(crossing(CrossingKind.ANONYMOUS_EXIT, received=later),
                    crossing(CrossingKind.ANONYMOUS_ENTRY, received=later, source=UUID(int=909)))
        self.assertEqual(self.state(later), "PRESENT")
        items = self.history()["items"]
        anonymous = [item for item in items if item["kind"].startswith("anonymous")]
        self.assertEqual(len(anonymous), 2)
        for item in anonymous:
            self.assertIsNone(item["confidence"])
            self.assertFalse(item["confirmed"])
            self.assertTrue(item["label"].startswith("Anonymous"))
        # Two cameras never share any correlation identifier.
        self.assertNotEqual(anonymous[0]["id"], anonymous[1]["id"])
        self.assertNeutral(self.history())

    def test_unknown_quality_update_writes_nothing(self):
        self.assertEqual(self.adapter.observations(TrackUpdate((), (), DetectionQuality.UNKNOWN)), ())
        with self.assertRaises(ValueError):
            self.adapter.observations(TrackUpdate((), (crossing(CrossingKind.ANONYMOUS_ENTRY),),
                                                  DetectionQuality.UNKNOWN))
        self.assertEqual(self.outbox.flush().recorded, 0)
        self.assertEqual(self.history()["items"], [])

    def test_storage_refusal_keeps_crossing_staged_and_replay_is_idempotent(self):
        event = crossing(CrossingKind.OWNER_ENTRY)
        self.refuse = True
        state = self.submit(event)
        self.assertEqual((state.recorded, state.pending), (0, 1))
        self.assertTrue(state.degraded)
        self.refuse = False
        self.assertEqual(self.outbox.flush().pending, 0)
        self.submit(event)
        self.assertEqual(len(self.history()["items"]), 1)
        self.assertEqual(self.state(), "PRESENT")


class OwnerTrackerEndToEndTests(PresenceFixture, TestCase):
    """Real tracker, quality gate and owner-verification service with synthetic frames."""
    setUp_owner = owner_fixtures.OwnerTests.setUp
    reservation = owner_fixtures.OwnerTests.reservation
    open_store = owner_fixtures.OwnerTests.open_store
    enroll = owner_fixtures.OwnerTests.enroll

    def setUp(self):
        self.setUp_owner()
        self.make_presence()
        self.adapter = EntranceObservationAdapter(self.outbox, owner_presence_validity=VALIDITY,
                                                  maximum_source_latency=LATENCY)
        self.enroll()

    def walk(self, *, stop_owner_quality=False, at=NOW):
        tracker = AnonymousEntranceTracker(SOURCE, POLICY, LINE)
        gate = QualityGate(SOURCE, calibrated_policy("entrance_crossing"))
        owner_gate = QualityGate(SOURCE, calibrated_policy("owner_verification"))
        assess(gate, synthetic_person(0))
        assess(owner_gate, synthetic_person(0))
        for sequence, x in ((1, .3), (2, .7)):
            sample = synthetic_person(sequence)
            candidate = FaceCandidate(uuid4(), sample)
            if stop_owner_quality and sequence == 2:
                owner_gate.invalidate(execution=Execution.STOPPED)
            owner = self.service.verify(candidate, owner_gate,
                                        self.service.assess(candidate, owner_gate, context=context(sample)))
            update = tracker.update(FrameIdentity.from_frame(sample),
                                    (PersonPoint(candidate.identifier, Point(x, .5)),),
                                    gate=gate, decision=assess(gate, sample), observed_ms=sequence * 10,
                                    occurred_at=at, received_at=at, clock_trusted=True, uncertainty_us=0,
                                    owner_results=(owner,), owner_verifier=self.service)
            self.assertTrue(self.adapter.submit(update))
        self.outbox.flush()
        return update

    def test_low_quality_owner_verification_stays_anonymous_and_presence_unknown(self):
        update = self.walk(stop_owner_quality=True)
        self.assertEqual(update.crossings[0].kind, CrossingKind.ANONYMOUS_ENTRY)
        self.assertEqual(self.presence.snapshot(now=NOW, clock_trusted=True)["state"], "UNKNOWN")
        item, = self.history()["items"]
        self.assertEqual(item["kind"], "anonymous_entry")
        self.assertIsNone(item["confidence"])

    def test_entry_then_movement_then_camera_offline_is_neutral_and_critical_path_runs(self):
        self.walk()
        self.assertEqual(self.presence.snapshot(now=NOW, clock_trusted=True)["state"], "PRESENT")
        movement_at = NOW + timedelta(seconds=30)
        delivery = CriticalDelivery(capacity=2, recorder=CriticalTimelineRecorder(
            self.presence, clock=Clock(movement_at), maximum_source_latency=LATENCY, capacity=4))
        self.assertTrue(delivery.submit((critical(at=movement_at),)).available)
        offline_at = NOW + timedelta(seconds=45)
        health = HealthTimeline(self.outbox, clock=Clock(offline_at))
        health.camera(HealthEvent(SOURCE, CameraState.OFFLINE, "device_disconnected"))
        self.outbox.flush()
        # Critical delivery runs while the Owner is PRESENT.
        self.presence.dispatch_pending()
        self.assertEqual(len(self.evidence), 1)
        self.assertEqual(len(self.notifications), 1)
        snapshot = self.presence.snapshot(now=offline_at, clock_trusted=True)
        self.assertEqual(snapshot["state"], "PRESENT")
        page = self.history()
        self.assertEqual([(item["kind"], item["value"]) for item in page["items"]],
                         [("owner_entry", "observed"), ("server_movement", "observed"),
                          ("camera_health", "offline")])
        self.assertTrue(all(item["source_id"] == str(SOURCE) for item in page["items"]))
        self.assertNeutral(page)
        with self.assertRaises(AccessDenied):
            self.history("live")


class CriticalRecorderTests(PresenceFixture, TestCase):
    def setUp(self):
        self.make_presence()
        self.recorder = CriticalTimelineRecorder(self.presence, clock=self.clock,
                                                 maximum_source_latency=LATENCY, capacity=2)

    def test_retry_after_refusal_reuses_receipt_and_queues_work_once(self):
        delivery = CriticalDelivery(capacity=2, recorder=self.recorder)
        item = critical(CriticalKind.CAMERA_TAMPER)
        self.refuse = True
        self.assertFalse(delivery.submit((item,)).available)
        self.refuse = False
        self.clock.at = NOW + timedelta(seconds=5)
        self.assertEqual(delivery.retry().accepted, (item.identifier,))
        stored, = self.history()["items"]
        self.assertEqual(stored["received_at"], NOW.isoformat(timespec="microseconds"))
        self.assertTrue(stored["confirmed"])
        # A second delivery of the same UUID stays a duplicate.
        self.recorder(item)
        self.presence.dispatch_pending()
        self.assertEqual((len(self.evidence), len(self.notifications)), (1, 1))

    def test_untrusted_clock_or_stale_sample_keeps_confirmation_but_marks_timing(self):
        self.clock.trusted = False
        self.recorder(critical())
        self.clock.trusted = True
        self.clock.at = NOW + timedelta(minutes=1)
        self.recorder(critical(at=NOW))
        for item in self.history()["items"]:
            self.assertTrue(item["confirmed"])
            self.assertFalse(item["clock_trusted"])
        self.presence.dispatch_pending()
        self.assertEqual(len(self.evidence), 2)

    def test_unconfirmed_or_insufficient_quality_is_refused_and_memo_is_bounded(self):
        for item in (critical(confirmed=False), critical(quality=DetectionQuality.DEGRADED)):
            with self.assertRaises(ValueError):
                self.recorder(item)
        self.refuse = True
        for _ in range(2):
            with self.assertRaises(RuntimeError):
                self.recorder(critical())
        with self.assertRaises(BufferError):
            self.recorder(critical())
        self.assertEqual(self.history()["items"], [])


class HealthTimelineTests(PresenceFixture, TestCase):
    def setUp(self):
        self.make_presence()
        self.health = HealthTimeline(self.outbox, clock=self.clock)

    def test_every_producer_state_maps_to_a_neutral_fact(self):
        other = UUID(int=77)
        for state in CameraState:
            self.health.camera(HealthEvent(SOURCE, state, "synthetic"))
        self.outbox.flush()
        for state in SourceHealthState:
            self.health.source(other, state, node_id=NODE)
        self.outbox.flush()
        for state in NodeHealthState:
            self.health.node(NODE, state)
        for state in StorageState:
            self.health.storage(StorageTransition(StorageState.NORMAL, state, 5))
        self.outbox.flush()
        for state in HealthState:
            self.health.recording(HealthResult(state, ()), NOW)
        state = self.outbox.flush()
        self.assertEqual((state.pending, state.refused, state.rejected), (0, 0, 0))
        facts = [(item["kind"], item["value"]) for item in self.history()["items"]]
        self.assertEqual(facts[:4], [("camera_health", "offline"), ("camera_health", "degraded"),
                                     ("camera_health", "online"),
                                     ("camera_health", "manual_intervention_required")])
        self.assertIn(("node_health", "revoked"), facts)
        self.assertIn(("storage", "failed"), facts)
        self.assertIn(("storage", "degraded"), facts)
        self.assertIn(("recording", "unknown"), facts)
        self.assertNotIn("synthetic", json.dumps(self.history()))
        self.assertNeutral(self.history())

    def test_storage_audit_callback_never_writes_while_admission_is_refused(self):
        self.refuse = True
        self.assertTrue(self.health.storage(StorageTransition(StorageState.NORMAL, StorageState.HARD_STOP, 1)))
        self.assertEqual(self.outbox.flush().pending, 1)
        self.refuse = False
        self.assertEqual(self.outbox.flush().recorded, 1)
        item, = self.history()["items"]
        self.assertEqual((item["kind"], item["value"], item["source_id"]), ("storage", "failed", None))

    def test_full_outbox_refuses_visibly_and_untrusted_clock_is_explicit(self):
        self.clock.trusted = False
        for _ in range(8):
            self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.assertFalse(self.health.node(NODE, NodeHealthState.ONLINE))
        self.assertEqual(self.outbox.state().refused, 1)
        self.assertTrue(self.outbox.flush().degraded)
        page = self.history()
        self.assertTrue(page["ordering_degraded"])
        self.assertTrue(all(not item["clock_trusted"] for item in page["items"]))

    def test_invalid_inputs_are_refused_before_staging(self):
        for call in (lambda: self.health.camera("offline"),
                     lambda: self.health.node(NODE, "offline"),
                     lambda: self.health.storage(StorageState.HARD_STOP),
                     lambda: self.health.recording("OK")):
            with self.assertRaises(ValueError):
                call()
        with self.assertRaises(ValueError):
            self.outbox.stage(replace(critical(), confirmed=True))
        self.assertEqual(self.outbox.state().pending, 0)
        with self.assertRaises(ValueError):
            TimelineOutbox(self.presence, capacity=0)
        # A health fact can never carry an Owner presence effect.
        fact = self.outbox
        node = HealthTimeline(fact, clock=self.clock)
        node.node(NODE, NodeHealthState.ONLINE)
        observation = fact._pending[0][0]
        self.assertIs(observation.kind, Kind.NODE_HEALTH)
        self.assertIs(observation.value, Value.ONLINE)
        self.assertIs(observation.quality, Quality.UNKNOWN)
        with self.assertRaises(ValueError):
            fact.stage(observation, presence_valid_until=NOW + VALIDITY)
        fact.flush()
        self.assertEqual(self.presence.snapshot(now=NOW, clock_trusted=True)["state"],
                         PresenceState.UNKNOWN.value)
