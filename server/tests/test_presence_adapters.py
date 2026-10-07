"""Synthetic producer-to-timeline adapters; generated geometry and mock ports only."""

from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from unittest import TestCase, mock
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
from app.logging import Event
from app.media.health.service import HealthResult, HealthState
from app.presence.access import AccessDenied
from app.presence.adapters import (CriticalTimelineRecorder, EntranceObservationAdapter, HealthTimeline,
                                   TimelineOutbox)
from app.presence.delivery import ActionResult
from app.presence.models import InvalidObservation, Kind, Observation, PresenceState, Quality, Value, timestamp
from app.presence.schema import CRITICAL_SOURCE_KINDS, STAGED_SOURCE_KINDS
from app.presence.service import SOURCE_CLOCK, SOURCE_CLOCK_TABLES, PresenceService
from app.storage.database import Database, PinnedDatabase, read_database_prefix
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
        self.clock = Clock()
        self.outbox = TimelineOutbox(self.presence, clock=self.clock, capacity=8)
        self.outbox.open()
        self.addCleanup(lambda: self.outbox._handle and self.outbox._handle.release())

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
        self.adapter = EntranceObservationAdapter(self.outbox, source_id=SOURCE, owner_presence_validity=VALIDITY,
                                                  maximum_source_latency=LATENCY)
        # The gate is already known to be sufficient, so these tests see only
        # crossings; `EntranceGateQualityTests` covers the gate-quality facts.
        self.adapter._gate = Quality.SUFFICIENT

    def submit(self, *crossings, quality=DetectionQuality.SUFFICIENT, flush_at=None):
        # The main-host receipt is stamped when presence writes the fact.
        self.clock.at = max(item.received_at for item in crossings)
        self.assertTrue(self.adapter.submit(TrackUpdate((), crossings, quality)))
        if flush_at is not None:
            self.clock.at = flush_at
        return self.outbox.flush()

    def state(self, now=NOW):
        return self.presence.snapshot(now=now, clock_trusted=True)["state"]

    def test_timing_policy_has_no_default(self):
        for values in ({}, {"owner_presence_validity": VALIDITY}, {"maximum_source_latency": LATENCY},
                       {"owner_presence_validity": timedelta(0), "maximum_source_latency": LATENCY}):
            with self.assertRaises((TypeError, ValueError)):
                EntranceObservationAdapter(self.outbox, source_id=SOURCE, **values)

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
        self.submit(crossing(CrossingKind.ANONYMOUS_EXIT, received=later))
        # Another camera has its own adapter; one adapter serves one source.
        other = EntranceObservationAdapter(self.outbox, source_id=UUID(int=909),
                                           owner_presence_validity=VALIDITY, maximum_source_latency=LATENCY)
        self.assertTrue(other.submit(TrackUpdate((), (crossing(CrossingKind.ANONYMOUS_ENTRY, received=later,
                                                                source=UUID(int=909)),),
                                                 DetectionQuality.SUFFICIENT)))
        self.outbox.flush()
        with self.assertRaisesRegex(ValueError, "invalid crossing"):
            self.adapter.submit(TrackUpdate((), (crossing(CrossingKind.ANONYMOUS_ENTRY, source=UUID(int=909)),),
                                            DetectionQuality.SUFFICIENT))
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
        self.assertEqual(self.adapter.crossings(TrackUpdate((), (), DetectionQuality.UNKNOWN)), ())
        with self.assertRaises(ValueError):
            self.adapter.crossings(TrackUpdate((), (crossing(CrossingKind.ANONYMOUS_ENTRY),),
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
        # A replay stamped later is still the same fact, not an identity conflict.
        state = self.submit(event, flush_at=NOW + timedelta(minutes=5))
        self.assertEqual((state.pending, state.rejected), (0, 0))
        self.assertEqual(len(self.history()["items"]), 1)

    def test_replay_with_different_tracker_confirmation_is_an_identity_conflict(self):
        # confirmed is receipt-derived too, so it is ignored when a restamped
        # replay is compared; the tracker's own confirmation must not be.
        for index, (first, second) in enumerate(((False, True), (True, False))):
            original = crossing(CrossingKind.OWNER_ENTRY, confirmed=first,
                                received=NOW + timedelta(minutes=10 * index))
            self.submit(original)
            before = self.outbox.state().rejected
            state = self.submit(replace(original, confirmed=second))
            self.assertEqual(state.rejected, before + 1, (first, second))
            self.assertTrue(state.degraded)
            items = [entry for entry in self.history()["items"] if entry["id"] == str(original.identifier)]
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["confirmed"], first)
        self.assertEqual(self.state(NOW + timedelta(minutes=10)), "PRESENT")
        status = self.presence.owner_status("owner", now=NOW + timedelta(minutes=10), clock_trusted=True)
        self.assertTrue(status["timeline_gap"])

    def test_staged_replay_with_different_tracker_confirmation_is_rejected(self):
        self.refuse = True
        staged = crossing(CrossingKind.OWNER_ENTRY, confirmed=False)
        self.assertEqual(self.submit(staged).pending, 1)
        self.assertFalse(self.adapter.submit(TrackUpdate((), (replace(staged, confirmed=True),),
                                                        DetectionQuality.SUFFICIENT)))
        state = self.outbox.state()
        self.assertEqual((state.pending, state.rejected), (1, 1))
        self.refuse = False
        self.outbox.flush()
        self.assertEqual(self.state(), "UNKNOWN")

    def test_source_fact_digest_expires_with_its_observation(self):
        self.submit(crossing(CrossingKind.OWNER_ENTRY))
        with closing(self.database.connect()) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM presence_source_facts").fetchone()[0], 1)
        self.presence.expire_history(now=NOW + timedelta(days=self.presence.periods.recording_days + 1))
        with closing(self.database.connect()) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM presence_source_facts").fetchone()[0], 0)

    def test_source_fact_digest_is_only_for_restamped_writes(self):
        observation = Observation(Kind.ANONYMOUS_ENTRY, NOW, NOW, source_id=SOURCE, quality=Quality.SUFFICIENT)
        for kwargs in ({"source_fact": "0" * 64}, {"source_fact": "g" * 64, "restamped": True},
                       {"source_fact": "0" * 63, "restamped": True}):
            with self.assertRaises(InvalidObservation):
                self.presence.record(observation, **kwargs)

    def test_crossing_held_past_latency_bound_cannot_confirm_presence_late(self):
        self.refuse = True
        self.submit(crossing(CrossingKind.OWNER_ENTRY))
        self.refuse = False
        later = NOW + LATENCY + timedelta(seconds=1)
        self.clock.at = later
        self.assertEqual(self.outbox.flush().recorded, 1)
        self.assertEqual(self.state(later), "UNKNOWN")
        item, = self.history()["items"]
        self.assertFalse(item["confirmed"])

    def test_facts_stamped_later_elsewhere_never_make_a_staged_owner_crossing_untrusted(self):
        # One main clock for 1-4 sources: a camera health fact reported while
        # the entrance frame was still being processed, and a critical
        # observation recorded directly, are both written before the crossing.
        health = HealthTimeline(self.outbox)
        recorder = CriticalTimelineRecorder(self.outbox, maximum_source_latency=LATENCY)
        self.clock.at = NOW + timedelta(milliseconds=300)
        health.camera(HealthEvent(SOURCE, CameraState.DEGRADED, "synthetic"))
        self.assertEqual(self.outbox.flush().recorded, 1)
        self.assertTrue(self.adapter.submit(TrackUpdate((), (crossing(CrossingKind.OWNER_ENTRY),),
                                                        DetectionQuality.SUFFICIENT)))
        self.clock.at = NOW + timedelta(milliseconds=600)
        recorder(critical(at=NOW + timedelta(milliseconds=500), source=UUID(int=909)))
        self.clock.at = NOW + timedelta(milliseconds=900)
        self.assertEqual(self.outbox.flush().recorded, 2)
        self.assertEqual(self.state(self.clock.at), "PRESENT")
        page = self.history()
        self.assertFalse(page["ordering_degraded"])
        self.assertTrue(all(item["clock_trusted"] for item in page["items"]))

    def test_critical_write_from_the_same_source_never_makes_a_staged_crossing_untrusted(self):
        # The critical path records synchronously while the crossing waits in
        # the outbox, so a later-occurring critical fact from the same camera
        # reaches presence first by design.
        recorder = CriticalTimelineRecorder(self.outbox, maximum_source_latency=LATENCY)
        self.clock.at = NOW
        self.assertTrue(self.adapter.submit(TrackUpdate((), (crossing(CrossingKind.OWNER_ENTRY),),
                                                        DetectionQuality.SUFFICIENT)))
        self.clock.at = NOW + timedelta(milliseconds=600)
        recorder(critical(at=NOW + timedelta(milliseconds=500)))
        self.clock.at = NOW + timedelta(milliseconds=900)
        self.assertEqual(self.outbox.flush().recorded, 1)
        self.assertEqual(self.state(self.clock.at), "PRESENT")
        page = self.history()
        self.assertFalse(page["ordering_degraded"])
        self.assertTrue(all(item["clock_trusted"] for item in page["items"]))

    def test_source_order_is_still_checked_within_each_path(self):
        recorder = CriticalTimelineRecorder(self.outbox, maximum_source_latency=LATENCY)
        self.clock.at = NOW + timedelta(milliseconds=600)
        recorder(critical(at=NOW + timedelta(milliseconds=500)))
        recorder(critical(at=NOW + timedelta(milliseconds=100)))
        self.submit(crossing(CrossingKind.OWNER_ENTRY, received=NOW + timedelta(milliseconds=700),
                             occurred=NOW + timedelta(milliseconds=500)))
        self.submit(crossing(CrossingKind.OWNER_ENTRY, received=NOW + timedelta(milliseconds=800),
                             occurred=NOW + timedelta(milliseconds=200)))
        by_kind = {}
        for item in self.history()["items"]:
            kind, occurred, value = item["kind"], item["occurred_at"], item["clock_trusted"]
            by_kind.setdefault(kind, []).append((occurred, value))
        for kind, items in by_kind.items():
            # The earlier-occurring fact arrived second on its own path.
            self.assertEqual([value for _, value in sorted(items)], [False, True], kind)

    def test_source_clock_paths_partition_every_source_dated_kind(self):
        self.assertEqual({kind.value for kind, table in SOURCE_CLOCK_TABLES.items()
                          if table == "presence_source_clock"}, set(STAGED_SOURCE_KINDS))
        self.assertEqual({kind.value for kind, table in SOURCE_CLOCK_TABLES.items()
                          if table == "presence_critical_source_clock"}, set(CRITICAL_SOURCE_KINDS))
        self.assertEqual(set(SOURCE_CLOCK_TABLES), SOURCE_CLOCK)

    def test_upgrade_rebuilds_each_path_mark_from_retained_observations(self):
        recorder = CriticalTimelineRecorder(self.outbox, maximum_source_latency=LATENCY)
        self.submit(crossing(CrossingKind.OWNER_ENTRY, received=NOW + timedelta(milliseconds=100)))
        self.clock.at = NOW + timedelta(milliseconds=600)
        recorder(critical(at=NOW + timedelta(milliseconds=500)))
        # A database from before the split: one shared mark that also held a
        # later main-host dated health fact for the same camera.
        legacy = Database(self.database.path.with_name("legacy.sqlite3"))
        with closing(legacy.connect()) as db:
            migrate(db, APPLICATION_MIGRATIONS[:16])
            with closing(self.database.connect()) as current:
                rows = current.execute("SELECT id,kind,source,received,payload FROM presence_observations").fetchall()
            db.executemany("INSERT INTO presence_observations(id,kind,source,received,payload) "
                           "VALUES (?,?,?,?,?)", rows)
            db.execute("INSERT INTO presence_source_clock VALUES (?,?)",
                       (str(SOURCE), (NOW + timedelta(milliseconds=900)).isoformat(timespec="microseconds")))
            db.commit()
            migrate(db, APPLICATION_MIGRATIONS)
            marks = {table: [tuple(row) for row in db.execute(f"SELECT source,latest_occurred FROM {table}")]
                     for table in ("presence_source_clock", "presence_critical_source_clock")}
        self.assertEqual(marks, {
            "presence_source_clock": [(str(SOURCE), timestamp(NOW + timedelta(milliseconds=100)))],
            "presence_critical_source_clock": [(str(SOURCE), timestamp(NOW + timedelta(milliseconds=500)))],
        })

    def test_unavailable_database_location_keeps_fact_staged(self):
        missing = Path(tempfile.gettempdir()) / f"absent-{uuid4()}" / "synthetic.sqlite3"
        self.presence.database = Database(missing)
        self.submit(crossing(CrossingKind.OWNER_ENTRY))
        state = self.outbox.state()
        self.assertEqual((state.pending, state.rejected), (1, 0))
        self.presence.database = self.database
        self.assertEqual(self.outbox.flush().recorded, 1)
        self.assertEqual(self.state(), "PRESENT")

    def test_invalid_receipt_clock_during_flush_keeps_fact_staged(self):
        entry = crossing(CrossingKind.OWNER_ENTRY)
        self.clock.at = entry.received_at
        self.assertTrue(self.adapter.submit(TrackUpdate((), (entry,), DetectionQuality.SUFFICIENT)))
        # A transient clock-port fault is not an observation contract error.
        for fault in ((NOW.replace(tzinfo=None), True), (NOW, None)):
            self.clock.at, self.clock.trusted = fault
            state = self.outbox.flush()
            self.assertEqual((state.pending, state.rejected, state.recorded), (1, 0, 0))
        self.clock.at, self.clock.trusted = entry.received_at, True
        self.assertEqual(self.outbox.flush().recorded, 1)
        self.assertEqual(self.state(), "PRESENT")

    def test_contract_rejection_is_counted_and_does_not_block_later_facts(self):
        taken = crossing(CrossingKind.ANONYMOUS_ENTRY)
        self.submit(taken)
        conflicting = replace(taken, kind=CrossingKind.ANONYMOUS_EXIT)
        self.submit(conflicting, crossing(CrossingKind.OWNER_ENTRY))
        state = self.outbox.state()
        self.assertEqual((state.pending, state.rejected, state.recorded), (0, 1, 2))
        self.assertTrue(state.degraded)
        self.assertEqual(self.state(), "PRESENT")

    def test_conflicting_pending_uuid_is_rejected_not_deduplicated(self):
        self.refuse = True
        staged = crossing(CrossingKind.ANONYMOUS_ENTRY)
        self.assertEqual(self.submit(staged).pending, 1)
        # The same fact staged again, stamped later, stays one pending duplicate.
        self.clock.at = NOW + timedelta(seconds=1)
        self.assertTrue(self.adapter.submit(TrackUpdate((), (staged,), DetectionQuality.SUFFICIENT)))
        conflicting = replace(staged, kind=CrossingKind.ANONYMOUS_EXIT)
        self.assertFalse(self.adapter.submit(TrackUpdate((), (conflicting,), DetectionQuality.SUFFICIENT)))
        state = self.outbox.state()
        self.assertEqual((state.pending, state.rejected, state.refused), (1, 1, 0))
        self.refuse = False
        state = self.outbox.flush()
        # The gap stays visible after the first fact is written.
        self.assertEqual((state.recorded, state.pending, state.rejected), (1, 0, 1))
        self.assertTrue(state.degraded)
        item, = self.history()["items"]
        self.assertEqual(item["kind"], "anonymous_entry")


class OwnerTrackerEndToEndTests(PresenceFixture, TestCase):
    """Real tracker, quality gate and owner-verification service with synthetic frames."""
    setUp_owner = owner_fixtures.OwnerTests.setUp
    reservation = owner_fixtures.OwnerTests.reservation
    open_store = owner_fixtures.OwnerTests.open_store
    enroll = owner_fixtures.OwnerTests.enroll

    def setUp(self):
        self.setUp_owner()
        self.make_presence()
        self.adapter = EntranceObservationAdapter(self.outbox, source_id=SOURCE, owner_presence_validity=VALIDITY,
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
        gate, item = self.history()["items"]
        self.assertEqual((gate["kind"], gate["value"], gate["quality"]), ("entrance_gate", "ready", "sufficient"))
        self.assertEqual(item["kind"], "anonymous_entry")
        self.assertIsNone(item["confidence"])

    def test_entry_then_movement_then_camera_offline_is_neutral_and_critical_path_runs(self):
        self.walk()
        self.assertEqual(self.presence.snapshot(now=NOW, clock_trusted=True)["state"], "PRESENT")
        movement_at = NOW + timedelta(seconds=30)
        self.clock.at = movement_at
        delivery = CriticalDelivery(capacity=2, recorder=CriticalTimelineRecorder(
            self.outbox, maximum_source_latency=LATENCY))
        self.assertTrue(delivery.submit((critical(at=movement_at),)).available)
        offline_at = NOW + timedelta(seconds=45)
        self.clock.at = offline_at
        health = HealthTimeline(self.outbox)
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
                         [("entrance_gate", "ready"), ("owner_entry", "observed"), ("server_movement", "observed"),
                          ("camera_health", "offline")])
        self.assertTrue(all(item["source_id"] == str(SOURCE) for item in page["items"]))
        self.assertNeutral(page)
        with self.assertRaises(AccessDenied):
            self.history("live")


class CriticalRecorderTests(PresenceFixture, TestCase):
    def setUp(self):
        self.make_presence()
        self.recorder = CriticalTimelineRecorder(self.outbox, maximum_source_latency=LATENCY)

    def test_retry_after_refusal_is_stamped_at_write_and_queues_work_once(self):
        delivery = CriticalDelivery(capacity=2, recorder=self.recorder)
        item = critical(CriticalKind.CAMERA_TAMPER)
        self.refuse = True
        self.assertFalse(delivery.submit((item,)).available)
        self.refuse = False
        self.clock.at = NOW + timedelta(seconds=1)
        self.assertEqual(delivery.retry().accepted, (item.identifier,))
        stored, = self.history()["items"]
        # The refused write was rolled back, so presence received it at retry.
        self.assertEqual(stored["received_at"], self.clock.at.isoformat(timespec="microseconds"))
        self.assertTrue(stored["confirmed"])
        # A second delivery of the same UUID, stamped later, stays a duplicate.
        self.clock.at = NOW + timedelta(minutes=5)
        self.recorder(item)
        self.presence.dispatch_pending()
        self.assertEqual((len(self.evidence), len(self.notifications)), (1, 1))

    def test_replay_after_restart_or_committed_failure_is_a_duplicate_not_a_stuck_conflict(self):
        item = critical()
        presence = self.presence

        class CommitThenFail:
            """The write commits, then the caller sees a failure (e.g. a lost ack)."""
            def record(self, observation, **options):
                presence.record(observation, **options)
                raise RuntimeError("synthetic failure after commit")

        failing = TimelineOutbox(CommitThenFail(), clock=self.clock, capacity=1)
        delivery = CriticalDelivery(capacity=2, recorder=CriticalTimelineRecorder(
            failing, maximum_source_latency=LATENCY))
        self.assertFalse(delivery.submit((item,)).available)
        # A restarted process has no in-memory receipt; the durable row decides.
        self.clock.at = NOW + timedelta(hours=1)
        restarted = CriticalDelivery(capacity=2, recorder=CriticalTimelineRecorder(
            self.outbox, maximum_source_latency=LATENCY))
        self.assertTrue(restarted.submit((item,)).available)
        self.assertEqual(len(self.history()["items"]), 1)
        self.presence.dispatch_pending()
        self.assertEqual((len(self.evidence), len(self.notifications)), (1, 1))
        # A different fact reusing the UUID is still an identity conflict.
        with self.assertRaisesRegex(ValueError, "identity conflict"):
            self.recorder(replace(item, kind=CriticalKind.CAMERA_TAMPER))

    def test_confirmed_delivery_of_a_stored_unconfirmed_critical_fact_queues_work_once(self):
        item = critical(CriticalKind.CAMERA_TAMPER)
        unconfirmed = self.recorder.observation(item, NOW, True)
        self.presence.record(replace(unconfirmed, confirmed=False))
        self.presence.dispatch_pending()
        self.assertEqual(self.evidence, [])
        self.clock.at = NOW + timedelta(seconds=1)
        self.recorder(item)
        stored, = self.history()["items"]
        self.assertTrue(stored["confirmed"])
        # The first receipt is kept; confirmation only adds the critical work.
        self.assertEqual(stored["received_at"], NOW.isoformat(timespec="microseconds"))
        self.clock.at = NOW + timedelta(minutes=5)
        self.recorder(item)
        self.presence.record(replace(unconfirmed, confirmed=False), restamped=True)
        self.assertTrue(self.history()["items"][0]["confirmed"])
        self.presence.dispatch_pending()
        self.assertEqual((len(self.evidence), len(self.notifications)), (1, 1))
        # A different fact under the same UUID still conflicts.
        with self.assertRaisesRegex(ValueError, "identity conflict"):
            self.recorder(replace(item, kind=CriticalKind.SERVER_MOVEMENT))

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

    def test_unconfirmed_or_insufficient_quality_is_refused_and_storage_refusal_raises(self):
        for item in (critical(confirmed=False), critical(quality=DetectionQuality.DEGRADED)):
            with self.assertRaises(ValueError):
                self.recorder(item)
        self.refuse = True
        with self.assertRaises(RuntimeError):
            self.recorder(critical())
        self.assertEqual(self.history()["items"], [])
        with self.assertRaises(ValueError):
            CriticalTimelineRecorder(self.presence, maximum_source_latency=LATENCY)


class HealthTimelineTests(PresenceFixture, TestCase):
    def setUp(self):
        self.make_presence()
        self.health = HealthTimeline(self.outbox)

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
            self.outbox.stage(uuid4(), replace(critical(), confirmed=True))
        # Critical work is recorded synchronously and is never deferred here.
        recorder = CriticalTimelineRecorder(self.outbox, maximum_source_latency=LATENCY)
        item = critical()
        with self.assertRaises(ValueError):
            self.outbox.stage(item.identifier, lambda received, trusted: (
                recorder.observation(item, received, trusted), None))
        self.assertEqual(self.outbox.state().pending, 0)
        for options in ({"clock": self.clock, "capacity": 0}, {"capacity": 1}):
            with self.assertRaises((TypeError, ValueError)):
                TimelineOutbox(self.presence, **options)
        # A health fact can never carry an Owner presence effect.
        fact = self.outbox
        node = HealthTimeline(fact)
        node.node(NODE, NodeHealthState.ONLINE)
        identifier, build, _, _ = fact._pending[0]
        observation, valid_until = build(NOW, True)
        self.assertIsNone(valid_until)
        self.assertEqual(observation.identifier, identifier)
        self.assertIs(observation.kind, Kind.NODE_HEALTH)
        self.assertIs(observation.value, Value.ONLINE)
        self.assertIs(observation.quality, Quality.UNKNOWN)
        with self.assertRaises(ValueError):
            fact.stage(uuid4(), lambda received, trusted: (
                replace(observation, identifier=UUID(int=5), received_at=received), received + VALIDITY))
        fact.flush()
        self.assertEqual(self.presence.snapshot(now=NOW, clock_trusted=True)["state"],
                         PresenceState.UNKNOWN.value)


class TimelineGapDurabilityTests(PresenceFixture, TestCase):
    """A known or possible timeline loss survives a restart until the Owner clears it."""

    def setUp(self):
        self.make_presence()
        self.health = HealthTimeline(self.outbox)

    def restart(self):
        # A new process: new service and outbox over the same database, and no
        # in-memory state carried over. The old process is gone, so the kernel
        # released its session lock; its durable rows stay as they were.
        if self.outbox._handle is not None:
            self.outbox._handle.release()
        self.presence = PresenceService(self.database, access=MockAccess(), evidence=self.presence.evidence,
                                        notifications=self.presence.notifications,
                                        reservation=self.presence.reservation,
                                        detection=lambda: True, storage_status=lambda: True)
        self.outbox = TimelineOutbox(self.presence, clock=self.clock, capacity=8)
        self.health = HealthTimeline(self.outbox)
        self.outbox.open()
        return self.outbox.flush()

    def gap(self):
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        return status["timeline_gap"], status["timeline_gap_detail"]

    def fill_and_refuse(self):
        for _ in range(8):
            self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.assertFalse(self.health.node(NODE, NodeHealthState.ONLINE))

    def test_refused_fact_stays_degraded_after_restart(self):
        self.fill_and_refuse()
        self.assertTrue(self.outbox.flush().degraded)
        self.outbox.close()
        state = self.restart()
        self.assertEqual((state.refused, state.rejected, state.pending), (0, 0, 0))
        self.assertTrue(state.degraded)
        self.assertTrue(state.gap)
        present, detail = self.gap()
        self.assertTrue(present)
        self.assertEqual((detail["refused"], detail["lost"], detail["interrupted"]), (1, 0, 0))

    def test_restart_without_clean_close_is_an_interrupted_gap(self):
        self.assertFalse(self.outbox.flush().degraded)
        self.refuse = True
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.assertEqual(self.outbox.flush().pending, 1)
        self.refuse = False
        # The process dies: the staged fact is gone with it.
        state = self.restart()
        self.assertTrue(state.degraded)
        self.assertEqual(self.gap()[1]["interrupted"], 1)
        self.assertEqual(self.history()["items"], [])

    def test_clean_close_without_loss_restarts_healthy(self):
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.assertEqual(self.outbox.flush().recorded, 1)
        self.outbox.close()
        state = self.restart()
        self.assertFalse(state.degraded)
        self.assertEqual(self.gap(), (False, None))

    def test_close_records_still_staged_facts_as_lost_and_refuses_later_staging(self):
        self.outbox.flush()
        self.refuse = True
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.outbox.flush()
        self.refuse = False
        self.outbox.close()
        with self.assertRaises(RuntimeError):
            self.health.node(NODE, NodeHealthState.ONLINE)
        with self.assertRaises(RuntimeError):
            self.outbox.flush()
        self.restart()
        detail = self.gap()[1]
        self.assertEqual((detail["lost"], detail["interrupted"]), (1, 0))

    def test_failed_close_keeps_the_session_so_restart_is_interrupted(self):
        self.outbox.flush()
        self.refuse = True
        with self.assertRaises(RuntimeError):
            self.outbox.close()
        self.refuse = False
        # The row is proven to stay, so staging and a retried close reopen.
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.assertTrue(self.restart().degraded)
        self.assertEqual(self.gap()[1]["interrupted"], 1)

    def fail_after_commit(self):
        """Reservations whose release raises after the transaction committed."""
        reservation = self.presence.reservation

        @contextmanager
        def failing():
            with reservation():
                yield
            raise RuntimeError("synthetic release failure after commit")

        self.presence.reservation = failing
        return reservation

    def test_close_that_committed_then_failed_keeps_the_outbox_closed(self):
        self.outbox.flush()
        reservation = self.fail_after_commit()
        with self.assertRaisesRegex(RuntimeError, "after commit"):
            self.outbox.close()
        self.presence.reservation = reservation
        # The session row is gone, so a fact accepted now could vanish on a
        # crash with nothing for the next start to mark as interrupted.
        with self.assertRaises(RuntimeError):
            self.health.node(NODE, NodeHealthState.OFFLINE)
        with self.assertRaises(RuntimeError):
            self.outbox.flush()
        self.assertFalse(self.outbox.state().session)
        self.assertEqual(self.outbox.close().pending, 0)
        # The committed close released its session lock for the next start.
        state = self.restart()
        self.assertFalse(state.degraded)
        self.assertEqual(self.gap(), (False, None))

    def test_close_with_an_unreadable_outcome_stays_closed_and_can_be_retried(self):
        self.outbox.flush()
        reservation = self.fail_after_commit()
        with mock.patch.object(self.presence, "timeline_session_recorded",
                               side_effect=RuntimeError("unreadable")):
            with self.assertRaisesRegex(RuntimeError, "after commit"):
                self.outbox.close()
        self.presence.reservation = reservation
        with self.assertRaises(RuntimeError):
            self.health.node(NODE, NodeHealthState.OFFLINE)
        self.assertTrue(self.outbox.state().session)
        # The retry finds the row already gone: never a clean close.
        self.assertFalse(self.outbox.close().session)
        self.assertTrue(self.restart().degraded)
        self.assertEqual(self.gap()[1]["interrupted"], 1)

    def test_pending_backlog_degrades_owner_status_without_counting_loss(self):
        self.assertFalse(self.outbox.flush().degraded)
        self.refuse = True
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.assertTrue(self.health.node(NODE, NodeHealthState.ONLINE))
        # A transient storage refusal stops the flush with the facts staged.
        state = self.outbox.flush()
        self.assertEqual((state.pending, state.unpersisted), (2, 0))
        self.refuse = False
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertTrue(status["timeline_pending"])
        self.assertEqual(status["timeline_pending_count"], 2)
        # Staged facts are not loss: no gap is reported or recorded for them.
        self.assertFalse(status["timeline_gap"])
        self.assertEqual(status["timeline_gap_unpersisted"], 0)
        self.assertIsNone(status["timeline_gap_detail"])
        self.assertEqual(self.outbox.flush().recorded, 2)
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual((status["timeline_pending"], status["timeline_pending_count"]), (False, 0))
        self.assertFalse(status["timeline_gap"])

    def test_pending_backlog_is_read_with_loss_in_one_step(self):
        # A staged fact rejected between two separate reads would be seen in
        # neither count; the backlog reader returns both under one lock.
        self.outbox.flush()
        self.refuse = True
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.outbox.flush()
        self.refuse = False
        session = self.outbox._handle
        session.unpersisted = mock.Mock(side_effect=AssertionError("read separately"))
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual((status["timeline_pending_count"], status["timeline_gap_unpersisted"]), (1, 0))

    def test_unreadable_backlog_is_never_reported_empty(self):
        self.outbox._handle.backlog = mock.Mock(side_effect=RuntimeError("unreadable"))
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertTrue(status["timeline_pending"])
        self.assertTrue(status["timeline_gap"])

    def test_pending_backlog_leaves_owner_status_after_a_clean_close(self):
        self.outbox.flush()
        self.refuse = True
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.outbox.flush()
        self.refuse = False
        self.outbox.close()
        # Close turned the staged fact into recorded loss; it is not also pending.
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual((status["timeline_pending"], status["timeline_pending_count"]), (False, 0))
        self.assertTrue(status["timeline_gap"])
        self.assertEqual(status["timeline_gap_detail"]["lost"], 1)

    def test_unpersisted_count_stays_visible_until_written(self):
        self.outbox.flush()
        self.refuse = True
        self.fill_and_refuse()
        state = self.outbox.flush()
        self.assertEqual((state.pending, state.unpersisted), (8, 1))
        self.assertTrue(state.degraded)
        self.assertEqual(self.gap(), (True, None))  # counted loss is a gap before it lands
        self.refuse = False
        state = self.outbox.flush()
        self.assertEqual((state.pending, state.unpersisted), (0, 0))
        self.assertEqual(self.gap()[1]["refused"], 1)

    def test_staging_is_refused_until_a_durable_session_is_open(self):
        self.outbox.close()
        outbox = TimelineOutbox(self.presence, clock=self.clock, capacity=8)
        health = HealthTimeline(outbox)
        self.assertFalse(outbox.state().session)
        self.assertTrue(outbox.state().degraded)
        with self.assertRaises(RuntimeError):
            health.node(NODE, NodeHealthState.OFFLINE)
        self.refuse = True
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            outbox.open()
        with self.assertRaises(RuntimeError):
            health.node(NODE, NodeHealthState.OFFLINE)
        self.refuse = False
        self.assertEqual(outbox.state().pending, 0)

    def test_process_exit_before_the_first_flush_is_an_interrupted_gap(self):
        # The session is opened at startup, so facts staged and never flushed
        # are found by the next start even though no write ever happened.
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        state = self.restart()
        self.assertTrue(state.degraded)
        self.assertEqual(self.gap()[1]["interrupted"], 1)

    def fresh_service(self):
        return PresenceService(self.database, access=MockAccess(), evidence=self.presence.evidence,
                               notifications=self.presence.notifications,
                               reservation=self.presence.reservation,
                               detection=lambda: True, storage_status=lambda: True)

    def test_stale_session_is_a_gap_before_a_replacement_opens(self):
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        # The process dies without a clean close and the next start cannot
        # open its replacement session: the stale row is never converted.
        self.outbox._handle.release()
        self.presence = self.fresh_service()
        self.outbox = TimelineOutbox(self.presence, clock=self.clock, capacity=8)
        self.refuse = True
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            self.outbox.open()
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertTrue(status["timeline_gap"])
        self.assertIsNone(status["timeline_gap_detail"])
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 1)
        # Once the replacement opens, the row becomes the durable marker.
        self.refuse = False
        self.outbox.open()
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertTrue(status["timeline_gap"])
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 0)
        self.assertEqual(status["timeline_gap_detail"]["interrupted"], 1)

    def test_a_live_session_elsewhere_is_not_an_orphan(self):
        # A status reader without its own session sees the row of the outbox
        # that holds the session lock; that outbox is live, nothing is lost.
        status = self.fresh_service().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 0)
        self.assertFalse(status["timeline_gap"])
        # Released without a clean close, the same row is an orphan.
        self.outbox._handle.release()
        status = self.fresh_service().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 1)
        self.assertTrue(status["timeline_gap"])

    def replacement_open_observed(self, *, fail):
        """Open a replacement session, reading status from another service mid-open.

        The status read happens inside the open transaction, after the session
        mutex is taken and the stale rows are converted but before commit.
        """
        replacement = self.fresh_service()
        original, seen = replacement._gap, []

        def gap(db):
            seen.append(self.fresh_service().owner_status("owner", now=NOW, clock_trusted=True))
            if fail:
                raise RuntimeError("synthetic open failure")
            return original(db)
        replacement._gap = gap
        outbox = TimelineOutbox(replacement, clock=self.clock, capacity=8)
        if fail:
            with self.assertRaisesRegex(RuntimeError, "synthetic open failure"):
                outbox.open()
        else:
            outbox.open()
            self.addCleanup(lambda: outbox._handle and outbox._handle.release())
        self.assertEqual(len(seen), 1)
        return seen[0]

    def test_an_open_in_flight_elsewhere_does_not_hide_stale_rows(self):
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.outbox._handle.release()
        # A replacement that holds the session mutex but has not committed
        # has not converted the stale row: it stays reported, and stays so
        # when that open rolls back.
        status = self.replacement_open_observed(fail=True)
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 1)
        self.assertTrue(status["timeline_gap"])
        status = self.fresh_service().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 1)
        self.assertIsNone(status["timeline_gap_detail"])
        status = self.replacement_open_observed(fail=False)
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 1)
        self.assertTrue(status["timeline_gap"])
        # Once committed, the live replacement owns its row and the stale one
        # is in the durable marker.
        status = self.fresh_service().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 0)
        self.assertEqual(status["timeline_gap_detail"]["interrupted"], 1)

    def test_clean_close_leaves_no_orphan_for_a_service_without_a_session(self):
        self.outbox.close()
        status = self.fresh_service().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 0)
        self.assertFalse(status["timeline_gap"])

    def test_repeated_close_returns_without_blocking(self):
        self.outbox.close()
        worker = threading.Thread(target=self.outbox.close, daemon=True)
        worker.start()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        with self.assertRaises(RuntimeError):
            self.outbox.open()

    def test_unreadable_marker_is_never_healthy(self):
        self.assertFalse(self.outbox.flush().degraded)
        missing = Path(tempfile.gettempdir()) / f"absent-{uuid4()}" / "synthetic.sqlite3"
        self.presence.database = Database(missing)
        state = self.outbox.flush()
        self.assertIsNone(state.gap)
        self.assertTrue(state.degraded)

    def test_only_the_owner_clears_the_gap_and_the_clear_is_audited(self):
        self.outbox.flush()
        self.restart()  # the first outbox never closed: interrupted
        with self.assertRaises(AccessDenied):
            self.presence.clear_timeline_gap("recordings", now=NOW, clock_trusted=True)
        with self.assertRaises(ValueError):
            self.presence.clear_timeline_gap("owner", now=NOW, clock_trusted=False)
        self.assertTrue(self.gap()[0])
        cleared = self.presence.clear_timeline_gap("owner", now=NOW, clock_trusted=True)
        self.assertEqual(cleared["interrupted"], 1)
        self.assertEqual(self.gap(), (False, None))
        self.assertFalse(self.outbox.flush().degraded)
        entry = self.presence.audit("owner")[-1]
        self.assertEqual((entry["action"], entry["actor"]), ("timeline_gap_cleared", str(OWNER)))
        self.assertEqual(entry["target"], "refused=0,rejected=0,lost=0,interrupted=1")
        with self.assertRaises(ValueError):
            self.presence.clear_timeline_gap("owner", now=NOW, clock_trusted=True)

    def hold_committed_probe(self):
        # A status read in another process: a shared probe on the committed lock.
        committed = self.database.path.with_name(self.database.path.name + ".timeline-session.committed.lock")
        descriptor = os.open(committed, os.O_RDONLY)
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return descriptor

    def test_concurrent_status_probe_does_not_fail_a_clean_open(self):
        self.outbox.close()
        probe = self.hold_committed_probe()
        timer = threading.Timer(0.05, os.close, (probe,))
        timer.start()
        self.addCleanup(timer.join)
        state = self.restart()
        self.assertTrue(self.outbox.state().session)
        self.assertFalse(state.degraded)
        self.assertEqual(self.gap(), (False, None))

    def test_committed_lock_held_beyond_the_wait_fails_the_open(self):
        self.outbox.close()
        probe = self.hold_committed_probe()
        self.addCleanup(os.close, probe)
        with mock.patch("app.presence.service.COMMITTED_LOCK_WAIT", 0.05):
            with self.assertRaisesRegex(RuntimeError, "committed-session lock"):
                self.restart()
        self.assertFalse(self.outbox.state().session)

    def test_refused_open_creates_no_lock_file(self):
        # Under STORAGE_HARD_STOP an outbox start writes nothing at all, not
        # even the session lock file that sits beside the database.
        self.outbox.close()
        lock = self.database.path.with_name(self.database.path.name + ".timeline-session.lock")
        committed = self.database.path.with_name(self.database.path.name + ".timeline-session.committed.lock")
        lock.unlink()
        committed.unlink()
        outbox = TimelineOutbox(self.presence, clock=self.clock, capacity=8)
        self.refuse = True
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            outbox.open()
        self.assertFalse(lock.exists())
        self.assertFalse(committed.exists())
        self.assertFalse(outbox.state().session)
        self.refuse = False
        outbox.open()
        self.addCleanup(lambda: outbox._handle and outbox._handle.release())
        self.assertTrue(lock.exists())
        self.assertTrue(committed.exists())
        self.assertTrue(outbox.state().session)

    def test_lock_file_is_created_while_the_reservation_is_held(self):
        self.outbox.close()
        lock = self.database.path.with_name(self.database.path.name + ".timeline-session.lock")
        lock.unlink()
        seen = []

        @contextmanager
        def recording():
            seen.append(("enter", lock.exists()))
            yield
            seen.append(("exit", lock.exists()))
        self.presence.reservation = recording
        outbox = TimelineOutbox(self.presence, clock=self.clock, capacity=8)
        outbox.open()
        self.addCleanup(lambda: outbox._handle and outbox._handle.release())
        self.assertEqual(seen[:2], [("enter", False), ("exit", True)])

    def test_gap_read_never_creates_a_missing_database(self):
        missing = self.database.path.with_name("absent.sqlite3")
        self.presence.database = Database(missing)
        with self.assertRaises(sqlite3.OperationalError):
            self.presence.timeline_gap()
        self.assertFalse(missing.exists())
        self.assertIsNone(self.outbox.flush().gap)

    def test_gap_read_opens_without_create_semantics(self):
        # The database vanishing between any existence check and the open
        # must not let the read-only check create it: the open itself fails.
        missing = self.database.path.with_name("vanished.sqlite3")
        self.presence.database = Database(missing)
        with mock.patch.object(Path, "is_file", return_value=True):
            with self.assertRaises(Exception):
                self.presence.timeline_gap()
        self.assertFalse(missing.exists())

    def test_status_and_history_reads_never_create_a_missing_database(self):
        missing = self.database.path.with_name("absent-status.sqlite3")
        self.presence.database = Database(missing)
        for read in (lambda: self.presence.snapshot(now=NOW, clock_trusted=True),
                     lambda: self.presence.audit("owner"), self.history):
            with self.assertRaises(sqlite3.OperationalError):
                read()
            self.assertFalse(missing.exists())

    def test_unpersisted_loss_is_a_gap_and_refuses_the_clear(self):
        self.outbox.flush()
        self.restart()  # interrupted: a durable marker the Owner may clear
        self.refuse = True
        self.fill_and_refuse()
        self.assertEqual(self.outbox.flush().unpersisted, 1)
        self.refuse = False
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertTrue(status["timeline_gap"])
        self.assertEqual(status["timeline_gap_unpersisted"], 1)
        with self.assertRaisesRegex(ValueError, "unpersisted"):
            self.presence.clear_timeline_gap("owner", now=NOW, clock_trusted=True)
        self.assertEqual(self.gap()[1]["interrupted"], 1)
        # Once the outbox writes the loss, the Owner can accept all of it.
        self.assertEqual(self.outbox.flush().unpersisted, 0)
        cleared = self.presence.clear_timeline_gap("owner", now=NOW, clock_trusted=True)
        self.assertEqual((cleared["refused"], cleared["interrupted"]), (1, 1))
        self.assertEqual(self.gap(), (False, None))

    def test_loss_counted_after_a_clear_keeps_status_degraded(self):
        self.outbox.flush()
        self.restart()
        self.presence.clear_timeline_gap("owner", now=NOW, clock_trusted=True)
        self.refuse = True
        self.fill_and_refuse()
        # The durable write is refused, yet status never reads healthy.
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.refuse = False
        self.assertTrue(status["timeline_gap"])
        self.assertIsNone(status["timeline_gap_detail"])
        self.assertEqual(status["timeline_gap_unpersisted"], 1)

    def count_one_refusal(self):
        # A clock fault at handoff: counted as refused, nothing staged.
        self.outbox.flush()
        self.clock.trusted = None
        self.assertFalse(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.clock.trusted = True
        state = self.outbox.state()
        self.assertEqual((state.pending, state.unpersisted, state.gap), (0, 1, False))

    def test_outbox_state_never_reads_healthy_while_loss_moves_to_the_marker(self):
        self.count_one_refusal()
        outbox, seen = self.outbox, []

        class Observing:
            # After every release of the outbox lock, poll state() the way a
            # concurrent status reader could.
            def __init__(self, inner):
                self.inner, self.polling = inner, False

            def __enter__(self):
                return self.inner.__enter__()

            def __exit__(self, *failure):
                self.inner.__exit__(*failure)
                if not self.polling:
                    self.polling = True
                    try:
                        seen.append(outbox.state().degraded)
                    finally:
                        self.polling = False
        outbox._lock = Observing(outbox._lock)
        state = outbox.flush()
        self.assertTrue(state.degraded)
        self.assertTrue(state.gap)
        self.assertTrue(seen)
        self.assertTrue(all(seen), seen)

    def test_status_never_reads_healthy_while_loss_moves_to_the_marker(self):
        self.count_one_refusal()
        original, fired = self.presence._gap, []

        def gap(db):
            result = original(db)
            if not fired and result is None:
                # The outbox persists its count while the status read is in
                # progress. The read holds its read transaction (#151), so the
                # flush commits as soon as that read ends.
                flush = threading.Thread(target=self.outbox.flush)
                fired.append(flush)
                flush.start()
            return result
        self.presence._gap = gap
        status = self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        self.assertTrue(fired)
        fired[0].join(30)
        self.assertFalse(fired[0].is_alive())
        self.assertTrue(status["timeline_gap"])
        del self.presence._gap
        self.assertEqual(self.gap()[1]["refused"], 1)

    def test_a_second_outbox_is_refused_while_the_first_is_open(self):
        second = TimelineOutbox(self.presence, clock=self.clock, capacity=8)
        with self.assertRaisesRegex(RuntimeError, "another timeline outbox"):
            second.open()
        # A refused open neither replaces the live session nor records a gap.
        self.assertEqual(self.gap(), (False, None))
        self.outbox.close()
        second.open()
        self.assertEqual(self.gap(), (False, None))
        # The second outbox now crashes; its own session row is still there.
        self.outbox = second
        self.assertTrue(self.restart().degraded)
        self.assertEqual(self.gap()[1]["interrupted"], 1)

    def test_clock_fault_before_staging_is_a_counted_gap(self):
        adapter = EntranceObservationAdapter(self.outbox, source_id=SOURCE, owner_presence_validity=VALIDITY,
                                             maximum_source_latency=LATENCY)

        def failing():
            raise OSError("synthetic clock port fault")
        for fault in ((NOW.replace(tzinfo=None), True), (NOW, None)):
            self.clock.at, self.clock.trusted = fault
            self.assertFalse(self.health.camera(HealthEvent(SOURCE, CameraState.OFFLINE, "synthetic")))
        self.outbox.clock = failing
        self.assertFalse(adapter.submit(TrackUpdate((), (crossing(CrossingKind.ANONYMOUS_ENTRY),),
                                                    DetectionQuality.SUFFICIENT)))
        self.assertFalse(self.health.node(NODE, NodeHealthState.OFFLINE))
        state = self.outbox.state()
        # The crossing and the gate-quality change it carried are both refused.
        self.assertEqual((state.refused, state.unpersisted, state.pending), (5, 5, 0))
        self.assertTrue(state.degraded)
        self.outbox.clock = self.clock
        self.clock.at, self.clock.trusted = NOW, True
        self.assertTrue(self.outbox.flush().degraded)
        self.assertEqual(self.gap()[1]["refused"], 5)


class EntranceGateQualityTests(PresenceFixture, TestCase):
    """Low-quality entrance periods stay distinguishable from periods with no crossing (#129)."""

    def setUp(self):
        self.make_presence()
        self.adapter = EntranceObservationAdapter(self.outbox, source_id=SOURCE, owner_presence_validity=VALIDITY,
                                                  maximum_source_latency=LATENCY)

    def gate_facts(self):
        return [(item["value"], item["quality"]) for item in self.history()["items"]
                if item["kind"] == "entrance_gate"]

    def update(self, quality, *crossings, at):
        self.clock.at = at
        result = self.adapter.submit(TrackUpdate((), crossings, quality))
        self.outbox.flush()
        return result

    def test_gate_quality_changes_are_neutral_timeline_facts(self):
        for minute, quality in enumerate((DetectionQuality.SUFFICIENT, DetectionQuality.SUFFICIENT,
                                          DetectionQuality.UNKNOWN, DetectionQuality.UNKNOWN,
                                          DetectionQuality.DEGRADED, DetectionQuality.INSUFFICIENT,
                                          DetectionQuality.SUFFICIENT)):
            self.assertTrue(self.update(quality, at=NOW + timedelta(minutes=minute)))
        # Only changes are recorded: ready, unknown (unknown), unknown
        # (insufficient, for degraded and insufficient alike), ready.
        self.assertEqual(self.gate_facts(), [("ready", "sufficient"), ("unknown", "unknown"),
                                             ("unknown", "insufficient"), ("ready", "sufficient")])
        page = self.history()
        self.assertNeutral(page)
        for item in page["items"]:
            self.assertEqual(item["source_id"], str(SOURCE))
            self.assertIsNone(item["confidence"])
            self.assertFalse(item["confirmed"])
            self.assertEqual(item["label"], "Entrance gate quality")
        # A gate fact is never a person, absence or presence conclusion.
        self.assertFalse(any(item["value"] in {"observed", "not_observed"} for item in page["items"]))
        self.assertEqual(self.presence.snapshot(now=NOW + timedelta(minutes=10), clock_trusted=True)["state"],
                         "UNKNOWN")
        with self.assertRaises(AccessDenied):
            self.history("live")

    def test_unknown_interval_brackets_the_period_without_conclusions(self):
        self.assertTrue(self.update(DetectionQuality.SUFFICIENT, crossing(CrossingKind.ANONYMOUS_ENTRY), at=NOW))
        self.assertTrue(self.update(DetectionQuality.UNKNOWN, at=NOW + timedelta(minutes=1)))
        later = NOW + timedelta(minutes=5)
        self.assertTrue(self.update(DetectionQuality.SUFFICIENT,
                                    crossing(CrossingKind.ANONYMOUS_EXIT, received=later), at=later))
        self.assertEqual([(item["kind"], item["value"]) for item in self.history()["items"]],
                         [("entrance_gate", "ready"), ("anonymous_entry", "observed"),
                          ("entrance_gate", "unknown"), ("entrance_gate", "ready"),
                          ("anonymous_exit", "observed")])

    def test_stopped_updates_are_recorded_as_unknown_once(self):
        self.assertTrue(self.update(DetectionQuality.SUFFICIENT, at=NOW))
        self.clock.at = NOW + timedelta(minutes=1)
        self.assertTrue(self.adapter.gate_unavailable())
        self.assertTrue(self.adapter.gate_unavailable())
        self.outbox.flush()
        self.assertEqual(self.gate_facts(), [("ready", "sufficient"), ("unknown", "unknown")])

    def test_refused_gate_fact_is_retried_by_the_next_update(self):
        self.clock.trusted = None  # the clock port fails the handoff
        self.assertFalse(self.adapter.submit(TrackUpdate((), (), DetectionQuality.UNKNOWN)))
        self.clock.trusted = True
        self.assertTrue(self.update(DetectionQuality.UNKNOWN, at=NOW))
        self.assertEqual(self.gate_facts(), [("unknown", "unknown")])
        self.assertEqual(self.outbox.state().refused, 1)

    def test_gate_fact_contract_is_ready_or_unknown_only(self):
        for value, quality in ((Value.READY, Quality.INSUFFICIENT), (Value.UNKNOWN, Quality.SUFFICIENT),
                               (Value.NOT_OBSERVED, Quality.UNKNOWN), (Value.OBSERVED, Quality.SUFFICIENT)):
            with self.assertRaises(InvalidObservation):
                Observation(Kind.ENTRANCE_GATE, NOW, NOW, value=value, quality=quality, source_id=SOURCE)
        with self.assertRaises(InvalidObservation):
            Observation(Kind.ENTRANCE_GATE, NOW, NOW, value=Value.READY, quality=Quality.SUFFICIENT)
        with self.assertRaises(ValueError):
            EntranceObservationAdapter(self.outbox, source_id=None, owner_presence_validity=VALIDITY,
                                       maximum_source_latency=LATENCY)


class OwnerTrackerGateTests(PresenceFixture, TestCase):
    """A real stopped entrance gate is recorded as unknown, never as an empty entrance."""

    def setUp(self):
        self.make_presence()
        self.adapter = EntranceObservationAdapter(self.outbox, source_id=SOURCE, owner_presence_validity=VALIDITY,
                                                  maximum_source_latency=LATENCY)

    def test_stopped_entrance_gate_is_unknown_not_an_empty_entrance(self):
        tracker = AnonymousEntranceTracker(SOURCE, POLICY, LINE)
        gate = QualityGate(SOURCE, calibrated_policy("entrance_crossing"))
        assess(gate, synthetic_person(0))
        gate.invalidate(execution=Execution.STOPPED)
        sample = synthetic_person(1)
        update = tracker.update(FrameIdentity.from_frame(sample), (), gate=gate,
                                decision=assess(gate, sample), observed_ms=10, occurred_at=NOW,
                                received_at=NOW, clock_trusted=True, uncertainty_us=0)
        self.assertIs(update.quality, DetectionQuality.UNKNOWN)
        self.assertTrue(self.adapter.submit(update))
        self.outbox.flush()
        item, = self.history()["items"]
        self.assertEqual((item["kind"], item["value"], item["quality"]), ("entrance_gate", "unknown", "unknown"))


OTHER_PROCESS_WRITE = """
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1], timeout=0, isolation_level=None)
try:
    connection.execute("BEGIN IMMEDIATE")
except sqlite3.OperationalError:
    print("locked")
else:
    connection.execute("ROLLBACK")
    print("acquired")
"""


# Opens the database now, and tries to take RESERVED once told to.
OTHER_PROCESS_LATER_WRITE = """
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1], timeout=0, isolation_level=None)
connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
print("ready", flush=True)
sys.stdin.readline()
try:
    connection.execute("BEGIN IMMEDIATE")
except sqlite3.OperationalError:
    print("locked", flush=True)
else:
    connection.execute("ROLLBACK")
    print("acquired", flush=True)
"""


def other_process_begin_immediate(path):
    """Whether a separate process can take RESERVED on ``path`` right now."""
    return subprocess.run([sys.executable, "-I", "-c", OTHER_PROCESS_WRITE, os.fspath(path)],
                          capture_output=True, text=True, check=True, timeout=30).stdout.strip()


class DatabaseLockTests(TestCase):
    """App-level database file handling never drops this process's SQLite locks (#129)."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Database(Path(directory.name) / "locks.sqlite3")
        with closing(self.database.connect()) as db:
            db.execute("CREATE TABLE t (x)")
        self.writer = sqlite3.connect(self.database.path, isolation_level=None)
        self.addCleanup(self.writer.close)
        self.writer.execute("BEGIN IMMEDIATE")
        self.assertEqual(other_process_begin_immediate(self.database.path), "locked")

    def test_pin_and_release_keep_the_writer_lock(self):
        pinned = PinnedDatabase(self.database)
        pinned.pin()
        with closing(pinned.connect_read_only()) as db:
            db.execute("SELECT count(*) FROM t").fetchone()
        pinned.pin()
        pinned.release()
        self.assertFalse(pinned.pinned)
        self.assertEqual(other_process_begin_immediate(self.database.path), "locked")

    def test_refused_pin_keeps_the_writer_lock(self):
        pinned = PinnedDatabase(self.database)
        with mock.patch.object(PinnedDatabase, "_path_identity", side_effect=ValueError("synthetic")):
            with self.assertRaises(ValueError):
                pinned.pin()
        self.assertEqual(other_process_begin_immediate(self.database.path), "locked")

    def test_replaced_database_keeps_the_old_file_writer_lock(self):
        # Another process already has the old file open. The path is then
        # unlinked and a new database created there; holding or probing the
        # new file must not close this process's descriptor on the old inode,
        # which would drop the in-process writer's lock on it.
        self.assertIsNotNone(read_database_prefix(self.database.path, 20))
        child = subprocess.Popen([sys.executable, "-I", "-c", OTHER_PROCESS_LATER_WRITE,
                                  os.fspath(self.database.path)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(child.wait, 30)
        self.addCleanup(child.kill)
        self.assertEqual(child.stdout.readline().strip(), "ready")
        os.unlink(self.database.path)
        with closing(self.database.connect()) as db:
            db.execute("CREATE TABLE replacement (x)")
        self.assertIsNotNone(read_database_prefix(self.database.path, 20))
        pinned = PinnedDatabase(self.database)
        pinned.pin()
        pinned.release()
        child.stdin.write("go\n")
        child.stdin.flush()
        self.assertEqual(child.stdout.readline().strip(), "locked")

    def test_connecting_to_an_existing_database_keeps_the_writer_lock(self):
        with closing(self.database.connect()) as db:
            db.execute("SELECT count(*) FROM t").fetchone()
        self.assertEqual(other_process_begin_immediate(self.database.path), "locked")


class WalReadTests(PresenceFixture, TestCase):
    """Status and history reads never create WAL sidecars outside a reservation (#129)."""

    def setUp(self):
        self.make_presence()
        self.entered = []
        refuse = self.presence.reservation

        @contextmanager
        def reservation():
            self.entered.append(self.sidecars())
            with refuse():
                yield
        self.presence.reservation = reservation
        with closing(sqlite3.connect(self.database.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        # The last connection to close removed both sidecars.
        self.assertEqual(self.sidecars(), [])

    def sidecars(self):
        return sorted(suffix for suffix in ("-wal", "-shm")
                      if self.database.path.with_name(self.database.path.name + suffix).exists())

    def reads(self):
        return (self.presence.timeline_gap, lambda: self.presence.snapshot(now=NOW, clock_trusted=True),
                lambda: self.presence.audit("owner"), self.history,
                lambda: self.presence.timeline_session_recorded(self.outbox._handle))

    def test_refused_reservation_refuses_the_read_and_creates_no_sidecar(self):
        self.refuse = True
        for read in self.reads():
            with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
                read()
            self.assertEqual(self.sidecars(), [])

    def test_missing_admission_port_refuses_the_read_and_creates_no_sidecar(self):
        self.presence.reservation = None
        with self.assertRaisesRegex(RuntimeError, "storage admission required"):
            self.presence.timeline_gap()
        self.assertEqual(self.sidecars(), [])

    def test_admitted_read_creates_sidecars_only_inside_the_reservation_and_removes_them(self):
        for read in self.reads():
            self.entered.clear()
            read()
            self.assertEqual(self.entered[0], [])
            self.assertEqual(self.sidecars(), [])
        self.assertEqual(self.presence.snapshot(now=NOW, clock_trusted=True)["state"], "UNKNOWN")

    def test_admitted_read_is_query_only(self):
        with self.presence._read() as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM presence_audit")

    def test_existing_sidecars_still_need_admission(self):
        # Sidecars kept by a connection held open elsewhere prove nothing:
        # that connection may close before this read opens. A refused
        # reservation fails the read; an admitted one reads.
        holder = sqlite3.connect(self.database.path)
        self.addCleanup(holder.close)
        holder.execute("SELECT count(*) FROM presence_audit").fetchone()
        self.assertEqual(self.sidecars(), ["-shm", "-wal"])
        self.refuse = True
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            self.presence.timeline_gap()
        self.assertEqual(self.entered, [["-shm", "-wal"]])
        self.refuse = False
        self.assertIsNone(self.presence.timeline_gap())
        self.assertEqual(self.sidecars(), ["-shm", "-wal"])

    def test_last_holder_closing_before_the_open_creates_no_sidecar(self):
        # The last other connection closes (deleting both sidecars) after the
        # read saw them but before SQLite opens the database. Under a refused
        # reservation that open must never happen.
        holder = sqlite3.connect(self.database.path)
        holder.execute("SELECT count(*) FROM presence_audit").fetchone()
        self.assertEqual(self.sidecars(), ["-shm", "-wal"])
        real_connect = sqlite3.connect

        def connect_after_holder_closes(*args, **kwargs):
            holder.close()
            return real_connect(*args, **kwargs)

        self.refuse = True
        with mock.patch.object(sqlite3, "connect", connect_after_holder_closes):
            with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
                self.presence.timeline_gap()
        holder.close()
        self.assertEqual(self.sidecars(), [])

    def test_malformed_sidecars_need_admission(self):
        # Both sidecar names are regular files, but the -shm is empty or a
        # partial region (an interrupted creation). SQLite would initialise or
        # resize it on open, so a refused reservation fails the read and the
        # files are left exactly as they were.
        for size in (0, 1000, 32 * 1024 + 4096):
            with self.subTest(size=size):
                for suffix, length in (("-wal", 0), ("-shm", size)):
                    with open(self.database.path.with_name(self.database.path.name + suffix), "wb") as handle:
                        handle.write(b"\0" * length)
                self.refuse = True
                self.entered.clear()
                with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
                    self.presence.timeline_gap()
                self.assertEqual(self.entered, [["-shm", "-wal"]])
                shm = self.database.path.with_name(self.database.path.name + "-shm")
                self.assertEqual(shm.stat().st_size, size)
                self.refuse = False
                self.entered.clear()
                self.assertIsNone(self.presence.timeline_gap())
                self.assertEqual(self.entered, [["-shm", "-wal"]])

    def test_read_keeps_this_process_sqlite_locks(self):
        # Closing any descriptor on the database file releases every POSIX
        # lock this process holds on it. A read (and its WAL header probe)
        # while an in-process writer holds RESERVED must leave that lock in
        # place, so another process still cannot begin a write.
        with closing(sqlite3.connect(self.database.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=DELETE").fetchone()[0], "delete")
        writer = sqlite3.connect(self.database.path, isolation_level=None)
        self.addCleanup(writer.close)
        writer.execute("BEGIN IMMEDIATE")
        self.assertEqual(other_process_begin_immediate(self.database.path), "locked")
        self.assertIsNone(self.presence.timeline_gap())
        self.assertEqual(other_process_begin_immediate(self.database.path), "locked")
        writer.execute("ROLLBACK")

    def test_rollback_journal_read_needs_no_reservation(self):
        with closing(sqlite3.connect(self.database.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=DELETE").fetchone()[0], "delete")
        self.refuse = True
        self.assertIsNone(self.presence.timeline_gap())
        self.assertEqual((self.entered, self.sidecars()), ([], []))

    def test_pinned_database_read_is_admitted_too(self):
        pinned = PinnedDatabase(self.database)
        pinned.pin()
        self.addCleanup(pinned.release)
        self.presence.database = pinned
        self.refuse = True
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            self.presence.timeline_gap()
        self.assertEqual(self.sidecars(), [])
        self.refuse = False
        self.entered.clear()
        self.assertIsNone(self.presence.timeline_gap())
        self.assertEqual(self.entered, [[]])
        self.assertEqual(self.sidecars(), [])


# Tries to switch the database to WAL from another process without waiting.
OTHER_PROCESS_SWITCH_TO_WAL = """
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1], timeout=0, isolation_level=None)
try:
    print(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])
except sqlite3.OperationalError:
    print("locked")
"""


class WalSwitchRaceTests(PresenceFixture, TestCase):
    """A switch to WAL after the header check never reads unadmitted (#151)."""

    def setUp(self):
        self.make_presence()
        self.entered = []
        refuse = self.presence.reservation

        @contextmanager
        def reservation():
            self.entered.append(self.sidecars())
            with refuse():
                yield
        self.presence.reservation = reservation
        self.assertFalse(self.wal())

    def sidecars(self):
        return sorted(suffix for suffix in ("-wal", "-shm")
                      if self.database.path.with_name(self.database.path.name + suffix).exists())

    def wal(self):
        header = read_database_prefix(self.database.path, 20)
        return header[18] == 2

    def switch_to_wal(self):
        # Another writer of the file changes its mode; closing as the last
        # connection removes the sidecars it created.
        with closing(sqlite3.connect(self.database.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        self.assertEqual(self.sidecars(), [])

    def switch_on_header_read(self, number):
        """Patch the header probe so the file turns WAL right after read ``number``."""
        real = read_database_prefix
        calls = []

        def probe(path, size):
            header = real(path, size)
            calls.append(header)
            if len(calls) == number:
                self.switch_to_wal()
            return header
        return mock.patch("app.presence.service.read_database_prefix", probe)

    def use_pinned(self):
        pinned = PinnedDatabase(self.database)
        pinned.pin()
        self.addCleanup(pinned.release)
        self.presence.database = pinned

    def assert_switch_before_the_open_refuses_the_read(self):
        self.refuse = True
        with self.switch_on_header_read(1):
            with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
                self.presence.timeline_gap()
        self.assertEqual((self.entered, self.sidecars()), ([[]], []))

    def test_switch_before_the_open_refuses_the_read_without_sidecars(self):
        self.assert_switch_before_the_open_refuses_the_read()

    def test_switch_before_the_pinned_open_refuses_the_read_without_sidecars(self):
        self.use_pinned()
        self.assert_switch_before_the_open_refuses_the_read()

    def test_switch_before_the_open_is_read_under_the_reservation(self):
        with self.switch_on_header_read(1):
            self.assertIsNone(self.presence.timeline_gap())
        self.assertEqual((self.entered, self.sidecars()), ([[]], []))

    def test_switch_after_the_reread_is_abandoned_and_retried_under_the_reservation(self):
        # The file turns WAL after the post-open re-read but before the
        # read's first statement. The connection reports WAL, the read is
        # retried under the reservation and its close removes the sidecars.
        for read in (self.presence.timeline_gap, lambda: self.presence.audit("owner"), self.history):
            with self.subTest(read=read):
                with closing(sqlite3.connect(self.database.path)) as db:
                    self.assertEqual(db.execute("PRAGMA journal_mode=DELETE").fetchone()[0], "delete")
                self.entered.clear()
                with self.switch_on_header_read(2):
                    read()
                self.assertEqual(len(self.entered), 1)
                self.assertEqual(self.sidecars(), [])

    def test_switch_after_the_reread_under_a_refused_reservation_fails_the_read(self):
        self.refuse = True
        with self.switch_on_header_read(2):
            with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
                self.presence.timeline_gap()
        # The residual race: SQLite created the sidecars before the read could
        # see the mode, bounded to an empty -wal and one 32 KiB -shm region.
        # Another read under the same hard stop is refused before its open
        # and adds nothing. The next admitted read removes them again.
        self.assertEqual(self.sidecars(), ["-shm", "-wal"])
        sizes = [os.path.getsize(self.database.path.with_name(self.database.path.name + suffix))
                 for suffix in ("-wal", "-shm")]
        self.assertEqual(sizes[0], 0)
        self.assertLessEqual(sizes[1], 32 * 1024)
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            self.presence.timeline_gap()
        self.assertEqual(sizes, [os.path.getsize(self.database.path.with_name(self.database.path.name + suffix))
                                 for suffix in ("-wal", "-shm")])
        self.refuse = False
        self.assertIsNone(self.presence.timeline_gap())
        self.assertEqual(self.sidecars(), [])

    def test_mode_cannot_change_while_a_read_is_open(self):
        self.refuse = True
        with self.presence._read() as db:
            self.assertIsNone(self.presence._gap(db))
            switched = subprocess.run([sys.executable, "-I", "-c", OTHER_PROCESS_SWITCH_TO_WAL,
                                       os.fspath(self.database.path)],
                                      capture_output=True, text=True, check=True, timeout=30).stdout.strip()
            self.assertEqual(switched, "locked")
            db.execute("SELECT count(*) FROM presence_audit").fetchone()
        self.assertFalse(self.wal())
        self.assertEqual((self.entered, self.sidecars()), ([], []))

    def test_read_does_not_keep_the_database_locked(self):
        self.refuse = True
        self.assertIsNone(self.presence.timeline_gap())
        self.assertEqual(other_process_begin_immediate(self.database.path), "acquired")
        with self.assertRaises(ZeroDivisionError):
            with self.presence._read() as db:
                db.execute("SELECT count(*) FROM presence_audit").fetchone()
                1 / 0
        self.assertEqual(other_process_begin_immediate(self.database.path), "acquired")


class ReadLockBoundTests(PresenceFixture, TestCase):
    """An unadmitted read holds its SHARED lock only for bounded work (#151).

    The read transaction keeps a writer of the same file (such as a recording
    append) waiting until the read ends, so the work done under it must not
    grow with the retained timeline. Work is counted in SQLite VM steps on
    the read's own connection rather than in wall time, so the bound is
    deterministic; the writer test below adds a wall-clock check with a wide
    margin.
    """

    ROWS = 20_000
    STEP = 100

    def setUp(self):
        self.make_presence()
        self.refuse = True
        self.steps = []
        original = PresenceService._unadmitted_connection

        def counted(service, path):
            connection = original(service, path)
            if connection is not None:
                self.steps.append(0)
                index = len(self.steps) - 1

                def tick():
                    self.steps[index] += 1
                    return 0
                connection.set_progress_handler(tick, self.STEP)
            return connection
        patcher = mock.patch.object(PresenceService, "_unadmitted_connection", counted)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fill(self):
        """Synthetic timeline rows spread over sixty days, in receipt order."""
        start = NOW - timedelta(days=60)
        rows = []
        for index in range(self.ROWS):
            at = start + timedelta(seconds=index * 60 * 86400 // self.ROWS)
            item = Observation(Kind.ANONYMOUS_ENTRY, at, at, source_id=SOURCE, quality=Quality.SUFFICIENT,
                               clock_trusted=True)
            rows.append((str(item.identifier), item.kind.value, str(SOURCE), timestamp(at),
                         json.dumps(item.payload())))
        with closing(sqlite3.connect(self.database.path)) as db, db:
            db.executemany("INSERT INTO presence_observations(id,kind,source,received,payload) "
                           "VALUES (?,?,?,?,?)", rows)

    def counted(self, read):
        self.steps.clear()
        result = read()
        return result, sum(self.steps)

    def page(self, after=None):
        return self.presence.history("recordings", received_from=NOW - timedelta(days=61),
                                     received_to=NOW + timedelta(days=1), limit=100, after=after)

    def test_a_late_history_page_reads_about_one_page_under_the_lock(self):
        self.fill()
        first, early = self.counted(self.page)
        with closing(sqlite3.connect(self.database.path)) as db:
            received, sequence = db.execute("SELECT received,sequence FROM presence_observations "
                                            "ORDER BY received,sequence LIMIT 1 OFFSET ?",
                                            (self.ROWS * 3 // 4,)).fetchone()
        cursor = {"received_at": received, "sequence": sequence}
        late, steps = self.counted(lambda: self.page(cursor))
        # The same rows as before: the page right after the cursor, in order.
        self.assertEqual(late["items"][0]["sequence"], sequence + 1)
        self.assertEqual([item["sequence"] for item in late["items"]], list(range(sequence + 1, sequence + 101)))
        # Without the cursor bound the page scans every row from the window
        # start to the cursor, about a hundred times the page itself here.
        self.assertLessEqual(steps, 3 * early + 10)
        # Pages still concatenate across a cursor that lies before the window.
        before = {"received_at": timestamp(NOW - timedelta(days=90)), "sequence": 0}
        self.assertEqual(self.page(before)["items"], first["items"])

    def test_status_read_work_does_not_grow_with_the_timeline(self):
        def status():
            return self.presence.owner_status("owner", now=NOW, clock_trusted=True)
        _, empty = self.counted(status)
        self.fill()
        _, full = self.counted(status)
        self.assertLessEqual(full, empty + 2)

    def test_a_writer_with_a_short_busy_timeout_commits_while_large_reads_run(self):
        self.fill()
        with closing(sqlite3.connect(self.database.path)) as db, db:
            db.executemany("INSERT INTO presence_audit(action,actor,at,state) VALUES ('hint_set',?,?,?)",
                           [(str(OWNER), timestamp(NOW - timedelta(minutes=index)), "probably_present")
                            for index in range(500)])
            db.execute("CREATE TABLE synthetic_writes (x)")
            received, sequence = db.execute("SELECT received,sequence FROM presence_observations "
                                            "ORDER BY received,sequence LIMIT 1 OFFSET ?",
                                            (self.ROWS // 2,)).fetchone()
        reads = (lambda: self.presence.owner_status("owner", now=NOW, clock_trusted=True),
                 lambda: self.page({"received_at": received, "sequence": sequence}),
                 lambda: self.presence.audit("owner"), self.page, self.presence.timeline_gap)
        reading, done, failures = threading.Event(), threading.Event(), []

        def reader():
            try:
                while not done.is_set():
                    for read in reads:
                        read()
                        reading.set()
            except BaseException as error:  # pragma: no cover - reported below
                failures.append(error)
                reading.set()

        threads = [threading.Thread(target=reader) for _ in range(2)]
        for thread in threads:
            thread.start()
        try:
            self.assertTrue(reading.wait(30))
            # Another process, like a recording append, with a busy timeout a
            # fifth of the service's: far above the milliseconds one read
            # holds its lock, so it fails only if reads keep the file locked.
            written = subprocess.run([sys.executable, "-I", "-c", OTHER_PROCESS_COMMITS,
                                      os.fspath(self.database.path), "1.0", "20"],
                                     capture_output=True, text=True, check=True, timeout=60).stdout.strip()
        finally:
            done.set()
            for thread in threads:
                thread.join(30)
        self.assertEqual((written, failures), ("20", []))

    def test_a_read_waiting_behind_a_writer_does_not_join_an_open_read(self):
        """Overlapping reads would let the next one in past a waiting writer."""
        with closing(sqlite3.connect(self.database.path)) as db, db:
            db.execute("CREATE TABLE synthetic_writes (x)")
        opened, finish, seen = threading.Event(), threading.Event(), []

        def first():
            with self.presence._read() as db:
                db.execute("SELECT count(*) FROM presence_audit").fetchone()
                opened.set()
                finish.wait(30)

        def second():
            with self.presence._read() as db:
                seen.append(db.execute("SELECT count(*) FROM synthetic_writes").fetchone()[0])

        holder = threading.Thread(target=first)
        holder.start()
        self.assertTrue(opened.wait(30))
        writer = subprocess.Popen([sys.executable, "-I", "-c", OTHER_PROCESS_COMMITS,
                                   os.fspath(self.database.path), "30", "1"], stdout=subprocess.PIPE, text=True)
        try:
            # The writer holds PENDING once a new reader of another process
            # can no longer take SHARED: it now waits only for the open read.
            for _ in range(3000):
                if other_process_read(self.database.path) == "locked":
                    break
                time.sleep(0.01)
            else:
                self.fail("the writer never reached PENDING")
            follower = threading.Thread(target=second)
            follower.start()
            # A read that joins the open one finishes here without waiting
            # for the writer; a serialized one is still waiting for its turn.
            follower.join(1.0)
            finish.set()
            follower.join(30)
            holder.join(30)
            self.assertEqual(writer.communicate(timeout=60)[0].strip(), "1")
        finally:
            finish.set()
            if writer.poll() is None:
                writer.kill()
                writer.wait()
        # The second read began only after the waiting writer committed.
        self.assertEqual(seen, [1])


# Commits ``count`` single-row transactions with the given busy timeout and
# prints how many committed, or "locked" when one timed out.
OTHER_PROCESS_COMMITS = """
import sqlite3, sys, time
connection = sqlite3.connect(sys.argv[1], timeout=float(sys.argv[2]), isolation_level=None)
committed = 0
try:
    for index in range(int(sys.argv[3])):
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO synthetic_writes VALUES (?)", (index,))
        connection.execute("COMMIT")
        committed += 1
        time.sleep(0.005)
except sqlite3.OperationalError:
    print("locked")
else:
    print(committed)
"""


OTHER_PROCESS_READ = """
import sqlite3, sys
connection = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True, timeout=0)
try:
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
except sqlite3.OperationalError:
    print("locked")
else:
    print("read")
"""


def other_process_read(path):
    """Whether a separate process can take SHARED on ``path`` right now."""
    return subprocess.run([sys.executable, "-I", "-c", OTHER_PROCESS_READ, os.fspath(path)],
                          capture_output=True, text=True, check=True, timeout=30).stdout.strip()


class BuildFaultTests(PresenceFixture, TestCase):
    """A permanent build fault never blocks the outbox silently (#129)."""

    def setUp(self):
        self.make_presence()
        self.health = HealthTimeline(self.outbox)

    def status(self):
        return self.presence.owner_status("owner", now=NOW, clock_trusted=True)

    @staticmethod
    def faulty(identifier, error):
        """A build that passes its stage-time contract check and then fails at flush."""
        calls = []

        def build(received, trusted):
            calls.append(received)
            if len(calls) > 1:
                raise error
            return Observation(Kind.NODE_HEALTH, NOW, received, value=Value.OFFLINE, node_id=NODE,
                               identifier=identifier), None
        return build

    def test_build_fault_is_quarantined_and_later_facts_are_written(self):
        identifier = uuid4()
        self.assertTrue(self.outbox.stage(identifier, self.faulty(identifier,
                                                                  AttributeError("synthetic programming error"))))
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        with self.assertLogs("app.presence.adapters", "ERROR") as logged:
            state = self.outbox.flush()
        self.assertEqual(logged.records[0].msg, Event.TIMELINE_FACT_QUARANTINED)
        self.assertNotIn("synthetic programming error", "".join(logged.output))
        self.assertEqual((state.recorded, state.pending, state.quarantined, state.rejected), (1, 0, 1, 0))
        self.assertTrue(state.degraded)
        status = self.status()
        self.assertTrue(status["timeline_gap"])
        self.assertEqual(status["timeline_quarantined_count"], 1)
        self.assertFalse(status["timeline_pending"])
        self.assertEqual([item["kind"] for item in self.history()["items"]], ["node_health"])
        # A clean close records the quarantined fact as lost; it never vanishes.
        self.outbox.close()
        self.assertEqual(self.presence.timeline_gap()["lost"], 1)

    def test_quarantine_counts_against_capacity_and_deduplicates(self):
        identifier = uuid4()
        self.assertTrue(self.outbox.stage(identifier, self.faulty(identifier, TypeError("synthetic"))))
        self.assertEqual(self.outbox.flush().quarantined, 1)
        self.assertTrue(self.outbox.stage(identifier, self.faulty(identifier, TypeError("synthetic"))))
        self.assertEqual(self.outbox.state().pending, 0)
        for _ in range(7):
            self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.assertFalse(self.health.node(NODE, NodeHealthState.ONLINE))
        self.assertEqual(self.outbox.state().refused, 1)

    def test_contract_error_in_build_is_still_rejected_not_quarantined(self):
        identifier = uuid4()
        self.assertTrue(self.outbox.stage(identifier, self.faulty(identifier,
                                                                  InvalidObservation("synthetic contract error"))))
        state = self.outbox.flush()
        self.assertEqual((state.rejected, state.quarantined), (1, 0))

    def test_transient_failures_are_counted_logged_and_cleared(self):
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.refuse = True
        with self.assertLogs("app.presence.adapters", "WARNING") as logged:
            for _ in range(3):
                state = self.outbox.flush()
        self.assertEqual((state.pending, state.failures, state.quarantined), (1, 3, 0))
        # The first failure and each doubling are logged, not every attempt.
        self.assertEqual([record.msg for record in logged.records], [Event.TIMELINE_FLUSH_FAILING] * 2)
        status = self.status()
        self.assertEqual((status["timeline_flush_failures"], status["timeline_pending_count"]), (3, 1))
        self.refuse = False
        with self.assertLogs("app.presence.adapters", "WARNING") as logged:
            state = self.outbox.flush()
        self.assertEqual([record.msg for record in logged.records], [Event.TIMELINE_FLUSH_RECOVERED])
        self.assertEqual((state.pending, state.failures, state.recorded), (0, 0, 1))
        self.assertEqual(self.status()["timeline_flush_failures"], 0)


CHILD_OUTBOX = """
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from app.presence.adapters import TimelineOutbox
from app.presence.service import PresenceService
from app.storage.database import Database


@contextmanager
def reservation():
    yield


service = PresenceService(Database(Path(sys.argv[1])), reservation=reservation)
outbox = TimelineOutbox(service, clock=lambda: (datetime(2026, 1, 1, tzinfo=timezone.utc), True), capacity=8)
outbox.open()
print("open", flush=True)
sys.stdin.read()
"""


class SharedBacklogTests(PresenceFixture, TestCase):
    """Owner status from another service or process never reports a hidden backlog as empty (#129)."""

    def setUp(self):
        self.make_presence()
        self.health = HealthTimeline(self.outbox)

    def other(self):
        return PresenceService(self.database, access=MockAccess(), reservation=self.presence.reservation,
                               detection=lambda: True, storage_status=lambda: True)

    def mark_interrupted(self):
        with closing(self.database.connect()) as db:
            db.execute("INSERT INTO presence_timeline_gap(singleton,since,latest,refused,rejected,lost,interrupted) "
                       "VALUES (1,?,?,0,0,0,1)", (timestamp(NOW), timestamp(NOW)))

    def test_another_service_in_this_process_sees_the_backlog(self):
        self.assertTrue(self.health.node(NODE, NodeHealthState.OFFLINE))
        self.refuse = True
        self.outbox.flush()
        status = self.other().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual((status["timeline_pending"], status["timeline_pending_count"]), (True, 1))
        self.assertTrue(status["timeline_backlog_visible"])
        # Counted but unwritten loss refuses a clear from that service too.
        for _ in range(8):
            self.health.node(NODE, NodeHealthState.OFFLINE)
        self.refuse = False
        self.mark_interrupted()
        status = self.other().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertEqual(status["timeline_gap_unpersisted"], 1)
        with self.assertRaisesRegex(ValueError, "unpersisted"):
            self.other().clear_timeline_gap("owner", now=NOW, clock_trusted=True)

    def test_an_outbox_in_another_process_is_reported_unknown_and_refuses_the_clear(self):
        self.outbox.close()
        self.mark_interrupted()
        server = Path(__file__).resolve().parents[1]
        child = subprocess.Popen([sys.executable, "-c", CHILD_OUTBOX, str(self.database.path)], cwd=server,
                                 env={**os.environ, "PYTHONPATH": str(server)}, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, text=True)
        self.addCleanup(child.wait, 10)
        self.addCleanup(child.stdout.close)
        self.addCleanup(child.stdin.close)
        self.assertEqual(child.stdout.readline().strip(), "open")
        status = self.other().owner_status("owner", now=NOW, clock_trusted=True)
        self.assertFalse(status["timeline_backlog_visible"])
        self.assertEqual(status["timeline_gap_orphaned_sessions"], 0)
        self.assertTrue(status["timeline_pending"])
        self.assertTrue(status["timeline_gap"])
        with self.assertRaisesRegex(ValueError, "another process"):
            self.other().clear_timeline_gap("owner", now=NOW, clock_trusted=True)
        self.assertIsNotNone(self.presence.timeline_gap())
