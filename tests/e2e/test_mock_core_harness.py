"""Hardware-free scenarios spanning the Agent and Main Server cores."""

from contextlib import closing
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from app.integrity.model import State as IntegrityState
from app.integrity.service import IntegrityService
from app.media.health.service import HealthState, RecordingHealthService, Stage
from app.presence.delivery import ActionResult
from app.presence.models import Kind, Observation, Quality
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import POST, PRE, SECOND, RingConfig, SegmentProfile
from media_capture_agent.storage import MediaStore

from tests.e2e.harness import (
    AllowRingControls,
    FaultPlan,
    MixedSourceTopology,
    SyntheticAccess,
    SyntheticClock,
    SyntheticIntegrityProbe,
    SyntheticRecorder,
    agent_settings,
    storage_reservation,
)


class IntegrityMemoryPort:
    """Persistence port for testing IntegrityService orchestration and compare."""

    def __init__(self, baseline):
        self.approved = baseline
        self.recorded = []

    def baseline(self):
        return 1, self.approved

    def record(self, findings, at):
        self.recorded.append((findings, at))

    def deliver(self, _sink):
        return True


class MockCoreHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.faults = FaultPlan()
        self.database = Database(self.root / "main.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)

    def presence(self, evidence=None, notifications=None):
        return PresenceService(
            self.database,
            access=SyntheticAccess(),
            evidence=evidence,
            notifications=notifications,
            reservation=storage_reservation,
            detection=lambda: True,
            storage_status=lambda: True,
        )

    def observation(self, kind, source, *, confirmed=False):
        return Observation(
            kind,
            self.clock.utcnow(),
            self.clock.utcnow(),
            source_id=source.source_id,
            node_id=source.node_id,
            confidence=0.99 if confirmed else None,
            quality=Quality.SUFFICIENT,
            clock_trusted=True,
            confirmed=confirmed,
        )

    def test_harness_bounds_health_isolation_and_consumable_faults(self):
        self.assertEqual(
            [source.source_type.value for source in self.topology.sources],
            ["local_uvc", "remote_agent", "local_uvc", "remote_agent"],
        )
        remote = self.topology.sources[1]
        self.topology.set_node_health(remote.node_id, "offline")
        self.assertEqual(self.topology.source_health[remote.source_id].value, "online")
        self.faults.arm("recording.decode", times=2)
        self.assertTrue(self.faults.trip("recording.decode"))
        self.assertTrue(self.faults.trip("recording.decode"))
        self.assertFalse(self.faults.trip("recording.decode"))
        with self.assertRaises(ValueError):
            MixedSourceTopology(5)

    def test_clock_rollback_is_visible_to_presence_and_ring(self):
        source = self.topology.sources[1]
        service = self.presence()
        first = service.record(self.observation(Kind.CAMERA_HEALTH, source))
        self.assertTrue(first.clock_trusted)

        self.clock.shift_wall(-5)
        corrected = service.record(self.observation(Kind.CAMERA_HEALTH, source))
        self.assertFalse(corrected.clock_trusted)
        self.assertFalse(corrected.confirmed)

        settings = agent_settings(self.root / "agent", source.node_id)
        store = MediaStore(settings, stable_device=lambda _expected: True)
        self.addCleanup(store.close)
        ring = DiskRing(
            settings,
            store,
            ledger_maximum_bytes=16 * 1024 * 1024,
            authority=AllowRingControls(),
        )
        self.addCleanup(ring.close)
        profile = SegmentProfile(source.source_id, 800, 400, 60 * SECOND, 100)
        anchor = self.clock.now_us() + 10 * SECOND
        ring.configure(RingConfig("duration", 600), (profile,), now_us=anchor, clock_trusted=True)
        for start in range(anchor - PRE, anchor, 60 * SECOND):
            ring.append(
                source.source_id,
                start,
                start + 60 * SECOND,
                b"synthetic-compressed-segment",
                now_us=start + 60 * SECOND,
                clock_trusted=True,
            )
        status = ring.tick(now_us=anchor - SECOND, clock_trusted=True)
        self.assertEqual((status["state"], status["reason"]), ("degraded", "clock_uncertain"))

    def test_capture_loss_and_critical_timeline_share_synthetic_source(self):
        source = self.topology.sources[1]
        settings = agent_settings(self.root / "capture", source.node_id)
        store = MediaStore(settings, stable_device=lambda _expected: True)
        self.addCleanup(store.close)
        ring = DiskRing(
            settings,
            store,
            ledger_maximum_bytes=16 * 1024 * 1024,
            authority=AllowRingControls(),
        )
        self.addCleanup(ring.close)
        profile = SegmentProfile(source.source_id, 800, 400, 60 * SECOND, 100)
        now = self.clock.now_us()
        ring.configure(RingConfig("duration", 600), (profile,), now_us=now, clock_trusted=True)
        payload = b"synthetic-compressed-segment"
        for start in range(now - PRE, now, 60 * SECOND):
            ring.append(
                source.source_id,
                start,
                start + 60 * SECOND,
                payload,
                now_us=start + 60 * SECOND,
                clock_trusted=True,
            )
        ring.observe_connection(
            authenticated=True, connected=True, unexpected=False,
            now_us=now, clock_trusted=True,
        )
        incident_id = ring.observe_connection(
            authenticated=True, connected=False, unexpected=True,
            now_us=now, clock_trusted=True,
        )
        incident = ring.incident(incident_id, now_us=now)
        self.assertEqual(incident["trigger_reason"], "main_connection_lost")
        self.assertEqual(incident["target_end_us"], now + POST)

        submitted = []

        def submit(item, complete):
            submitted.append(item.kind)
            complete(ActionResult.DELIVERED)
            return ActionResult.DELIVERED

        presence = self.presence(submit, submit)
        critical = presence.record(self.observation(Kind.SERVER_MOVEMENT, source, confirmed=True))
        presence.dispatch_pending()
        self.assertEqual(submitted, [Kind.SERVER_MOVEMENT, Kind.SERVER_MOVEMENT])
        history = presence.history(
            "recordings",
            received_from=self.clock.utcnow() - timedelta(seconds=1),
            received_to=self.clock.utcnow() + timedelta(seconds=1),
        )
        self.assertEqual(history["items"][0]["id"], str(critical.identifier))

    def test_named_faults_are_reported_by_integrity_and_recording_cores(self):
        probe = SyntheticIntegrityProbe(self.faults)
        integrity_port = IntegrityMemoryPort(probe.inventory)
        integrity = IntegrityService(
            integrity_port,
            probe,
            lambda *_args: None,
            monotonic=self.clock.monotonic,
            utcnow=self.clock.utcnow,
        )
        self.assertTrue(all(item.state == IntegrityState.OK for item in integrity.startup()))
        self.faults.arm("integrity.collect")
        self.clock.advance(86400)
        findings = integrity.tick()
        self.assertTrue(findings)
        self.assertTrue(all(item.state == IntegrityState.UNVERIFIABLE for item in findings))

        results = []
        recorder = SyntheticRecorder(self.topology, self.faults)
        health = RecordingHealthService(
            recorder,
            lambda *result: results.append(result),
            monotonic=self.clock.monotonic,
            utcnow=self.clock.utcnow,
        )
        self.faults.arm("recording.decode")
        failed = health.startup()
        self.assertEqual(failed.state, HealthState.FAILED)
        self.assertIn(Stage.REOPEN_DECODE, failed.stages)
        self.assertFalse(recorder.leftover)
        self.assertEqual(results[-1][0], failed)


if __name__ == "__main__":
    unittest.main()
