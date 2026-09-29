"""Slack unset or failing never hides the local Dashboard/Audit fault.

Slack delivery uses an injected transport that raises; no request leaves the
process. Local fault records go to a disposable SQLite table standing in for
the durable Dashboard/Audit sink, and every scenario runs under the network
guard.
"""

from contextlib import closing
from datetime import timedelta
from pathlib import Path
import sqlite3
import tempfile
import unittest

from app.media.health.service import HealthState, RecordingHealthService, Stage
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery, SlackEndpoint
from app.presence.delivery import ActionResult, NotificationAdapter
from app.presence.models import Kind, Observation, Quality
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.e2e.harness import (
    FaultPlan,
    MixedSourceTopology,
    NetworkGuard,
    SyntheticAccess,
    SyntheticClock,
    SyntheticRecorder,
    storage_reservation,
)


def endpoint():
    # Generated placeholder components never identify a real Slack webhook.
    return SlackEndpoint("https://hooks.slack.com/" + "/".join(
        ("services", "T" + "0" * 8, "B" + "0" * 8, "generated_dummy_value")))


class FailingTransport:
    """Injected opener: records the attempt and fails like an outage."""

    def __init__(self):
        self.requests = 0

    def open(self, _request, *, timeout):
        self.requests += 1
        raise OSError("synthetic Slack outage")


class NotificationFaultScenarios(unittest.TestCase):
    def setUp(self):
        self.network = NetworkGuard().__enter__()
        self.addCleanup(self.network.__exit__)
        self.addCleanup(lambda: self.assertEqual([], self.network.attempts))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.faults = FaultPlan()
        self.database = Database(self.root / "main.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.log = sqlite3.connect(self.root / "faults.sqlite3", isolation_level=None)
        self.addCleanup(self.log.close)
        self.log.execute("CREATE TABLE local_faults (id TEXT PRIMARY KEY, kind TEXT, delivery TEXT)")
        self.health_log = []

    def local_sink(self, event):
        # Durable upsert keyed by event id, as NotificationService requires.
        self.log.execute("INSERT INTO local_faults VALUES (?,?,?) ON CONFLICT(id) DO UPDATE "
                         "SET delivery=excluded.delivery",
                         (str(event.event_id), event.kind.value, event.delivery.value))

    def faults_logged(self):
        return [tuple(row) for row in self.log.execute("SELECT kind,delivery FROM local_faults ORDER BY kind")]

    def service(self, slack):
        service = NotificationService(self.local_sink, slack)
        self.addCleanup(service.close)
        return service

    def drain(self, service):
        while service.pending_count:
            self.assertTrue(service._worker.ready.wait(5), "synthetic delivery did not finish")
            service.poll()

    def health(self, service):
        def record(result, at):
            self.health_log.append((result.state, result.stages, at))
            if result.state != HealthState.OK:
                service.record(NotificationKind.RECORDING_HEALTH_FAILURE, at=at)
        return RecordingHealthService(SyntheticRecorder(self.topology, self.faults), record,
                                      monotonic=self.clock.monotonic, utcnow=self.clock.utcnow)

    def presence(self, service):
        evidence = []

        def preserve(observation, complete):
            evidence.append(observation.identifier)
            complete(ActionResult.DELIVERED)
            return ActionResult.DELIVERED

        return PresenceService(
            self.database, access=SyntheticAccess(), evidence=preserve,
            notifications=NotificationAdapter(service, NotificationKind),
            reservation=storage_reservation, detection=lambda: True, storage_status=lambda: True,
        ), evidence

    def movement(self):
        source = self.topology.sources[1]
        now = self.clock.utcnow()
        return Observation(Kind.SERVER_MOVEMENT, now, now, source_id=source.source_id,
                           node_id=source.node_id, confidence=0.99, quality=Quality.SUFFICIENT,
                           clock_trusted=True, confirmed=True)

    def assert_dashboard_fault(self, presence, evidence, critical, *, unfinished):
        status = presence.owner_status("owner", now=self.clock.utcnow(), clock_trusted=True)
        self.assertEqual("unavailable", status["critical_notifications"])
        self.assertEqual("armed", status["critical_evidence"])
        self.assertTrue(status["critical_paths_degraded"])
        # Disabled is a configuration outcome, failed is unfinished work; both
        # keep the notification path reported as unavailable.
        self.assertEqual(unfinished, status["pending_critical_actions"])
        self.assertEqual([critical.identifier], evidence)
        # The critical event itself stays on the recordings timeline.
        history = presence.history("recordings",
                                   received_from=critical.received_at - timedelta(seconds=1),
                                   received_to=critical.received_at + timedelta(seconds=1))
        self.assertEqual([str(critical.identifier)], [item["id"] for item in history["items"]])

    def test_slack_unset_keeps_health_failure_and_critical_fault_locally_visible(self):
        service = self.service(SlackDelivery())
        self.faults.arm("recording.decode")
        result = self.health(service).startup()
        self.assertEqual((HealthState.FAILED, (Stage.REOPEN_DECODE,)), (result.state, result.stages))
        self.assertEqual(DeliveryResult.DISABLED, service.last_delivery)

        presence, evidence = self.presence(service)
        critical = presence.record(self.movement())
        presence.dispatch_pending()
        self.assertEqual([("recording_health_failure", "disabled"), ("server_movement", "disabled")],
                         self.faults_logged())
        self.assert_dashboard_fault(presence, evidence, critical, unfinished=0)
        self.assertEqual(1, len(self.health_log))

    def test_slack_failure_is_recorded_locally_and_never_reported_as_delivered(self):
        transport = FailingTransport()
        service = self.service(SlackDelivery(endpoint(), opener=transport))
        self.faults.arm("recording.write")
        self.assertEqual(HealthState.FAILED, self.health(service).startup().state)

        presence, evidence = self.presence(service)
        critical = presence.record(self.movement())
        presence.dispatch_pending()
        self.drain(service)
        self.assertEqual(2, transport.requests)
        self.assertTrue(service.delivery_failed)
        self.assertEqual(DeliveryResult.FAILED, service.last_delivery)
        self.assertEqual([("recording_health_failure", "failed"), ("server_movement", "failed")],
                         self.faults_logged())
        self.assert_dashboard_fault(presence, evidence, critical, unfinished=1)
        # No automatic resend: a later dispatch leaves the failure in place.
        presence.dispatch_pending()
        self.assertEqual(2, transport.requests)
        self.assert_dashboard_fault(presence, evidence, critical, unfinished=1)


if __name__ == "__main__":
    unittest.main()
