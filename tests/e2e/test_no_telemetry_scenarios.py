"""No analytics, telemetry or crash reporting in normal and error paths.

Main and Agent cores run under a guard that refuses every outbound socket
attempt from any thread. Only the explicitly configured Slack integration may
try to reach its own endpoint, and even that attempt is refused here.
"""

from contextlib import closing
import io
import logging
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from uuid import UUID

from app.integrity.service import IntegrityService
from app.logging import Event, SafeJsonFormatter, SafeStreamHandler
from app.media.health.service import HealthState, RecordingHealthService
from app.notifications.service import DailySummary, NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from app.presence.delivery import NotificationAdapter
from app.presence.models import Kind, Observation, Quality
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.policy import StorageState
from app.storage.schema import APPLICATION_MIGRATIONS
from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import PRE, SECOND, RingConfig, RingRefused, SegmentProfile
from media_capture_agent.storage import MediaStore

from tests.e2e.harness import (
    AllowRingControls,
    FaultPlan,
    MixedSourceTopology,
    NetworkGuard,
    OutboundNetworkForbidden,
    SyntheticAccess,
    SyntheticClock,
    SyntheticIntegrityProbe,
    SyntheticRecorder,
    agent_settings,
    storage_reservation,
)
from tests.e2e.test_notification_fault_scenarios import endpoint
from tests.e2e.test_mock_core_harness import IntegrityMemoryPort


# Well-known analytics, telemetry and crash-reporting SDK import names.
REPORTING_MODULES = frozenset({
    "sentry_sdk", "raven", "bugsnag", "rollbar", "honeybadger", "opentelemetry",
    "ddtrace", "datadog", "newrelic", "elasticapm", "posthog", "mixpanel",
    "analytics", "segment", "amplitude", "statsd", "prometheus_client",
    "google.analytics", "firebase_admin",
})


class NoTelemetryScenarios(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.faults = FaultPlan()

    def test_guard_refuses_and_records_every_outbound_entry_point(self):
        with NetworkGuard() as guard:
            for attempt in (
                lambda: socket.create_connection(("telemetry.invalid", 443), timeout=1),
                lambda: socket.getaddrinfo("telemetry.invalid", 443),
                lambda: socket.gethostbyname("telemetry.invalid"),
            ):
                with self.assertRaises(OutboundNetworkForbidden):
                    attempt()
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as udp:
                with self.assertRaises(OutboundNetworkForbidden):
                    udp.sendto(b"generated", ("192.0.2.1", 9))
                with self.assertRaises(OutboundNetworkForbidden):
                    udp.connect(("192.0.2.1", 9))
        self.assertEqual(
            [("create_connection", "telemetry.invalid"), ("getaddrinfo", "telemetry.invalid"),
             ("gethostbyname", "telemetry.invalid"), ("sendto", "192.0.2.1"),
             ("connect", "192.0.2.1")],
            guard.attempts)

    def test_guard_refuses_and_records_every_resolver_entry_point(self):
        import _socket

        originals = {(module, name): getattr(module, name)
                     for module in (socket, _socket)
                     for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                                  "gethostbyaddr", "getnameinfo")}
        with NetworkGuard() as guard:
            for module in (socket, _socket):
                for attempt in (
                    lambda: module.getaddrinfo("telemetry.invalid", 443),
                    lambda: module.gethostbyname("telemetry.invalid"),
                    lambda: module.gethostbyname_ex("telemetry.invalid"),
                    lambda: module.gethostbyaddr("192.0.2.1"),
                    lambda: module.getnameinfo(("192.0.2.1", 443), 0),
                ):
                    with self.assertRaises(OutboundNetworkForbidden):
                        attempt()
        expected = [("getaddrinfo", "telemetry.invalid"), ("gethostbyname", "telemetry.invalid"),
                    ("gethostbyname_ex", "telemetry.invalid"), ("gethostbyaddr", "192.0.2.1"),
                    ("getnameinfo", "192.0.2.1")]
        self.assertEqual(expected * 2, guard.attempts)
        # Every patch is reverted on exit.
        for (module, name), original in originals.items():
            self.assertIs(getattr(module, name), original)

    def test_guard_refuses_low_level_socket_and_captured_resolvers(self):
        import _socket
        from socket import gethostbyname_ex as captured_before_guard

        with NetworkGuard() as guard:
            with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)) as raw:
                for attempt in (
                    lambda: raw.connect(("192.0.2.1", 9)),
                    lambda: raw.connect_ex(("192.0.2.2", 9)),
                    lambda: raw.sendto(b"generated", ("192.0.2.3", 9)),
                    lambda: raw.sendmsg([b"generated"], [], 0, ("192.0.2.4", 9)),
                ):
                    with self.assertRaises(OutboundNetworkForbidden):
                        attempt()
            with self.assertRaises(OutboundNetworkForbidden):
                captured_before_guard("telemetry.invalid")
            errors = []

            def worker():
                try:
                    with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)) as other:
                        other.connect(("192.0.2.5", 9))
                except OutboundNetworkForbidden as error:
                    errors.append(error)
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join()
            self.assertEqual(1, len(errors))
        self.assertEqual(
            [("connect", "192.0.2.1"), ("connect", "192.0.2.2"), ("sendto", "192.0.2.3"),
             ("sendmsg", "192.0.2.4"), ("gethostbyname", "telemetry.invalid"),
             ("connect", "192.0.2.5")],
            guard.attempts)
        # The process-wide hook is inert once no guard is active.
        with closing(_socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)) as local:
            with self.assertRaises(OSError) as raised:
                local.connect(str(self.root / "absent.sock"))
            self.assertNotIsInstance(raised.exception, OutboundNetworkForbidden)
        self.assertEqual(6, len(guard.attempts))

    def test_guard_fails_closed_on_sockets_connected_before_it_started(self):
        import _socket

        local_a, local_b = socket.socketpair()
        self.addCleanup(local_a.close)
        self.addCleanup(local_b.close)
        with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)) as early:
            # UDP connect only records the peer; nothing is transmitted.
            early.connect(("192.0.2.9", 9))
            guard = NetworkGuard()
            with self.assertRaises(OutboundNetworkForbidden):
                guard.__enter__()
            self.assertEqual([("preconnected", "192.0.2.9")], guard.attempts)
            # The failed entry left no patch or active guard behind.
            with self.assertRaises(OSError) as raised:
                socket.getaddrinfo("telemetry.invalid", 443,
                                   flags=getattr(socket, "AI_NUMERICHOST", 0))
            self.assertNotIsInstance(raised.exception, OutboundNetworkForbidden)
        # Local AF_UNIX pairs are not outbound and do not trip the guard.
        with NetworkGuard() as guard:
            local_a.send(b"local")
        self.assertEqual(b"local", local_b.recv(16))
        self.assertEqual([], guard.attempts)

    def run_main_paths(self):
        # Hardware integrity: startup success, then a failing daily probe.
        probe = SyntheticIntegrityProbe(self.faults)
        integrity = IntegrityService(IntegrityMemoryPort(probe.inventory), probe, lambda *_: None,
                                     monotonic=self.clock.monotonic, utcnow=self.clock.utcnow)
        integrity.startup()
        self.faults.arm("integrity.collect")
        self.clock.advance(86400)
        self.assertTrue(integrity.tick())

        # Recording health success and failure with Slack left unset.
        local = []
        notifications = NotificationService(local.append)
        self.addCleanup(notifications.close)

        def record(result, at):
            if result.state != HealthState.OK:
                notifications.record(NotificationKind.RECORDING_HEALTH_FAILURE, at=at)

        health = RecordingHealthService(SyntheticRecorder(self.topology, self.faults), record,
                                        monotonic=self.clock.monotonic, utcnow=self.clock.utcnow)
        self.assertEqual(HealthState.OK, health.startup().state)
        self.faults.arm("recording.decode")
        self.clock.advance(86400)
        self.assertEqual(HealthState.FAILED, health.tick().state)
        for kind in NotificationKind:
            if kind != NotificationKind.DAILY_SUMMARY:
                notifications.record(kind, at=self.clock.utcnow(), confirmed=True)
        self.assertEqual(DeliveryResult.DISABLED, notifications.daily(
            DailySummary(3600, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, StorageState.PRESSURE),
            at=self.clock.utcnow()))

        # Presence, critical dispatch and the owner status snapshot.
        database = Database(self.root / "main.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        presence = PresenceService(
            database, access=SyntheticAccess(), evidence=None,
            notifications=NotificationAdapter(notifications, NotificationKind),
            reservation=storage_reservation, detection=lambda: False, storage_status=lambda: False,
        )
        source = self.topology.sources[1]
        now = self.clock.utcnow()
        presence.record(Observation(Kind.SERVER_MOVEMENT, now, now, source_id=source.source_id,
                                    node_id=source.node_id, confidence=0.99,
                                    quality=Quality.SUFFICIENT, clock_trusted=True, confirmed=True))
        presence.dispatch_pending()
        self.assertTrue(presence.owner_status("owner", now=now, clock_trusted=True)
                        ["critical_paths_degraded"])
        with self.assertRaises(PermissionError):
            presence.owner_status("recordings", now=now, clock_trusted=True)

        # Error logging stays local structured output.
        stream = io.StringIO()
        handler = SafeStreamHandler(stream)
        handler.setFormatter(SafeJsonFormatter())
        logger = logging.getLogger("serversentinel.synthetic.e2e")
        logger.addHandler(handler)
        logger.propagate = False
        try:
            try:
                raise RuntimeError("synthetic startup failure")
            except RuntimeError:
                logger.exception(Event.STARTUP_FAILED)
        finally:
            logger.removeHandler(handler)
        self.assertIn('"event":"application_startup_failed"', stream.getvalue())
        self.assertNotIn("synthetic startup failure", stream.getvalue())

    def run_agent_paths(self):
        settings = agent_settings(self.root / "agent", UUID(int=300))
        store = MediaStore(settings, stable_device=lambda _expected: True)
        self.addCleanup(store.close)
        ring = DiskRing(settings, store, ledger_maximum_bytes=16 * 1024 * 1024,
                        authority=AllowRingControls())
        self.addCleanup(ring.close)
        source = UUID(int=400)
        t0 = self.clock.now_us()
        ring.configure(RingConfig("duration", 600),
                       (SegmentProfile(source, 800, 400, 60 * SECOND, 100),),
                       now_us=t0, clock_trusted=True)
        for start in range(t0 - PRE, t0, 60 * SECOND):
            ring.append(source, start, start + 60 * SECOND, b"synthetic-compressed-segment",
                        now_us=start + 60 * SECOND, clock_trusted=True)
        ring.observe_connection(authenticated=True, connected=True, unexpected=False,
                                now_us=t0, clock_trusted=True)
        self.assertIsNotNone(ring.observe_connection(authenticated=True, connected=False,
                                                     unexpected=True, now_us=t0, clock_trusted=True))
        # Error paths: profile violation and a lost mount.
        with self.assertRaises(RingRefused):
            ring.append(source, t0, t0 + SECOND, b"x", now_us=t0 + SECOND, clock_trusted=True)
        store.mounts = lambda: []
        self.assertEqual("STORAGE_HARD_STOP", ring.status(now_us=t0, clock_trusted=True)["state"])

    def test_normal_and_error_paths_make_no_outbound_connection(self):
        with NetworkGuard() as guard:
            self.run_main_paths()
            self.run_agent_paths()
        self.assertEqual([], guard.attempts)
        self.assertEqual(set(), REPORTING_MODULES & set(sys.modules))

    def test_opt_in_slack_is_the_only_destination_and_is_not_telemetry(self):
        with NetworkGuard() as guard:
            local = []
            service = NotificationService(local.append, SlackDelivery(endpoint(), timeout_seconds=1))
            self.addCleanup(service.close)
            self.assertEqual(DeliveryResult.PENDING, service.record(
                NotificationKind.RECORDING_HEALTH_FAILURE, at=self.clock.utcnow()))
            while service.pending_count:
                self.assertTrue(service._worker.ready.wait(5))
                service.poll()
        self.assertEqual(DeliveryResult.FAILED, service.last_delivery)
        self.assertEqual(["pending", "failed"], [event.delivery.value for event in local])
        self.assertTrue(guard.attempts)
        self.assertEqual({"hooks.slack.com"}, {host for _name, host in guard.attempts})


if __name__ == "__main__":
    unittest.main()
