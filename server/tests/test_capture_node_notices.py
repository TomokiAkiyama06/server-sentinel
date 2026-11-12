"""Issue #14 (Owner decision 2026-11-12): capture-node health and ingest listener notices.

Generated clocks, synthetic node views, an in-memory sink, disposable SQLite
files and an intercepted Slack transport only. No real host, node, credential
or network is used.
"""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.cameras.remote_agent.ingest_wire import NodeHeartbeat
from app.cameras.remote_agent.node_health import CaptureNodeHealthRegistry
from app.main import create_app
from app.monitoring.capture_nodes import (
    HOURLY_LIMIT, NOTICE_AFTER_SECONDS, CaptureNodeHealthMonitor, CaptureNodeView,
)
from app.monitoring.runtime import MonitoringDependencies
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery

from tests.test_camera_offline_notifications import Clock, Sink
from tests.test_monitoring_runtime import RuntimeFixture
from tests.test_storage_notifications import Transport, endpoint
import unittest


AT = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
STORAGE = NotificationKind.CAPTURE_NODE_STORAGE_FAILURE
NUMBERS = NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED
CLOCK = NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED
LISTENER = NotificationKind.CAPTURE_INGEST_UNAVAILABLE


class Provider:
    def __init__(self):
        self.state = "running"
        self.nodes = {}

    def set(self, node, state, *reasons):
        self.nodes[node] = CaptureNodeView(node, state, tuple(reasons))

    def __call__(self):
        return self.state, tuple(self.nodes.values())


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.sink = Sink()
        self.transport = Transport()
        self.service = NotificationService(self.sink,
                                           SlackDelivery(endpoint(), opener=self.transport))
        self.addCleanup(self.service.close)
        self.provider = Provider()
        self.monitor = CaptureNodeHealthMonitor(self.provider)
        self.node = uuid4()

    def drain(self, at=AT):
        status = self.monitor.drain(self.service, at=at, monotonic=self.clock.value)
        self.service.poll()
        return status

    def advance(self, seconds):
        self.clock.value += seconds

    def kinds(self):
        return sorted(event.kind.value for event in self.sink.rows.values())

    def test_a_storage_failure_is_notified_at_once_and_once_per_episode(self):
        self.provider.set(self.node, "degraded", "storage_unavailable")
        status = self.drain()
        self.assertEqual(self.kinds(), [STORAGE.value])
        self.assertEqual((status.degraded_nodes, status.held_notices), (1, 0))
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [STORAGE.value])
        # Recovery is not notified; a new outage is a new episode.
        self.provider.set(self.node, "online")
        self.drain()
        self.assertEqual(self.kinds(), [STORAGE.value])
        self.provider.set(self.node, "degraded", "storage_unavailable")
        self.drain(AT + timedelta(hours=1))
        self.assertEqual(self.kinds(), [STORAGE.value, STORAGE.value])

    def test_renumbered_disk_and_clock_wait_five_minutes(self):
        for kind, reason in ((NUMBERS, "storage_device_numbers_stale"),
                             (CLOCK, "clock_offset"), (CLOCK, "clock_uncertain")):
            with self.subTest(reason=reason):
                self.sink.rows.clear()
                node = uuid4()
                self.provider.nodes.clear()
                self.provider.set(node, "degraded", reason)
                self.drain()
                self.advance(NOTICE_AFTER_SECONDS - 1)
                self.drain()
                self.assertEqual(self.kinds(), [])
                self.advance(1)
                self.drain()
                self.assertEqual(self.kinds(), [kind.value])

    def test_a_short_episode_is_not_notified(self):
        self.provider.set(self.node, "degraded", "clock_step")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS - 10)
        self.provider.set(self.node, "online")
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [])

    def test_unconfigured_capture_and_unknown_reasons_are_never_notified(self):
        self.provider.set(self.node, "degraded", "capture_unconfigured", "other")
        self.drain()
        self.advance(3600)
        status = self.drain()
        self.assertEqual(self.kinds(), [])
        self.assertEqual(status.degraded_nodes, 1)

    def test_an_offline_node_keeps_its_episode_without_becoming_due(self):
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.provider.set(self.node, "offline")
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [])
        # Back with the same reason: the episode is older than 5 min.
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.assertEqual(self.kinds(), [CLOCK.value])

    def test_time_offline_does_not_make_a_recovered_episode_owed(self):
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.advance(60)
        self.provider.set(self.node, "offline")
        self.drain()
        self.advance(3600)
        self.provider.set(self.node, "online")
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [])

    def test_a_forgotten_node_drops_its_episodes(self):
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        del self.provider.nodes[self.node]
        self.drain()
        # Re-paired and back with the same reason after 5 min: a new episode,
        # not the forgotten one.
        self.advance(NOTICE_AFTER_SECONDS)
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.assertEqual(self.kinds(), [])

    def test_each_node_has_its_own_hourly_cap(self):
        other = uuid4()
        for index in range(HOURLY_LIMIT + 1):
            self.provider.set(self.node, "degraded", "storage_unavailable")
            self.provider.set(other, "degraded", "storage_unavailable")
            status = self.drain(AT + timedelta(minutes=index))
            self.provider.set(self.node, "online")
            self.provider.set(other, "online")
            self.drain(AT + timedelta(minutes=index))
            self.advance(60)
        counts = [event.kind for event in self.sink.rows.values()]
        self.assertEqual(len(counts), 2 * HOURLY_LIMIT)
        self.assertEqual(status.held_notices, 2)
        # The held episodes recovered meanwhile: sent once the hour frees,
        # saying so.
        self.advance(3600)
        self.drain(AT + timedelta(hours=2))
        self.assertEqual(len(self.sink.rows), 2 * HOURLY_LIMIT + 2)
        texts = [text for text in self.texts() if text.endswith("(already recovered)")]
        self.assertEqual(texts, ["ServerSentinel critical alert: capture_node_storage_failure"
                                 " (already recovered)"] * 2)

    def texts(self):
        import json
        import time
        for _ in range(1000):
            self.service.poll()
            if not self.service.pending_count:
                break
            time.sleep(0.01)
        return [json.loads(request.data)["text"] for request, _ in self.transport.requests]

    def test_an_unrecorded_notice_is_retried(self):
        self.provider.set(self.node, "degraded", "storage_unavailable")
        original = self.service.record
        self.service.record = lambda *args, **kwargs: DeliveryResult.FAILED
        status = self.drain()
        self.assertEqual((self.kinds(), status.held_notices), ([], 1))
        self.service.record = original
        self.drain()
        self.assertEqual(self.kinds(), [STORAGE.value])

    def test_notices_are_value_free_and_named_per_episode(self):
        self.provider.set(self.node, "degraded", "storage_unavailable")
        self.drain()
        self.provider.set(self.node, "online")
        self.drain()
        self.provider.set(self.node, "degraded", "storage_unavailable")
        self.drain(AT + timedelta(minutes=1))
        events = list(self.sink.rows.values())
        self.assertEqual(len({event.event_id for event in events}), 2)
        for text in self.texts():
            self.assertNotIn(str(self.node), text)
            self.assertEqual(text, "ServerSentinel critical alert: capture_node_storage_failure")

    def test_attention_notices_are_not_critical(self):
        self.provider.set(self.node, "degraded", "storage_device_numbers_stale")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS)
        self.drain()
        self.assertEqual(self.texts(), [
            "ServerSentinel attention notice: capture_node_device_numbers_changed"])

    def test_a_listener_not_running_for_five_minutes_is_notified_once(self):
        for state in ("starting", "unavailable"):
            with self.subTest(state=state):
                self.sink.rows.clear()
                self.provider.state = state
                status = self.drain()
                self.assertTrue(status.listener_unavailable)
                self.advance(NOTICE_AFTER_SECONDS)
                self.drain()
                self.advance(3600)
                self.drain()
                self.assertEqual(self.kinds(), [LISTENER.value])
                self.provider.state = "running"
                self.assertFalse(self.drain().listener_unavailable)
        for state in ("disabled", "stopped"):
            with self.subTest(state=state):
                self.sink.rows.clear()
                self.provider.state = state
                self.drain()
                self.advance(3600)
                self.drain()
                self.assertEqual(self.kinds(), [])

    def test_a_listener_that_recovers_within_five_minutes_is_not_notified(self):
        self.provider.state = "unavailable"
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS - 1)
        self.provider.state = "running"
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [])

    def test_the_registry_view_carries_state_and_reason_words(self):
        clock = [0.0]
        registry = CaptureNodeHealthRegistry(stale_after_seconds=30, monotonic=lambda: clock[0])
        registry.connected(self.node, 1)
        self.assertEqual(registry.nodes(), ((self.node, "offline", ()),))
        registry.heartbeat(1, NodeHeartbeat(self.node, 1, "degraded", ("storage_unavailable",),
                                            "failed", "online", 0))
        self.assertEqual(registry.nodes(), ((self.node, "degraded", ("storage_unavailable",)),))
        clock[0] = 31
        self.assertEqual(registry.nodes()[0][1], "offline")


class RuntimeWiringTests(RuntimeFixture):
    async def test_an_unavailable_listener_is_notified_through_the_runtime(self):
        values = dict(
            integrity_probe=self.probe, slack_opener=self.transport, utcnow=self.clock.utcnow,
            monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0)
        from tests.test_recording import SyntheticValidator
        application = create_app(self.settings, monitoring=self.configuration(),
                                 monitoring_dependencies=MonitoringDependencies(
                                     segment_validator=SyntheticValidator(), **values),
                                 capture_ingest_unavailable=True)
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertIsNotNone(runtime.dependencies.capture_nodes)
            await runtime.call(runtime.tick)
            self.assertTrue(runtime.status.capture_ingest_unavailable)
            self.clock.advance(timedelta(seconds=NOTICE_AFTER_SECONDS))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertIn(("capture_ingest_unavailable", "sent"), self.events())
            self.assertIn("ServerSentinel critical alert: capture_ingest_unavailable",
                          self.slack_texts())
            summary = await runtime.call(runtime._summary, self.clock.utcnow())
            self.assertEqual((summary.agents_online, summary.agents_offline), (0, 0))

    async def test_no_monitor_without_a_capture_ingest_section(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            self.assertIsNone(application.state.monitoring.dependencies.capture_nodes)

    async def test_the_application_owns_the_monitor(self):
        with self.assertRaises(TypeError):
            self.application(capture_nodes=CaptureNodeHealthMonitor(lambda: ("disabled", ())))


if __name__ == "__main__":
    unittest.main()
