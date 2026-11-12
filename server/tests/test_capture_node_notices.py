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
from tests.test_capture_mtls import CaptureTlsHarness, Owner
from tests.test_monitoring_runtime import RuntimeFixture
from tests.test_storage_notifications import Transport, endpoint
import unittest


AT = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
STORAGE = NotificationKind.CAPTURE_NODE_STORAGE_FAILURE
NUMBERS = NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED
CLOCK = NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED
LISTENER = NotificationKind.CAPTURE_INGEST_UNAVAILABLE
LOST = NotificationKind.CAPTURE_NODE_HEARTBEAT_LOST


class Provider:
    def __init__(self):
        self.state = "running"
        self.nodes = {}
        # Issue #397: the ledger's active nodes (None: not readable).
        self.expected = None

    def set(self, node, state, *reasons):
        self.nodes[node] = CaptureNodeView(node, state, tuple(reasons))

    def __call__(self):
        return self.state, tuple(self.nodes.values()), self.expected


class MonitorFixture:
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

    def texts(self):
        import json
        import time
        for _ in range(1000):
            self.service.poll()
            if not self.service.pending_count:
                break
            time.sleep(0.01)
        return [json.loads(request.data)["text"] for request, _ in self.transport.requests]


class MonitorTests(MonitorFixture, unittest.TestCase):

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
        self.advance(200)
        self.provider.set(self.node, "offline")
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [])
        # Back with the same reason: only the 200 s observed count so far.
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS - 201)
        self.drain()
        self.assertEqual(self.kinds(), [])
        self.advance(1)
        self.drain()
        self.assertEqual(self.kinds(), [CLOCK.value])

    def fill_cap(self, at=AT):
        for index in range(HOURLY_LIMIT):
            self.provider.set(self.node, "degraded", "storage_unavailable")
            self.drain(at + timedelta(minutes=index))
            self.provider.set(self.node, "online")
            self.drain(at + timedelta(minutes=index))
        self.assertEqual(len(self.sink.rows), HOURLY_LIMIT)

    def test_a_held_notice_survives_the_node_going_offline(self):
        # PR #408 review: owed once it reached its delay while observed.
        self.fill_cap()
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS)
        self.assertEqual(self.drain().held_notices, 1)
        self.provider.set(self.node, "offline")
        self.advance(1800)
        self.assertEqual(self.drain().held_notices, 1)
        self.advance(1800)
        self.drain()
        self.assertIn(CLOCK.value, self.kinds())

    def test_a_delay_reached_just_before_going_offline_is_owed(self):
        # Observed degraded for the whole 5 min; offline seen at that drain.
        self.fill_cap()
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS)
        self.provider.set(self.node, "offline")
        self.assertEqual(self.drain().held_notices, 1)
        self.provider.set(self.node, "online")
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertIn(CLOCK.value, self.kinds())

    def test_a_held_recovered_notice_is_not_lost_to_a_short_new_episode(self):
        # PR #408 review: a newer short episode does not replace it.
        self.fill_cap()
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS)
        self.drain()
        self.provider.set(self.node, "online")
        self.drain()
        self.provider.set(self.node, "degraded", "clock_offset")
        self.drain()
        self.advance(120)
        self.provider.set(self.node, "online")
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds().count(CLOCK.value), 1)
        self.assertIn("ServerSentinel attention notice: capture_node_clock_degraded"
                      " (already recovered)", self.texts())

    def test_the_restored_hour_counts_against_every_node(self):
        # PR #408 review: a restart loop cannot exceed the cap.
        self.monitor.restore_window([(uuid4(), 60.0)] * HOURLY_LIMIT, monotonic=self.clock.value)
        self.provider.set(self.node, "degraded", "storage_unavailable")
        self.assertEqual(self.drain().held_notices, 1)
        self.assertEqual(self.kinds(), [])
        self.advance(3600 - 60)
        self.drain()
        self.assertEqual(self.kinds(), [STORAGE.value])

    def test_a_full_queue_keeps_the_notice_owed_with_its_first_time(self):
        # PR #408 review: the camera convention (can_accept, first `at`).
        self.provider.set(self.node, "degraded", "storage_unavailable")
        original = self.service.can_accept
        self.service.can_accept = lambda event_id: False
        self.assertEqual(self.drain().held_notices, 1)
        self.service.can_accept = original
        self.drain(AT + timedelta(minutes=5))
        [event] = self.sink.rows.values()
        self.assertEqual(event.at, AT)

    def test_only_notified_reasons_count_as_degraded(self):
        self.provider.set(self.node, "degraded", "capture_unconfigured")
        status = self.drain()
        self.assertEqual((status.degraded_nodes, status.notable_degraded_nodes), (1, 0))
        self.provider.set(self.node, "degraded", "capture_unconfigured", "clock_offset")
        self.assertEqual(self.drain().notable_degraded_nodes, 1)

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


class HeartbeatLossTests(MonitorFixture, unittest.TestCase):
    """Issue #397 (Owner decision 2026-11-12)."""

    def setUp(self):
        super().setUp()
        self.provider.expected = (self.node,)

    def test_a_node_that_never_connects_is_notified_after_five_minutes(self):
        status = self.drain()
        self.assertEqual(status.offline_nodes, 1)
        self.advance(NOTICE_AFTER_SECONDS - 1)
        self.drain()
        self.assertEqual(self.kinds(), [])
        self.advance(1)
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [LOST.value])
        self.assertEqual(self.texts(),
                         ["ServerSentinel critical alert: capture_node_heartbeat_lost"])

    def test_a_node_that_goes_quiet_is_notified_once_and_recovery_is_silent(self):
        self.provider.set(self.node, "online")
        self.drain()
        self.provider.set(self.node, "offline")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS)
        self.drain()
        self.provider.set(self.node, "online")
        self.drain()
        self.assertEqual(self.kinds(), [LOST.value])
        # A later loss is a new episode.
        self.provider.set(self.node, "offline")
        self.drain(AT + timedelta(hours=1))
        self.advance(NOTICE_AFTER_SECONDS)
        self.drain(AT + timedelta(hours=1))
        self.assertEqual(self.kinds(), [LOST.value, LOST.value])

    def test_a_short_gap_is_not_notified(self):
        self.provider.set(self.node, "offline")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS - 10)
        self.provider.set(self.node, "degraded", "capture_unconfigured")
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [])

    def test_a_revoked_node_is_not_watched(self):
        self.drain()
        self.provider.expected = ()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.kinds(), [])

    def test_no_loss_notice_while_the_listener_is_down_or_the_ledger_unreadable(self):
        for index, change in enumerate(({"state": "unavailable"}, {"expected": None})):
            # Each episode its own time, so its own event ID.
            at = AT + timedelta(days=index)
            with self.subTest(change=change):
                self.sink.rows.clear()
                self.monitor = CaptureNodeHealthMonitor(self.provider)
                self.provider.state, self.provider.expected = "running", (self.node,)
                self.drain(at)
                for name, value in change.items():
                    setattr(self.provider, name, value)
                self.drain(at)
                self.advance(3600)
                self.drain(at)
                self.assertNotIn(LOST.value, self.kinds())
                # Back: only observed time counts, so it is due 5 min later.
                self.provider.state, self.provider.expected = "running", (self.node,)
                self.drain(at)
                self.assertNotIn(LOST.value, self.kinds())
                self.advance(NOTICE_AFTER_SECONDS)
                self.drain(at)
                self.assertIn(LOST.value, self.kinds())

    def held_loss(self):
        """A loss notice owed and held by the cap; the registry forgot the node."""
        for index in range(HOURLY_LIMIT):
            self.provider.set(self.node, "degraded", "storage_unavailable")
            self.drain(AT + timedelta(minutes=index))
            self.provider.set(self.node, "online")
            self.drain(AT + timedelta(minutes=index))
        del self.provider.nodes[self.node]
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS)
        self.assertEqual(self.drain().held_notices, 1)

    def test_a_revoked_node_loses_its_held_loss_notice(self):
        self.held_loss()
        self.provider.expected = ()
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertNotIn(LOST.value, self.kinds())

    def test_an_unreadable_ledger_keeps_a_held_loss_notice(self):
        self.held_loss()
        self.provider.expected = None
        self.drain()
        self.provider.expected = (self.node,)
        self.advance(3600)
        self.drain()
        self.assertIn(LOST.value, self.kinds())

    def test_the_loss_notice_shares_the_node_cap(self):
        for index in range(HOURLY_LIMIT):
            self.provider.set(self.node, "degraded", "storage_unavailable")
            self.drain(AT + timedelta(minutes=index))
            self.provider.set(self.node, "online")
            self.drain(AT + timedelta(minutes=index))
        self.provider.set(self.node, "offline")
        self.drain()
        self.advance(NOTICE_AFTER_SECONDS)
        status = self.drain()
        self.assertNotIn(LOST.value, self.kinds())
        self.assertEqual(status.held_notices, 1)
        self.advance(3600)
        self.drain()
        self.assertIn(LOST.value, self.kinds())


class ActiveNodeLedgerTests(CaptureTlsHarness):
    """Issue #397: the nodes the Main expects heartbeats from."""

    def test_only_nodes_with_an_active_credential_are_expected(self):
        first = self._paired_node("a")[0].node_id
        second = self._paired_node("b")[0].node_id
        pending = self._paired_node("c", activate=False)[0].node_id
        self.assertEqual(set(self.ledger.active_node_ids()), {first, second})
        self.ledger.revoke(Owner(), "owner", node_id=second)
        self.assertEqual(self.ledger.active_node_ids(), (first,))
        self.assertNotIn(pending, self.ledger.active_node_ids())


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
            self.application(capture_nodes=CaptureNodeHealthMonitor(lambda: ("disabled", (), None)))


if __name__ == "__main__":
    unittest.main()
