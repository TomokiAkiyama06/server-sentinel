"""Issue #318: a confirmed scene critical attempts Slack while its record is refused.

Disposable SQLite files, generated observations and an intercepted Slack
transport only. No real Slack endpoint, camera, host or network is used.
"""

import asyncio
from dataclasses import replace
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
import threading
import time
import unittest
from uuid import uuid4

from app.detection.roi.contracts import CriticalKind
from app.logging import Event
from app.notifications.service import NotificationKind
from app.notifications.slack import DeliveryResult
from app.presence.delivery import ActionResult, NotificationAdapter, UnrecordedCriticalAlerts
from app.presence.models import Kind
from app.presence.runtime import CriticalDispatcher, SceneTimeline

from tests.test_critical_notifications import ALERT, Fixture, GatedTransport, configuration, texts
from tests.test_presence import NOW, MockAccess, observation
from tests.test_presence_adapters import critical
from tests.test_storage_notifications import Transport


class Unrecorded(Fixture):
    """A notification service whose local event store is refused (hard stop)."""

    def adapter(self, service, *, configured=None):
        def outcomes(identifiers):
            if self.store.refuse or getattr(self, "lookup_fails", False):
                raise RuntimeError("synthetic STORAGE_HARD_STOP read")
            return {identifier: self.store.rows[identifier].delivery
                    for identifier in identifiers if identifier in self.store.rows}

        return NotificationAdapter(lambda: service, NotificationKind, provided=True,
                                   configured=configured, outcomes=outcomes)

    def presence_for(self, adapter, **changes):
        # The timeline itself admits writes again (storage recovered), while
        # `self.store.refuse` decides the notification event rows.
        from app.presence.service import PresenceService
        return PresenceService(self.database, reservation=nullcontext,
                               notifications=adapter, **changes)

    def settle(self, service, transport, count):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            service.poll()
            if len(transport.requests) >= count:
                return
            time.sleep(0.01)
        self.fail("synthetic delivery did not finish")


class HandOverTests(Unrecorded, unittest.TestCase):
    def test_a_refused_record_attempts_slack_once_with_the_fixed_category(self):
        transport = Transport()
        service = self.notifications(transport)
        alerts = UnrecordedCriticalAlerts(self.adapter(service))
        self.store.refuse = True
        item = observation(Kind.SERVER_MOVEMENT)
        with self.assertLogs("app.presence.delivery", level="WARNING") as logs:
            alerts.refused(item.identifier, CriticalKind.SERVER_MOVEMENT)
            # The scene runtime retries the refused record: no second attempt.
            alerts.refused(item.identifier, CriticalKind.SERVER_MOVEMENT)
            self.assertEqual(0, alerts.drain(at=NOW))
        self.settle(service, transport, 1)
        alerts.refused(item.identifier, CriticalKind.SERVER_MOVEMENT)
        self.assertEqual(0, alerts.drain(at=NOW))
        self.assertEqual([ALERT + "server_movement"], texts(transport))
        self.assertEqual((1, 0), (alerts.submitted, alerts.dropped))
        # Value-free log: the fixed event only, no identifier or kind.
        self.assertEqual([f"WARNING:app.presence.delivery:{Event.UNRECORDED_CRITICAL_ALERT_ATTEMPTED.value}"],
                         logs.output)
        # Its outcome cannot be written yet, so it stays in the service.
        self.assertTrue(service.in_flight(item.identifier))
        self.assertEqual({}, self.store.rows)
        self.store.refuse = False
        service.poll()
        self.assertFalse(service.in_flight(item.identifier))
        stored = self.store.rows[item.identifier]
        self.assertEqual((NotificationKind.SERVER_MOVEMENT, True, DeliveryResult.SENT),
                         (stored.kind, stored.confirmed, stored.delivery))

    def test_hand_over_never_touches_the_service_or_blocks_on_another_thread(self):
        class Untouchable:
            def __getattr__(self, name):
                raise AssertionError("service touched on the scene thread")

        alerts = UnrecordedCriticalAlerts(NotificationAdapter(Untouchable(), NotificationKind))
        finished = []
        thread = threading.Thread(target=lambda: finished.append(
            alerts.refused(uuid4(), CriticalKind.CAMERA_TAMPER)))
        thread.start()
        thread.join(5)
        self.assertEqual([None], finished)
        self.assertEqual(1, alerts.queued)

    def test_the_drain_runs_only_on_the_service_owner_thread(self):
        service = self.notifications(Transport())
        alerts = UnrecordedCriticalAlerts(self.adapter(service))
        alerts.refused(uuid4(), CriticalKind.CAMERA_TAMPER)
        failure = []

        def elsewhere():
            try:
                alerts.drain(at=NOW)
            except RuntimeError as error:
                failure.append(error)

        thread = threading.Thread(target=elsewhere)
        thread.start()
        thread.join(5)
        self.assertEqual(1, len(failure))
        self.assertEqual(1, alerts.queued)

    def test_without_slack_nothing_is_attempted(self):
        service = self.notifications(slack=False)
        alerts = UnrecordedCriticalAlerts(self.adapter(service, configured=lambda: False))
        alerts.refused(uuid4(), CriticalKind.SERVER_MOVEMENT)
        self.assertEqual(0, alerts.queued)
        self.assertEqual(0, alerts.drain(at=NOW))
        self.assertEqual({}, self.store.rows)

    def test_overflow_is_counted_and_logged_value_free(self):
        service = self.notifications(Transport())
        alerts = UnrecordedCriticalAlerts(self.adapter(service), capacity=2, remembered=4)
        with self.assertLogs("app.presence.delivery", level="WARNING") as logs:
            for _ in range(5):
                alerts.refused(uuid4(), CriticalKind.CAMERA_TAMPER)
        self.assertEqual((2, 3), (alerts.queued, alerts.dropped))
        # The first drop and every doubling: drops 1 and 2, not 3.
        self.assertEqual(2 * [f"WARNING:app.presence.delivery:{Event.UNRECORDED_CRITICAL_ALERT_DROPPED.value}"],
                         logs.output)
        with self.assertRaises(ValueError):
            UnrecordedCriticalAlerts(self.adapter(service), capacity=0)
        with self.assertRaises(ValueError):
            alerts.refused(uuid4(), Kind.PERSON)

    def test_at_most_half_of_the_queue_is_held_until_storage_returns(self):
        transport = Transport()
        service = self.notifications(transport, capacity=4)
        alerts = UnrecordedCriticalAlerts(self.adapter(service))
        self.store.refuse = True
        identifiers = [uuid4() for _ in range(3)]
        for identifier in identifiers:
            alerts.refused(identifier, CriticalKind.CAMERA_TAMPER)
        self.assertEqual(1, alerts.drain(at=NOW))
        self.settle(service, transport, 2)
        # Sent, but held in the service while the outcome rows are refused;
        # room stays for a recording-health or integrity alert.
        self.assertEqual(1, alerts.drain(at=NOW))
        self.assertEqual(2, len(transport.requests))
        self.assertEqual(2, service.pending_count)
        self.assertTrue(service.can_accept(uuid4()))
        self.store.refuse = False
        service.poll()
        self.assertEqual(0, alerts.drain(at=NOW))
        self.settle(service, transport, 3)
        self.assertEqual(3, len(transport.requests))
        self.assertEqual(set(identifiers), set(self.store.rows))

    def test_an_already_stored_or_dispatched_alert_is_not_attempted(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport)
        adapter = self.adapter(service)
        alerts = UnrecordedCriticalAlerts(adapter)
        presence = self.presence_for(adapter)
        item = presence.record(observation(Kind.CAMERA_TAMPER))
        presence.dispatch_pending()
        self.assertTrue(service.in_flight(item.identifier))
        # A transient record failure handed it over although the dispatcher
        # submitted it meanwhile: joined by identity, nothing sent twice.
        alerts.refused(item.identifier, CriticalKind.CAMERA_TAMPER)
        # Another time than the dispatched delivery's and an unreadable row:
        # only the in-flight check keeps it from a refused second submission.
        self.lookup_fails = True
        self.assertEqual(0, alerts.drain(at=NOW + timedelta(minutes=1)))
        self.lookup_fails = False
        self.assertFalse(service.delivery_failed)
        transport.gate.set()
        self.drain(service, transport, 1)
        self.assertEqual("delivered", self.state(item.identifier))
        other = uuid4()
        self.store.rows[other] = type("Row", (), {"delivery": DeliveryResult.SENT})()
        alerts.refused(other, CriticalKind.CAMERA_TAMPER)
        self.assertEqual(0, alerts.drain(at=NOW))
        self.assertEqual(1, len(transport.requests))
        self.assertEqual(0, alerts.submitted)


    def test_an_attempted_alert_is_not_attempted_again_while_its_row_is_unreadable(self):
        transport = Transport()
        service = self.notifications(transport)
        alerts = UnrecordedCriticalAlerts(self.adapter(service))
        identifier = uuid4()
        alerts.refused(identifier, CriticalKind.SERVER_MOVEMENT)
        alerts.drain(at=NOW)
        self.drain(service, transport, 1)
        self.assertFalse(service.in_flight(identifier))
        # Neither in flight nor readable: only the remembered attempt keeps a
        # later hand-over of the same observation from a second message.
        self.lookup_fails = True
        alerts.refused(identifier, CriticalKind.SERVER_MOVEMENT)
        alerts.escalate()
        self.assertEqual(0, alerts.drain(at=NOW + timedelta(minutes=1)))
        # Waits until nothing is pending, so a second POST would be counted.
        self.drain(service, transport, 1)
        self.assertEqual(1, len(transport.requests))
        self.assertEqual(1, alerts.submitted)

    def test_a_queue_of_one_still_attempts_one_alert(self):
        transport = Transport()
        service = self.notifications(transport, capacity=1)
        alerts = UnrecordedCriticalAlerts(self.adapter(service))
        self.store.refuse = True
        alerts.refused(uuid4(), CriticalKind.CAMERA_TAMPER)
        alerts.refused(uuid4(), CriticalKind.CAMERA_TAMPER)
        self.assertEqual(1, alerts.drain(at=NOW))
        self.settle(service, transport, 1)
        self.assertEqual({"attempted": 1, "waiting": 1, "dropped": 0, "untracked": 0},
                         alerts.counts())


class ClaimRefusedTests(Unrecorded, unittest.TestCase):
    """Recorded just before the hard stop, but the claim is refused (Issue #318)."""

    def setUp(self):
        super().setUp()
        self.refusing = False

    def reservation(self):
        @contextmanager
        def admission():
            if self.refusing:
                raise RuntimeError("synthetic STORAGE_HARD_STOP")
            yield

        return admission()

    def timeline(self, service):
        timeline = SceneTimeline(configuration(), self.database, self.reservation,
                                 notifications=self.adapter(service))
        timeline._pin()
        return timeline

    def refuse(self, refusing):
        # The timeline and the notification event rows share the storage.
        self.refusing = self.store.refuse = refusing

    def test_a_record_just_before_the_hard_stop_alerts_once_and_reconciles(self):
        transport = Transport()
        service = self.notifications(transport)
        timeline = self.timeline(service)
        item = critical(CriticalKind.SERVER_MOVEMENT, at=datetime.now(timezone.utc))
        timeline.recorder(item)
        self.assertEqual((item.identifier,), timeline.unrecorded.awaiting())
        # The disk is removed before the next dispatch step claims the row.
        self.refuse(True)
        with self.assertRaises(Exception):
            timeline.dispatch()
        self.assertEqual("pending", self.state(item.identifier))
        timeline.unrecorded.drain(at=NOW)
        self.settle(service, transport, 1)
        self.assertEqual([ALERT + "server_movement"], texts(transport))
        # Later failing steps attempt nothing again.
        with self.assertRaises(Exception):
            timeline.dispatch()
        self.assertEqual(0, timeline.unrecorded.drain(at=NOW))
        self.refuse(False)
        service.poll()
        timeline.dispatch()
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual((), timeline.unrecorded.awaiting())
        self.assertEqual([ALERT + "server_movement"], texts(transport))
        status = timeline.presence.snapshot(now=datetime.now(timezone.utc), clock_trusted=True)
        self.assertEqual({"attempted": 1, "waiting": 0, "dropped": 0, "untracked": 0},
                         status["unrecorded_critical_alerts"])

    def test_a_row_left_unavailable_for_queue_space_is_covered_too(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport, capacity=2)
        timeline = self.timeline(service)
        # Two other immediate alerts fill the notification queue.
        for _ in range(2):
            service.record(NotificationKind.RECORDING_HEALTH_FAILURE, at=NOW)
        item = critical(CriticalKind.CAMERA_TAMPER, at=datetime.now(timezone.utc))
        timeline.recorder(item)
        timeline.dispatch()
        self.assertEqual("unavailable", self.state(item.identifier))
        self.assertEqual((item.identifier,), timeline.unrecorded.awaiting())
        transport.gate.set()
        self.settle(service, transport, 2)
        service.poll()
        self.refuse(True)
        with self.assertRaises(Exception):
            timeline.dispatch()
        timeline.unrecorded.drain(at=NOW)
        self.settle(service, transport, 3)
        self.assertEqual(1, texts(transport).count(ALERT + "camera_tamper"))
        self.refuse(False)
        service.poll()
        timeline.dispatch()
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual(1, texts(transport).count(ALERT + "camera_tamper"))

    def test_a_replay_of_an_already_delivered_record_is_not_watched(self):
        # Codex P2 on dae0154d: an idempotent replay of an observation whose
        # notification was already delivered has no unclaimed work, so a
        # later hard stop with unreadable outcomes must not resend it.
        transport = Transport()
        service = self.notifications(transport)
        timeline = self.timeline(service)
        item = critical(CriticalKind.SERVER_MOVEMENT, at=datetime.now(timezone.utc))
        timeline.recorder(item)
        timeline.dispatch()
        self.settle(service, transport, 1)
        service.poll()
        timeline.dispatch()
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual((), timeline.unrecorded.awaiting())
        # The scene runtime hands the same observation over again.
        timeline.recorder(item)
        self.assertEqual((), timeline.unrecorded.awaiting())
        self.refuse(True)
        with self.assertRaises(Exception):
            timeline.dispatch()
        self.assertEqual(0, timeline.unrecorded.drain(at=NOW))
        self.assertEqual(0, timeline.unrecorded.submitted)
        self.assertEqual([ALERT + "server_movement"], texts(transport))

    def test_a_replay_whose_notification_is_still_unclaimed_stays_watched(self):
        service = self.notifications(Transport())
        timeline = self.timeline(service)
        item = critical(CriticalKind.CAMERA_TAMPER, at=datetime.now(timezone.utc))
        timeline.recorder(item)
        timeline.unrecorded.prune(timeline.unrecorded.awaiting(), ())
        timeline.recorder(item)
        self.assertEqual((item.identifier,), timeline.unrecorded.awaiting())

    def test_a_successful_step_stops_watching_and_overflow_is_counted(self):
        service = self.notifications(Transport())
        adapter = self.adapter(service)
        alerts = UnrecordedCriticalAlerts(adapter, watched=2)
        for _ in range(3):
            alerts.recorded(uuid4(), CriticalKind.CAMERA_TAMPER)
        self.assertEqual(2, len(alerts.awaiting()))
        self.assertEqual(1, alerts.counts()["untracked"])
        checked = alerts.awaiting()
        alerts.prune(checked, {checked[1]})
        self.assertEqual((checked[1],), alerts.awaiting())


class RecoveryTests(Unrecorded, unittest.TestCase):
    """After recovery the durable record reconciles with the attempted alert."""

    def attempt(self, service, adapter, transport, kind=Kind.SERVER_MOVEMENT):
        alerts = UnrecordedCriticalAlerts(adapter)
        item = observation(kind)
        self.store.refuse = True
        alerts.refused(item.identifier, kind)
        alerts.drain(at=NOW)
        return item

    def test_a_recorded_observation_takes_the_stored_outcome_without_resending(self):
        transport = Transport()
        service = self.notifications(transport)
        adapter = self.adapter(service)
        item = self.attempt(service, adapter, transport)
        self.settle(service, transport, 1)
        self.store.refuse = False
        service.poll()
        presence = self.presence_for(adapter)
        presence.record(item)
        # The notification row and the portless evidence row both progress.
        self.assertEqual(2, presence.dispatch_pending())
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual([ALERT + "server_movement"], texts(transport))

    def test_a_recorded_observation_joins_the_delivery_still_held(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport)
        adapter = self.adapter(service)
        item = self.attempt(service, adapter, transport, Kind.CAMERA_TAMPER)
        # The timeline accepts the record first; the POST is still running
        # and the event row is still refused.
        presence = self.presence_for(adapter)
        presence.record(item)
        presence.dispatch_pending()
        self.assertEqual("queued", self.state(item.identifier))
        transport.gate.set()
        self.settle(service, transport, 1)
        self.assertEqual("queued", self.state(item.identifier))
        self.store.refuse = False
        service.poll()
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual([ALERT + "camera_tamper"], texts(transport))

    def test_a_failed_attempt_stays_failed_until_an_owner_requeue_resends_it(self):
        transport = Transport(error=OSError("synthetic Slack outage"))
        service = self.notifications(transport)
        adapter = self.adapter(service)
        item = self.attempt(service, adapter, transport)
        self.settle(service, transport, 1)
        self.store.refuse = False
        service.poll()
        self.assertEqual(DeliveryResult.FAILED, self.store.rows[item.identifier].delivery)
        presence = self.presence_for(adapter, access=MockAccess())
        presence.record(item)
        presence.dispatch_pending()
        self.assertEqual("failed", self.state(item.identifier))
        self.assertEqual(1, len(transport.requests))
        transport.error = None
        presence.requeue_action("owner", item.identifier, "notification",
                                now=NOW + timedelta(seconds=1), clock_trusted=True)
        presence.dispatch_pending()
        self.drain(service, transport, 2)
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual(2, len(transport.requests))

    def test_a_stored_row_left_pending_by_an_earlier_process_is_uncertain(self):
        transport = Transport()
        service = self.notifications(transport)
        adapter = self.adapter(service)
        item = observation(Kind.CAMERA_TAMPER)
        self.store.rows[item.identifier] = type("Row", (), {"delivery": DeliveryResult.PENDING})()
        presence = self.presence_for(adapter)
        presence.record(item)
        presence.dispatch_pending()
        self.assertEqual("uncertain", self.state(item.identifier))
        self.assertEqual([], transport.requests)

    def test_an_unreadable_outcome_leaves_the_action_for_a_later_step(self):
        transport = Transport()
        service = self.notifications(transport)
        adapter = self.adapter(service)
        presence = self.presence_for(adapter)
        item = presence.record(observation(Kind.SERVER_MOVEMENT))
        self.store.refuse = True
        # Only the portless evidence row progresses.
        self.assertEqual(1, presence.dispatch_pending())
        self.assertEqual("unavailable", self.state(item.identifier))
        self.assertEqual([], transport.requests)

    def test_restart_during_hard_stop_sends_at_most_one_documented_duplicate(self):
        # Process 1 attempted the alert while storage was refused and ended
        # before its outcome row could be written.
        first_transport = Transport()
        first = self.notifications(first_transport)
        item = self.attempt(first, self.adapter(first), first_transport)
        self.settle(first, first_transport, 1)
        first.close()
        self.assertEqual({}, self.store.rows)
        # Process 2 starts while storage is still refused: it remembers
        # nothing and sends nothing on its own.
        second_transport = Transport()
        second = self.notifications(second_transport)
        adapter = self.adapter(second)
        alerts = UnrecordedCriticalAlerts(adapter)
        self.assertEqual(0, alerts.drain(at=NOW))
        self.assertEqual([], second_transport.requests)
        # Storage returns and the observation is recorded (a timeline that
        # kept it). No row proves the earlier attempt, so it is notified once
        # more: the one duplicate the Owner accepted (2026-10-22).
        self.store.refuse = False
        presence = self.presence_for(adapter)
        presence.record(item)
        presence.dispatch_pending()
        self.drain(second, second_transport, 1)
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual(1, len(second_transport.requests))
        # The process after that finds the row and sends nothing.
        third_transport = Transport()
        third = self.notifications(third_transport)
        third_presence = self.presence_for(self.adapter(third))
        self.assertEqual(0, third_presence.dispatch_pending())
        self.assertEqual([], third_transport.requests)


class RecorderTests(Unrecorded, unittest.TestCase):
    def critical(self):
        return critical(CriticalKind.CAMERA_TAMPER, at=datetime.now(timezone.utc))

    def test_a_refused_record_is_handed_over_and_still_raised(self):
        handed = []

        @contextmanager
        def refused():
            raise RuntimeError("synthetic STORAGE_HARD_STOP")
            yield

        timeline = SceneTimeline(configuration(), self.database, refused)
        timeline.recorder.refused = lambda identifier, kind: handed.append((identifier, kind))
        item = self.critical()
        with self.assertRaises(Exception):
            timeline.recorder(item)
        self.assertEqual([(item.identifier, CriticalKind.CAMERA_TAMPER)], handed)

    def test_a_raising_hand_over_never_changes_the_failure(self):
        timeline = SceneTimeline(configuration(), self.database, nullcontext)

        def raising(identifier, kind):
            raise RuntimeError("synthetic hand-over fault")

        timeline.recorder.refused = raising
        # Not pinned: the record fails like a refused admission.
        with self.assertRaises(ValueError):
            timeline.recorder(self.critical())

    def test_a_recorded_or_contract_refused_observation_is_not_handed_over(self):
        handed = []
        timeline = SceneTimeline(configuration(), self.database, nullcontext)
        timeline._pin()
        timeline.recorder.refused = lambda identifier, kind: handed.append(identifier)
        item = self.critical()
        timeline.recorder(item)
        conflict = replace(item, kind=CriticalKind.SERVER_MOVEMENT)
        with self.assertRaises(ValueError):
            timeline.recorder(conflict)
        self.assertEqual([], handed)

    def test_the_timeline_wires_the_hand_over_only_for_a_notification_adapter(self):
        service = self.notifications(Transport())
        adapter = self.adapter(service)
        timeline = SceneTimeline(configuration(), self.database, nullcontext, notifications=adapter)
        self.assertIsInstance(timeline.unrecorded, UnrecordedCriticalAlerts)
        self.assertEqual(timeline.unrecorded.refused, timeline.recorder.refused)
        plain = SceneTimeline(configuration(), self.database, nullcontext,
                              notifications=lambda item, complete: ActionResult.QUEUED)
        self.assertIsNone(plain.unrecorded)
        self.assertIsNone(plain.recorder.refused)


class DispatcherAlertTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def test_alerts_run_every_interval_while_the_dispatch_step_backs_off(self):
        timeline = SceneTimeline(configuration(dispatch_interval_seconds=0.01,
                                               dispatch_backoff_seconds=3600),
                                 self.database, nullcontext)
        steps, alerts = [], []

        def step():
            steps.append(1)
            raise RuntimeError("synthetic STORAGE_HARD_STOP")

        def alert():
            alerts.append(1)
            if len(alerts) == 2:
                raise RuntimeError("synthetic worker fault")
            return 0

        async def run_step(function):
            return function()

        dispatcher = CriticalDispatcher(timeline, run_step, step, alerts=alert)
        with self.assertLogs("app.presence.runtime", level="ERROR") as logs:
            task = asyncio.create_task(dispatcher.run())
            await asyncio.sleep(0.3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        # The step backs off exponentially (20, 40, 80, 160 ms ...), while
        # the alerts keep their 10 ms interval.
        self.assertLessEqual(len(steps), 6)
        self.assertGreater(len(alerts), 2 * len(steps))
        self.assertIn(f"ERROR:app.presence.runtime:{Event.UNRECORDED_CRITICAL_ALERTS_FAILING.value}",
                      logs.output)
        with self.assertRaises(TypeError):
            CriticalDispatcher(timeline, run_step, step, alerts=1)


if __name__ == "__main__":
    unittest.main()
