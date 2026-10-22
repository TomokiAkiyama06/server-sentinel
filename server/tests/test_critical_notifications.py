"""Issue #26: confirmed scene critical events notify the Owner through #21.

Disposable SQLite files, generated observations and an intercepted Slack
transport only. No real Slack endpoint, camera, host or network is used.
"""

import asyncio
from concurrent.futures import Future
from contextlib import closing, contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
import json
import queue
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from uuid import uuid4

from app.cameras.registry.models import SourceType
from app.detection.roi.runtime import SceneMonitoringConfiguration, SceneMonitoringDependencies
from app.logging import Event
from app.main import create_app
from app.monitoring.runtime import MonitoringDependencies
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from app.presence.delivery import ActionResult, NotificationAdapter
from app.presence.models import Kind
from app.presence.runtime import (
    DISPATCH_BATCH, CriticalDispatcher, SceneTimeline, SceneTimelineConfiguration,
    TimelineNotPinned,
)
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_detector_roi import HEIGHT, WIDTH, pixels, policy
from tests.test_monitoring_runtime import RuntimeFixture
from tests.test_presence import NOW, MockAccess, observation
from tests.test_recording import SyntheticValidator
from tests.test_scene_runtime import MOVED, OTHER, binding, calibration_for
from tests.test_storage_notifications import Transport, endpoint


ALERT = "ServerSentinel critical alert: "


class GatedTransport(Transport):
    """Slack double whose POSTs wait until the test opens the gate."""

    def __init__(self):
        super().__init__()
        self.gate = threading.Event()

    def open(self, request, *, timeout):
        self.gate.wait(10)
        return super().open(request, timeout=timeout)


def texts(transport):
    return [json.loads(request.data)["text"] for request, _ in transport.requests]


class Store:
    """In-memory durable sink keyed by event ID, like `NotificationEventStore`."""

    def __init__(self):
        self.rows = {}
        self.refuse = False

    def __call__(self, event):
        if self.refuse:
            raise RuntimeError("synthetic STORAGE_HARD_STOP")
        self.rows[event.event_id] = event


class Fixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as db:
            migrate(db, APPLICATION_MIGRATIONS)
        self.store = Store()

    def notifications(self, transport=None, *, capacity=16, slack=True):
        service = NotificationService(
            self.store, SlackDelivery(endpoint(), opener=transport or Transport()) if slack else None,
            queue_capacity=capacity)
        self.addCleanup(service.close)
        return service

    def presence(self, service, **changes):
        return PresenceService(
            self.database, reservation=nullcontext,
            notifications=NotificationAdapter(lambda: service, NotificationKind, provided=True),
            **changes)

    def deliveries(self):
        with closing(sqlite3.connect(self.database.path)) as db:
            return dict(((row[0], row[1]), row[2]) for row in db.execute(
                "SELECT observation, action, state FROM presence_deliveries"))

    def state(self, identifier, action="notification"):
        return self.deliveries()[(str(identifier), action)]

    def drain(self, service, transport, count):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            service.poll()
            if len(transport.requests) >= count and service.pending_count == 0:
                return
            time.sleep(0.01)
        self.fail("synthetic delivery did not finish")


class CanAcceptTests(Fixture, unittest.TestCase):
    def test_capacity_closed_queue_and_owner_thread(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport, capacity=1)
        first, second = uuid4(), uuid4()
        self.assertTrue(service.can_accept(first))
        service.record(NotificationKind.SERVER_MOVEMENT, at=NOW, confirmed=True, event_id=first)
        # The pending event still fits (it coalesces); a new one does not.
        self.assertTrue(service.can_accept(first))
        self.assertFalse(service.can_accept(second))
        transport.gate.set()
        self.drain(service, transport, 1)
        self.assertTrue(service.can_accept(second))
        service.close()
        self.assertFalse(service.can_accept(second))
        with self.assertRaises(ValueError):
            service.can_accept("not-a-uuid")
        errors = []

        def elsewhere():
            try:
                service.can_accept(first)
            except RuntimeError as error:
                errors.append(error)

        thread = threading.Thread(target=elsewhere)
        thread.start()
        thread.join()
        self.assertEqual(1, len(errors))

    def test_without_slack_every_event_is_accepted(self):
        service = self.notifications(slack=False, capacity=1)
        service.close()
        self.assertTrue(service.can_accept(uuid4()))


class AdapterTests(Fixture, unittest.TestCase):
    def test_missing_refusing_or_unanswerable_service_submits_nothing(self):
        class Refusing:
            def __init__(self, answer):
                self.answer, self.recorded = answer, []

            def can_accept(self, event_id):
                if isinstance(self.answer, Exception):
                    raise self.answer
                return self.answer

            def record(self, *arguments, **fields):
                self.recorded.append(fields)

        critical = observation(Kind.SERVER_MOVEMENT)
        self.assertIs(ActionResult.UNAVAILABLE, NotificationAdapter(
            lambda: None, NotificationKind, provided=True)(critical, None))
        for answer in (False, RuntimeError("wrong thread"), 1):
            service = Refusing(answer)
            with self.subTest(answer=answer):
                self.assertIs(ActionResult.UNAVAILABLE, NotificationAdapter(
                    service, NotificationKind)(critical, None))
                self.assertEqual([], service.recorded)
        with self.assertRaises(ValueError):
            NotificationAdapter(None, NotificationKind, provided=True)

    def test_only_confirmed_critical_observations_are_notified(self):
        adapter = NotificationAdapter(self.notifications(), NotificationKind)
        for item in (observation(Kind.PERSON), observation(Kind.CAMERA_TAMPER, confirmed=False)):
            with self.subTest(kind=item.kind), self.assertRaises(ValueError):
                adapter(item, None)


class PresenceNotificationTests(Fixture, unittest.TestCase):
    def test_confirmed_events_send_one_fixed_category_message_each(self):
        transport = Transport()
        service = self.notifications(transport)
        presence = self.presence(service)
        movement = presence.record(observation(Kind.SERVER_MOVEMENT))
        tamper = presence.record(observation(Kind.CAMERA_TAMPER, at=NOW + timedelta(seconds=1)))
        self.assertEqual(4, presence.dispatch_pending())
        self.assertEqual("queued", self.state(movement.identifier))
        # No evidence-preservation port: recorded unavailable, never pending.
        self.assertEqual("unavailable", self.state(movement.identifier, "evidence"))
        self.drain(service, transport, 2)
        self.assertEqual("delivered", self.state(movement.identifier))
        self.assertEqual("delivered", self.state(tamper.identifier))
        # Fixed category text only: no image, source, person, place or cause.
        self.assertEqual([ALERT + "server_movement", ALERT + "camera_tamper"], texts(transport))
        rows = self.store.rows
        self.assertEqual(DeliveryResult.SENT, rows[movement.identifier].delivery)
        self.assertTrue(rows[movement.identifier].confirmed)
        self.assertEqual(NotificationKind.CAMERA_TAMPER, rows[tamper.identifier].kind)
        status = presence.snapshot(now=NOW + timedelta(seconds=2), clock_trusted=True)
        self.assertEqual("armed", status["critical_notifications"])
        self.assertEqual("unavailable", status["critical_evidence"])
        # Retried dispatch never sends a delivered notification again.
        presence.dispatch_pending()
        self.drain(service, transport, 2)
        self.assertEqual(2, len(transport.requests))

    def test_unconfirmed_critical_and_ordinary_observations_notify_nobody(self):
        transport = Transport()
        service = self.notifications(transport)
        presence = self.presence(service)
        presence.record(observation(Kind.SERVER_MOVEMENT, confirmed=False))
        presence.record(observation(Kind.PERSON, at=NOW + timedelta(seconds=1)))
        self.assertEqual(0, presence.dispatch_pending())
        self.assertEqual([], transport.requests)
        self.assertEqual({}, self.store.rows)

    def test_a_full_queue_leaves_work_for_a_later_step_instead_of_failing_it(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport, capacity=1)
        presence = self.presence(service)
        first = presence.record(observation(Kind.SERVER_MOVEMENT))
        second = presence.record(observation(Kind.SERVER_MOVEMENT, at=NOW + timedelta(seconds=1)))
        presence.dispatch_pending()
        self.assertEqual("queued", self.state(first.identifier))
        # Nothing was submitted for the second: it is retried, not failed.
        self.assertEqual("unavailable", self.state(second.identifier))
        self.assertNotIn(second.identifier, self.store.rows)
        transport.gate.set()
        self.drain(service, transport, 1)
        presence.dispatch_pending()
        self.drain(service, transport, 2)
        self.assertEqual("delivered", self.state(first.identifier))
        self.assertEqual("delivered", self.state(second.identifier))
        self.assertEqual(2, len(transport.requests))

    def test_failed_delivery_stays_failed_and_is_never_resent_automatically(self):
        transport = Transport(error=RuntimeError("generated transport failure"))
        service = self.notifications(transport)
        presence = self.presence(service)
        item = presence.record(observation(Kind.CAMERA_TAMPER))
        presence.dispatch_pending()
        self.drain(service, transport, 1)
        self.assertEqual("failed", self.state(item.identifier))
        self.assertEqual(DeliveryResult.FAILED, self.store.rows[item.identifier].delivery)
        presence.dispatch_pending()
        self.drain(service, transport, 1)
        self.assertEqual(1, len(transport.requests))
        status = presence.snapshot(now=NOW + timedelta(seconds=1), clock_trusted=True)
        self.assertEqual("unavailable", status["critical_notifications"])

    def test_an_unconfigured_delivery_capability_is_unavailable_before_any_event(self):
        service = self.notifications(slack=False)
        for configured, expected in ((lambda: False, "unavailable"), (lambda: True, "armed"),
                                     (lambda: 1, "unavailable"), (self.raising, "unavailable")):
            presence = PresenceService(
                self.database, reservation=nullcontext,
                notifications=NotificationAdapter(lambda: service, NotificationKind,
                                                  provided=True, configured=configured))
            with self.subTest(expected=expected, configured=configured):
                status = presence.snapshot(now=NOW, clock_trusted=True)
                self.assertEqual(expected, status["critical_notifications"])
        with self.assertRaises(ValueError):
            NotificationAdapter(service, NotificationKind, configured=object())

    @staticmethod
    def raising():
        raise RuntimeError("synthetic probe failure")

    def test_disabled_slack_records_the_local_event_and_reports_the_path_unavailable(self):
        service = self.notifications(slack=False)
        presence = self.presence(service)
        item = presence.record(observation(Kind.SERVER_MOVEMENT))
        presence.dispatch_pending()
        self.assertEqual("disabled", self.state(item.identifier))
        self.assertEqual(DeliveryResult.DISABLED, self.store.rows[item.identifier].delivery)
        status = presence.snapshot(now=NOW + timedelta(seconds=1), clock_trusted=True)
        self.assertEqual("unavailable", status["critical_notifications"])


    def test_a_stalled_endpoint_with_a_backlog_costs_one_claim_per_step(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport, capacity=16)
        presence = self.presence(service)
        for index in range(100):
            presence.record(observation(Kind.CAMERA_TAMPER, at=NOW + timedelta(seconds=index)))
        results = [presence.dispatch_pending(limit=DISPATCH_BATCH) for _ in range(10)]
        # Never a full batch while the port refuses, so the dispatcher waits
        # its interval instead of rerunning at once.
        self.assertTrue(all(result < DISPATCH_BATCH for result in results), results)
        with closing(sqlite3.connect(self.database.path)) as db:
            attempts = db.execute("SELECT sum(attempts) FROM presence_deliveries "
                                  "WHERE action='notification'").fetchone()[0]
            queued = db.execute("SELECT count(*) FROM presence_deliveries "
                                "WHERE action='notification' AND state='queued'").fetchone()[0]
        self.assertEqual(16, queued)
        # 16 accepted submissions plus at most one refused claim per step.
        self.assertLessEqual(attempts, 16 + len(results))
        transport.gate.set()

    def test_disabled_slack_with_a_refused_local_write_stays_retryable(self):
        service = self.notifications(slack=False, capacity=1)
        presence = self.presence(service)
        self.store.refuse = True
        first = presence.record(observation(Kind.SERVER_MOVEMENT))
        second = presence.record(observation(Kind.SERVER_MOVEMENT, at=NOW + timedelta(seconds=1)))
        presence.dispatch_pending()
        # The first is retained for the local retry; nothing was sent, so the
        # action is retryable, never finalized as failed.
        self.assertEqual("unavailable", self.state(first.identifier))
        self.assertTrue(service.retained(first.identifier))
        # The retry buffer is full: the second is not even submitted.
        self.assertFalse(service.can_accept(second.identifier))
        self.assertEqual("pending", self.state(second.identifier))
        self.store.refuse = False
        presence.dispatch_pending()
        presence.dispatch_pending()
        self.assertEqual("disabled", self.state(first.identifier))
        self.assertEqual("disabled", self.state(second.identifier))
        self.assertEqual({first.identifier, second.identifier}, set(self.store.rows))

    def test_an_owner_requeue_of_a_running_delivery_completes_from_its_outcome(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport)
        presence = self.presence(service, access=MockAccess())
        item = presence.record(observation(Kind.SERVER_MOVEMENT))
        presence.dispatch_pending()
        self.assertEqual("queued", self.state(item.identifier))
        presence.requeue_action("owner", item.identifier, "notification",
                                now=NOW + timedelta(seconds=1), clock_trusted=True)
        presence.dispatch_pending()
        # The resubmission joined the delivery still running (no second POST)
        # and its new claim generation is completed by that outcome.
        self.assertEqual("queued", self.state(item.identifier))
        transport.gate.set()
        self.drain(service, transport, 1)
        self.assertEqual("delivered", self.state(item.identifier))
        self.assertEqual(1, len(transport.requests))

    def test_every_coalesced_callback_is_told_and_a_raising_one_is_retried_alone(self):
        transport = GatedTransport()
        self.addCleanup(transport.gate.set)
        service = self.notifications(transport)
        identifier, calls = uuid4(), []

        def first(result):
            calls.append(("first", result))

        def flaky(result):
            calls.append(("flaky", result))
            if len([call for call in calls if call[0] == "flaky"]) == 1:
                raise RuntimeError("synthetic presence write refused")

        for callback in (first, flaky):
            service.record(NotificationKind.CAMERA_TAMPER, at=NOW, confirmed=True,
                           event_id=identifier, on_complete=callback)
        transport.gate.set()
        deadline = time.monotonic() + 10
        while service.pending_count and time.monotonic() < deadline:
            service.poll()
            time.sleep(0.01)
        self.assertEqual([("first", DeliveryResult.SENT), ("flaky", DeliveryResult.SENT),
                          ("flaky", DeliveryResult.SENT)], calls)
        self.assertEqual(1, len(transport.requests))


def configuration(**changes):
    values = dict(maximum_source_latency=timedelta(seconds=30),
                  clock=lambda: (datetime.now(timezone.utc), True),
                  dispatch_interval_seconds=0.01, dispatch_backoff_seconds=0.08)
    values.update(changes)
    return SceneTimelineConfiguration(**values)


class ReconciliationTests(Fixture, unittest.TestCase):
    """A restart completes claims only from the durable notification row."""

    def timeline(self, port):
        timeline = SceneTimeline(configuration(), self.database, nullcontext, notifications=port)
        # Pinned as `open()` would; records below precede the dispatch.
        timeline._pin()
        return timeline

    def test_only_final_rows_complete_an_earlier_process_claim(self):
        # A port whose completion never arrives, like a process that stopped.
        earlier = self.timeline(lambda item, complete: ActionResult.QUEUED)
        sent, pending, absent, failed = (
            earlier.presence.record(observation(Kind.SERVER_MOVEMENT, at=NOW + timedelta(seconds=index)))
            for index in range(4))
        earlier.dispatch()
        for item in (sent, pending, absent, failed):
            self.assertEqual("queued", self.state(item.identifier))
        calls = []

        def reconcile(identifiers):
            calls.append(set(identifiers))
            return {sent.identifier: DeliveryResult.SENT, pending.identifier: DeliveryResult.PENDING,
                    failed.identifier: DeliveryResult.FAILED}

        submitted = []
        restarted = self.timeline(lambda item, complete: submitted.append(item) or ActionResult.QUEUED)
        restarted.dispatch(reconcile=reconcile)
        self.assertEqual([{sent.identifier, pending.identifier, absent.identifier, failed.identifier}],
                         calls)
        self.assertEqual("delivered", self.state(sent.identifier))
        self.assertEqual("failed", self.state(failed.identifier))
        # An uncertain or unknown POST is never resent automatically.
        self.assertEqual("queued", self.state(pending.identifier))
        self.assertEqual("queued", self.state(absent.identifier))
        self.assertEqual([], submitted)
        # Reconciliation runs once per process, before its own claims exist.
        restarted.dispatch(reconcile=reconcile)
        self.assertEqual(1, len(calls))

    def test_a_failed_reconciliation_is_retried_before_dispatching(self):
        timeline = self.timeline(lambda item, complete: ActionResult.QUEUED)
        timeline.presence.record(observation(Kind.SERVER_MOVEMENT))
        timeline.dispatch()
        restarted = self.timeline(lambda item, complete: ActionResult.QUEUED)
        attempts = []

        def reconcile(identifiers):
            attempts.append(identifiers)
            if len(attempts) == 1:
                raise RuntimeError("synthetic store unavailable")
            return {}

        with self.assertRaises(RuntimeError):
            restarted.dispatch(reconcile=reconcile)
        restarted.dispatch(reconcile=reconcile)
        self.assertEqual(2, len(attempts))

    def test_dispatch_never_pins_or_creates_the_database(self):
        timeline = SceneTimeline(configuration(), self.database, nullcontext,
                                 notifications=lambda item, complete: ActionResult.QUEUED)
        with self.assertRaises(TimelineNotPinned):
            timeline.dispatch()
        self.assertFalse(timeline._pinned.pinned)
        self.database.path.unlink()
        with self.assertRaises(Exception):
            timeline.dispatch()
        self.assertFalse(self.database.path.exists())

    def test_dispatch_configuration_is_bounded(self):
        for changes in (dict(dispatch_interval_seconds=0), dict(dispatch_backoff_seconds=float("inf")),
                        dict(dispatch_interval_seconds=2.0, dispatch_backoff_seconds=1.0),
                        dict(dispatch_settle_seconds=-1), dict(dispatch_settle_seconds=31)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                configuration(**changes)
        defaults = SceneTimelineConfiguration(
            maximum_source_latency=timedelta(seconds=30), clock=lambda: None)
        # Owner decision 2026-10-22: 5 s dispatch interval, 60 s backoff cap;
        # the shutdown wait (12 s) outlasts the 10 s Slack transport timeout.
        self.assertEqual((5.0, 60.0, 12.0), (defaults.dispatch_interval_seconds,
                                             defaults.dispatch_backoff_seconds,
                                             defaults.dispatch_settle_seconds))

    def test_dispatch_on_the_worker_never_waits_for_a_pin_held_by_another_thread(self):
        """Review of PR #316: `open()` holds `_pin_lock` while its admission
        waits for the single monitoring worker; a dispatch step queued on that
        worker ahead of the admission must not wait for the lock, or neither
        ever finishes."""
        # A daemon fake of the single monitoring worker: a regression blocks
        # it on `_pin_lock`, and the test then fails on its timeouts and the
        # process still exits (a ThreadPoolExecutor worker would hang it).
        executor = DaemonWorker()
        owner = executor.submit(threading.get_ident).result(5)

        @contextmanager
        def reservation():
            # The `MonitoringRuntime.reservation()` shape: direct on the
            # worker; elsewhere the worker parks holding it until the caller ends.
            if threading.get_ident() == owner:
                yield
                return
            granted, finished = threading.Event(), threading.Event()

            def hold():
                granted.set()
                finished.wait(10)

            future = executor.submit(hold)
            if not granted.wait(10):
                raise TimeoutError("synthetic admission not granted")
            try:
                yield
            finally:
                finished.set()
                future.result(10)

        timeline = SceneTimeline(configuration(), self.database, reservation,
                                 notifications=lambda item, complete: ActionResult.QUEUED)
        busy = threading.Event()
        executor.submit(busy.wait, 10)                   # a monitoring tick in progress
        step = executor.submit(timeline.dispatch)        # the dispatcher's step, queued
        opener = threading.Thread(target=timeline.open, daemon=True)
        opener.start()
        self.addCleanup(busy.set)
        deadline = time.monotonic() + 5
        while not timeline._pin_lock.locked() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(timeline._pin_lock.locked())     # open holds it, waiting
        busy.set()
        opener.join(5)
        self.assertFalse(opener.is_alive())
        self.assertTrue(timeline.opened)
        with self.assertRaises(TimelineNotPinned):
            step.result(5)
        # Once pinned, the next step on the worker dispatches normally.
        self.assertEqual(0, executor.submit(timeline.dispatch).result(5))
        timeline.finish(None)


class DaemonWorker:
    """One daemon thread running submitted calls in order, like the monitoring
    worker's single-thread executor, but never blocking interpreter exit."""

    def __init__(self):
        self._work = queue.Queue()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            future, function, arguments = self._work.get()
            try:
                future.set_result(function(*arguments))
            except BaseException as error:
                future.set_exception(error)

    def submit(self, function, *arguments):
        future = Future()
        self._work.put((future, function, arguments))
        return future


class DispatcherTests(Fixture, unittest.IsolatedAsyncioTestCase):
    def dispatcher(self, step, **changes):
        timeline = SceneTimeline(configuration(**changes), self.database, nullcontext)

        async def run_step(function):
            return await asyncio.to_thread(function)

        return CriticalDispatcher(timeline, run_step, step)

    async def test_failures_back_off_exponentially_to_the_bound_and_recover(self):
        outcomes = [RuntimeError("synthetic refusal")] * 5 + [0, DISPATCH_BATCH]

        def step():
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        dispatcher = self.dispatcher(step)
        delays = []
        with self.assertLogs("app.presence.runtime", level="INFO") as logs:
            for _ in range(7):
                delays.append(await dispatcher.once())
                if len(delays) == 5:
                    self.assertTrue(dispatcher.failing)
        self.assertEqual([0.02, 0.04, 0.08, 0.08, 0.08, 0.01, 0.0], delays)
        self.assertFalse(dispatcher.failing)
        failing = sum(Event.CRITICAL_DISPATCH_FAILING.value in line for line in logs.output)
        # First failure of the streak and every doubling (1, 2, 4), value-free.
        self.assertEqual(3, failing)
        self.assertEqual(1, sum(Event.CRITICAL_DISPATCH_RECOVERED.value in line
                                for line in logs.output))
        self.assertFalse(any("synthetic refusal" in line for line in logs.output))

    async def test_cancelling_the_loop_waits_for_the_step_in_flight(self):
        started, release, finished = threading.Event(), threading.Event(), []

        def step():
            started.set()
            release.wait(10)
            finished.append(True)
            return 0

        dispatcher = self.dispatcher(step)
        task = asyncio.create_task(dispatcher.run())
        self.assertTrue(await asyncio.to_thread(started.wait, 10))
        task.cancel()
        await asyncio.sleep(0.05)
        self.assertFalse(task.done())
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual([True], finished)

    def test_a_dispatcher_requires_its_timeline_and_step(self):
        with self.assertRaises(TypeError):
            CriticalDispatcher(object(), lambda step: None, lambda: 0)
        timeline = SceneTimeline(configuration(), self.database, nullcontext)
        with self.assertRaises(TypeError):
            CriticalDispatcher(timeline, None, lambda: 0)



class LifespanTests(RuntimeFixture):
    """Main lifespan: scene evidence -> presence -> monitoring notifications."""

    def scene_application(self, **timeline):
        remote = binding(OTHER, SourceType.REMOTE_AGENT, sample_interval_ns=1)
        rules = policy(maximum_gap_ns=10_000_000_000, confirmation_ns=1)
        return create_app(
            self.settings,
            monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0),
            scene_monitoring=SceneMonitoringConfiguration((remote,)),
            scene_monitoring_dependencies=SceneMonitoringDependencies(
                calibrations=lambda value: calibration_for(value, rules=rules),
                tick_seconds=0.01),
            scene_timeline=configuration(**timeline),
        )

    async def until(self, predicate, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.01)
        return predicate()

    async def offer(self, runtime, stream, luma):
        evaluated = runtime.status().sources[0].evaluated
        await asyncio.sleep(0.002)
        self.assertTrue(runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                           height=HEIGHT, pixels=luma))
        self.assertTrue(await self.until(lambda: runtime.status().sources[0].evaluated > evaluated))

    def rows(self, query):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute(query).fetchall()

    def critical_texts(self):
        return [text for text in self.slack_texts()
                if text in (ALERT + "server_movement", ALERT + "camera_tamper")]

    async def test_confirmed_server_movement_notifies_the_owner_once_across_restart(self):
        application = self.scene_application()
        self.assertIsNotNone(application.state.critical_dispatcher)
        timeline = application.state.scene_timeline
        runtime = application.state.scene_monitoring
        async with asyncio.timeout(30), application.router.lifespan_context(application):
            stream = uuid4()
            for luma in (pixels(), pixels(), MOVED, MOVED):
                await self.offer(runtime, stream, luma)
            self.assertTrue(await self.until(
                lambda: self.critical_texts() == [ALERT + "server_movement"]))
            self.assertTrue(await self.until(lambda: self.rows(
                "SELECT action, state FROM presence_deliveries ORDER BY action")
                == [("evidence", "unavailable"), ("notification", "delivered")]))
            identifier = self.rows("SELECT id FROM presence_observations "
                                   "WHERE kind='server_movement'")[0][0]
            # The same durable event row as the other immediate Owner alerts,
            # keyed by the observation identity; fixed category only.
            self.assertEqual([("server_movement", 1, "sent")], self.rows(
                "SELECT kind, confirmed, delivery FROM notification_events "
                f"WHERE event_id='{identifier}'"))
            status = timeline.presence.snapshot(now=datetime.now(timezone.utc), clock_trusted=True)
            self.assertEqual("armed", status["critical_notifications"])
            self.assertEqual("unavailable", status["critical_evidence"])
        # A restart over the same database sends nothing again.
        restarted = self.scene_application()
        async with asyncio.timeout(30), restarted.router.lifespan_context(restarted):
            await asyncio.sleep(0.2)
        self.assertEqual([ALERT + "server_movement"], self.critical_texts())

    async def test_work_queued_while_dispatch_steps_fail_is_sent_after_recovery(self):
        application = self.scene_application()
        timeline = application.state.scene_timeline
        async with asyncio.timeout(30), application.router.lifespan_context(application):
            monitoring = application.state.monitoring
            dispatcher = application.state.critical_dispatcher
            # A confirmed observation recorded while dispatch steps fail (a
            # stubbed step; the real admission refusal is the next test).
            original = monitoring.dispatch_notifications

            def refused(step):
                raise RuntimeError("synthetic refusal")

            monitoring.dispatch_notifications = refused
            with self.assertLogs("app.presence.runtime", level="INFO") as logs:
                timeline.presence.record(observation(Kind.CAMERA_TAMPER))
                self.assertTrue(await self.until(lambda: dispatcher.failing))
                self.assertEqual([], self.critical_texts())
                self.assertEqual([("pending",), ("pending",)], self.rows(
                    "SELECT state FROM presence_deliveries"))
                monitoring.dispatch_notifications = original
                self.assertTrue(await self.until(
                    lambda: ALERT + "camera_tamper" in self.slack_texts()))
                self.assertTrue(await self.until(lambda: not dispatcher.failing))
            self.assertTrue(any(Event.CRITICAL_DISPATCH_FAILING.value in line for line in logs.output))
            self.assertTrue(any(Event.CRITICAL_DISPATCH_RECOVERED.value in line for line in logs.output))
        self.assertEqual(1, self.slack_texts().count(ALERT + "camera_tamper"))

    async def test_a_refused_storage_admission_keeps_work_pending_until_it_recovers(self):
        application = self.scene_application(dispatch_interval_seconds=3600,
                                              dispatch_backoff_seconds=3600)
        timeline = application.state.scene_timeline
        async with asyncio.timeout(30), application.router.lifespan_context(application):
            dispatcher = application.state.critical_dispatcher
            item = timeline.presence.record(observation(Kind.CAMERA_TAMPER))
            # The recording filesystem is replaced: every admission, and so
            # the dispatch step, is refused by the real storage policy.
            detached = self.recordings.with_name("detached")
            self.recordings.rename(detached)
            self.recordings.mkdir(mode=0o700)
            with self.assertLogs("app.presence.runtime", level="INFO") as logs:
                await dispatcher.once()
                self.assertTrue(dispatcher.failing)
                self.assertEqual([("pending",), ("pending",)], self.rows(
                    "SELECT state FROM presence_deliveries"))
                self.assertEqual([], self.critical_texts())
                self.recordings.rmdir()
                detached.rename(self.recordings)
                await dispatcher.once()
                self.assertFalse(dispatcher.failing)
            self.assertTrue(any(Event.CRITICAL_DISPATCH_FAILING.value in line for line in logs.output))
            self.assertTrue(await self.until(lambda: self.critical_texts() == [ALERT + "camera_tamper"]))
            # Neither the dispatch loop nor the monitoring tick runs here, so
            # the completion is persisted by an explicit poll on the worker;
            # the POST may finish after the poll that followed the step.
            monitoring = application.state.monitoring
            self.assertEqual(0, await monitoring.call(monitoring.settle_notifications, 10))
            self.assertEqual([("sent",)], self.rows(
                f"SELECT delivery FROM notification_events WHERE event_id='{item.identifier}'"))
            self.assertEqual([("delivered",)], self.rows(
                "SELECT state FROM presence_deliveries WHERE action='notification'"))

    async def test_settle_waits_for_a_slow_delivery_and_gives_up_at_its_bound(self):
        self.transport = GatedTransport()
        self.addCleanup(self.transport.gate.set)
        application = self.scene_application(dispatch_interval_seconds=3600,
                                              dispatch_backoff_seconds=3600,
                                              dispatch_settle_seconds=0.2)
        timeline = application.state.scene_timeline
        try:
            async with asyncio.timeout(30), application.router.lifespan_context(application):
                monitoring = application.state.monitoring
                item = timeline.presence.record(observation(Kind.SERVER_MOVEMENT))
                await application.state.critical_dispatcher.once()
                started = time.monotonic()
                unsettled = await monitoring.call(monitoring.settle_notifications, 0.3)
                self.assertGreaterEqual(time.monotonic() - started, 0.3)
                self.assertGreaterEqual(unsettled, 1)
                self.assertEqual("queued", self.rows(
                    "SELECT state FROM presence_deliveries WHERE action='notification'")[0][0])
                self.transport.gate.set()
                self.assertEqual(0, await monitoring.call(monitoring.settle_notifications, 10))
                self.assertEqual("delivered", self.rows(
                    "SELECT state FROM presence_deliveries WHERE action='notification'")[0][0])
                self.assertEqual([("sent",)], self.rows(
                    f"SELECT delivery FROM notification_events WHERE event_id='{item.identifier}'"))
        finally:
            self.transport.gate.set()

    async def test_shutdown_gives_up_on_a_stalled_delivery_after_the_settle_bound(self):
        self.transport = GatedTransport()
        self.addCleanup(self.transport.gate.set)
        application = self.scene_application(dispatch_interval_seconds=3600,
                                              dispatch_backoff_seconds=3600,
                                              dispatch_settle_seconds=0.3)
        timeline = application.state.scene_timeline
        lifespan = application.router.lifespan_context(application)
        try:
            await lifespan.__aenter__()
            timeline.presence.record(observation(Kind.SERVER_MOVEMENT))
            started = time.monotonic()
            with self.assertLogs("app.main", level="ERROR") as logs:
                await asyncio.wait_for(lifespan.__aexit__(None, None, None), 30)
            self.assertGreaterEqual(time.monotonic() - started, 0.3)
            self.assertTrue(any(Event.CRITICAL_NOTIFICATIONS_UNSETTLED.value in line
                                for line in logs.output))
            # Submitted but unconfirmed: unresolved, never reported delivered.
            self.assertEqual("queued", self.rows(
                "SELECT state FROM presence_deliveries WHERE action='notification'")[0][0])
        finally:
            self.transport.gate.set()

    async def test_restart_reconciles_claims_from_the_stored_notification_rows(self):
        application = self.scene_application()
        timeline = application.state.scene_timeline
        async with asyncio.timeout(30), application.router.lifespan_context(application):
            # Current times: the restart's retention cleanup must not expire them.
            now = datetime.now(timezone.utc)
            sent = timeline.presence.record(observation(Kind.SERVER_MOVEMENT, at=now))
            uncertain = timeline.presence.record(
                observation(Kind.CAMERA_TAMPER, at=now + timedelta(milliseconds=1)))
            self.assertTrue(await self.until(lambda: self.rows(
                "SELECT count(*) FROM presence_deliveries "
                "WHERE action='notification' AND state='delivered'") == [(2,)]))
        self.assertEqual(2, len(self.critical_texts()))
        # As if the process had stopped after the POSTs: both completions were
        # lost; one result reached `notification_events`, the other did not.
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute("UPDATE presence_deliveries SET state='queued' WHERE action='notification'")
            db.execute("UPDATE notification_events SET delivery='pending' WHERE event_id=?",
                       (str(uncertain.identifier),))
            db.commit()
        restarted = self.scene_application()
        async with asyncio.timeout(30), restarted.router.lifespan_context(restarted):
            self.assertTrue(await self.until(lambda: self.rows(
                "SELECT state FROM presence_deliveries WHERE action='notification' "
                f"AND observation='{sent.identifier}'") == [("delivered",)]))
            await asyncio.sleep(0.2)
        # The uncertain one stays unresolved for an Owner requeue; nothing is
        # sent again by the restart.
        self.assertEqual([("queued",)], self.rows(
            "SELECT state FROM presence_deliveries WHERE action='notification' "
            f"AND observation='{uncertain.identifier}'"))
        self.assertEqual(2, len(self.critical_texts()))

    async def test_shutdown_submits_queued_work_and_waits_for_its_delivery(self):
        # The loop never runs during this test, so only shutdown dispatches.
        application = self.scene_application(dispatch_interval_seconds=3600,
                                              dispatch_backoff_seconds=3600)
        timeline = application.state.scene_timeline
        async with asyncio.timeout(30), application.router.lifespan_context(application):
            item = timeline.presence.record(observation(Kind.SERVER_MOVEMENT))
            self.assertEqual([], self.critical_texts())
        self.assertEqual([ALERT + "server_movement"], self.critical_texts())
        self.assertEqual([("sent",)], self.rows(
            f"SELECT delivery FROM notification_events WHERE event_id='{item.identifier}'"))
        self.assertEqual("delivered", self.rows(
            "SELECT state FROM presence_deliveries WHERE action='notification'")[0][0])

    async def test_path_health_follows_the_configured_slack_capability_from_the_start(self):
        for slack, expected in ((False, "unavailable"), (True, "armed")):
            with self.subTest(slack=slack):
                self.setUp()
                self.slack = slack
                application = self.scene_application()
                timeline = application.state.scene_timeline
                async with asyncio.timeout(30), application.router.lifespan_context(application):
                    # A fresh deployment, before any critical event.
                    self.assertTrue(await self.until(lambda: timeline.opened))
                    status = timeline.presence.snapshot(
                        now=datetime.now(timezone.utc), clock_trusted=True)
                    self.assertEqual(expected, status["critical_notifications"])
                    if not slack:
                        # The local event is still recorded, as `disabled`,
                        # and the path stays unavailable afterwards too.
                        item = timeline.presence.record(observation(
                            Kind.SERVER_MOVEMENT, at=datetime.now(timezone.utc)))
                        self.assertTrue(await self.until(lambda: self.rows(
                            "SELECT delivery FROM notification_events "
                            f"WHERE event_id='{item.identifier}'") == [("disabled",)]))
                        status = timeline.presence.snapshot(
                            now=datetime.now(timezone.utc), clock_trusted=True)
                        self.assertEqual("unavailable", status["critical_notifications"])
                        self.assertEqual([], self.critical_texts())

    async def test_without_monitoring_no_dispatcher_runs_and_the_path_stays_unavailable(self):
        remote = binding(OTHER, SourceType.REMOTE_AGENT)
        with closing(Database(self.settings.database_path).connect()) as db:
            migrate(db, APPLICATION_MIGRATIONS)
        application = create_app(
            self.settings, storage_reservation=nullcontext,
            scene_monitoring=SceneMonitoringConfiguration((remote,)),
            scene_timeline=configuration())
        self.assertIsNone(application.state.critical_dispatcher)
        self.assertIsNone(application.state.scene_timeline.presence.notifications)


if __name__ == "__main__":
    unittest.main()
