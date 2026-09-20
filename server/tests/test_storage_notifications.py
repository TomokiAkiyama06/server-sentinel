"""No actual Slack request: bounded transport mocks, real local schedule database."""

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import HTTPError
from uuid import uuid4
from zoneinfo import ZoneInfo
import contextlib
import io
import json
from queue import Queue
import sqlite3
import threading
import unittest

from app.notifications.schedule import DailySummaryScheduler, notification_migration
from app.notifications.service import DailySummary, NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, NoRedirect, SlackDelivery, SlackEndpoint
from app.notifications.worker import DeliveryWorker
from app.storage.migrations import BUILTIN_MIGRATIONS, migrate
from app.storage.policy import StorageState


def endpoint():
    # Generated dummy components never identify a real Slack workspace/webhook.
    return SlackEndpoint("https://hooks.slack.com/" + "/".join(
        ("services", "T" + "0" * 8, "B" + "0" * 8, "generated_dummy_value")))


def summary():
    return DailySummary(3600, 2, 1, 1, 1, 0, 20, 50, 4, 2, 6, 1, 1234, StorageState.PRESSURE)


def drain(test, service):
    while service.pending_count:
        test.assertTrue(service._worker.ready.wait(2), 'mock delivery did not finish')
        service.poll()


class Reply:
    def __init__(self, status=200, body=b"ok"):
        self.status, self.body = status, body

    def read(self, size):
        return self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class Transport:
    def __init__(self, reply=None, error=None):
        self.requests = []
        self.reply, self.error = reply or Reply(), error

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return self.reply


class NotificationTests(unittest.TestCase):
    def test_delivery_result_readiness_is_atomic_with_poll_drain(self):
        entered, release, drained = threading.Event(), threading.Event(), threading.Event()

        class PausingResults:
            def __init__(self):
                self.queue = Queue()

            def put_nowait(self, value):
                self.queue.put_nowait(value)
                entered.set()
                release.wait(2)

            def get_nowait(self):
                return self.queue.get_nowait()

        class SentTransport:
            def send(self, _):
                return DeliveryResult.SENT

        worker = DeliveryWorker(SentTransport(), 1)
        worker._results = PausingResults()
        self.addCleanup(release.set)
        self.addCleanup(worker.close)
        worker.submit("synthetic", "summary")
        self.assertTrue(entered.wait(2))
        result = []
        reader = threading.Thread(target=lambda: (result.extend(worker.results()), drained.set()))
        reader.start()
        self.assertFalse(drained.wait(1))
        release.set()
        reader.join(2)
        self.assertFalse(reader.is_alive())
        self.assertEqual([("synthetic", DeliveryResult.SENT)], result)
        self.assertFalse(worker.ready.is_set())

    def test_disabled_default_does_not_create_transport_or_attempt_network(self):
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")), \
                patch("app.notifications.slack.build_opener", side_effect=AssertionError("disabled")):
            local = []
            service = NotificationService(local.append)
            result = service.record(NotificationKind.RECORDING_HEALTH_FAILURE,
                                    at=datetime.now(timezone.utc))
            self.assertEqual(DeliveryResult.DISABLED, result)
            self.assertEqual(NotificationKind.RECORDING_HEALTH_FAILURE, local[0].kind)

    def test_only_configured_slack_https_destination_without_redirects(self):
        for value in ("http://hooks.slack.com/services/a/b/c", "https://outside.invalid/services/a/b/c",
                      "https://user@hooks.slack.com/services/a/b/c",
                      "https://hooks.slack.com:444/services/a/b/c",
                      "https://hooks.slack.com/services/a/b/c?query=1",
                      "https://hooks.slack.com/services/a/b/c#fragment",
                      "https://hooks.slack.com/services/a/b/c\n", "https://hooks.slack.com/services/../b/c"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "invalid Slack endpoint"):
                SlackEndpoint(value)
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, None, None, "https://outside.invalid"))
        transport = Transport()
        delivery = SlackDelivery(endpoint(), opener=transport)
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            self.assertEqual(DeliveryResult.SENT, delivery.send("generated summary"))
        request, timeout = transport.requests[0]
        self.assertEqual(endpoint().url, request.full_url)
        self.assertEqual("POST", request.method)
        self.assertEqual({"text": "generated summary"}, json.loads(request.data))
        self.assertEqual(10, timeout)
        self.assertEqual(DeliveryResult.SENT, SlackDelivery(endpoint(), opener=Transport(reply=Reply(body=b'ok\n'))).send('summary'))
        self.assertEqual(DeliveryResult.FAILED, SlackDelivery(endpoint(), opener=Transport(reply=Reply(body=b'ok' + b' ' * 31))).send('summary'))

    def test_failures_redact_credential_response_and_exception(self):
        secret = endpoint().url
        output = io.StringIO()
        for transport in [Transport(error=RuntimeError(secret)),
                          Transport(reply=Reply(200, secret.encode())),
                          Transport(error=HTTPError(secret, 302, secret, {}, None)),
                          Transport(reply=Reply(429, b"retry later"))]:
            delivery = SlackDelivery(endpoint(), opener=transport)
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertEqual(DeliveryResult.FAILED, delivery.send("generated event"))
            self.assertNotIn(secret, repr(delivery))
            self.assertNotIn(secret, repr(endpoint()))
            self.assertEqual(1, len(transport.requests))
        self.assertEqual("", output.getvalue())

    def test_person_motion_entry_offline_do_not_flood_immediate_channel(self):
        transport, local = Transport(), []
        service = NotificationService(local.append, SlackDelivery(endpoint(), opener=transport))
        for _ in range(100):
            for kind in [NotificationKind.PERSON, NotificationKind.MOTION,
                         NotificationKind.ENTRY, NotificationKind.CAMERA_OFFLINE]:
                self.assertEqual(DeliveryResult.SUPPRESSED, service.record(
                    kind, at=datetime.now(timezone.utc), confirmed=True))
        self.assertEqual([], transport.requests)
        self.assertEqual(400, len(local))

    def test_confirmed_critical_and_integrity_failures_enqueue_immediately(self):
        transport = Transport()
        local = []
        service = NotificationService(local.append, SlackDelivery(endpoint(), opener=transport))
        self.addCleanup(service.close)
        for kind in (NotificationKind.SERVER_MOVEMENT, NotificationKind.CAMERA_TAMPER):
            self.assertEqual(DeliveryResult.SUPPRESSED, service.record(kind, at=datetime.now(timezone.utc)))
            self.assertEqual(DeliveryResult.PENDING, service.record(kind, at=datetime.now(timezone.utc), confirmed=True))
        for kind in (NotificationKind.HARDWARE_INTEGRITY_FAILURE, NotificationKind.RECORDING_HEALTH_FAILURE):
            self.assertEqual(DeliveryResult.PENDING, service.record(kind, at=datetime.now(timezone.utc)))
        drain(self, service)
        self.assertEqual(4, len(transport.requests))
        self.assertEqual(4, sum(event.delivery == DeliveryResult.SENT for event in local))

    def test_failed_local_sink_still_alerts_and_completion_remains_pending_for_persistence(self):
        transport = Transport()
        def failed(_):
            raise RuntimeError('synthetic private error')
        service = NotificationService(failed, SlackDelivery(endpoint(), opener=transport))
        self.addCleanup(service.close)
        self.assertEqual(DeliveryResult.PENDING, service.record(NotificationKind.HARDWARE_INTEGRITY_FAILURE,
                                                               at=datetime.now(timezone.utc)))
        self.assertTrue(service._worker.ready.wait(2))
        self.assertEqual((), service.poll())
        self.assertEqual(1, len(transport.requests))
        self.assertEqual(1, service.pending_count)
        self.assertTrue(service.local_delivery_failed)

    def test_full_queue_and_shutdown_leave_visible_local_failure_without_blocking(self):
        entered, release = threading.Event(), threading.Event()
        class SlowTransport(Transport):
            def open(self, request, *, timeout):
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test release missing')
                return super().open(request, timeout=timeout)
        local = []
        service = NotificationService(local.append, SlackDelivery(endpoint(), opener=SlowTransport()), queue_capacity=1)
        self.addCleanup(release.set)
        self.addCleanup(service.close)
        now = datetime.now(timezone.utc)
        self.assertEqual(DeliveryResult.PENDING, service.record(NotificationKind.CAMERA_TAMPER, at=now, confirmed=True))
        self.assertTrue(entered.wait(2))
        self.assertEqual(DeliveryResult.FAILED, service.record(NotificationKind.HARDWARE_INTEGRITY_FAILURE, at=now))
        self.assertTrue(service.delivery_failed)
        self.assertEqual(DeliveryResult.FAILED, local[-1].delivery)
        service.close()
        self.assertFalse(release.is_set())
        self.assertEqual(1, service.pending_count)
        release.set()
        drain(self, service)

    def test_summary_only_contains_validated_fixed_aggregates(self):
        text = summary().text()
        for part in ("3600", "2/1/1", "20/50/4", "Critical events: 2", "recordings: 6",
                     "STORAGE_PRESSURE", "Errors: 1"):
            self.assertIn(part, text)
        with self.assertRaises(ValueError):
            DailySummary(-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, StorageState.NORMAL)
        with self.assertRaises(ValueError):
            NotificationService(lambda _: None).daily(summary(), at=datetime(2026, 1, 1))

    def test_upstream_identifier_coalesces_pending_retry_and_completion_runs_on_owner(self):
        transport, local, results = Transport(), [], []
        service = NotificationService(local.append, SlackDelivery(endpoint(), opener=transport))
        self.addCleanup(service.close)
        identifier, now = uuid4(), datetime.now(timezone.utc)
        for _ in range(2):
            self.assertEqual(DeliveryResult.PENDING, service.record(
                NotificationKind.CAMERA_TAMPER, at=now, confirmed=True, event_id=identifier,
                on_complete=lambda result: results.append((threading.get_ident(), result))))
        drain(self, service)
        self.assertEqual([(threading.get_ident(), DeliveryResult.SENT)], results)
        self.assertEqual(1, len(transport.requests))
        self.assertEqual([identifier, identifier], [event.event_id for event in local])


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="sentinel-summary-clock-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "schedule.sqlite"
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(self.db.close)
        migrate(self.db, BUILTIN_MIGRATIONS + (notification_migration(len(BUILTIN_MIGRATIONS) + 1),))
        self.transport, self.local = Transport(), []
        self.service = NotificationService(self.local.append, SlackDelivery(endpoint(), opener=self.transport))
        self.addCleanup(self.service.close)

    def scheduler(self, zone="Asia/Tokyo", **kwargs):
        return DailySummaryScheduler(self.db, ZoneInfo(zone), self.service, contextlib.nullcontext, **kwargs)

    def test_2300_local_default_once_and_persisted_restart(self):
        scheduler = self.scheduler()
        self.assertEqual(DeliveryResult.SUPPRESSED, scheduler.tick(
            datetime(2026, 1, 1, 13, 59, tzinfo=timezone.utc), summary()))
        now = datetime(2026, 1, 1, 14, 0, tzinfo=timezone.utc)
        self.assertEqual(DeliveryResult.PENDING, scheduler.tick(now, summary()))
        drain(self, self.service)
        restarted = self.scheduler()
        self.assertEqual(DeliveryResult.SUPPRESSED, restarted.tick(now, summary()))
        self.assertEqual({"local_date": "2026-01-01", "result": "sent"}, restarted.status())
        self.assertEqual(1, len(self.transport.requests))

    def test_dst_gap_sends_at_first_existing_wall_time_after_target(self):
        scheduler = self.scheduler("America/New_York", hour=2, minute=30)
        self.assertEqual(DeliveryResult.SUPPRESSED, scheduler.tick(
            datetime(2026, 3, 8, 6, 59, tzinfo=timezone.utc), summary()))
        self.assertEqual(DeliveryResult.PENDING, scheduler.tick(
            datetime(2026, 3, 8, 7, 0, tzinfo=timezone.utc), summary()))
        drain(self, self.service)

    def test_dst_fold_and_backward_clock_do_not_duplicate(self):
        scheduler = self.scheduler("America/New_York", hour=1, minute=30)
        self.assertEqual(DeliveryResult.PENDING, scheduler.tick(
            datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc), summary()))
        drain(self, self.service)
        self.assertEqual(DeliveryResult.SUPPRESSED, scheduler.tick(
            datetime(2026, 11, 1, 6, 30, tzinfo=timezone.utc), summary()))
        self.assertEqual(DeliveryResult.SUPPRESSED, scheduler.tick(
            datetime(2026, 10, 31, 23, 30, tzinfo=timezone.utc), summary()))
        self.assertEqual(1, len(self.transport.requests))

    def test_delivery_failure_is_persisted_without_automatic_retry_loop(self):
        self.transport.error = RuntimeError(endpoint().url)
        scheduler = self.scheduler()
        now = datetime(2026, 1, 1, 23, 0, tzinfo=ZoneInfo("Asia/Tokyo"))
        self.assertEqual(DeliveryResult.PENDING, scheduler.tick(now, summary()))
        drain(self, self.service)
        self.assertEqual("failed", scheduler.status()["result"])
        self.assertEqual(DeliveryResult.SUPPRESSED, scheduler.tick(now, summary()))
        self.assertEqual(2, len(self.local))
        self.assertEqual(1, len(self.transport.requests))

    def test_denied_metadata_guard_prevents_delivery(self):
        def denied():
            raise RuntimeError("STORAGE_HARD_STOP")
        scheduler = DailySummaryScheduler(self.db, ZoneInfo("Asia/Tokyo"), self.service, denied)
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            scheduler.tick(datetime(2026, 1, 1, 23, 0, tzinfo=ZoneInfo("Asia/Tokyo")), summary())
        self.assertEqual([], self.transport.requests)
        self.assertIsNone(scheduler.status())

    def test_crash_after_claim_stays_pending_and_restart_does_not_resend(self):
        entered, release = threading.Event(), threading.Event()
        class SlowTransport(Transport):
            def open(self, request, *, timeout):
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test release missing')
                return super().open(request, timeout=timeout)
        service = NotificationService(self.local.append, SlackDelivery(endpoint(), opener=SlowTransport()))
        self.addCleanup(service.close)
        self.addCleanup(release.set)
        scheduler = DailySummaryScheduler(self.db, ZoneInfo('UTC'), service, contextlib.nullcontext)
        now = datetime(2026, 1, 1, 23, tzinfo=timezone.utc)
        self.assertEqual(DeliveryResult.PENDING, scheduler.tick(now, summary()))
        self.assertTrue(entered.wait(2))
        service.close()
        restarted = DailySummaryScheduler(self.db, ZoneInfo('UTC'), self.service, contextlib.nullcontext)
        self.assertEqual(DeliveryResult.SUPPRESSED, restarted.tick(now, summary()))
        self.assertEqual('pending', restarted.status()['result'])
        self.assertEqual([], self.transport.requests)
        release.set()
        self.assertTrue(service._worker.ready.wait(2))
        # The network thread never persists SQLite completion after shutdown.
        self.assertEqual('pending', restarted.status()['result'])

    def test_failed_completion_persistence_retries_locally_without_resending(self):
        allowed = [True]
        @contextlib.contextmanager
        def reserve():
            if not allowed[0]:
                raise RuntimeError('STORAGE_HARD_STOP')
            yield
        scheduler = DailySummaryScheduler(self.db, ZoneInfo('UTC'), self.service, reserve)
        self.assertEqual(DeliveryResult.PENDING, scheduler.tick(
            datetime(2026, 1, 1, 23, tzinfo=timezone.utc), summary()))
        self.assertTrue(self.service._worker.ready.wait(2))
        allowed[0] = False
        self.assertEqual((), self.service.poll())
        self.assertTrue(self.service.local_delivery_failed)
        self.assertEqual('pending', scheduler.status()['result'])
        allowed[0] = True
        self.assertEqual(1, len(self.service.poll()))
        self.assertEqual('sent', scheduler.status()['result'])
        self.assertEqual(1, len(self.transport.requests))
