"""Issue #301 item 2: a camera source offline for the threshold notifies the Owner.

Generated clocks, in-memory sinks, disposable SQLite files, synthetic UVC
discovery/capture and an intercepted Slack transport only. No real camera,
Slack endpoint, host or network is used.
"""

import asyncio
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import threading
import time
from types import SimpleNamespace
import unittest
from uuid import uuid4

from app.audit import AuditStore, OwnerAuditService
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry, SourceHealthState, SourceType
from app.cameras.uvc.config import LocalUvcConfiguration
from app.cameras.uvc.identity import CameraState, DeviceEvidence, HealthEvent
from app.cameras.uvc.runtime import LocalUvcDependencies
from app.logging import Event
from app.main import create_app
from app.monitoring.cameras import CameraOfflineMonitor
from app.monitoring.config import CameraOfflineNotification, parse_monitoring
from app.monitoring.runtime import MonitoringDependencies
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from app.settings import ConfigurationError
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_monitoring_runtime import RuntimeFixture
from tests.test_recording import SyntheticValidator
from tests.test_storage_notifications import Transport, endpoint
from tests.test_uvc_runtime import FAST, PROFILE, CaptureFactory, Discovery, PermitOwner


AT = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
ALERT = "ServerSentinel critical alert: camera_offline"


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


class Sink:
    """In-memory durable sink keyed by event ID."""

    def __init__(self):
        self.rows = {}
        self.refuse = False

    def __call__(self, event):
        if self.refuse:
            raise RuntimeError("synthetic STORAGE_HARD_STOP")
        self.rows[event.event_id] = event


def event(source, state, reason="synthetic"):
    return HealthEvent(source, state, reason)


class MonitorFixture:
    def setUp(self):
        self.clock = Clock()
        self.sources = (uuid4(), uuid4())
        self.sink = Sink()
        self.transport = Transport()
        self.service = NotificationService(
            self.sink, SlackDelivery(endpoint(), opener=self.transport))
        self.addCleanup(self.service.close)

    def monitor(self, **changes):
        values = dict(after_seconds=300, hourly_limit=4, monotonic=self.clock)
        values.update(changes)
        return CameraOfflineMonitor(self.sources, **values)

    def online(self, monitor, *sources):
        for source in sources or self.sources:
            monitor.health_sink(event(source, CameraState.ONLINE, "video_capture_ready"))

    def drain(self, monitor, **changes):
        status = monitor.drain(self.service, at=AT, monotonic=self.clock.value, **changes)
        self.service.poll()
        return status

    def sent(self):
        return [event for event in self.sink.rows.values()
                if event.kind is NotificationKind.CAMERA_OFFLINE]

    def advance(self, seconds):
        self.clock.value += seconds


class EpisodeTests(MonitorFixture, unittest.TestCase):
    def test_one_notification_after_the_threshold_and_none_before(self):
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE, "device_disconnected"))
        self.advance(299)
        self.assertEqual(0, self.drain(monitor).offline_sources)
        self.assertEqual([], self.sent())
        self.advance(1)
        self.assertEqual(1, self.drain(monitor).offline_sources)
        rows = self.sent()
        self.assertEqual(1, len(rows))
        self.assertTrue(rows[0].confirmed)
        # The same episode is never notified again.
        for _ in range(5):
            self.advance(600)
            self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_recovery_before_the_threshold_cancels_and_is_recorded(self):
        monitor = self.monitor()
        self.online(monitor)
        recovered = monitor.recovered
        source = self.sources[0]
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(200)
        monitor.health_sink(event(source, CameraState.ONLINE))
        self.advance(1000)
        self.assertEqual(0, self.drain(monitor).offline_sources)
        self.assertEqual([], self.sent())
        self.assertEqual(recovered + 1, monitor.recovered)

    def test_degraded_and_manual_count_as_not_online(self):
        # A camera that keeps failing negotiation flaps between offline and
        # degraded; neither delivers monitored video.
        monitor = self.monitor()
        self.online(monitor)
        source = self.sources[0]
        for state in (CameraState.OFFLINE, CameraState.DEGRADED, CameraState.MANUAL,
                      CameraState.OFFLINE):
            monitor.health_sink(event(source, state))
            self.advance(100)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_disabled_or_stopping_sources_are_not_notified(self):
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE, "disabled"))
        monitor.health_sink(event(self.sources[1], CameraState.OFFLINE,
                                  "capture_service_stopping"))
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual([], self.sent())

    def test_a_source_that_never_comes_online_is_notified(self):
        # Missing at boot, or capture never started: no event arrives at all.
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        self.advance(300)
        self.assertEqual(1, self.drain(monitor).offline_sources)
        self.assertEqual(1, len(self.sent()))

    def test_a_brief_recovery_after_the_threshold_does_not_reset_the_outage(self):
        # PR #320 review 重要 1: offline past the threshold, a brief online and
        # offline again, all before the next drain: the outage that already
        # lasted the threshold is notified on that drain, exactly once.
        monitor = self.monitor()
        self.online(monitor)
        source = self.sources[0]
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(310)
        monitor.health_sink(event(source, CameraState.ONLINE))
        self.advance(3)
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(1)
        self.assertEqual(1, self.drain(monitor).offline_sources)
        self.assertEqual(1, len(self.sent()))
        self.assertEqual(0, monitor.dropped)
        for _ in range(3):
            self.advance(600)
            self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_episode_that_recovered_after_the_threshold_before_the_drain_is_notified(self):
        monitor = self.monitor()
        self.online(monitor)
        source = self.sources[0]
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(310)
        monitor.health_sink(event(source, CameraState.ONLINE))
        self.advance(50)
        self.assertEqual(0, self.drain(monitor).offline_sources)
        self.assertEqual(1, len(self.sent()))
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_unknown_sources_and_values_are_ignored(self):
        monitor = self.monitor()
        self.online(monitor)
        monitor.observe(uuid4(), "offline")
        monitor.observe(self.sources[0], "exploded")
        monitor.health_sink(object())
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual([], self.sent())

    def test_stop_ends_notification(self):
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        monitor.stop()
        monitor.health_sink(event(self.sources[1], CameraState.OFFLINE))
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual([], self.sent())

    def test_settings_are_validated(self):
        for values in (dict(after_seconds=59), dict(after_seconds=86401),
                       dict(after_seconds=float("nan")), dict(after_seconds=True),
                       dict(hourly_limit=0), dict(hourly_limit=61), dict(hourly_limit=1.0)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.monitor(**values)
        with self.assertRaises(ValueError):
            CameraOfflineMonitor((), monotonic=self.clock)
        with self.assertRaises(ValueError):
            CameraOfflineMonitor((self.sources[0], self.sources[0]), monotonic=self.clock)

    def test_message_is_the_fixed_category_only(self):
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE, "device_disconnected"))
        self.advance(300)
        self.drain(monitor)
        deadline = 200
        while self.service.pending_count and deadline:
            self.service.poll()
            deadline -= 1
            time.sleep(0.01)
        texts = [json.loads(request.data)["text"] for request, _ in self.transport.requests]
        self.assertEqual([ALERT], texts)
        self.assertNotIn(str(self.sources[0]), texts[0])


class Refusing:
    """A `NotificationService` whose capacity check refuses until opened."""

    def __init__(self, service):
        self.service, self.accept = service, False

    def can_accept(self, event_id):
        return self.accept and self.service.can_accept(event_id)

    def record(self, *arguments, **fields):
        return self.service.record(*arguments, **fields)

    def retained(self, event_id):
        return self.service.retained(event_id)


class OwedEpisodeTests(MonitorFixture, unittest.TestCase):
    def test_a_long_recovery_keeps_the_owed_episode_apart_from_a_new_outage(self):
        # PR #320 re-review 提案 1: the queue refused the first alert for two
        # hours; the camera recovered for longer than the threshold and then
        # went offline again. Each outage is notified under its own time and
        # ID once the service accepts, never as one merged old alert.
        monitor = self.monitor()
        self.online(monitor)
        refusing = Refusing(self.service)
        source = self.sources[0]
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(310)
        monitor.drain(refusing, at=AT, monotonic=self.clock.value)
        monitor.health_sink(event(source, CameraState.ONLINE))
        for _ in range(12):
            self.advance(600)
            monitor.drain(refusing, at=AT, monotonic=self.clock.value)
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(300)
        later = AT + timedelta(hours=2)
        monitor.drain(refusing, at=later, monotonic=self.clock.value)
        self.assertEqual([], self.sent())
        refusing.accept = True
        status = monitor.drain(refusing, at=later, monotonic=self.clock.value)
        self.service.poll()
        rows = sorted(self.sent(), key=lambda row: row.at)
        self.assertEqual([AT, later], [row.at for row in rows])
        self.assertEqual(2, len({row.event_id for row in rows}))
        self.assertEqual((1, 0), (status.offline_sources, monitor.dropped))
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual(2, len(self.sent()))

    def test_owed_episodes_still_obey_the_cap(self):
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        refusing = Refusing(self.service)
        source = self.sources[0]
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(310)
        monitor.drain(refusing, at=AT, monotonic=self.clock.value)
        monitor.health_sink(event(source, CameraState.ONLINE))
        self.advance(400)
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(300)
        refusing.accept = True
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            monitor.drain(refusing, at=AT, monotonic=self.clock.value)
        self.service.poll()
        self.assertEqual(1, len(self.sent()))
        self.advance(3600)
        monitor.drain(refusing, at=AT, monotonic=self.clock.value)
        self.service.poll()
        self.assertEqual(2, len(self.sent()))


class CapTests(MonitorFixture, unittest.TestCase):
    def test_a_held_episode_that_recovers_is_dropped_and_logged(self):
        # PR #320 re-review 提案 2: held back by the cap, then online for good.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        monitor.health_sink(event(self.sources[1], CameraState.OFFLINE))
        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as held:
            self.assertEqual(1, self.drain(monitor).held)
        self.assertEqual(1, len(self.sent()))
        self.assertTrue(any(line.endswith(Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED.value)
                            for line in held.output))
        # Whichever source was held recovers and stays online.
        self.online(monitor)
        self.advance(60)
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as dropped:
            status = self.drain(monitor)
        self.assertEqual([f"WARNING:app.monitoring.cameras:{Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED.value}"],
                         dropped.output)
        self.assertEqual((0, 0, 1), (status.offline_sources, status.held, monitor.dropped))
        self.advance(7200)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def flap(self, monitor, source, seconds=301):
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(seconds)
        self.drain(monitor)
        monitor.health_sink(event(source, CameraState.ONLINE))
        self.advance(1)

    def test_a_flapping_source_is_not_notified_more_than_the_cap(self):
        monitor = self.monitor(hourly_limit=2)
        self.online(monitor)
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
            for _ in range(6):
                self.flap(monitor, self.sources[0])
        self.assertEqual(2, len(self.sent()))
        # Value-free: only the fixed event names.
        self.assertTrue(all(line.endswith(Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED.value)
                            or line.endswith(Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED.value)
                            for line in logs.output), logs.output)
        self.assertTrue(any(str(Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED) in line
                            for line in logs.output))
        # A recovery of a few seconds is folded into the held outage, which
        # stays owed rather than being dropped.
        self.assertEqual(0, monitor.dropped)

    def test_a_held_episode_is_notified_once_the_hour_allows(self):
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        monitor.health_sink(event(self.sources[1], CameraState.OFFLINE))
        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            status = self.drain(monitor)
        self.assertEqual((2, 1), (status.offline_sources, status.held))
        self.assertEqual(1, len(self.sent()))
        self.advance(3599)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))
        self.advance(1)
        self.assertEqual(0, self.drain(monitor).held)
        self.assertEqual(2, len(self.sent()))

    def test_restored_window_keeps_the_cap_across_a_restart(self):
        monitor = self.monitor(hourly_limit=2)
        self.online(monitor)
        earlier = [(uuid4(), 100.0), (uuid4(), 3000.0)]
        monitor.restore_window(earlier, monotonic=self.clock.value)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.drain(monitor)
        self.assertEqual([], self.sent())
        # The older row leaves the hour 600 s after it was accepted.
        self.advance(300)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))
        with self.assertRaises(ValueError):
            monitor.restore_window([(uuid4(), 1.0)] * 3, monotonic=self.clock.value)
        with self.assertRaises(ValueError):
            monitor.restore_window([("x", 1.0)], monotonic=self.clock.value)


class IdentityTests(MonitorFixture, unittest.TestCase):
    def test_a_known_durable_id_is_not_notified_again(self):
        # A restarted process finds the same outage (same last-frame time).
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        durable = uuid4()
        self.drain(monitor, durable_id=lambda source: durable, known=lambda value: value == durable)
        self.assertEqual([], self.sent())
        self.advance(3600)
        self.drain(monitor, durable_id=lambda source: durable, known=lambda value: value == durable)
        self.assertEqual([], self.sent())

    def test_the_durable_id_names_the_row_and_a_reused_one_is_not_trusted(self):
        monitor = self.monitor()
        self.online(monitor)
        durable = uuid4()
        source = self.sources[0]
        for _ in range(2):
            # The second episode reports the same last-frame time (a refused
            # frame-time write); it must still be notified, under its own ID.
            monitor.health_sink(event(source, CameraState.OFFLINE))
            self.advance(300)
            self.drain(monitor, durable_id=lambda value: durable,
                       known=lambda value: value in self.sink.rows)
            monitor.health_sink(event(source, CameraState.ONLINE))
        rows = self.sent()
        self.assertEqual(2, len(rows))
        self.assertIn(durable, self.sink.rows)
        self.assertEqual(2, len({row.event_id for row in rows}))

    def test_failing_lookups_fall_back_to_a_process_id(self):
        def broken(value):
            raise RuntimeError("synthetic database error")

        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        self.drain(monitor, durable_id=broken, known=broken)
        self.assertEqual(1, len(self.sent()))

    def test_a_full_queue_retries_under_the_same_id_and_time(self):
        blocker = uuid4()
        gate = threading.Event()
        self.addCleanup(gate.set)

        class Gated(Transport):
            def open(inner, request, *, timeout):
                gate.wait(10)
                return super().open(request, timeout=timeout)

        service = NotificationService(self.sink, SlackDelivery(endpoint(), opener=Gated()),
                                      queue_capacity=1)
        self.addCleanup(service.close)
        service.record(NotificationKind.HARDWARE_INTEGRITY_FAILURE, at=AT, event_id=blocker)
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        monitor.drain(service, at=AT, monotonic=self.clock.value)
        self.assertEqual([], self.sent())
        gate.set()
        for _ in range(500):
            service.poll()
            if not service.pending_count:
                break
            time.sleep(0.01)
        self.advance(60)
        monitor.drain(service, at=AT + timedelta(minutes=1), monotonic=self.clock.value)
        rows = self.sent()
        self.assertEqual(1, len(rows))
        # The retry kept the time of the first attempt.
        self.assertEqual(AT, rows[0].at)

    def test_refused_local_write_without_slack_is_retained_not_resubmitted(self):
        service = NotificationService(self.sink, None)
        self.addCleanup(service.close)
        self.sink.refuse = True
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        monitor.drain(service, at=AT, monotonic=self.clock.value)
        self.assertEqual(1, service.unpersisted_count)
        self.sink.refuse = False
        service.poll()
        rows = self.sent()
        self.assertEqual(1, len(rows))
        self.assertIs(DeliveryResult.DISABLED, rows[0].delivery)
        self.advance(60)
        monitor.drain(service, at=AT, monotonic=self.clock.value)
        self.assertEqual(1, len(self.sent()))


class RuntimeSignalTests(MonitorFixture, unittest.TestCase):
    def status(self, source, running, camera):
        return SimpleNamespace(source_id=source, worker_running=running, camera_state=camera)

    def test_a_worker_that_is_not_running_is_not_online(self):
        monitor = self.monitor()
        self.online(monitor)
        versions = monitor.version()
        monitor.observe_runtime([self.status(self.sources[0], False, CameraState.ONLINE)],
                                versions)
        self.advance(300)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_a_running_worker_reported_online_ends_the_episode(self):
        monitor = self.monitor()
        versions = monitor.version()
        monitor.observe_runtime([self.status(source, True, CameraState.ONLINE)
                                 for source in self.sources], versions)
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual([], self.sent())

    def test_a_status_older_than_an_event_never_overrides_it(self):
        monitor = self.monitor()
        self.online(monitor)
        versions = monitor.version()
        # The status was read while the camera was still online; the offline
        # event arrives before the status is applied.
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        monitor.observe_runtime([self.status(self.sources[0], True, CameraState.ONLINE)],
                                versions)
        self.advance(300)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_a_running_worker_reported_not_online_starts_an_episode(self):
        # PR #320 review 提案 3: a health event that never reached the sink
        # cannot hide an outage the polled status shows.
        for state in (CameraState.OFFLINE, CameraState.DEGRADED, CameraState.MANUAL):
            with self.subTest(state=state):
                self.sink.rows.clear()
                monitor = self.monitor()
                self.online(monitor)
                monitor.observe_runtime([self.status(self.sources[0], True, state)],
                                        monitor.version())
                self.advance(300)
                self.drain(monitor)
                self.assertEqual(1, len(self.sent()))

    def test_an_inactive_source_stays_inactive(self):
        monitor = self.monitor()
        self.online(monitor)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE, "disabled"))
        monitor.observe_runtime([self.status(self.sources[0], False, None)], monitor.version())
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual([], self.sent())


class ConfigurationTests(unittest.TestCase):
    def parse(self, value):
        return parse_monitoring({"time_zone": "UTC", **value}, recordings_directory=Path("/"),
                                resolve_device=lambda uuid: 0, root_device=lambda: 0)

    def test_defaults_and_values(self):
        self.assertEqual(CameraOfflineNotification(300.0, 4), self.parse({}).camera_offline)
        configured = self.parse({"camera_offline_notification": {
            "after_seconds": 600, "hourly_limit": 2}}).camera_offline
        self.assertEqual((600.0, 2), (configured.after_seconds, configured.hourly_limit))
        self.assertEqual(900.0, self.parse({"camera_offline_notification": {
            "after_seconds": 900}}).camera_offline.after_seconds)

    def test_invalid_values_are_refused_without_echoing_them(self):
        for value in ([], {"after_seconds": 59}, {"after_seconds": 86401},
                      {"after_seconds": 300.5}, {"after_seconds": True},
                      {"after_seconds": "300"}, {"hourly_limit": 0}, {"hourly_limit": 61},
                      {"source": "camera-1"}):
            with self.subTest(value=value):
                with self.assertRaises(ConfigurationError) as raised:
                    self.parse({"camera_offline_notification": value})
                self.assertNotIn("59", str(raised.exception))
                self.assertNotIn("camera-1", str(raised.exception))


class LifespanTests(RuntimeFixture):
    """The deployed path: UVC health sink → monitor → monitoring tick → Slack."""

    def setUp(self):
        super().setUp()
        database = Database(self.settings.database_path)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.database = database
        self.source = CameraRegistry(database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=PROFILE)
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial-a")
        self.discovery = Discovery([self.camera])
        self.captures = CaptureFactory(self.discovery)

    def uvc_application(self, configuration=None):
        return create_app(
            self.settings, monitoring=configuration or self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0),
            local_uvc=LocalUvcConfiguration((self.source.id,), **FAST),
            local_uvc_dependencies=LocalUvcDependencies(discovery=self.discovery,
                                                        capture_factory=self.captures))

    def last_seen(self):
        return CameraRegistry(self.database).get_source(self.source.id).last_seen_at

    def health(self):
        return CameraRegistry(self.database).get_source(self.source.id).health_state

    async def until(self, predicate, timeout=10.0):
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.02)
        return predicate()

    def slack_texts(self):
        # Only this path's messages (an unapproved synthetic hardware
        # baseline raises its own integrity alert).
        return [text for text in super().slack_texts() if text == ALERT]

    async def tick(self, runtime):
        await runtime.call(runtime.tick)
        await self.settle(runtime)

    def offline_rows(self):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute(
                "SELECT confirmed, delivery FROM notification_events WHERE kind=?",
                (NotificationKind.CAMERA_OFFLINE.value,)).fetchall()

    async def bring_online(self, application):
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()),
            CameraRegistry(self.database))
        await asyncio.to_thread(application.state.local_uvc.reapprove, admin,
                                "synthetic-owner", self.source.id, self.camera)
        self.assertTrue(await self.until(lambda: self.health() is SourceHealthState.ONLINE))
        monitor = application.state.camera_offline
        self.assertTrue(await self.until(
            lambda: monitor._sources[self.source.id].online))

    async def test_unplugged_camera_notifies_once_after_the_threshold(self):
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertTrue(runtime.status.camera_offline_notifications)
            await self.bring_online(application)
            monitor = application.state.camera_offline
            recovered = monitor.recovered
            self.discovery.devices = []
            self.assertTrue(await self.until(lambda: self.health() is SourceHealthState.OFFLINE))
            self.assertTrue(await self.until(lambda: not monitor._sources[self.source.id].online))
            self.clock.advance(timedelta(seconds=299))
            await self.tick(runtime)
            self.assertEqual([], self.slack_texts())
            self.assertFalse(runtime.status.camera_offline_degraded)
            self.clock.advance(timedelta(seconds=2))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            self.assertEqual([(1, "sent")], self.offline_rows())
            self.assertTrue(runtime.status.camera_offline_degraded)
            for _ in range(3):
                self.clock.advance(timedelta(minutes=30))
                await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            # Recovery is recorded, not notified.
            self.discovery.devices = [self.camera]
            self.assertTrue(await self.until(lambda: self.health() is SourceHealthState.ONLINE))
            self.assertTrue(await self.until(lambda: monitor._sources[self.source.id].online))
            await self.tick(runtime)
            self.assertFalse(runtime.status.camera_offline_degraded)
            self.assertEqual([ALERT], self.slack_texts())
            self.assertEqual(recovered + 1, monitor.recovered)

    async def test_a_restart_during_the_same_outage_does_not_notify_again(self):
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            self.discovery.devices = []
            self.assertTrue(await self.until(lambda: self.health() is SourceHealthState.OFFLINE))
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
        # The camera is still unplugged when the service starts again.
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.clock.advance(timedelta(hours=2))
            await self.tick(runtime)
            self.assertTrue(runtime.status.camera_offline_degraded)
        self.assertEqual([ALERT], self.slack_texts())
        self.assertEqual([(1, "sent")], self.offline_rows())

    async def test_the_hourly_cap_continues_across_a_restart(self):
        configuration = self.configuration(
            camera_offline=CameraOfflineNotification(300, 1))
        application = self.uvc_application(configuration)
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            self.discovery.devices = []
            self.assertTrue(await self.until(lambda: self.health() is SourceHealthState.OFFLINE))
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.assertEqual(1, len(self.slack_texts()))
            # A new episode: the camera comes back (frames move its durable
            # last-frame time) and is gone again when the service restarts.
            seen = self.last_seen()
            self.discovery.devices = [self.camera]
            self.assertTrue(await self.until(lambda: self.health() is SourceHealthState.ONLINE))
            self.assertTrue(await self.until(
                lambda: application.state.camera_offline._sources[self.source.id].online))
            self.assertTrue(await self.until(lambda: self.last_seen() != seen))
        self.discovery.devices = []
        application = self.uvc_application(configuration)
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=301))
            with self.assertLogs("app.monitoring.cameras", level="WARNING"):
                await self.tick(runtime)
            self.assertEqual(1, len(self.slack_texts()))
            self.clock.advance(timedelta(hours=1))
            await self.tick(runtime)
            self.assertEqual(2, len(self.slack_texts()))

    async def test_a_worker_that_stopped_without_a_transition_is_not_online(self):
        # The application's capture watcher polls the runtime status: a
        # source whose worker is no longer running is offline for the
        # monitor even though its last camera transition was `online`.
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            uvc = application.state.local_uvc
            real_status = uvc.status

            def dead_worker_status():
                status = real_status()
                return replace(status, sources=tuple(
                    replace(item, worker_running=False) for item in status.sources))

            uvc.status = dead_worker_status
            monitor = application.state.camera_offline
            self.assertTrue(await self.until(lambda: not monitor._sources[self.source.id].online))
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            uvc.status = real_status

    def stored_row(self, *, confirmed, delivery, age):
        at = (self.clock.now - timedelta(seconds=age)).isoformat()
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute(
                "INSERT INTO notification_events(event_id,kind,at,confirmed,delivery,accepted_at) "
                "VALUES (?,?,?,?,?,?)",
                (str(uuid4()), NotificationKind.CAMERA_OFFLINE.value, at, int(confirmed),
                 delivery, at))
            db.commit()

    async def test_restored_window_counts_confirmed_alerts_including_pending(self):
        # Codex PR #320 P2: an unconfirmed local observation never used the
        # budget; an accepted `pending` alert did (it is never resent).
        configuration = self.configuration(camera_offline=CameraOfflineNotification(300, 1))
        self.stored_row(confirmed=False, delivery="suppressed", age=60)
        application = self.uvc_application(configuration)
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.discovery.devices = []
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
        self.transport.requests.clear()
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute("DELETE FROM notification_events WHERE kind=?",
                       (NotificationKind.CAMERA_OFFLINE.value,))
            db.commit()
        self.stored_row(confirmed=True, delivery="pending", age=60)
        application = self.uvc_application(configuration)
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=301))
            with self.assertLogs("app.monitoring.cameras", level="WARNING"):
                await self.tick(runtime)
            self.assertEqual([], self.slack_texts())
            self.clock.advance(timedelta(hours=1))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())

    async def test_without_slack_the_row_is_disabled_and_the_path_unavailable(self):
        self.slack = False
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertFalse(runtime.status.camera_offline_notifications)
            self.discovery.devices = []
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.assertTrue(runtime.status.camera_offline_degraded)
        self.assertEqual([], self.slack_texts())
        self.assertEqual([(1, "disabled")], self.offline_rows())

    async def test_shutdown_never_notifies(self):
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            self.clock.advance(timedelta(hours=1))
            await self.tick(runtime)
        # Stopping capture lowered the source; nothing was notified.
        self.assertEqual([], self.slack_texts())
        self.assertEqual([], self.offline_rows())

    def test_the_application_owns_the_monitor(self):
        monitor = CameraOfflineMonitor((self.source.id,), monotonic=lambda: 0.0)
        with self.assertRaises(TypeError):
            create_app(self.settings, monitoring=self.configuration(),
                       monitoring_dependencies=MonitoringDependencies(camera_offline=monitor),
                       local_uvc=LocalUvcConfiguration((self.source.id,), **FAST))
        # No local UVC configuration: no monitor and no path.
        application = create_app(self.settings, monitoring=self.configuration())
        self.assertIsNone(application.state.camera_offline)
        self.assertFalse(application.state.monitoring.status.camera_offline_notifications)


if __name__ == "__main__":
    unittest.main()
