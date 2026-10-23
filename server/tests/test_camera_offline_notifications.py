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
import math
from uuid import uuid4, uuid5

from app.audit import AuditStore, OwnerAuditService
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry, SourceHealthState, SourceType
from app.cameras.uvc.config import LocalUvcConfiguration
from app.cameras.uvc.identity import CameraState, DeviceEvidence, HealthEvent
from app.cameras.uvc.runtime import LocalUvcDependencies
from app.logging import Event
from app.main import create_app
from app.monitoring.cameras import DOWN_BINS, CameraOfflineMonitor
from app.monitoring.config import CameraOfflineNotification, parse_monitoring
from app.monitoring.runtime import (
    CAMERA_OFFLINE_RENOTIFY_CHAIN, EVENT_NAMESPACE, MonitoringDependencies,
)
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


class FlappingTests(MonitorFixture, unittest.TestCase):
    """Refs #301 (Owner decision 2026-10-22): short outages that repeat."""

    def off(self, monitor, source=None, reason="device_disconnected"):
        monitor.health_sink(event(source or self.sources[0], CameraState.OFFLINE, reason))

    def on(self, monitor, source=None):
        monitor.health_sink(event(source or self.sources[0], CameraState.ONLINE))

    def run_for(self, monitor, seconds, step=30):
        while seconds > 0:
            self.advance(min(step, seconds))
            seconds -= step
            self.drain(monitor)

    def cycle(self, monitor, offline=240, online=2):
        self.off(monitor)
        self.run_for(monitor, offline)
        self.on(monitor)
        self.run_for(monitor, online)

    def test_owner_example_four_minutes_offline_two_seconds_online(self):
        # PR #320 review 提案 2: 4 min offline / 2 s online notified nothing.
        monitor = self.monitor()
        self.online(monitor)
        self.cycle(monitor)
        self.assertEqual([], self.sent())
        self.off(monitor)
        self.run_for(monitor, 30)
        self.assertEqual([], self.sent())
        # 240 s + 60 s: five minutes in total within fifteen.
        self.run_for(monitor, 30)
        self.assertEqual(1, len(self.sent()))
        self.assertTrue(self.sent()[0].confirmed)
        self.assertEqual(1, self.drain(monitor).flapping_sources)
        # The same flapping period for two hours, never offline for five
        # minutes on end: still one notification.
        self.run_for(monitor, 180)
        self.on(monitor)
        self.run_for(monitor, 2)
        for _ in range(30):
            self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))
        self.assertEqual(0, monitor.dropped)

    def test_less_than_the_total_within_the_window_is_not_notified(self):
        monitor = self.monitor()
        self.online(monitor)
        for _ in range(2):
            self.cycle(monitor, offline=149, online=2)
        self.run_for(monitor, 3600)
        self.assertEqual([], self.sent())
        # Only the part of an outage inside the window counts: 200 s
        # outages 750 s apart never add up to 300 s within 900 s.
        for _ in range(4):
            self.cycle(monitor, offline=200, online=750)
        self.assertEqual([], self.sent())

    def test_window_and_total_are_configurable(self):
        monitor = self.monitor(flapping_window_seconds=600, flapping_offline_seconds=120)
        self.online(monitor)
        for _ in range(2):
            self.cycle(monitor, offline=61, online=60)
        self.assertEqual(1, len(self.sent()))

    def test_a_single_outage_is_left_to_the_continuous_rule(self):
        # A total shorter than `after_seconds` does not shorten it: one
        # outage is one not-online period.
        monitor = self.monitor(flapping_offline_seconds=120)
        self.online(monitor)
        self.off(monitor)
        self.run_for(monitor, 270)
        self.assertEqual([], self.sent())
        self.run_for(monitor, 30)
        self.assertEqual(1, len(self.sent()))
        self.run_for(monitor, 3600)
        self.assertEqual(1, len(self.sent()))

    def test_a_period_that_ended_before_the_window_is_not_the_second(self):
        # An outage that ended before the window plus one in progress is a
        # single period within the window: left to the continuous rule.
        monitor = self.monitor(flapping_offline_seconds=120)
        self.online(monitor)
        self.cycle(monitor, offline=60, online=1000)
        self.off(monitor)
        self.run_for(monitor, 270)
        self.assertEqual([], self.sent())
        self.run_for(monitor, 30)
        self.assertEqual(1, len(self.sent()))

    def test_a_continuous_outage_after_a_ratio_alert_is_notified_once_more(self):
        # Owner decision 2026-10-23 (PR #335): flapping, the ratio alert,
        # then offline for `after_seconds` on end: a second notification by
        # the continuous rule, and never a third in that flapping period.
        monitor = self.monitor()
        self.online(monitor)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))
        self.off(monitor)
        self.run_for(monitor, 270)
        self.assertEqual(1, len(self.sent()))
        self.run_for(monitor, 30)
        self.assertEqual(2, len(self.sent()))
        self.assertEqual(2, len({row.event_id for row in self.sent()}))
        self.run_for(monitor, 3 * 3600, step=60)
        self.assertEqual(2, len(self.sent()))
        self.assertEqual(1, self.drain(monitor).offline_sources)
        # Flapping and further five-minute outages inside the same period
        # (online shorter than the window) add nothing.
        self.on(monitor)
        self.run_for(monitor, 2)
        for _ in range(3):
            self.cycle(monitor)
        self.off(monitor)
        self.run_for(monitor, 600, step=60)
        self.on(monitor)
        self.run_for(monitor, 2)
        self.assertEqual(2, len(self.sent()))
        # Back for a whole window: the period closes and a later flapping
        # period is notified again, with its own second notification.
        self.run_for(monitor, 900, step=60)
        self.assertEqual(0, self.drain(monitor).flapping_sources)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(3, len(self.sent()))
        self.off(monitor)
        self.run_for(monitor, 300)
        self.assertEqual(4, len(self.sent()))
        self.run_for(monitor, 3600, step=60)
        self.assertEqual(4, len(self.sent()))

    def test_the_second_notification_obeys_the_hourly_cap(self):
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
            self.off(monitor)
            self.run_for(monitor, 600)
        self.assertEqual(1, len(self.sent()))
        self.assertTrue(all(line.endswith(Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED.value)
                            for line in logs.output), logs.output)
        self.run_for(monitor, 3600, step=60)
        self.assertEqual(2, len(self.sent()))

    def test_an_outage_after_a_long_online_is_an_ordinary_episode(self):
        # PR #335 review 重大 1: after the ratio alert the camera was back for
        # ten minutes (longer than `after_seconds`, shorter than the window);
        # each later outage of five minutes is its own episode.
        monitor = self.monitor()
        self.online(monitor)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))
        for count in range(2, 5):
            self.run_for(monitor, 600)
            self.off(monitor)
            self.run_for(monitor, 300)
            self.assertEqual(count, len(self.sent()))
            self.run_for(monitor, 3 * 3600 - 300, step=600)
            self.on(monitor)
        self.assertEqual(4, len(self.sent()))

    def test_a_long_window_does_not_silence_later_outages(self):
        monitor = self.monitor(flapping_window_seconds=86400, flapping_offline_seconds=60)
        self.online(monitor)
        for _ in range(2):
            self.cycle(monitor, offline=40, online=2)
        self.assertEqual(1, len(self.sent()))
        for count in range(2, 5):
            self.run_for(monitor, 6 * 3600, step=600)
            self.off(monitor)
            self.run_for(monitor, 3600, step=60)
            self.on(monitor)
            self.assertEqual(count, len(self.sent()))

    def test_a_dropped_episode_does_not_silence_the_source(self):
        # PR #335 review 重要 2: an outage held back by the cap and dropped
        # (online at a drain) was never notified; the flapping that follows
        # is, once the hour allows.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        second = self.sources[1]
        self.off(monitor, second)
        self.run_for(monitor, 300)
        self.on(monitor, second)
        self.assertEqual(1, len(self.sent()))
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
            self.off(monitor)
            self.run_for(monitor, 360)
            self.on(monitor)
            self.run_for(monitor, 30)
        self.assertIn(Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED.value, logs.output[-1])
        self.assertEqual(1, monitor.dropped)
        for _ in range(60):
            self.cycle(monitor, offline=180, online=60)
        self.assertEqual(2, len(self.sent()))

    def test_an_online_shorter_than_the_window_keeps_the_period_open(self):
        monitor = self.monitor()
        self.online(monitor)
        for _ in range(2):
            self.cycle(monitor)
        # Online 2 s + 897 s: one second short of the window.
        self.run_for(monitor, 897, step=60)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_the_outage_in_progress_counts_again_from_the_ratio_alert(self):
        # The ratio reaches the total before the continuous threshold. The
        # outage in progress belongs to that alert and is notified once more
        # only after `after_seconds` past the alert, not past its own start.
        monitor = self.monitor()
        self.online(monitor)
        self.cycle(monitor, offline=120, online=60)
        self.off(monitor)
        self.run_for(monitor, 180)
        self.assertEqual(1, len(self.sent()))
        # 300 s after its start, 120 s after the alert: nothing more.
        self.run_for(monitor, 120)
        self.assertEqual(1, len(self.sent()))
        self.run_for(monitor, 150)
        self.assertEqual(1, len(self.sent()))
        self.run_for(monitor, 30)
        self.assertEqual(2, len(self.sent()))
        self.run_for(monitor, 3600, step=60)
        self.assertEqual(2, len(self.sent()))

    def test_an_outage_that_ends_before_the_threshold_from_the_alert_adds_nothing(self):
        monitor = self.monitor()
        self.online(monitor)
        self.cycle(monitor, offline=120, online=60)
        self.off(monitor)
        self.run_for(monitor, 180)
        self.run_for(monitor, 290)
        self.on(monitor)
        self.run_for(monitor, 3600, step=60)
        self.assertEqual(1, len(self.sent()))

    def test_flapping_after_a_continuous_alert_is_the_same_period(self):
        monitor = self.monitor()
        self.online(monitor)
        self.off(monitor)
        self.run_for(monitor, 360)
        self.assertEqual(1, len(self.sent()))
        self.on(monitor)
        self.run_for(monitor, 2)
        for _ in range(10):
            self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))
        # Unchanged continuous rule: a new outage of five minutes is its own
        # episode even inside that period.
        self.off(monitor)
        self.run_for(monitor, 300)
        self.assertEqual(2, len(self.sent()))
        self.on(monitor)
        self.run_for(monitor, 900, step=60)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(3, len(self.sent()))

    def test_inactive_time_never_counts(self):
        monitor = self.monitor()
        self.online(monitor)
        for reason in ("disabled", "capture_service_stopping"):
            for _ in range(4):
                self.off(monitor, reason=reason)
                self.run_for(monitor, 240)
                self.on(monitor)
                self.run_for(monitor, 2)
        self.assertEqual([], self.sent())

    def test_each_source_is_counted_on_its_own(self):
        monitor = self.monitor()
        self.online(monitor)
        first, second = self.sources
        self.off(monitor, first)
        self.run_for(monitor, 150)
        self.on(monitor, first)
        self.off(monitor, second)
        self.run_for(monitor, 149)
        self.on(monitor, second)
        self.off(monitor, first)
        self.run_for(monitor, 149)
        self.on(monitor, first)
        self.run_for(monitor, 900)
        # The first source: 150 s + 149 s; the second: 149 s.
        self.assertEqual([], self.sent())

    def test_ratio_alerts_share_the_hourly_cap(self):
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        second = self.sources[1]
        self.off(monitor, second)
        self.run_for(monitor, 300)
        self.assertEqual(1, len(self.sent()))
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
            for _ in range(2):
                self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))
        self.assertEqual(1, self.drain(monitor).held)
        self.assertTrue(all(line.endswith(Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED.value)
                            for line in logs.output), logs.output)
        # Still flapping when the hour allows: sent.
        for _ in range(14):
            self.cycle(monitor)
        self.assertEqual(2, len(self.sent()))

    def test_an_owed_continuous_episode_is_not_also_a_ratio_alert(self):
        # The queue refused an outage past the threshold; after a recovery
        # longer than the threshold a shorter outage follows. Together they
        # pass the ratio, but the owed outage is the continuous rule's to
        # report and it opens the alerted period: one notification.
        monitor = self.monitor()
        self.online(monitor)
        refusing = Refusing(self.service)

        def drain_for(seconds):
            for _ in range(seconds // 30):
                self.advance(30)
                monitor.drain(refusing, at=AT, monotonic=self.clock.value)

        self.off(monitor)
        drain_for(330)
        self.on(monitor)
        drain_for(390)
        self.off(monitor)
        drain_for(240)
        self.on(monitor)
        drain_for(30)
        refusing.accept = True
        self.run_for(monitor, 600)
        self.service.poll()
        self.assertEqual(1, len(self.sent()))

    def test_a_held_ratio_alert_whose_period_closed_is_dropped(self):
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        second = self.sources[1]
        self.off(monitor, second)
        self.run_for(monitor, 300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            for _ in range(2):
                self.cycle(monitor)
        # The period closes while the hour is still closed.
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as dropped:
            self.run_for(monitor, 900, step=60)
        self.assertEqual(
            [f"WARNING:app.monitoring.cameras:{Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED.value}"],
            dropped.output)
        self.assertEqual(1, monitor.dropped)
        self.run_for(monitor, 3600, step=600)
        self.assertEqual(1, len(self.sent()))

    def test_a_ratio_alert_an_earlier_process_sent_is_not_sent_again(self):
        monitor = self.monitor()
        self.online(monitor)
        earlier = uuid4()
        calls = []

        def flapping_id(source):
            calls.append(source)
            return earlier, True

        for _ in range(2):
            self.off(monitor)
            self.advance(240)
            self.drain(monitor, flapping_id=flapping_id)
            self.on(monitor)
            self.advance(2)
            self.drain(monitor, flapping_id=flapping_id)
        self.advance(60)
        self.off(monitor)
        self.advance(60)
        self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual([self.sources[0]], calls)
        self.assertEqual([], self.sent())
        # The period is open: the ratio rule stays silent; an outage that
        # lasts `after_seconds` from the alert is the one continuous
        # notification of the period (Owner decision 2026-10-23).
        self.advance(3600)
        self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual(1, len(self.sent()))
        self.assertNotEqual(earlier, self.sent()[0].event_id)
        self.advance(3600)
        self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual([self.sources[0]], calls)
        self.assertEqual(1, len(self.sent()))

    def test_the_flapping_id_names_the_row(self):
        monitor = self.monitor()
        self.online(monitor)
        name = uuid4()
        for _ in range(2):
            self.off(monitor)
            self.advance(240)
            self.drain(monitor, flapping_id=lambda source: (name, False))
            self.on(monitor)
            self.advance(2)
        self.assertEqual([name], [row.event_id for row in self.sent()])

    def test_failing_or_reused_flapping_ids_fall_back_to_a_process_id(self):
        def broken(source):
            raise RuntimeError("synthetic database error")

        for flapping_id in (broken, lambda source: "x", lambda source: (uuid4(), 1)):
            with self.subTest(flapping_id=flapping_id):
                self.sink.rows.clear()
                monitor = self.monitor()
                self.online(monitor)
                for _ in range(2):
                    self.off(monitor)
                    self.advance(240)
                    self.drain(monitor, flapping_id=flapping_id)
                    self.on(monitor)
                    self.advance(2)
                self.assertEqual(1, len(self.sent()))

    def test_memory_is_bounded_and_the_total_is_kept(self):
        monitor = self.monitor()
        self.online(monitor)
        for _ in range(DOWN_BINS * 20):
            self.off(monitor)
            self.advance(0.2)
            self.on(monitor)
            self.advance(0.2)
        down = monitor._sources[self.sources[0]].down
        self.assertLessEqual(len(down.bins), DOWN_BINS + 2)
        # Half of the last 900 s was not online, about 450 s in total.
        total = sum(seconds for _index, seconds in down.bins)
        self.assertGreaterEqual(total, 450 - 0.2)
        self.assertLessEqual(total, 450 + 900 / DOWN_BINS)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))
        # Quiet sources keep nothing beyond the window.
        self.advance(901)
        self.drain(monitor)
        self.assertEqual(0, len(down.bins))
        self.assertEqual(0, len(monitor._sources[self.sources[1]].down.bins))

    def test_frequent_short_dropouts_are_counted_as_they_are(self):
        # PR #335 review 提案 3: 0.1 s not online every 2 s (5 %) for an hour
        # is about 45 s within fifteen minutes, never five minutes.
        monitor = self.monitor()
        self.online(monitor)
        for step in range(1800):
            self.off(monitor)
            self.advance(0.1)
            self.on(monitor)
            self.advance(1.9)
            if step % 30 == 0:
                self.drain(monitor)
        self.drain(monitor)
        self.assertEqual([], self.sent())
        down = monitor._sources[self.sources[0]].down
        self.assertLessEqual(sum(seconds for _index, seconds in down.bins), 45 + 0.1 * 4)
        # A long window: the same dropouts reach a one-minute total only once
        # the window holds at least a minute of them.
        monitor = self.monitor(flapping_window_seconds=86400, flapping_offline_seconds=60)
        self.online(monitor)
        for _ in range(590):
            self.off(monitor)
            self.advance(0.1)
            self.on(monitor)
            self.advance(1.9)
        self.drain(monitor)
        self.assertEqual([], self.sent())
        for _ in range(20):
            self.off(monitor)
            self.advance(0.1)
            self.on(monitor)
            self.advance(1.9)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_odd_clocks_never_raise(self):
        monitor = self.monitor()
        self.online(monitor)
        self.cycle(monitor)
        self.clock.value -= 10_000
        self.cycle(monitor)
        self.clock.value = float("nan")
        self.off(monitor)
        self.drain(monitor)
        # An unknown time notifies the outage rather than hiding it (#320).
        self.assertEqual(1, len(self.sent()))
        self.clock.value = 50_000.0
        self.on(monitor)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(1, len(self.sent()))
        # Once the clock is sane, a later flapping period is detected.
        self.run_for(monitor, 900, step=60)
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(2, len(self.sent()))

    def test_flapping_settings_are_validated(self):
        for values in (dict(flapping_window_seconds=119), dict(flapping_window_seconds=86401),
                       dict(flapping_offline_seconds=59),
                       dict(flapping_window_seconds=600, flapping_offline_seconds=601),
                       dict(flapping_window_seconds=float("nan")),
                       dict(flapping_offline_seconds=float("inf")),
                       dict(flapping_window_seconds=True)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.monitor(**values)
        # PR #335 review 提案 5: a total equal to the window can never be
        # reached over two periods; one tick below it is the most allowed.
        with self.assertRaises(ValueError):
            self.monitor(flapping_window_seconds=300, flapping_offline_seconds=300)
        with self.assertRaises(ValueError):
            self.monitor(flapping_window_seconds=300, flapping_offline_seconds=241)
        monitor = self.monitor(flapping_window_seconds=300, flapping_offline_seconds=240)
        self.assertEqual((300.0, 240.0), (monitor.window, monitor.flapping_offline))


class ConfigurationTests(unittest.TestCase):
    def parse(self, value):
        return parse_monitoring({"time_zone": "UTC", **value}, recordings_directory=Path("/"),
                                resolve_device=lambda uuid: 0, root_device=lambda: 0)

    def test_defaults_and_values(self):
        self.assertEqual(CameraOfflineNotification(300.0, 4, 900.0, 300.0),
                         self.parse({}).camera_offline)
        flapping = self.parse({"camera_offline_notification": {
            "flapping_window_seconds": 1200, "flapping_offline_seconds": 600}}).camera_offline
        self.assertEqual((1200.0, 600.0), (flapping.flapping_window_seconds,
                                           flapping.flapping_offline_seconds))
        configured = self.parse({"camera_offline_notification": {
            "after_seconds": 600, "hourly_limit": 2}}).camera_offline
        self.assertEqual((600.0, 2), (configured.after_seconds, configured.hourly_limit))
        self.assertEqual(900.0, self.parse({"camera_offline_notification": {
            "after_seconds": 900}}).camera_offline.after_seconds)

    def test_invalid_values_are_refused_without_echoing_them(self):
        for value in ([], {"after_seconds": 59}, {"after_seconds": 86401},
                      {"after_seconds": 300.5}, {"after_seconds": True},
                      {"after_seconds": "300"}, {"hourly_limit": 0}, {"hourly_limit": 61},
                      {"flapping_window_seconds": 119}, {"flapping_window_seconds": 86401},
                      {"flapping_offline_seconds": 59}, {"flapping_offline_seconds": 901},
                      {"flapping_offline_seconds": 841},
                      {"flapping_window_seconds": 600, "flapping_offline_seconds": 600},
                      {"flapping_window_seconds": 600, "flapping_offline_seconds": 601},
                      {"flapping_window_seconds": 900.5}, {"flapping_offline_seconds": False},
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

    async def first_outage_notified(self):
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            self.discovery.devices = []
            self.assertTrue(await self.until(lambda: self.health() is SourceHealthState.OFFLINE))
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
        self.assertEqual([ALERT], self.slack_texts())

    async def restart_offline(self, hours):
        # A later start with the camera absent and the registry last-frame
        # time unchanged (as when a short online period could not write it).
        self.clock.advance(timedelta(hours=hours))
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)

    async def test_a_row_older_than_a_day_does_not_hide_a_later_outage(self):
        # Owner decision 2026-10-22 (PR #320 提案 1): a camera_offline row of
        # the derived name accepted more than 24 h ago no longer suppresses.
        await self.first_outage_notified()
        await self.restart_offline(23)
        self.assertEqual([ALERT], self.slack_texts())
        await self.restart_offline(25)
        self.assertEqual([ALERT, ALERT], self.slack_texts())
        rows = self.offline_rows()
        self.assertEqual([(1, "sent"), (1, "sent")], rows)
        # The repeat has a durable name too: a restart within a day of it
        # sends nothing again.
        await self.restart_offline(1)
        self.assertEqual([ALERT, ALERT], self.slack_texts())
        await self.restart_offline(25)
        self.assertEqual([ALERT] * 3, self.slack_texts())

    async def test_a_repeat_after_a_day_still_obeys_the_hourly_cap(self):
        await self.first_outage_notified()
        self.clock.advance(timedelta(hours=25))
        # A fresh confirmed alert from another source within the hour.
        self.stored_row(confirmed=True, delivery="sent", age=60)
        configuration = self.configuration(camera_offline=CameraOfflineNotification(300, 1))
        application = self.uvc_application(configuration)
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=301))
            with self.assertLogs("app.monitoring.cameras", level="WARNING"):
                await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            self.clock.advance(timedelta(hours=1))
            await self.tick(runtime)
            self.assertEqual([ALERT, ALERT], self.slack_texts())

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

    def insert_row(self, event_id, at, accepted_at):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute(
                "INSERT INTO notification_events(event_id,kind,at,confirmed,delivery,accepted_at) "
                "VALUES (?,?,?,?,?,?)",
                (str(event_id), NotificationKind.CAMERA_OFFLINE.value, at, 1, "sent",
                 accepted_at))
            db.commit()

    def delete_rows(self):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute("DELETE FROM notification_events WHERE kind=?",
                       (NotificationKind.CAMERA_OFFLINE.value,))
            db.commit()

    def chain_name(self, repeat=0):
        base = f"camera-offline:{self.source.id}:never"
        return uuid5(EVENT_NAMESPACE, base if not repeat else f"{base}:repeat:{repeat}")

    async def test_the_24_hour_chain_boundaries(self):
        # PR #320 re-review 3 提案: chain exhausted, a future time and an
        # unreadable time.
        old = (self.clock.now - timedelta(days=2)).isoformat()
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            def name():
                return runtime.call(runtime._camera_offline_event, self.source.id)

            self.assertEqual(self.chain_name(), await name())
            # Unreadable: treated as old, so the next name is used.
            self.insert_row(self.chain_name(), old, "not a time")
            self.assertEqual(self.chain_name(1), await name())
            # A time in the future (a clock moved back) counts as recent.
            future = (self.clock.now + timedelta(hours=1)).isoformat()
            self.insert_row(self.chain_name(1), future, future)
            self.assertEqual(self.chain_name(1), await name())
        self.delete_rows()
        # Every name of the chain was used more than a day ago: no durable
        # name, and the outage is still notified under a process-local ID.
        names = [self.chain_name(repeat) for repeat in range(CAMERA_OFFLINE_RENOTIFY_CHAIN)]
        for event_id in names:
            self.insert_row(event_id, old, old)
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertIsNone(await runtime.call(runtime._camera_offline_event, self.source.id))
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
        self.assertEqual([ALERT], self.slack_texts())
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            sent = {row[0] for row in db.execute(
                "SELECT event_id FROM notification_events WHERE kind=? AND accepted_at!=?",
                (NotificationKind.CAMERA_OFFLINE.value, old))}
        self.assertEqual(1, len(sent))
        self.assertNotIn(sent.pop(), {str(event_id) for event_id in names})

    async def test_a_chain_row_stamped_in_the_future_is_not_resent(self):
        # The future row counts as this outage's notification: not resent.
        future = (self.clock.now + timedelta(hours=1)).isoformat()
        self.insert_row(self.chain_name(), future, future)
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
        self.assertEqual([], self.slack_texts())

    def flapping_name(self, index):
        return uuid5(EVENT_NAMESPACE,
                     f"camera-offline-flapping:{self.source.id}:900:{index}")

    async def test_the_flapping_name(self):
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            def name():
                return runtime.call(runtime._camera_flapping_event, self.source.id)

            bucket = math.floor(self.clock.now.timestamp() / 900)
            self.assertEqual((self.flapping_name(bucket), False), await name())
            # The previous bucket, triggered less than a window ago.
            recent = (self.clock.now - timedelta(seconds=100)).isoformat()
            self.insert_row(self.flapping_name(bucket - 1), recent, recent)
            self.assertEqual((self.flapping_name(bucket - 1), True), await name())
            # More than a window ago by its event time (which a retry keeps),
            # even when accepted later.
            self.delete_rows()
            self.insert_row(self.flapping_name(bucket - 1),
                            (self.clock.now - timedelta(seconds=1000)).isoformat(),
                            self.clock.now.isoformat())
            self.assertEqual((self.flapping_name(bucket), False), await name())
            # A future time counts as recent; an unreadable one as old.
            future = (self.clock.now + timedelta(hours=1)).isoformat()
            self.insert_row(self.flapping_name(bucket), future, future)
            self.assertEqual((self.flapping_name(bucket), True), await name())
            self.delete_rows()
            self.insert_row(self.flapping_name(bucket), "not a time", "not a time")
            self.assertIsNone(await name())

    async def flap(self, application, offline):
        monitor = application.state.camera_offline
        self.discovery.devices = []
        self.assertTrue(await self.until(lambda: not monitor._sources[self.source.id].online))
        self.clock.advance(timedelta(seconds=offline))
        self.discovery.devices = [self.camera]
        self.assertTrue(await self.until(lambda: monitor._sources[self.source.id].online))
        self.clock.advance(timedelta(seconds=2))

    async def test_a_flapping_camera_is_not_notified_twice_across_a_restart(self):
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            await self.flap(application, 240)
            await self.tick(runtime)
            self.assertEqual([], self.slack_texts())
            monitor = application.state.camera_offline
            self.discovery.devices = []
            self.assertTrue(await self.until(lambda: not monitor._sources[self.source.id].online))
            self.clock.advance(timedelta(seconds=61))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            self.assertEqual([(1, "sent")], self.offline_rows())
            self.assertTrue(runtime.status.camera_offline_degraded)
            self.discovery.devices = [self.camera]
            self.assertTrue(await self.until(lambda: monitor._sources[self.source.id].online))
        # Still flapping when the service starts again: the earlier process's
        # alert is found and nothing is sent twice.
        self.discovery.devices = []
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=200))
            monitor = application.state.camera_offline
            self.discovery.devices = [self.camera]
            self.assertTrue(await self.until(lambda: monitor._sources[self.source.id].online))
            self.clock.advance(timedelta(seconds=2))
            self.discovery.devices = []
            self.assertTrue(await self.until(lambda: not monitor._sources[self.source.id].online))
            self.clock.advance(timedelta(seconds=120))
            await self.tick(runtime)
            self.assertTrue(runtime.status.camera_offline_degraded)
            self.assertEqual([ALERT], self.slack_texts())
            # Offline on end from then on: the period's one continuous
            # notification (Owner decision 2026-10-23), and no third.
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.assertEqual([ALERT, ALERT], self.slack_texts())
            self.clock.advance(timedelta(hours=1))
            await self.tick(runtime)
        self.assertEqual([ALERT, ALERT], self.slack_texts())
        self.assertEqual([(1, "sent"), (1, "sent")], self.offline_rows())

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
