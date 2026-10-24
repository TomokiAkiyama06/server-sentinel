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
from app.monitoring.cameras import _BY_CONTINUOUS, _BY_RATIO, DOWN_BINS, CameraOfflineMonitor
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
# Issue #349: an alert sent after its outage had already recovered.
RECOVERED = "ServerSentinel critical alert: camera_offline (already recovered)"


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

    def clear_sent(self):
        # Wait for the delivery thread first: an outcome stored after the
        # clear would bring an earlier row back.
        for _ in range(1000):
            self.service.poll()
            if not self.service.pending_count:
                break
            time.sleep(0.01)
        # Never clear silently over a delivery still in flight.
        self.assertEqual(0, self.service.pending_count)
        self.sink.rows.clear()

    def advance(self, seconds):
        self.clock.value += seconds

    def texts(self):
        """Slack texts posted so far, once every delivery has completed."""
        for _ in range(1000):
            self.service.poll()
            if not self.service.pending_count:
                break
            time.sleep(0.01)
        self.assertEqual(0, self.service.pending_count)
        return [json.loads(request.data)["text"] for request, _ in self.transport.requests]


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
        # Issue #349: the fixed text says the camera already recovered.
        self.assertEqual([RECOVERED], self.texts())
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

    def test_only_a_camera_offline_alert_can_be_marked_recovered(self):
        # Issue #349: the suffix is the only change, and only for this kind.
        for kind in (NotificationKind.HARDWARE_INTEGRITY_FAILURE, NotificationKind.PERSON):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.service.record(kind, at=AT, confirmed=True, recovered=True)
        with self.assertRaises(ValueError):
            self.service.record(NotificationKind.CAMERA_OFFLINE, at=AT, confirmed=True,
                                recovered=1)
        event_id = uuid4()
        self.service.record(NotificationKind.CAMERA_OFFLINE, at=AT, confirmed=True,
                            event_id=event_id, recovered=True)
        self.assertEqual([RECOVERED], self.texts())
        row = self.sink.rows[event_id]
        self.assertEqual((NotificationKind.CAMERA_OFFLINE, AT, True),
                         (row.kind, row.at, row.confirmed))


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

    def test_one_recovered_episode_is_owed_while_the_cap_holds(self):
        # Issue #349: held episodes that recovered wait for the cap, but a
        # source keeps at most one owed besides the latest: after a long
        # recovery and a third outage the oldest is dropped and logged.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        monitor.restore_window([(uuid4(), 0.0)], monotonic=self.clock.value)
        source = self.sources[0]
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
            for _ in range(3):
                monitor.health_sink(event(source, CameraState.OFFLINE))
                self.advance(330)
                self.drain(monitor)
                monitor.health_sink(event(source, CameraState.ONLINE))
                self.advance(330)
                self.drain(monitor)
        self.assertEqual(1, sum(line.endswith(Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED.value)
                                for line in logs.output))
        self.assertEqual(([], 1), (self.sent(), monitor.dropped))
        for _ in range(3):
            self.advance(3600)
            self.drain(monitor)
        self.assertEqual(2, len(self.sent()))
        self.assertEqual([RECOVERED] * 2, self.texts())
        self.assertEqual(1, monitor.dropped)

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
    def test_a_held_episode_that_recovers_is_sent_once_when_the_hour_allows(self):
        # Owner decision 2026-10-24 (Issue #349): held back by the cap, then
        # online for good. The outage reached the threshold, so it is still
        # notified once when the hour allows (as PR #320's "recovered before
        # the drain"), saying it already recovered; the cap stays absolute.
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
        with self.assertNoLogs("app.monitoring.cameras", level="WARNING"):
            status = self.drain(monitor)
        self.assertEqual((0, 1, 0), (status.offline_sources, status.held, monitor.dropped))
        self.assertEqual(1, len(self.sent()))
        # One second before the slot expires: still held.
        self.advance(3600 - 60 - 1)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))
        self.advance(1)
        status = self.drain(monitor)
        self.assertEqual((0, 0, 0), (status.offline_sources, status.held, monitor.dropped))
        self.assertEqual(2, len(self.sent()))
        self.assertEqual(1, len({row.at for row in self.sent()}))
        self.assertEqual([ALERT, RECOVERED], self.texts())
        for _ in range(3):
            self.advance(3600)
            self.drain(monitor)
        self.assertEqual(2, len(self.sent()))

    def test_an_outage_in_progress_goes_before_a_recovered_one(self):
        # Issue #349 review 重要 1: A was held and recovered, B went offline
        # later and is still offline. When the slot frees, B (in progress)
        # is sent first; A's late "already recovered" notice waits.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        monitor.restore_window([(uuid4(), 0.0)], monotonic=self.clock.value)
        first, second = self.sources
        monitor.health_sink(event(first, CameraState.OFFLINE))
        self.advance(310)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.drain(monitor)
        monitor.health_sink(event(first, CameraState.ONLINE))
        self.advance(10)
        monitor.health_sink(event(second, CameraState.OFFLINE))
        self.advance(310)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.assertEqual(2, self.drain(monitor).held)
        self.advance(3600 - 630)
        status = self.drain(monitor)
        self.assertEqual((1, 1), (status.offline_sources, status.held))
        self.assertEqual([ALERT], self.texts())
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual([ALERT, RECOVERED], self.texts())
        self.assertEqual(0, monitor.dropped)

    def test_held_recovered_episodes_never_exceed_the_cap(self):
        # Issue #349: every source held and recovered; each is sent once,
        # never more than `hourly_limit` in any rolling hour.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        for source in self.sources:
            monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.drain(monitor)
        self.online(monitor)
        times = []
        for _ in range(200):
            self.advance(60)
            before = len(self.sent())
            self.drain(monitor)
            times.extend([self.clock.value] * (len(self.sent()) - before))
        self.assertEqual(2, len(self.sent()))
        self.assertEqual(1, len(times))
        self.assertGreaterEqual(times[0] - 1300.0, 3600)
        self.assertEqual(0, monitor.dropped)

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

    def test_a_pending_durable_id_is_sent_again_under_its_id_and_time(self):
        # Issue #336: a `pending` row (the earlier process exited before the
        # Slack outcome was stored) is not confirmed: `known` gives its
        # stored time and the alert is submitted again under that ID. The
        # cap is absolute (PR #339): while the row's uncertain delivery still
        # holds a slot of the hour, the resend waits for that slot.
        durable, stored = uuid4(), AT - timedelta(hours=2)
        monitor = self.monitor(hourly_limit=2)
        self.online(monitor)
        monitor.restore_window([(durable, 600.0)], monotonic=self.clock.value)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        known = {durable: stored}
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.assertEqual(1, self.drain(monitor, durable_id=lambda source: durable,
                                           known=lambda value: known.get(value, False)).held)
        self.assertEqual([], self.sent())
        self.advance(2699)
        self.drain(monitor, durable_id=lambda source: durable,
                   known=lambda value: known.get(value, False))
        self.assertEqual([], self.sent())
        self.advance(1)
        self.drain(monitor, durable_id=lambda source: durable,
                   known=lambda value: known.get(value, False))
        rows = self.sent()
        self.assertEqual([(durable, stored, "sent")],
                         [(row.event_id, row.at, row.delivery.value) for row in rows])
        self.assertEqual(1, len(monitor._sent))

    def test_restored_pending_rows_are_sent_again_once(self):
        # Issue #336: rows the runtime found still `pending` at start, sent
        # whether or not the outage is still in progress (the row does not
        # name its source), and never twice when an episode maps to them.
        monitor = self.monitor(hourly_limit=2)
        self.online(monitor)
        counted, older = uuid4(), uuid4()
        monitor.restore_window([(counted, 60.0), (uuid4(), 120.0)],
                               monotonic=self.clock.value)
        stored, earlier = AT - timedelta(minutes=1), AT - timedelta(hours=3)
        monitor.restore_pending([(counted, stored), (older, earlier)])
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.assertEqual(2, self.drain(monitor).held)
        self.assertEqual([], self.sent())
        # One slot frees: the restored rows go by their stored time, but the
        # counted one still holds its own slot and waits for it.
        self.advance(3600 - 120)
        self.assertEqual(1, self.drain(monitor).held)
        self.assertEqual([(older, earlier)], [(row.event_id, row.at) for row in self.sent()])
        self.advance(60)
        self.assertEqual(0, self.drain(monitor).held)
        self.assertEqual({counted: stored, older: earlier},
                         {row.event_id: row.at for row in self.sent()})
        self.assertEqual(2, len(monitor._sent))
        # A restored ID that the outage in progress since the start maps to
        # is covered: one alert. A later episode reusing that name gets its
        # own ID.
        monitor = self.monitor()
        self.clear_sent()
        self.online(monitor, self.sources[1])
        durable = uuid4()
        monitor.restore_pending([(durable, stored)])
        source = self.sources[0]
        for _ in range(2):
            monitor.health_sink(event(source, CameraState.OFFLINE))
            self.advance(300)
            self.drain(monitor, durable_id=lambda value: durable,
                       known=lambda value: stored if value == durable else False)
            monitor.health_sink(event(source, CameraState.ONLINE))
        rows = self.sent()
        self.assertEqual(2, len(rows))
        self.assertIn(durable, {row.event_id for row in rows})
        # The flapping name is covered the same way.
        monitor = self.monitor()
        self.clear_sent()
        self.online(monitor)
        durable = uuid4()
        monitor.restore_pending([(durable, stored)])
        self.drain(monitor)
        for _ in range(2):
            monitor.health_sink(event(source, CameraState.OFFLINE))
            self.advance(240)
            self.drain(monitor, flapping_id=lambda value: (durable, stored))
            monitor.health_sink(event(source, CameraState.ONLINE))
            self.advance(2)
        self.assertEqual([durable], [row.event_id for row in self.sent()])
        self.assertEqual(1, self.drain(monitor).flapping_sources)
        for rows in ([(uuid4(), stored)] * 5, [(uuid4(), AT.replace(tzinfo=None))],
                     [("x", stored)]):
            with self.assertRaises(ValueError):
                monitor.restore_pending(rows)
        with self.assertRaises(ValueError):
            monitor.restore_pending([], unrestored=-1)

    def test_a_covered_episode_is_settled_before_the_cap(self):
        # PR #339 重要 1: the hour is full and one of its rows is the pending
        # alert P of the outage still in progress. The episode is covered by
        # P's resend at once (never held, then dropped on recovery, leaving P
        # claimed), so a later outage reusing the name is still notified.
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        pending, stored = uuid4(), AT - timedelta(minutes=2)
        monitor.restore_window([(pending, 120.0)] + [(uuid4(), 600.0) for _ in range(3)],
                               monotonic=self.clock.value)
        monitor.restore_pending([(pending, stored)])

        def known(value):
            return stored if value == pending else False

        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
            status = self.drain(monitor, durable_id=lambda source: pending, known=known)
        # Only P's resend waits for the hour; the episode is settled.
        self.assertEqual(1, status.held)
        self.assertEqual(1, len(logs.output))
        self.assertIn(pending, monitor._restored)
        self.assertEqual([], self.sent())
        monitor.health_sink(event(self.sources[0], CameraState.ONLINE))
        self.advance(60)
        self.drain(monitor, durable_id=lambda source: pending, known=known)
        self.assertEqual(0, monitor.dropped)
        self.advance(3600)
        self.drain(monitor, durable_id=lambda source: pending, known=known)
        self.assertEqual([(pending, stored)], [(row.event_id, row.at) for row in self.sent()])
        self.assertNotIn(pending, monitor._restored)
        # A new outage with the same last-frame time (a refused write).
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        self.drain(monitor, durable_id=lambda source: pending, known=lambda value: True)
        self.assertEqual(2, len(self.sent()))

    def test_a_sent_resend_still_covers_the_outage_in_progress(self):
        # The resend goes out before the outage in progress since the start
        # reaches the threshold: that outage is still covered, not resent.
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        pending, stored = uuid4(), AT - timedelta(hours=2)
        monitor.restore_pending([(pending, stored)])
        self.drain(monitor)
        self.assertEqual([pending], [row.event_id for row in self.sent()])
        self.assertNotIn(pending, monitor._restored)
        self.advance(300)
        self.drain(monitor, durable_id=lambda source: pending, known=lambda value: True)
        self.assertEqual(1, len(self.sent()))
        self.assertEqual(1, self.drain(monitor).offline_sources)

    def later_outage_reusing_a_restored_name(self, *, sent_first):
        # Codex PR #339 P2: the restored row's outage recovered before the
        # restart, so no episode claims its resend. A later, distinct outage
        # that reuses the durable name (its online last-frame write was
        # refused) must still be notified, under a per-process ID, whether
        # the resend was already sent or is still waiting for the hour.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        pending, stored = uuid4(), AT - timedelta(hours=2)
        monitor.restore_pending([(pending, stored)])
        if sent_first:
            self.drain(monitor)
            self.assertEqual([pending], [row.event_id for row in self.sent()])
            self.advance(3600)
        else:
            monitor.restore_window([(uuid4(), 60.0)], monotonic=self.clock.value)
        monitor.health_sink(event(self.sources[0], CameraState.OFFLINE))
        self.advance(300)
        for _ in range(3):
            # The row is final once sent, pending while it waits.
            self.drain(monitor, durable_id=lambda source: pending,
                       known=lambda value: True if sent_first else stored)
            self.advance(3600)
        ids = [row.event_id for row in self.sent()]
        self.assertEqual(2, len(ids))
        self.assertIn(pending, ids)
        self.assertEqual(2, len(set(ids)))

    def test_a_sent_restored_name_does_not_cover_a_later_outage(self):
        self.later_outage_reusing_a_restored_name(sent_first=True)

    def test_an_unsent_restored_name_does_not_cover_a_later_outage(self):
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.later_outage_reusing_a_restored_name(sent_first=False)

    def test_an_initial_episode_recovered_before_the_drain_keeps_its_name(self):
        # Issue #342 D: named on the first running tick (`name_initial`),
        # it reached the threshold and recovered before the drain; the live
        # name has moved with the new frame. It is matched by the name kept.
        pending, stored, moved = uuid4(), AT - timedelta(minutes=10), uuid4()
        rows = {pending: stored}

        def run(rows, restore):
            self.clear_sent()
            monitor = self.monitor()
            self.online(monitor, self.sources[1])
            monitor.restore_window([], monotonic=self.clock.value)
            if restore:
                monitor.restore_pending([(pending, stored)])
            monitor.name_initial(lambda source: pending)
            self.assertEqual(pending, monitor._sources[self.sources[0]].episode.name)
            self.assertIsNone(monitor._sources[self.sources[1]].episode)
            self.advance(310)
            monitor.health_sink(event(self.sources[0], CameraState.ONLINE))
            for _ in range(2):
                self.drain(monitor, durable_id=lambda source: moved,
                           known=lambda value: rows.get(value, False))
                self.advance(3600)
            return [(row.event_id, row.at) for row in self.sent()]

        # A restored row: covered by its resend, one notification.
        self.assertEqual([(pending, stored)], run(rows, restore=True))
        # Left out of the restore (beyond the cap): sent again by name.
        self.assertEqual([(pending, stored)], run(rows, restore=False))
        # A final row: the earlier process notified this outage.
        self.assertEqual([], run({pending: True}, restore=False))
        # No row: a per-process ID as before (never the kept name).
        sent = run({}, restore=False)
        self.assertEqual(1, len(sent))
        self.assertNotIn(sent[0][0], {pending, moved})

    def test_name_initial_does_not_name_a_recovered_initial_episode(self):
        # PR #348 review 提案 2 (R14): its last-frame time may have moved.
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        self.advance(310)
        monitor.health_sink(event(self.sources[0], CameraState.ONLINE))
        episode = monitor._sources[self.sources[0]].episode
        self.assertIsNotNone(episode.recovered)
        monitor.name_initial(lambda source: uuid4())
        self.assertIsNone(episode.name)

    def test_a_live_name_is_not_replaced_by_the_kept_name_found_by_known(self):
        # PR #348 review 提案 2 (R15): while the episode is named live, the
        # kept name is used only when it is a restored row, never because
        # `known` finds it.
        kept, live, stored = uuid4(), uuid4(), AT - timedelta(minutes=10)
        rows = {kept: stored}
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        monitor.name_initial(lambda source: kept)
        self.advance(300)
        self.drain(monitor, durable_id=lambda source: live,
                   known=lambda value: rows.get(value, False))
        self.assertEqual([live], [row.event_id for row in self.sent()])

    def test_name_initial_names_only_an_initial_outage_in_progress(self):
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        calls = []

        def durable(source):
            calls.append(source)
            if source == self.sources[0]:
                raise RuntimeError("synthetic database error")
            return uuid4()

        monitor.name_initial(durable)
        monitor.name_initial(None)
        self.assertEqual([self.sources[0]], calls)
        self.assertIsNone(monitor._sources[self.sources[0]].episode.name)

    def initial_sent_before_running(self, *, refused):
        # Issue #342 E: the runtime was not RUNNING for the threshold (no
        # names without storage), so the initial outage was notified under a
        # per-process ID (or its submission was refused). The first running
        # tick restores the pending row P of the same outage and names the
        # episode P: P's resend is not sent (the Owner already has this
        # process's notification), or the refused one is named and covered.
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        self.advance(300)
        if refused:
            self.service.close()
        self.drain(monitor)
        pending, stored = uuid4(), AT - timedelta(minutes=10)
        if refused:
            self.assertEqual([], self.sent())
            self.service = NotificationService(
                self.sink, SlackDelivery(endpoint(), opener=self.transport))
            self.addCleanup(self.service.close)
        else:
            self.assertEqual(1, len(self.sent()))
        monitor.restore_window([], monotonic=self.clock.value)
        monitor.restore_pending([(pending, stored)])
        monitor.name_initial(lambda source: pending)
        for _ in range(3):
            self.drain(monitor, durable_id=lambda source: pending,
                       known=lambda value: stored if value == pending else False)
            self.advance(3600)
        return monitor, pending

    def test_an_initial_outage_sent_before_running_covers_its_restored_row(self):
        monitor, pending = self.initial_sent_before_running(refused=False)
        rows = self.sent()
        self.assertEqual(1, len(rows))
        self.assertNotEqual(pending, rows[0].event_id)
        self.assertEqual((1, [], set()), (monitor.covered, monitor._resend, monitor._restored))
        # A later outage that reuses the name (a refused last-frame write)
        # is still notified, under a per-process ID.
        source = self.sources[0]
        monitor.health_sink(event(source, CameraState.ONLINE))
        monitor.health_sink(event(source, CameraState.OFFLINE))
        self.advance(300)
        self.drain(monitor, durable_id=lambda value: pending, known=lambda value: False)
        ids = [row.event_id for row in self.sent()]
        self.assertEqual(2, len(set(ids)))
        self.assertNotIn(pending, ids)

    def test_a_refused_initial_submission_is_covered_by_its_restored_row(self):
        monitor, pending = self.initial_sent_before_running(refused=True)
        self.assertEqual([pending], [row.event_id for row in self.sent()])
        self.assertEqual(0, monitor.covered)

    def test_live_alerts_go_before_restored_rows(self):
        # PR #339 重要 3: an outage in progress is not held back behind an
        # earlier process's uncertain delivery of an older outage.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor, self.sources[1])
        old, older = uuid4(), uuid4()
        # The newer handed over first: the order is by stored time.
        monitor.restore_pending([(old, AT - timedelta(hours=5))])
        monitor.restore_pending([(older, AT - timedelta(hours=10))])
        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.assertEqual(2, self.drain(monitor).held)
        rows = self.sent()
        self.assertEqual(1, len(rows))
        self.assertNotIn(rows[0].event_id, {old, older})
        # Then the restored rows, by their stored time.
        self.advance(3600)
        self.assertEqual(1, self.drain(monitor).held)
        self.assertEqual(older, self.sent()[-1].event_id)
        self.advance(3600)
        self.assertEqual(0, self.drain(monitor).held)
        self.assertEqual(old, self.sent()[-1].event_id)

    def test_this_process_rows_are_not_restored(self):
        # A row this process wrote itself (it notified while monitoring was
        # still `failed`) is its own delivery, not a restart's.
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        self.advance(300)
        self.drain(monitor)
        own = self.sent()[0].event_id
        monitor.restore_pending([(own, AT)])
        self.assertNotIn(own, monitor._restored)
        self.assertEqual([], monitor._resend)
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_a_restored_pending_row_waits_for_the_queue(self):
        monitor = self.monitor()
        self.online(monitor)
        pending, stored = uuid4(), AT - timedelta(minutes=1)
        monitor.restore_pending([(pending, stored)])
        self.service.close()
        self.drain(monitor)
        self.assertEqual([], self.sent())
        self.service = NotificationService(
            self.sink, SlackDelivery(endpoint(), opener=self.transport))
        self.addCleanup(self.service.close)
        self.drain(monitor)
        self.assertEqual([(pending, stored)], [(row.event_id, row.at) for row in self.sent()])
        # Stopped: nothing further.
        monitor.restore_pending([(uuid4(), stored)])
        monitor.stop()
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

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
                self.clear_sent()
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

    def test_a_held_episode_sent_late_opens_the_period(self):
        # PR #335 review 重要 2 dropped a held episode that recovered and
        # opened no period. Since Issue #349 it is sent once the hour allows
        # and, sent, opens the alerted period like any notification: the
        # flapping that follows (online shorter than the window) belongs to
        # that period and adds no ratio alert.
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
        self.assertNotIn(Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED.value, "".join(logs.output))
        for _ in range(60):
            self.cycle(monitor, offline=180, online=60)
        self.assertEqual(2, len(self.sent()))
        self.assertEqual(0, monitor.dropped)
        self.assertEqual(_BY_CONTINUOUS, monitor._sources[self.sources[0]].period)

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

    def test_an_ended_ratio_alert_is_dropped_when_the_hour_has_room_again(self):
        # Issue #338 item 2 (Codex PR #335 P2): drains were delayed until
        # both the quiet window and the hour had passed. The ended alert is
        # dropped before the cap, as when the cap is still closed.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        second = self.sources[1]
        self.off(monitor, second)
        self.run_for(monitor, 300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            for _ in range(2):
                self.cycle(monitor)
        self.assertIsNotNone(monitor._sources[self.sources[0]].flap)
        self.advance(3700)
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as dropped:
            status = self.drain(monitor)
        self.assertEqual(
            [f"WARNING:app.monitoring.cameras:{Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED.value}"],
            dropped.output)
        self.assertEqual((1, 0), (monitor.dropped, status.flapping_sources))
        self.assertIsNone(monitor._sources[self.sources[0]].flap)
        self.assertEqual(1, len(self.sent()))
        # Not sent: it opened no period, so later flapping is a new alert.
        for _ in range(2):
            self.cycle(monitor)
        self.assertEqual(2, len(self.sent()))

    def refused_ratio_alert_whose_period_closed(self, monitor):
        # The cap allowed the alert but the queue refused it (delivery
        # backpressure) until the source had been stable for a window.
        self.online(monitor)
        self.service.close()
        for _ in range(2):
            self.cycle(monitor)
        attempt = monitor._sources[self.sources[0]].flap.attempt
        self.assertIsNotNone(attempt)
        self.service = NotificationService(
            self.sink, SlackDelivery(endpoint(), opener=self.transport))
        self.addCleanup(self.service.close)
        self.advance(901)
        return attempt

    def test_a_refused_ratio_alert_is_sent_after_its_period_closed(self):
        # PR #348 review 提案 1: like a refused continuous episode that
        # recovered, it is sent under its time and ID once the queue takes
        # it, so a backpressure lasting a window never leaves the period
        # unnotified.
        monitor = self.monitor()
        attempt = self.refused_ratio_alert_whose_period_closed(monitor)
        self.drain(monitor)
        self.assertEqual([(attempt[1], attempt[0])],
                         [(row.event_id, row.at) for row in self.sent()])
        self.assertEqual(0, monitor.dropped)
        self.assertIsNone(monitor._sources[self.sources[0]].flap)
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual(1, len(self.sent()))

    def test_a_refused_ratio_alert_waits_if_the_cap_closed_meanwhile(self):
        # As a refused continuous episode that recovered (Issue #349): held
        # while the hour is full by the time the queue would take it, then
        # sent once under its time and ID, saying the camera recovered.
        monitor = self.monitor(hourly_limit=1)
        attempt = self.refused_ratio_alert_whose_period_closed(monitor)
        monitor.restore_window([(uuid4(), 60.0)], monotonic=self.clock.value)
        with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
            self.assertEqual(1, self.drain(monitor).held)
        self.assertEqual(
            [f"WARNING:app.monitoring.cameras:{Event.CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED.value}"],
            logs.output)
        self.assertEqual(([], 0), (self.sent(), monitor.dropped))
        self.advance(3540)
        self.drain(monitor)
        self.assertEqual([(attempt[1], attempt[0])],
                         [(row.event_id, row.at) for row in self.sent()])
        self.assertEqual([RECOVERED], self.texts())
        self.advance(3600)
        self.drain(monitor)
        self.assertEqual((1, 0), (len(self.sent()), monitor.dropped))

    def test_a_late_notice_of_a_long_recovered_outage_opens_no_period(self):
        # Issue #349 review 提案 2 and Codex PR #359 P2: an outage held by
        # the cap recovered more than a window before the source starts
        # flapping. The held episode no longer keeps the ratio rule from
        # evaluating the source, so the ratio alert of the current flapping
        # is created at once and, in progress, takes the freed slot first;
        # the late "already recovered" notice follows in the next hour and
        # opens no period of its own, nor counts as the period's continuous
        # notification.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor)
        monitor.restore_window([(uuid4(), 0.0)], monotonic=self.clock.value)
        source = monitor._sources[self.sources[0]]
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.off(monitor)
            self.run_for(monitor, 330)
            self.on(monitor)
            self.run_for(monitor, 1200, step=60)
            for _ in range(3):
                self.cycle(monitor)
            # Triggered while the cap still holds both.
            self.assertEqual(_BY_RATIO, source.period)
            self.assertIsNotNone(source.flap)
            self.assertEqual([], self.sent())
            while self.clock.value < 1000 + 3600 + 300:
                self.cycle(monitor)
        self.assertEqual([ALERT], self.texts())
        while self.clock.value < 1000 + 7200 + 300:
            self.cycle(monitor)
        self.assertEqual([ALERT, RECOVERED], self.texts())
        self.assertEqual((_BY_RATIO, False), (source.period, source.continuous_sent))
        self.assertEqual(0, monitor.dropped)

    def test_the_stale_boundary_is_a_window_and_one_bin(self):
        # Issue #349 re-review 提案 1: a late notice sent one second before
        # a window and one bin after its recovery opens the period, one
        # second after it does not.
        bin_width = 900 / DOWN_BINS
        for offset, period in ((-1, _BY_CONTINUOUS), (1, None)):
            with self.subTest(offset=offset):
                self.clock.value = 1000.0
                monitor = self.monitor(hourly_limit=1)
                self.online(monitor)
                self.off(monitor)
                recovered = self.clock.value + 310
                send = recovered + 900 + bin_width + offset
                # The one slot of the hour frees exactly at `send`.
                monitor.restore_window([(uuid4(), self.clock.value + 3600 - send)],
                                       monotonic=self.clock.value)
                self.advance(310)
                with self.assertLogs("app.monitoring.cameras", level="WARNING"):
                    self.drain(monitor)
                self.on(monitor)
                self.clock.value = send - 1
                self.assertEqual(1, self.drain(monitor).held)
                self.clock.value = send
                self.assertEqual(0, self.drain(monitor).held)
                self.assertEqual(period, monitor._sources[self.sources[0]].period)

    def test_a_late_notice_of_a_recent_outage_still_opens_the_period(self):
        # PR #320: one that recovered within the window before it was sent
        # opens the period, so the ratio rule does not report it again.
        monitor = self.monitor()
        self.online(monitor)
        self.off(monitor)
        self.advance(310)
        self.on(monitor)
        self.advance(50)
        self.drain(monitor)
        self.assertEqual([RECOVERED], self.texts())
        self.assertEqual(_BY_CONTINUOUS, monitor._sources[self.sources[0]].period)

    def test_a_waiting_ended_ratio_alert_never_blocks_a_new_period(self):
        # Issue #349 review 提案 3: a refused ratio alert whose period closed
        # waits for the cap apart from the source's current ratio alert, so
        # new flapping is still evaluated and alerted.
        monitor = self.monitor(hourly_limit=1)
        attempt = self.refused_ratio_alert_whose_period_closed(monitor)
        monitor.restore_window([(uuid4(), 0.0)], monotonic=self.clock.value)
        source = monitor._sources[self.sources[0]]
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            self.drain(monitor)
            self.assertIsNone(source.flap)
            self.assertIsNotNone(source.late_flap)
            for _ in range(2):
                self.cycle(monitor)
        self.assertEqual(_BY_RATIO, source.period)
        self.assertIsNotNone(source.flap)
        self.assertIsNot(source.flap, source.late_flap)
        self.assertEqual([], self.sent())
        for _ in range(32):
            self.cycle(monitor)
        rows = sorted(self.sent(), key=lambda row: row.at)
        self.assertEqual(2, len(rows))
        self.assertIn((attempt[1], attempt[0]), [(row.event_id, row.at) for row in rows])
        # The new period's alert (in progress) goes first.
        self.assertEqual([ALERT, RECOVERED], self.texts())
        self.assertIsNone(source.late_flap)
        self.assertEqual(0, monitor.dropped)

    def test_a_refused_continuous_episode_is_sent_after_it_recovered(self):
        # The continuous rule the refused ratio alert now matches.
        monitor = self.monitor()
        self.online(monitor)
        self.service.close()
        self.off(monitor)
        self.advance(300)
        self.drain(monitor)
        self.on(monitor)
        self.advance(901)
        self.service = NotificationService(
            self.sink, SlackDelivery(endpoint(), opener=self.transport))
        self.addCleanup(self.service.close)
        self.drain(monitor)
        self.assertEqual((1, 0), (len(self.sent()), monitor.dropped))

    def restart_in_a_ratio_period(self, found, *, restore=False):
        # Issue #338 item 1 (Codex PR #335 P2): an earlier process sent a
        # ratio alert; the camera is still offline at the restart, so the
        # initial episode reaches the threshold and the ratio rule is never
        # evaluated. The continuous path finds the recent ratio alert once
        # and restores the period, so the period still yields one
        # continuous notification and later flapping episodes none.
        monitor = self.monitor()
        self.online(monitor, self.sources[1])
        ratio, stored = uuid4(), AT - timedelta(minutes=8)
        if restore:
            monitor.restore_pending([(ratio, stored)])
        calls = []

        def flapping_id(source):
            calls.append(source)
            return ratio, {"final": True, "pending": stored, "none": False}[found]

        self.advance(300)
        self.drain(monitor, flapping_id=flapping_id)
        for _ in range(2):
            self.on(monitor)
            self.advance(2)
            self.off(monitor)
            self.advance(300)
            self.drain(monitor, flapping_id=flapping_id)
        return monitor, ratio, stored, calls

    def test_a_restart_in_a_ratio_period_keeps_the_period(self):
        monitor, ratio, _stored, calls = self.restart_in_a_ratio_period("final")
        rows = self.sent()
        self.assertEqual(1, len(rows))
        self.assertNotEqual(ratio, rows[0].event_id)
        self.assertEqual([self.sources[0]], calls)
        self.assertEqual(1, self.drain(monitor).flapping_sources)

    def test_a_pending_ratio_row_found_from_the_continuous_path(self):
        # Sent again under its ID and time (found only by name), or covered
        # by its restored resend; the episode is the period's continuous one.
        for restore in (False, True):
            with self.subTest(restore=restore):
                self.clear_sent()
                _monitor, ratio, stored, _calls = self.restart_in_a_ratio_period(
                    "pending", restore=restore)
                rows = self.sent()
                self.assertEqual(2, len(rows))
                self.assertEqual([(ratio, stored)],
                                 [(row.event_id, row.at) for row in rows if row.event_id == ratio])

    def test_without_a_recent_ratio_row_the_continuous_rule_is_unchanged(self):
        monitor, _ratio, _stored, calls = self.restart_in_a_ratio_period("none")
        # A period opened by the continuous notification: each outage after
        # a short online that lasts the threshold is its own episode.
        self.assertEqual(3, len(self.sent()))
        self.assertEqual(0, self.drain(monitor).flapping_sources)
        # Looked up once: the period it opened is known from then on.
        self.assertEqual([self.sources[0]], calls)

    def test_the_recent_ratio_row_is_looked_up_once_per_episode(self):
        # Held by the cap, the episode stays due without a period: the
        # lookup is not repeated on every drain.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor, self.sources[1])
        monitor.restore_window([(uuid4(), 60.0)], monotonic=self.clock.value)
        calls = []

        def flapping_id(source):
            calls.append(source)
            return uuid4(), False

        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            for _ in range(3):
                self.drain(monitor, flapping_id=flapping_id)
                self.advance(60)
        self.assertEqual([self.sources[0]], calls)
        self.advance(3600)
        self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual(1, len(self.sent()))
        self.assertEqual([self.sources[0]], calls)

    def test_a_recovery_during_the_lookup_does_not_end_it(self):
        # Issue #353 (Codex PR #348 P2): the source recovers while the
        # lookup runs outside the lock, so its result is discarded, and the
        # outage resumes after a short online (folded into the same held
        # episode). The lookup runs again for it, so the earlier process's
        # ratio period is still restored. The hook pins the interleaving.
        monitor = self.monitor(hourly_limit=1)
        self.online(monitor, self.sources[1])
        monitor.restore_window([(uuid4(), 60.0)], monotonic=self.clock.value)
        ratio, calls = uuid4(), []

        def flapping_id(source):
            calls.append(source)
            if len(calls) == 1:
                self.on(monitor)
            return ratio, True

        self.advance(300)
        with self.assertLogs("app.monitoring.cameras", level="WARNING"):
            status = self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual((1, 0), (status.held, status.flapping_sources))
        self.advance(2)
        self.off(monitor)
        self.advance(60)
        status = self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual([self.sources[0]] * 2, calls)
        self.assertEqual(1, status.flapping_sources)
        # The period's one continuous notification once the hour allows;
        # later flapping episodes of the period are not notified.
        self.advance(3600)
        self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual(1, len(self.sent()))
        for _ in range(2):
            self.on(monitor)
            self.advance(2)
            self.off(monitor)
            self.advance(300)
            self.drain(monitor, flapping_id=flapping_id)
            self.advance(3600)
            self.drain(monitor, flapping_id=flapping_id)
        self.assertEqual(1, len(self.sent()))
        self.assertEqual([self.sources[0]] * 2, calls)

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

    def test_a_pending_flapping_row_is_sent_again_under_its_id_and_time(self):
        # Issue #336: `pending` is not confirmed delivery.
        stored = AT - timedelta(minutes=5)
        for notified, expected in ((stored, [(stored, True)]), (True, [])):
            with self.subTest(notified=notified):
                self.clear_sent()
                monitor = self.monitor()
                self.online(monitor)
                name = uuid4()
                for _ in range(2):
                    self.off(monitor)
                    self.advance(240)
                    self.drain(monitor, flapping_id=lambda source: (name, notified))
                    self.on(monitor)
                    self.advance(2)
                self.assertEqual(expected,
                                 [(row.at, row.event_id == name) for row in self.sent()])
                # Either way the period is open: no second ratio alert.
                self.assertEqual(1, self.drain(monitor).flapping_sources)

    def test_failing_or_reused_flapping_ids_fall_back_to_a_process_id(self):
        def broken(source):
            raise RuntimeError("synthetic database error")

        for flapping_id in (broken, lambda source: "x", lambda source: (uuid4(), 1)):
            with self.subTest(flapping_id=flapping_id):
                self.clear_sent()
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

    def stale_drain(self, back):
        # PR #335 re-review 提案 1: the runtime reads the clock before it
        # drains, outside the lock; a health event observed meanwhile carries
        # a later time than the drain.
        monitor = self.monitor()
        self.online(monitor)
        self.off(monitor)
        self.advance(240)
        self.on(monitor)
        self.advance(2)
        self.off(monitor)
        monitor.drain(self.service, at=AT, monotonic=self.clock.value - back)
        return monitor

    def test_a_drain_slightly_behind_an_event_keeps_the_count(self):
        monitor = self.stale_drain(0.01)
        self.run_for(monitor, 60)
        self.assertEqual(1, len(self.sent()))

    def test_a_clock_far_behind_restarts_the_count(self):
        monitor = self.stale_drain(10)
        self.run_for(monitor, 60)
        self.assertEqual([], self.sent())
        self.on(monitor)
        self.advance(2)
        self.off(monitor)
        self.run_for(monitor, 210)
        self.assertEqual([], self.sent())
        self.run_for(monitor, 30)
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

    def stored_row(self, *, confirmed, delivery, age, event_id=None, accepted_age=None,
                   at=None):
        event_id = event_id or uuid4()
        at = at or (self.clock.now - timedelta(seconds=age)).isoformat()
        accepted = (self.clock.now - timedelta(
            seconds=age if accepted_age is None else accepted_age)).isoformat()
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute(
                "INSERT INTO notification_events(event_id,kind,at,confirmed,delivery,accepted_at) "
                "VALUES (?,?,?,?,?,?)",
                (str(event_id), NotificationKind.CAMERA_OFFLINE.value, at, int(confirmed),
                 delivery, accepted))
            db.commit()
        return event_id

    def delivery(self, event_id):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            row = db.execute("SELECT delivery, at FROM notification_events WHERE event_id=?",
                             (str(event_id),)).fetchone()
        return None if row is None else row[0]

    def stored_at(self, event_id):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute("SELECT at FROM notification_events WHERE event_id=?",
                              (str(event_id),)).fetchone()[0]

    def all_pending_again(self):
        # A process that died before the Slack outcome was stored.
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute("UPDATE notification_events SET delivery=? WHERE kind=?",
                       (DeliveryResult.PENDING.value, NotificationKind.CAMERA_OFFLINE.value))
            db.commit()

    async def test_a_pending_alert_of_the_same_outage_is_sent_again(self):
        # Issue #336: the earlier process exited before the Slack outcome of
        # this outage's alert was stored. The restarted process finds the
        # same durable name and sends it again under that ID and time.
        pending = self.stored_row(confirmed=True, delivery="pending", age=7200,
                                  event_id=self.chain_name())
        at = self.stored_at(pending)
        self.discovery.devices = []
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(datetime.fromisoformat(at),
                             await runtime.call(runtime._notification_known, pending))
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            self.assertTrue(await runtime.call(runtime._notification_known, pending))
            # The same outage is not notified a third time.
            self.clock.advance(timedelta(hours=2))
            await self.tick(runtime)
        self.assertEqual([ALERT], self.slack_texts())
        self.assertEqual([(1, "sent")], self.offline_rows())
        self.assertEqual(at, self.stored_at(pending))

    async def test_a_final_row_of_the_same_outage_is_not_sent_again(self):
        for delivery in ("sent", "failed", "disabled"):
            with self.subTest(delivery=delivery):
                self.delete_rows()
                self.stored_row(confirmed=True, delivery=delivery, age=600,
                                event_id=self.chain_name())
                self.discovery.devices = []
                application = self.uvc_application()
                async with asyncio.timeout(60), application.router.lifespan_context(application):
                    runtime = application.state.monitoring
                    self.assertIs(True, await runtime.call(
                        runtime._notification_known, self.chain_name()))
                    self.clock.advance(timedelta(seconds=301))
                    await self.tick(runtime)
                self.assertEqual([], self.slack_texts())
                self.assertEqual([(1, delivery)], self.offline_rows())

    async def test_a_pending_alert_of_a_recovered_outage_is_sent_again(self):
        # The outage ended while the service was down; the alert reached the
        # threshold, so it is sent once, as one that recovered before the
        # drain (Issue #336).
        pending = self.stored_row(confirmed=True, delivery="pending", age=7200)
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            self.assertEqual("sent", self.delivery(pending))
            self.clock.advance(timedelta(hours=2))
            await self.tick(runtime)
        self.assertEqual([ALERT], self.slack_texts())
        # An event older than a day is superseded and not sent again, also
        # when a restart loop moved its acceptance time (PR #339 重要 2);
        # final and unconfirmed rows never are.
        self.delete_rows()
        self.transport.requests.clear()
        old = self.stored_row(confirmed=True, delivery="pending", age=25 * 3600)
        refreshed = self.stored_row(confirmed=True, delivery="pending", age=25 * 3600,
                                    accepted_age=7200)
        self.stored_row(confirmed=True, delivery="sent", age=7200)
        self.stored_row(confirmed=False, delivery="pending", age=7200)
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            await self.tick(runtime)
        self.assertEqual([], self.slack_texts())
        self.assertEqual(["pending", "pending"], [self.delivery(old), self.delivery(refreshed)])

    async def test_a_pending_row_with_an_unreadable_time(self):
        # Issue #342: skipped like a row whose ID cannot be read, however
        # recently it was accepted (`accepted_at` moves with every resend,
        # so it cannot bound the row to a day). A naive time is unreadable;
        # it must not fail the tick (PR #348 review 提案 2, R10): the readable
        # row beside it is still sent again.
        readable = self.stored_row(confirmed=True, delivery="pending", age=7200)
        recent = self.stored_row(confirmed=True, delivery="pending", age=0, at="not a time",
                                 accepted_age=7200)
        stale = self.stored_row(confirmed=True, delivery="pending", age=0, at="not a time",
                                accepted_age=25 * 3600)
        naive = self.stored_row(confirmed=True, delivery="pending", age=0,
                                at=(self.clock.now - timedelta(hours=1)).replace(
                                    tzinfo=None).isoformat())
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            await self.tick(runtime)
            self.assertEqual([], application.state.camera_offline._resend)
            self.assertTrue(runtime._camera_window_restored)
        self.assertEqual([ALERT], self.slack_texts())
        self.assertEqual("sent", self.delivery(readable))
        self.assertEqual(["pending"] * 3,
                         [self.delivery(row) for row in (recent, stale, naive)])
        self.assertEqual("not a time", self.stored_at(recent))

    async def test_a_pending_chain_row_is_aged_by_its_event_time(self):
        # Issue #342: on the name path a `pending` row counts as old once its
        # event is 24 h old, although a resend just wrote `accepted_at`
        # again; the chain moves to the next name, so a restart loop during
        # one long outage does not resend that row for ever. A final row is
        # still aged by its acceptance, an unreadable pending time is old.
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring

            def name():
                return runtime.call(runtime._camera_offline_event, self.source.id)

            self.stored_row(confirmed=True, delivery="pending", age=25 * 3600,
                            accepted_age=600, event_id=self.chain_name())
            self.assertEqual(self.chain_name(1), await name())
            self.stored_row(confirmed=True, delivery="pending", age=23 * 3600,
                            accepted_age=600, event_id=self.chain_name(1))
            self.assertEqual(self.chain_name(1), await name())
            self.delete_rows()
            self.stored_row(confirmed=True, delivery="pending", age=0, at="not a time",
                            accepted_age=600, event_id=self.chain_name())
            self.assertEqual(self.chain_name(1), await name())
            self.delete_rows()
            self.stored_row(confirmed=True, delivery="sent", age=25 * 3600,
                            accepted_age=600, event_id=self.chain_name())
            self.assertEqual(self.chain_name(), await name())
        # The whole path: the camera is still offline at a restart and the
        # outage's pending alert is more than a day old by its event time.
        self.delete_rows()
        old = self.stored_row(confirmed=True, delivery="pending", age=25 * 3600,
                              accepted_age=7200, event_id=self.chain_name())
        self.discovery.devices = []
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.tick(runtime)
            self.assertEqual([], self.slack_texts())
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.clock.advance(timedelta(hours=2))
            await self.tick(runtime)
        self.assertEqual([ALERT], self.slack_texts())
        self.assertEqual("pending", self.delivery(old))
        self.assertEqual("sent", self.delivery(self.chain_name(1)))

    async def test_an_initial_outage_that_recovers_before_it_is_named_is_sent_once(self):
        # Issue #342 D: the camera is still offline at the restart and the
        # outage's alert is still `pending`. The first running tick resends
        # it and names the initial episode; the episode reaches the
        # threshold and the camera is back (a new last-frame time) before
        # the next tick. It is covered by the resend, not sent again.
        pending = self.stored_row(confirmed=True, delivery="pending", age=7200,
                                  event_id=self.chain_name())
        self.discovery.devices = []
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            monitor = application.state.camera_offline
            self.assertEqual(pending, monitor._sources[self.source.id].episode.name)
            self.clock.advance(timedelta(seconds=301))
            self.discovery.devices = [self.camera]
            await self.bring_online(application)
            self.assertTrue(await self.until(lambda: self.last_seen() is not None))
            self.assertNotEqual(pending, await runtime.call(runtime._camera_offline_event,
                                                            self.source.id))
            await self.tick(runtime)
            self.clock.advance(timedelta(hours=2))
            await self.tick(runtime)
        self.assertEqual([ALERT], self.slack_texts())
        self.assertEqual([(1, "sent")], self.offline_rows())

    async def test_more_pending_alerts_than_an_hour_allows(self):
        # At most `hourly_limit` are taken (newest event first); the older
        # ones are left out, counted in `unrestored` and logged.
        configuration = self.configuration(camera_offline=CameraOfflineNotification(300, 2))
        rows = [self.stored_row(confirmed=True, delivery="pending", age=age)
                for age in (7200, 7260, 7320)]
        application = self.uvc_application(configuration)
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.bring_online(application)
            with self.assertLogs("app.monitoring.cameras", level="WARNING") as logs:
                await self.tick(runtime)
            self.assertIn(Event.CAMERA_OFFLINE_NOTIFICATION_UNRESTORED, "".join(logs.output))
            self.assertNotIn(Event.CAMERA_OFFLINE_NOTIFICATION_DROPPED, "".join(logs.output))
            self.assertEqual([ALERT, ALERT], self.slack_texts())
            self.assertEqual(["sent", "sent", "pending"], [self.delivery(row) for row in rows])
            monitor = application.state.camera_offline
            self.assertEqual((2, 1, 0), (len(monitor._sent), monitor.unrestored, monitor.dropped))

    async def test_a_restart_loop_never_exceeds_the_hourly_cap(self):
        # PR #339 重要 2 (Owner decision: the cap is absolute). Five starts
        # within one hour, each dying before the Slack outcome is stored: a
        # resend holds its slot, so at most `hourly_limit` (4) POSTs go out.
        for age in (7200, 7260, 7320, 7380):
            self.stored_row(confirmed=True, delivery="pending", age=age)
        for _ in range(5):
            application = self.uvc_application()
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                runtime = application.state.monitoring
                await self.tick(runtime)
            self.all_pending_again()
            self.clock.advance(timedelta(minutes=11))
        self.assertEqual([ALERT] * 4, self.slack_texts())

    async def test_a_pending_row_just_inside_a_day(self):
        # PR #339 提案 3: the outage's own pending alert, 23 h 59 min old at
        # the restart, is sent again once; its resend renews the chain name,
        # so the outage gets no `:repeat:1` alert as well.
        pending = self.stored_row(confirmed=True, delivery="pending", age=23 * 3600 + 59 * 60,
                                  event_id=self.chain_name())
        self.discovery.devices = []
        application = self.uvc_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            self.clock.advance(timedelta(seconds=301))
            await self.tick(runtime)
            self.clock.advance(timedelta(hours=2))
            await self.tick(runtime)
        self.assertEqual([ALERT], self.slack_texts())
        self.assertEqual([(1, "sent")], self.offline_rows())
        self.assertEqual("sent", self.delivery(pending))

    async def test_restored_window_counts_confirmed_alerts_including_pending(self):
        # Codex PR #320 P2: an unconfirmed local observation never used the
        # budget; an accepted `pending` alert did. Issue #336 / PR #339: that
        # alert is sent again only once its own slot expired (the cap is
        # absolute), after the live outage.
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
        pending = self.stored_row(confirmed=True, delivery="pending", age=60)
        application = self.uvc_application(configuration)
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.clock.advance(timedelta(seconds=301))
            with self.assertLogs("app.monitoring.cameras", level="WARNING"):
                await self.tick(runtime)
            self.assertEqual([], self.slack_texts())
            # The hour frees one slot: the live outage takes it first.
            self.clock.advance(timedelta(hours=1))
            await self.tick(runtime)
            self.assertEqual([ALERT], self.slack_texts())
            self.assertEqual("pending", self.delivery(pending))
            self.clock.advance(timedelta(hours=1))
            await self.tick(runtime)
            self.assertEqual([ALERT, ALERT], self.slack_texts())
            self.assertEqual("sent", self.delivery(pending))

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
            # A `pending` row is not confirmed: its stored time (Issue #336).
            self.delete_rows()
            pending = self.stored_row(confirmed=True, delivery="pending", age=100,
                                      event_id=self.flapping_name(bucket - 1))
            self.assertEqual((pending, datetime.fromisoformat(self.stored_at(pending))),
                             await name())
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
