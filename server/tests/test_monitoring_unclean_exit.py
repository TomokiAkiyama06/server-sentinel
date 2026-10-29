"""Issues #351 and #347: refusals between ticks, unclean exits, pending alerts.

* #347: a UUID, mount or `st_dev` mismatch seen only by a storage admission
  between two monitoring ticks, and restored before the next one, still
  raises one immediate `recording_health_failure` per episode and sets
  `recording_health` `FAILED`, like the topology refusal (PR #344).
* #351 (Owner decision 2026-10-26, option 2): the runtime keeps a running
  marker in the Main database; a start that finds the previous process's
  marker (crash, kill, OOM, power loss: no graceful stop) notifies the Owner
  once, conservatively, since a refusal kept only in memory may have been
  lost. A graceful stop deletes the marker, so a graceful restart sends
  nothing.
* Owner decision 2026-10-29 (PR #366): at most `UNCLEAN_EXIT_HOURLY_LIMIT`
  unclean-exit notices per rolling hour, counted from persisted rows so the
  cap holds across the restarts of a crash loop; the pending resend is not
  counted against it.
* #351: a `recording_health_failure` row an earlier process left `pending`
  is submitted again once by the next start, under its ID and time, as the
  stale device-number notice (#323) and camera offline (#339) are.

A "crash" is simulated by replacing the runtime's close with one that only
releases its resources (no final storage sample, no marker delete), which is
what a SIGKILL leaves in the autocommit database. Disposable directories,
injected UUID/mount lookups, a test clock and an intercepted Slack transport
only; no real block device, mount, process kill or Slack endpoint is used.
"""

import asyncio
import contextlib
from dataclasses import replace
from datetime import timedelta
import os
from pathlib import Path
import sqlite3
import time
from unittest.mock import patch
from uuid import uuid4, uuid5

from app.media.health.service import HealthState
from app.media.recording.model import RecordingError
from app.monitoring.config import RecordingFilesystem
from app.monitoring.runtime import (
    EVENT_NAMESPACE, PENDING_HEALTH_RESEND_LIMIT, UNCLEAN_EXIT_HOURLY_LIMIT, RuntimeState,
)
from app.notifications.service import NotificationKind, NotificationService

from tests.test_device_numbers_reboot import HeldAlertTransport
from tests.test_monitoring_runtime import RuntimeFixture
from tests.test_storage_notifications import Transport


ALERT = "ServerSentinel critical alert: recording_health_failure"


class SlowTransport(Transport):
    """Mock Slack that answers each POST after a short delay."""

    def open(self, request, *, timeout):
        time.sleep(0.3)
        return super().open(request, timeout=timeout)


def crash(runtime):
    """Make the coming stop behave like a kill: nothing of `_close` runs but
    releasing the resources, so the marker and any in-memory flag are lost."""
    def killed():
        runtime.notifications.close()
        if runtime.recordings is not None:
            runtime.recordings.close()
        if runtime._connection is not None:
            runtime._connection.close()
        runtime._set(state=RuntimeState.STOPPED)
    runtime._close = killed


class RefusalFixture(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.mounted = True

    def configuration(self, **overrides):
        configuration = super().configuration(**overrides)
        filesystem = RecordingFilesystem(
            self.recordings, "00000000-1111-2222-3333-444444444444",
            (os.major(self.device), os.minor(self.device)), self.recordings.parent,
            lambda uuid: self.approved_device, lambda path: self.mounted,
        )
        return replace(configuration, recording_filesystem=filesystem)

    def alerts(self):
        return [text for text in self.slack_texts() if "recording_health_failure" in text]

    def stored_alerts(self):
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute("SELECT event_id, at, delivery FROM notification_events "
                              "WHERE kind='recording_health_failure' ORDER BY at").fetchall()

    def marker(self):
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute("SELECT token FROM monitoring_run_marker").fetchall()

    def sql(self, statement, values=()):
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db, db:
            db.execute(statement, values)

    @staticmethod
    async def admit(runtime):
        def admit():
            with runtime._policy.control():
                pass
        try:
            await runtime.call(admit)
        except RecordingError as error:
            return str(error)
        return None

    async def run_once(self, *, crashed=False, ticks=0):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            for _ in range(ticks):
                self.clock.advance(timedelta(minutes=1))
                await runtime.call(runtime.tick)
                await self.settle(runtime)
            if crashed:
                crash(runtime)
        self.clock.advance(timedelta(minutes=5))
        return runtime


class BetweenTickIdentityRefusalTests(RefusalFixture):
    """Issue #347: every identity refusal of an admission reaches the tick."""

    def changes(self, runtime):
        """(name, change, restore) for the UUID, mount and `st_dev` cases."""
        def uuid_moved():
            self.approved_device = self.device + 7

        def unmounted():
            self.mounted = False

        def mount_elsewhere():
            runtime.filesystem.identity = replace(healthy, mount_point=Path("/proc"))

        def restore():
            self.approved_device, self.mounted = self.device, True
            runtime.filesystem.identity = healthy
        healthy = runtime.filesystem.identity
        self.assertNotEqual(self.device, Path("/proc").stat().st_dev)
        return (("uuid", uuid_moved), ("mount", unmounted), ("st_dev", mount_elsewhere)), restore

    async def test_a_refusal_restored_before_the_tick_alerts_once_per_episode(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            self.assertIsNone(await self.admit(runtime))
            cases, restore = self.changes(runtime)
            for count, (name, change) in enumerate(cases, start=1):
                with self.subTest(case=name):
                    change()
                    for _ in range(3):
                        self.assertEqual("STORAGE_HARD_STOP", await self.admit(runtime))
                    restore()
                    self.assertIsNone(await self.admit(runtime))
                    self.assertEqual(count - 1, len(self.alerts()))
                    # The next tick: one immediate alert, `FAILED` / STORAGE.
                    self.clock.advance(timedelta(minutes=1))
                    await runtime.call(runtime.tick)
                    await self.settle(runtime)
                    self.assertEqual([ALERT] * count, self.alerts())
                    self.assertEqual(HealthState.FAILED, runtime.status.recording_health)
                    with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db:
                        self.assertEqual(
                            [("FAILED", '["STORAGE"]')],
                            db.execute("SELECT state, stages FROM recording_health_status"
                                       ).fetchall())
                    # The healthy tick after it ends the episode, silently.
                    self.clock.advance(timedelta(minutes=1))
                    await runtime.call(runtime.tick)
                    await self.settle(runtime)
                    self.assertTrue(runtime.status.recording_filesystem_ok)
                    self.assertEqual(count, len(self.alerts()))
        self.assertEqual(3, len(self.alerts()))
        self.assertEqual(["sent"] * 3, [row[2] for row in self.stored_alerts()])

    async def test_a_refusal_within_an_alerted_episode_adds_nothing(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.approved_device = self.device + 7
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual([ALERT], self.alerts())
            self.assertEqual("STORAGE_HARD_STOP", await self.admit(runtime))
            self.approved_device = self.device
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertTrue(runtime.status.recording_filesystem_ok)
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
        self.assertEqual([ALERT], self.alerts())

    async def test_a_uuid_refusal_before_a_graceful_stop_alerts_during_the_stop(self):
        # PR #363's final storage sample now covers the identity refusals too.
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.approved_device = self.device + 7
            self.assertEqual("STORAGE_HARD_STOP", await self.admit(runtime))
            self.approved_device = self.device
            self.assertEqual([], self.alerts())
        self.assertEqual([ALERT], self.alerts())
        self.assertEqual(["sent"], [row[2] for row in self.stored_alerts()])
        # Graceful: the marker is gone and the restart adds nothing.
        self.assertEqual([], self.marker())
        self.clock.advance(timedelta(minutes=5))
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())


class UncleanExitTests(RefusalFixture):
    """Issue #351 (option 2): a start after an unclean exit notifies once."""

    async def test_a_crash_after_an_admission_only_refusal_notifies_at_the_next_start(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.assertEqual(1, len(self.marker()))
            self.approved_device = self.device + 7
            self.assertEqual("STORAGE_HARD_STOP", await self.admit(runtime))
            self.approved_device = self.device
            # Killed before the tick: the in-memory flag is lost.
            crash(runtime)
        self.assertEqual([], self.alerts())
        self.assertEqual(1, len(self.marker()))
        self.clock.advance(timedelta(minutes=5))
        with self.assertLogs("app.monitoring.runtime", "ERROR") as logs:
            runtime = await self.run_once()
        self.assertIn("monitoring_previous_run_unclean", "\n".join(logs.output))
        self.assertEqual([ALERT], self.alerts())
        self.assertEqual(["sent"], [row[2] for row in self.stored_alerts()])
        self.assertEqual(RuntimeState.STOPPED, runtime.status.state)
        # That start stopped gracefully: further restarts send nothing.
        self.assertEqual([], self.marker())
        await self.run_once()
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())

    async def test_every_unclean_exit_notifies_once_and_graceful_restarts_never(self):
        await self.run_once()
        await self.run_once()
        self.assertEqual([], self.alerts())
        # A crash without any refusal is still notified (conservative).
        await self.run_once(crashed=True)
        self.assertEqual([], self.alerts())
        await self.run_once(crashed=True)
        self.assertEqual([ALERT], self.alerts())
        await self.run_once()
        self.assertEqual([ALERT] * 2, self.alerts())
        await self.run_once()
        self.assertEqual([ALERT] * 2, self.alerts())
        self.assertEqual(2, len(self.stored_alerts()))

    async def test_a_marker_found_again_after_its_notice_sends_nothing(self):
        # A start that crashed after notifying but before replacing the
        # marker leaves the same token: the next start finds the row.
        await self.run_once(crashed=True)
        [(token,)] = self.marker()
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())
        self.sql("INSERT INTO monitoring_run_marker VALUES (1, ?)", (token,))
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())
        self.assertEqual([], self.marker())

    async def test_a_process_that_never_ran_leaves_no_marker(self):
        # Storage refused at the start: nothing was admitted, so nothing can
        # have been lost; only the startup failure itself alerts.
        await self.run_once()
        self.approved_device = self.device + 7
        runtime = await self.run_once(crashed=True)
        self.assertEqual(RuntimeState.STOPPED, runtime.status.state)
        self.assertEqual([ALERT], self.alerts())
        self.approved_device = self.device
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())

    async def test_a_refused_marker_write_is_retried_by_the_tick(self):
        # The marker is written under the storage policy only; a refused
        # write is retried (after `retry_seconds`) rather than skipped.
        await self.run_once()
        refuse = patch("app.monitoring.store.RunMarkerStore.mark",
                       side_effect=RecordingError("STORAGE_HARD_STOP"))
        application = self.application()
        refuse.start()
        try:
            async with application.router.lifespan_context(application):
                runtime = application.state.monitoring
                await self.settle(runtime)
                self.assertFalse(runtime._run_marked)
                self.assertEqual([], self.marker())
                # Visible while a crash of this process would go undetected.
                self.assertTrue(runtime.status.unclean_exit_detection_degraded)
                summary = await runtime.call(runtime._summary, self.clock.utcnow())
                self.assertGreaterEqual(summary.error_count, 1)
                refuse.stop()
                self.clock.advance(timedelta(minutes=1))
                await runtime.call(runtime.tick)
                self.assertFalse(runtime._run_marked)
                self.clock.advance(timedelta(minutes=20))
                await runtime.call(runtime.tick)
                self.assertTrue(runtime._run_marked)
                self.assertFalse(runtime.status.unclean_exit_detection_degraded)
                self.assertEqual(1, len(self.marker()))
        finally:
            with contextlib.suppress(RuntimeError):
                refuse.stop()
        self.assertEqual([], self.marker())
        self.assertEqual([], self.alerts())


    async def test_a_full_queue_retries_the_notice_instead_of_storing_failed(self):
        # PR #366 review 提案 2: a queue that cannot take the notice leaves
        # no final `failed` row and keeps the earlier marker for a retry.
        await self.run_once(crashed=True)
        [(token,)] = self.marker()
        full = patch.object(NotificationService, "can_accept", return_value=False)
        application = self.application()
        full.start()
        try:
            async with application.router.lifespan_context(application):
                runtime = application.state.monitoring
                await self.settle(runtime)
                self.assertEqual([], self.alerts())
                self.assertEqual([], self.stored_alerts())
                self.assertEqual([(token,)], self.marker())
                self.assertTrue(runtime.status.unclean_exit_detection_degraded)
                full.stop()
                self.clock.advance(timedelta(minutes=20))
                await runtime.call(runtime.tick)
                await self.settle(runtime)
                self.assertEqual([ALERT], self.alerts())
                self.assertEqual(["sent"], [row[2] for row in self.stored_alerts()])
                self.assertFalse(runtime.status.unclean_exit_detection_degraded)
                self.assertNotEqual([(token,)], self.marker())
        finally:
            with contextlib.suppress(RuntimeError):
                full.stop()
        self.assertEqual([], self.marker())


class CrashLoopTests(RefusalFixture):
    """PR #366 review 重要 1: a crash loop sends one notice per crash, and an
    undelivered row is resent at most once, never once per later start."""

    async def crash_soon(self, seconds):
        """Start with the real run loop (no test settle) and crash after ``seconds``."""
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await asyncio.sleep(seconds)
            crash(runtime)
        self.clock.advance(timedelta(minutes=1))

    async def test_delivered_notices_are_stored_before_the_tick_and_not_resent(self):
        # Slack answers in 0.3 s; each process crashes about 1.6 s after it
        # started, long before its first tick (an hour here). The outcome is
        # stored by the run loop's poll, so the next start resends nothing.
        # Owner decision 2026-10-29: the starts are a minute apart, so the
        # 5th and 6th crash of the hour are not notified; once the hour of
        # the first notice has passed, the next crash is notified again.
        self.transport = SlowTransport()
        posts = []
        for _ in range(7):
            await self.crash_soon(1.6)
            posts.append(len(self.alerts()))
        self.assertEqual(4, UNCLEAN_EXIT_HOURLY_LIMIT)
        self.assertEqual([0, 1, 2, 3, 4, 4, 4], posts)
        self.assertEqual(["sent"] * 4, [row[2] for row in self.stored_alerts()])
        self.clock.advance(timedelta(hours=1))
        await self.crash_soon(1.6)
        self.assertEqual(5, len(self.alerts()))
        self.assertEqual(["sent"] * 5, [row[2] for row in self.stored_alerts()])

    async def test_undelivered_notices_are_resent_at_most_once(self):
        # Slack never answers: every notice stays `pending`. Each start
        # submits its own notice and resends each earlier one at most once.
        self.transport = HeldAlertTransport()
        self.addCleanup(self.transport.release.set)
        submitted = []
        record = NotificationService.record

        def spy(service, kind, **values):
            if kind is NotificationKind.RECORDING_HEALTH_FAILURE:
                submitted.append(values["event_id"])
            return record(service, kind, **values)
        per_start = []
        with patch.object(NotificationService, "record", spy):
            for _ in range(8):
                before = len(submitted)
                await self.crash_soon(0.2)
                per_start.append(len(submitted) - before)
        # The 6th start finds a 5th crash within the hour: no notice of its
        # own (Owner decision 2026-10-29), only the once-per-row resend of
        # the 5th start's notice, which the cap does not hold back; later
        # starts within the hour submit nothing.
        self.assertEqual([0, 1, 2, 2, 2, 1, 0, 0], per_start)
        self.assertEqual(UNCLEAN_EXIT_HOURLY_LIMIT, len(set(submitted)))
        self.assertLessEqual(max(submitted.count(event_id) for event_id in submitted), 2)
        # PR #366 review: in this run (all starts within one hour, from an
        # empty history) the 4 notices are each posted twice, 8 in total.
        # This is not a bound for every 60-minute interval: a resend can land
        # in a later interval than its notice, so one can hold more than 8.
        self.assertEqual(2 * UNCLEAN_EXIT_HOURLY_LIMIT, len(submitted))


class UncleanExitHourlyCapTests(RefusalFixture):
    """Owner decision 2026-10-29: at most 4 unclean-exit notices per rolling
    hour, counted from persisted rows with `abs(now - at) < 1 h` (as the 24 h
    resend window), so a crash loop cannot reset it and a clock step keeps
    it closed for at most an hour."""

    def notices(self):
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute("SELECT event_id, at FROM monitoring_unclean_exit_notices "
                              "ORDER BY at").fetchall()

    def seed(self, *offsets):
        """Notice rows of other crashes at ``now + offset``; a fresh foreign marker."""
        now = self.clock.utcnow()
        for offset in offsets:
            self.sql("INSERT INTO monitoring_unclean_exit_notices VALUES (?, ?)",
                     (str(uuid4()), (now + offset).isoformat()))
        token = str(uuid4())
        self.sql("INSERT INTO monitoring_run_marker VALUES (1, ?) ON CONFLICT(singleton) "
                 "DO UPDATE SET token=excluded.token", (token,))
        return uuid5(EVENT_NAMESPACE, f"recording-unclean-exit:{token}")

    async def start_capped(self):
        with self.assertLogs("app.monitoring.runtime", "WARNING") as logs:
            runtime = await self.run_once()
        output = "\n".join(logs.output)
        self.assertIn("monitoring_previous_run_unclean", output)
        self.assertIn("unclean_exit_notification_dropped", output)
        self.assertEqual(1, runtime.unclean_exit_notices_dropped)
        # The marker is still replaced, and the graceful stop deletes it.
        self.assertEqual([], self.marker())
        return runtime

    async def test_crashes_beyond_the_cap_are_not_notified_until_the_hour_passed(self):
        await self.run_once(crashed=True)
        counts, starts = [], []
        for _ in range(6):
            starts.append(self.clock.utcnow())
            await self.run_once(crashed=True)
            counts.append(len(self.alerts()))
        # Five minutes apart: the 5th and 6th unclean exit of the hour are
        # not notified; each process still ran and replaced the marker.
        self.assertEqual([1, 2, 3, 4, 4, 4], counts)
        self.assertEqual(4, len(self.stored_alerts()))
        self.assertEqual([at.isoformat() for at in starts[:4]],
                         [at for _event_id, at in self.notices()])
        self.assertEqual(1, len(self.marker()))
        # A second before the first notice is an hour old the hour is full.
        self.clock.now = starts[0] + timedelta(hours=1) - timedelta(seconds=1)
        await self.start_capped()
        self.assertEqual(4, len(self.alerts()))
        # Exactly an hour after the first notice its slot is free again.
        self.seed()
        self.clock.now = starts[0] + timedelta(hours=1)
        runtime = await self.run_once()
        self.assertEqual(0, runtime.unclean_exit_notices_dropped)
        self.assertEqual(5, len(self.alerts()))
        self.assertEqual(5, len(self.notices()))
        # Graceful restarts never notify.
        await self.run_once()
        self.assertEqual(5, len(self.alerts()))

    async def test_the_hour_is_counted_from_the_database_not_the_process(self):
        await self.run_once()
        self.seed(*(-timedelta(minutes=minutes) for minutes in (1, 10, 20, 59)))
        await self.start_capped()
        self.assertEqual([], self.alerts())
        self.assertEqual(4, len(self.notices()))
        # Rows an hour old or older do not count.
        self.sql("DELETE FROM monitoring_unclean_exit_notices")
        self.seed(*(-timedelta(hours=1, minutes=minutes) for minutes in (0, 0, 1, 30)))
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())

    async def test_a_clock_moved_back_counts_rows_less_than_an_hour_ahead(self):
        await self.run_once()
        # Rows less than an hour in the future (the clock moved back) still
        # count, as the 24 h resend window counts both directions.
        self.seed(*(timedelta(minutes=minutes) for minutes in (1, 10, 30, 59)))
        await self.start_capped()
        self.assertEqual([], self.alerts())
        # An hour or more ahead they do not: a large step never keeps the
        # cap closed for longer than the hour.
        self.sql("DELETE FROM monitoring_unclean_exit_notices")
        now = self.clock.utcnow()
        self.seed(timedelta(hours=1), timedelta(hours=2), timedelta(hours=30),
                  -timedelta(hours=30))
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())
        # The insert pruned the rows a day or more from the notice.
        self.assertEqual(sorted([now.isoformat(), (now + timedelta(hours=1)).isoformat(),
                                 (now + timedelta(hours=2)).isoformat()]),
                         sorted(at for _event_id, at in self.notices()))

    async def test_a_notice_taken_before_a_crash_is_sent_without_a_second_slot(self):
        # A start that wrote its notice row and crashed before submitting it
        # leaves the slot taken: the next start sends that notice under the
        # stored time although the hour is otherwise full.
        await self.run_once()
        taken_at = self.clock.utcnow() - timedelta(minutes=10)
        event_id = self.seed(*(-timedelta(minutes=minutes) for minutes in (1, 2, 3)))
        self.sql("INSERT INTO monitoring_unclean_exit_notices VALUES (?, ?)",
                 (str(event_id), taken_at.isoformat()))
        runtime = await self.run_once()
        self.assertEqual(0, runtime.unclean_exit_notices_dropped)
        self.assertEqual([ALERT], self.alerts())
        self.assertEqual([(str(event_id), taken_at.isoformat(), "sent")], self.stored_alerts())
        self.assertEqual(4, len(self.notices()))

    async def test_the_pending_resend_is_not_held_back_by_the_cap(self):
        # The hour is full and another unclean exit is found: no new notice,
        # but a `pending` failure row is still resent once, and the resend
        # takes no slot of the cap.
        await self.run_once()
        at = (self.clock.utcnow() - timedelta(minutes=30)).isoformat()
        pending = str(uuid4())
        self.sql("INSERT INTO notification_events(event_id,kind,at,confirmed,delivery) "
                 "VALUES (?, 'recording_health_failure', ?, 0, 'pending')", (pending, at))
        self.seed(*(-timedelta(minutes=minutes) for minutes in (1, 2, 3, 4)))
        await self.start_capped()
        self.assertEqual([ALERT], self.alerts())
        self.assertEqual([(pending, at, "sent")], self.stored_alerts())
        self.assertEqual(4, len(self.notices()))

    async def test_without_slack_the_cap_still_limits_the_local_rows(self):
        self.slack = False
        await self.run_once()
        self.seed(*(-timedelta(minutes=minutes) for minutes in (1, 2, 3, 4)))
        await self.start_capped()
        self.assertEqual([], self.stored_alerts())


class PendingHealthFailureResendTests(RefusalFixture):
    """Issue #351: a `pending` failure row is resent once by the next start."""

    async def raise_one_alert(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.approved_device = self.device + 7
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.approved_device = self.device
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
        self.clock.advance(timedelta(minutes=5))

    async def test_a_pending_row_is_resent_once_under_its_id_and_time(self):
        await self.raise_one_alert()
        [(event_id, at, delivery)] = self.stored_alerts()
        self.assertEqual("sent", delivery)
        # The process exited before the outcome was stored.
        self.sql("UPDATE notification_events SET delivery='pending' WHERE event_id=?",
                 (event_id,))
        await self.run_once()
        self.assertEqual([ALERT] * 2, self.alerts())
        self.assertEqual([(event_id, at, "sent")], self.stored_alerts())
        await self.run_once()
        self.assertEqual([ALERT] * 2, self.alerts())

    async def test_a_stop_alert_left_pending_is_resent_by_the_next_start(self):
        # PR #363: Slack did not answer the final sample's alert within the
        # bound; the row stayed `pending`. The next start sends it once more.
        self.transport = HeldAlertTransport()
        self.addCleanup(self.transport.release.set)
        application = self.application()
        with patch("app.monitoring.runtime.SHUTDOWN_STORAGE_SETTLE_SECONDS", 0.2):
            async with application.router.lifespan_context(application):
                runtime = application.state.monitoring
                await self.settle(runtime)
                self.approved_device = self.device + 7
                self.assertEqual("STORAGE_HARD_STOP", await self.admit(runtime))
                self.approved_device = self.device
                with self.assertLogs("app.monitoring.runtime", "ERROR"):
                    await runtime.stop()
        [(event_id, at, delivery)] = self.stored_alerts()
        self.assertEqual("pending", delivery)
        self.transport.release.set()
        self.transport = Transport()
        self.clock.advance(timedelta(minutes=5))
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())
        self.assertEqual([(event_id, at, "sent")], self.stored_alerts())
        await self.run_once()
        self.assertEqual([ALERT], self.alerts())

    async def test_only_recent_rows_are_resent_newest_first_within_the_limit(self):
        await self.run_once()
        now = self.clock.utcnow()
        ages = [timedelta(hours=hours) for hours in (1, 2, 3, 4, 5, 6)] + [timedelta(hours=25)]
        rows = [(str(uuid4()), (now - age).isoformat()) for age in ages]
        for event_id, at in rows:
            self.sql("INSERT INTO notification_events(event_id,kind,at,confirmed,delivery) "
                     "VALUES (?, 'recording_health_failure', ?, 0, 'pending')", (event_id, at))
        self.sql("INSERT INTO notification_events(event_id,kind,at,confirmed,delivery) "
                 "VALUES ('not-a-uuid', 'recording_health_failure', ?, 0, 'pending')",
                 (now.isoformat(),))
        with self.assertLogs("app.monitoring.runtime", "WARNING") as logs:
            await self.run_once()
        self.assertIn("recording_health_failure_unrestored", "\n".join(logs.output))
        self.assertEqual(PENDING_HEALTH_RESEND_LIMIT, len(self.alerts()))
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db:
            outcome = dict(db.execute(
                "SELECT event_id, delivery FROM notification_events "
                "WHERE kind='recording_health_failure'").fetchall())
        self.assertEqual(["sent"] * PENDING_HEALTH_RESEND_LIMIT
                         + ["pending"] * (len(rows) - PENDING_HEALTH_RESEND_LIMIT),
                         [outcome[event_id] for event_id, _ in rows])
        self.assertEqual("pending", outcome["not-a-uuid"])
        # A later start takes the recent rows left out; the day-old row and
        # the unreadable one are never resent.
        await self.run_once()
        self.assertEqual(PENDING_HEALTH_RESEND_LIMIT + 2, len(self.alerts()))
        await self.run_once()
        self.assertEqual(PENDING_HEALTH_RESEND_LIMIT + 2, len(self.alerts()))

    async def test_a_row_far_in_the_future_takes_no_slot(self):
        # PR #366 review 提案 5: a row stamped more than a day ahead (the
        # clock moved back) is neither resent nor ahead of the recent rows.
        await self.run_once()
        now = self.clock.utcnow()
        future = str(uuid4())
        recent = [str(uuid4()) for _ in range(PENDING_HEALTH_RESEND_LIMIT)]
        rows = [(future, now + timedelta(hours=30))] + [
            (event_id, now - timedelta(hours=index + 1)) for index, event_id in enumerate(recent)]
        for event_id, at in rows:
            self.sql("INSERT INTO notification_events(event_id,kind,at,confirmed,delivery) "
                     "VALUES (?, 'recording_health_failure', ?, 0, 'pending')",
                     (event_id, at.isoformat()))
        await self.run_once()
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db:
            outcome = dict(db.execute(
                "SELECT event_id, delivery FROM notification_events "
                "WHERE kind='recording_health_failure'").fetchall())
        self.assertEqual(["sent"] * PENDING_HEALTH_RESEND_LIMIT, [outcome[i] for i in recent])
        self.assertEqual("pending", outcome[future])

    async def test_without_slack_a_pending_row_becomes_disabled(self):
        await self.raise_one_alert()
        [(event_id, _at, _delivery)] = self.stored_alerts()
        self.sql("UPDATE notification_events SET delivery='pending' WHERE event_id=?",
                 (event_id,))
        self.slack = False
        await self.run_once()
        self.assertEqual("disabled", self.stored_alerts()[0][2])
