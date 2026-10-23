"""Main-runtime timeline outbox wiring for scene evidence (#205).

Covers the acceptance conditions on Issue #205: the undelivered sink is
`CriticalTimelineRecorder.record_undelivered` and does no I/O, scene
monitoring starts only after `TimelineOutbox.open()` succeeded, the outbox is
flushed and closed only after scene `stop()` returned, and never closed
cleanly after `STOP_FAILED` or an unrecorded undelivered count.

Every pixel is generated in memory; no camera, real scene or person is used.
"""

import asyncio
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import tempfile
import threading
import time
import unittest
from pathlib import Path
from uuid import uuid4

from app.cameras.registry.models import SourceType
from app.detection.roi import CriticalKind
from app.detection.roi.runtime import (
    SceneMonitoringConfiguration, SceneMonitoringDependencies, SceneRuntimeState,
)
from app.main import create_app
from app.audit.runtime import AuditRetentionHealth, AuditRetentionRuntime
from app.presence.runtime import (
    RetentionClockUntrusted, SceneTimeline, SceneTimelineConfiguration, TimelineFinish,
)
from app.settings import Settings
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from app.presence.models import timestamp
from app.storage.retention import RetentionPeriods

from tests.test_detector_roi import HEIGHT, WIDTH, pixels, policy
from tests.test_presence_adapters import NOW as PRESENCE_NOW, critical
from tests.test_scene_runtime import MOVED, OTHER, Recorder, binding, calibration_for


def main_clock():
    return datetime.now(timezone.utc), True


def timeline_configuration(**changes):
    values = dict(maximum_source_latency=timedelta(seconds=30), clock=main_clock,
                  flush_interval_seconds=0.02, open_retry_seconds=0.02)
    values.update(changes)
    return SceneTimelineConfiguration(**values)


class Admission:
    """Synthetic storage admission that can refuse like a hard stop."""

    def __init__(self):
        self.lock = threading.Lock()
        self.refuse = False
        self.admitted = 0

    @contextmanager
    def __call__(self):
        with self.lock:
            if self.refuse:
                raise RuntimeError("synthetic STORAGE_HARD_STOP")
            self.admitted += 1
        yield


class Fixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.settings = Settings(Path(temporary.name))
        self.database = Database(self.settings.database_path)
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.admission = Admission()

    def rows(self, query):
        with closing(self.database.connect()) as connection:
            return connection.execute(query).fetchall()

    def sessions(self):
        return self.rows("SELECT count(*) FROM presence_outbox_sessions")[0][0]

    def gap(self):
        rows = self.rows("SELECT refused, rejected, lost, interrupted FROM presence_timeline_gap")
        return tuple(rows[0]) if rows else None

    def critical_kinds(self):
        return [row[0] for row in self.rows(
            "SELECT kind FROM presence_observations ORDER BY sequence")]


def refuse_outbox_open(timeline):
    """Refuse the outbox open (storage refused) until `refusing` is cleared."""
    refusing = threading.Event()
    refusing.set()
    open_outbox = timeline.outbox.open

    def refused():
        if refusing.is_set():
            raise RuntimeError("synthetic STORAGE_HARD_STOP")
        return open_outbox()

    timeline.outbox.open = refused
    return refusing


def scene_status(state, undelivered_recorded=None):
    return type("Status", (), {"state": state, "undelivered_recorded": undelivered_recorded})()


class SceneTimelineConfigurationTests(unittest.TestCase):
    def test_timing_policy_has_no_default(self):
        with self.assertRaises(TypeError):
            SceneTimelineConfiguration()
        with self.assertRaises(TypeError):
            SceneTimelineConfiguration(maximum_source_latency=timedelta(seconds=1))
        for invalid in (dict(maximum_source_latency=timedelta(0)),
                        dict(maximum_source_latency=5),
                        dict(clock=None),
                        dict(outbox_capacity=0),
                        dict(flush_interval_seconds=0),
                        dict(open_retry_seconds=float("inf"))):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                timeline_configuration(**invalid)


class SceneTimelineLifecycleTests(Fixture, unittest.TestCase):
    def timeline(self):
        return SceneTimeline(timeline_configuration(), self.database, self.admission)

    def test_undelivered_sink_is_the_critical_recorders_count_only_record(self):
        timeline = self.timeline()
        # Condition 1: the bound method of this composition's recorder.
        self.assertEqual(timeline.recorder.record_undelivered, timeline.undelivered)
        self.assertIs(timeline.recorder.outbox, timeline.outbox)

    def test_sink_before_open_is_refused_and_after_open_does_no_io(self):
        timeline = self.timeline()
        # Condition 4/5: a count before open() is refused; the wiring
        # therefore starts scene monitoring only after open() succeeded.
        with self.assertRaises(RuntimeError):
            timeline.undelivered(1)
        self.assertTrue(timeline.open())
        # Condition 7: no storage admission, database or clock is touched.
        admitted = self.admission.admitted
        self.admission.refuse = True
        timeline.configuration.clock  # the clock is not called by the sink
        timeline.undelivered(2)
        self.assertEqual(admitted, self.admission.admitted)
        self.assertEqual(2, timeline.state().unpersisted)
        self.admission.refuse = False
        timeline.finish(scene_status(SceneRuntimeState.STOPPED, True))

    def test_open_failure_is_reported_and_retried(self):
        timeline = self.timeline()
        self.admission.refuse = True
        with self.assertLogs("app.presence.runtime", level="ERROR") as logs:
            self.assertFalse(timeline.open())
            self.assertFalse(timeline.open())
            self.assertFalse(timeline.open())
        # The first failure and every doubling, not every retry.
        self.assertEqual(2, sum("timeline_outbox_open_failed" in line for line in logs.output))
        self.assertFalse(timeline.opened)
        self.admission.refuse = False
        self.assertTrue(timeline.open())
        self.assertEqual(1, self.sessions())
        self.assertIs(TimelineFinish.CLOSED,
                      timeline.finish(scene_status(SceneRuntimeState.STOPPED)))

    def test_clean_stop_closes_the_session(self):
        timeline = self.timeline()
        self.assertTrue(timeline.open())
        self.assertEqual(1, self.sessions())
        self.assertIs(TimelineFinish.CLOSED,
                      timeline.finish(scene_status(SceneRuntimeState.STOPPED)))
        self.assertEqual(0, self.sessions())
        self.assertIsNone(self.gap())

    def test_counts_handed_over_at_a_clean_stop_reach_the_marker(self):
        timeline = self.timeline()
        self.assertTrue(timeline.open())
        timeline.undelivered(3)
        self.assertIs(TimelineFinish.CLOSED,
                      timeline.finish(scene_status(SceneRuntimeState.STOPPED, True)))
        self.assertEqual((0, 0, 3, 0), self.gap())
        self.assertEqual(0, self.sessions())

    def test_unclean_stop_never_closes_but_flushes_counts(self):
        cases = (scene_status(SceneRuntimeState.STOP_FAILED, True),
                 scene_status(SceneRuntimeState.STOPPED, False),
                 scene_status(SceneRuntimeState.UNAVAILABLE),
                 None)
        for status in cases:
            with self.subTest(status=getattr(status, "state", None)):
                self.setUp()
                timeline = self.timeline()
                self.assertTrue(timeline.open())
                timeline.undelivered(2)
                close = timeline.outbox.close
                calls = []
                timeline.outbox.close = lambda: calls.append(True) or close()
                with self.assertLogs("app.presence.runtime", level="ERROR") as logs:
                    self.assertIs(TimelineFinish.LEFT_OPEN, timeline.finish(status))
                self.assertTrue(any("timeline_outbox_left_open" in line for line in logs.output))
                # Condition 6: close() is never called.
                self.assertEqual([], calls)
                # Condition 8: flushed, so the count is durable although the
                # session stays open.
                self.assertEqual((0, 0, 2, 0), self.gap())
                self.assertEqual(1, self.sessions())
                # The next start (here: after this process's lock is gone)
                # records the session as an interrupted gap.
                timeline.outbox._handle.release()
                successor = self.timeline()
                self.assertTrue(successor.open())
                self.assertEqual((0, 0, 2, 1), self.gap())
                successor.finish(scene_status(SceneRuntimeState.STOPPED))

    def test_finish_without_open_closes_nothing(self):
        timeline = self.timeline()
        self.assertIs(TimelineFinish.NOT_OPENED,
                      timeline.finish(scene_status(SceneRuntimeState.STOPPED)))
        self.assertEqual(0, self.sessions())
        # A finished composition never opens afterwards.
        self.assertFalse(timeline.open())

    def test_failed_close_is_reported(self):
        timeline = self.timeline()
        self.assertTrue(timeline.open())

        def failing():
            raise RuntimeError("synthetic close failure")

        timeline.outbox.close = failing
        with self.assertLogs("app.presence.runtime", level="ERROR") as logs:
            self.assertIs(TimelineFinish.CLOSE_FAILED,
                          timeline.finish(scene_status(SceneRuntimeState.STOPPED)))
        self.assertTrue(any("timeline_outbox_close_failed" in line for line in logs.output))
        self.assertEqual(1, self.sessions())
        timeline.outbox._handle.release()

    def test_missing_database_is_refused_never_created(self):
        self.settings.database_path.unlink()
        timeline = self.timeline()
        with self.assertLogs("app.presence.runtime", level="ERROR"):
            self.assertFalse(timeline.open())
        self.assertFalse(self.settings.database_path.exists())


class MutableClock:
    def __init__(self, at):
        self.at = at

    def __call__(self):
        return self.at, True


class SceneTimelineRetentionTests(Fixture, unittest.TestCase):
    """Codex PR #296: the owned presence timeline expires on the schedule."""

    def setUp(self):
        Fixture.setUp(self)
        self.clock = MutableClock(PRESENCE_NOW + timedelta(seconds=1))
        self.timeline = SceneTimeline(
            timeline_configuration(clock=self.clock, maximum_source_latency=timedelta(days=2)),
            self.database, self.admission)

    def audit_row(self, at):
        with closing(self.database.connect()) as connection:
            connection.execute("INSERT INTO presence_audit(action,actor,at) VALUES (?,?,?)",
                               ("synthetic", "owner", timestamp(at)))
            connection.commit()

    def cleanup(self):
        history, audit = self.timeline.retention_stores
        return history.cleanup_expired_batch(), audit.cleanup_expired_batch()

    def test_windows_are_the_shared_retention_periods(self):
        self.assertEqual(RetentionPeriods(), self.timeline.presence.periods)
        self.assertEqual((20, 90), (self.timeline.presence.periods.recording_days,
                                    self.timeline.presence.periods.audit_days))
        for store in self.timeline.retention_stores:
            self.assertEqual(1000, store.cleanup_batch_size)

    def test_timeline_and_audit_rows_expire_after_their_retention(self):
        self.assertTrue(self.timeline.open())
        # A critical observation with its delivery still unfinished (no
        # evidence or notification port yet) is held to the audit horizon.
        self.timeline.recorder(critical(at=PRESENCE_NOW))
        self.audit_row(PRESENCE_NOW)
        self.timeline.finish(scene_status(SceneRuntimeState.STOPPED))
        self.assertEqual(1, len(self.critical_kinds()))
        self.clock.at = PRESENCE_NOW + timedelta(days=21)
        self.assertEqual((0, 0), self.cleanup())
        self.assertEqual(1, len(self.critical_kinds()))
        self.clock.at = PRESENCE_NOW + timedelta(days=91)
        self.assertEqual((1, 1), self.cleanup())
        self.assertEqual([], self.critical_kinds())
        self.assertEqual([], self.rows("SELECT * FROM presence_audit"))

    def seed_expired(self):
        self.assertTrue(self.timeline.open())
        self.timeline.recorder(critical(at=PRESENCE_NOW))
        self.audit_row(PRESENCE_NOW)
        self.timeline.finish(scene_status(SceneRuntimeState.STOPPED))

    def test_untrusted_clock_deletes_nothing(self):
        # Codex PR #296 P1: a skewed, untrusted clock must not move the
        # cutoffs forward and delete rows early.
        self.seed_expired()
        audit = self.rows("SELECT count(*) FROM presence_audit")[0][0]
        far = PRESENCE_NOW + timedelta(days=400)
        for clock in (lambda: (far, False), lambda: (far.replace(tzinfo=None), True),
                      lambda: (far, 1), lambda: None):
            with self.subTest(clock=clock):
                self.timeline.configuration = replace(self.timeline.configuration, clock=clock)
                for store in self.timeline.retention_stores:
                    with self.assertRaises(RetentionClockUntrusted):
                        store.cleanup_expired_batch()
                self.assertEqual(1, len(self.critical_kinds()))
                self.assertEqual(audit, self.rows("SELECT count(*) FROM presence_audit")[0][0])
        # Trusted again: the same rows expire as before.
        self.timeline.configuration = replace(self.timeline.configuration,
                                              clock=lambda: (far, True))
        self.assertEqual((1, 1), self.cleanup())

    def test_scheduled_cleanup_reports_and_retries_an_untrusted_clock(self):
        self.seed_expired()
        far = PRESENCE_NOW + timedelta(days=400)
        self.timeline.configuration = replace(self.timeline.configuration,
                                              clock=lambda: (far, False))
        retention = AuditRetentionRuntime(*self.timeline.retention_stores,
                                          interval_seconds=3600, retry_seconds=60)
        with self.assertRaises(RetentionClockUntrusted):
            asyncio.run(retention.startup_cleanup())
        self.assertEqual(AuditRetentionHealth.DEGRADED, retention.health)
        # Retried on the shorter interval, never abandoned.
        self.assertEqual(60, retention.retry_seconds)
        self.assertEqual(1, len(self.critical_kinds()))
        self.timeline.configuration = replace(self.timeline.configuration,
                                              clock=lambda: (far, True))
        self.assertEqual(2, asyncio.run(retention.startup_cleanup()))
        self.assertEqual(AuditRetentionHealth.HEALTHY, retention.health)

    def test_expiry_is_refused_without_storage_admission(self):
        self.admission.refuse = True
        history, audit = self.timeline.retention_stores
        for store in (history, audit):
            with self.assertRaises(Exception):
                store.cleanup_expired_batch()

    def test_missing_database_is_never_created_by_expiry(self):
        self.settings.database_path.unlink()
        with self.assertRaises(Exception):
            self.timeline.retention_stores[0].cleanup_expired_batch()
        self.assertFalse(self.settings.database_path.exists())


class SceneTimelineApplicationTests(Fixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        Fixture.setUp(self)

    async def _until(self, predicate, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.01)
        return predicate()

    def application(self, **dependencies):
        remote = binding(OTHER, SourceType.REMOTE_AGENT, sample_interval_ns=1)
        rules = policy(maximum_gap_ns=10_000_000_000, confirmation_ns=1)
        return create_app(
            self.settings, database=self.database, storage_reservation=self.admission,
            scene_monitoring=SceneMonitoringConfiguration((remote,)),
            scene_monitoring_dependencies=SceneMonitoringDependencies(
                calibrations=lambda value: calibration_for(value, rules=rules),
                tick_seconds=0.01, **dependencies),
            scene_timeline=timeline_configuration(),
        )

    async def offer(self, runtime, stream, luma):
        evaluated = runtime.status().sources[0].evaluated
        await asyncio.sleep(0.002)
        self.assertTrue(runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                           height=HEIGHT, pixels=luma))
        self.assertTrue(await self._until(
            lambda: runtime.status().sources[0].evaluated > evaluated))

    def test_composition_is_refused_when_it_could_not_own_the_recorder(self):
        with self.assertRaises(TypeError):
            create_app(self.settings, scene_timeline=timeline_configuration())
        with self.assertRaises(TypeError):
            create_app(self.settings, scene_monitoring=SceneMonitoringConfiguration(
                (binding(OTHER, SourceType.REMOTE_AGENT),)), scene_timeline=object())
        for dependencies in (dict(recorder=Recorder()), dict(undelivered=lambda count: None)):
            with self.subTest(dependencies=sorted(dependencies)), self.assertRaises(TypeError):
                self.application(**dependencies)

    async def test_confirmed_scene_evidence_reaches_presence_and_outbox_closes_cleanly(self):
        application = self.application()
        timeline = application.state.scene_timeline
        runtime = application.state.scene_monitoring
        # The recorder and sink handed to the runtime are this outbox's.
        self.assertIs(timeline.recorder, runtime._deps.recorder)
        self.assertEqual(timeline.undelivered, runtime._deps.undelivered)
        stream = uuid4()
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            self.assertTrue(timeline.opened)
            self.assertEqual(1, self.sessions())
            self.assertIs(SceneRuntimeState.RUNNING, application.state.scene_monitoring_state)
            for luma in (pixels(), pixels(), MOVED, MOVED):
                await self.offer(runtime, stream, luma)
            self.assertTrue(await self._until(
                lambda: self.critical_kinds() == [CriticalKind.SERVER_MOVEMENT.value]))
            # Presence reports scene detection as armed only while running.
            self.assertTrue(timeline.presence.detection())
        self.assertIs(SceneRuntimeState.STOPPED, application.state.scene_monitoring_state)
        self.assertIs(TimelineFinish.CLOSED, application.state.scene_timeline_finish)
        self.assertEqual(0, self.sessions())
        self.assertIsNone(self.gap())
        self.assertFalse(timeline.presence.detection())

    async def test_stop_returns_before_the_outbox_closes(self):
        application = self.application()
        timeline = application.state.scene_timeline
        runtime = application.state.scene_monitoring
        order = []
        stop, close = runtime.stop, timeline.outbox.close

        def stopping(*arguments, **options):
            status = stop(*arguments, **options)
            order.append("scene_stop_returned")
            return status

        def closing_outbox():
            order.append("outbox_close")
            return close()

        runtime.stop, timeline.outbox.close = stopping, closing_outbox
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            pass
        self.assertEqual(["scene_stop_returned", "outbox_close"], order)

    async def test_undelivered_evidence_at_stop_is_recorded_as_lost(self):
        application = self.application()
        timeline = application.state.scene_timeline
        runtime = application.state.scene_monitoring

        def refused(*arguments, **options):
            raise RuntimeError("synthetic presence write failure")

        stream = uuid4()
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            # The critical recorder writes through `record_critical`.
            timeline.presence.record = timeline.presence.record_critical = refused
            for luma in (pixels(), pixels(), MOVED, MOVED):
                await self.offer(runtime, stream, luma)
            self.assertTrue(await self._until(lambda: runtime.status().critical_pending == 1))
        status = runtime.status()
        self.assertIs(SceneRuntimeState.STOPPED, status.state)
        self.assertTrue(status.undelivered_recorded)
        # Clean stop with every count recorded: closed, and the count is in
        # the durable gap marker (no observation content).
        self.assertIs(TimelineFinish.CLOSED, application.state.scene_timeline_finish)
        self.assertEqual((0, 0, 1, 0), self.gap())
        self.assertEqual([], self.critical_kinds())
        self.assertEqual(0, self.sessions())

    async def test_stop_failed_leaves_the_session_for_an_interrupted_gap(self):
        for case in ("stop_failed", "unrecorded", "stop_raised"):
            with self.subTest(case=case):
                self.setUp()
                application = self.application()
                timeline = application.state.scene_timeline
                runtime = application.state.scene_monitoring
                stop = runtime.stop

                def failing(*arguments, case=case, stop=stop, **options):
                    status = stop(*arguments, **options)
                    if case == "stop_raised":
                        raise RuntimeError("synthetic stop failure")
                    if case == "stop_failed":
                        return replace(status, state=SceneRuntimeState.STOP_FAILED)
                    return replace(status, undelivered_recorded=False)

                runtime.stop = failing
                async with asyncio.timeout(20), application.router.lifespan_context(application):
                    self.assertTrue(timeline.opened)
                self.assertIs(TimelineFinish.LEFT_OPEN, application.state.scene_timeline_finish)
                self.assertEqual(1, self.sessions())
                timeline.outbox._handle.release()

    def refuse_outbox_open(self, timeline):
        return refuse_outbox_open(timeline)

    async def test_scene_monitoring_waits_for_a_deferred_outbox_open(self):
        application = self.application()
        timeline = application.state.scene_timeline
        runtime = application.state.scene_monitoring
        refusing = self.refuse_outbox_open(timeline)
        with self.assertLogs("app", level="ERROR") as logs:
            async with asyncio.timeout(20), application.router.lifespan_context(application):
                # Condition 5: not started while the outbox is not open, so
                # every conclusion stays unknown.
                self.assertFalse(timeline.opened)
                self.assertIs(SceneRuntimeState.UNAVAILABLE,
                              application.state.scene_monitoring_state)
                self.assertIs(SceneRuntimeState.CONFIGURED, runtime.status().state)
                self.assertFalse(runtime.offer_luma(OTHER, stream_id=uuid4(), width=WIDTH,
                                                    height=HEIGHT, pixels=pixels()))
                refusing.clear()
                self.assertTrue(await self._until(
                    lambda: application.state.scene_monitoring_state
                    is SceneRuntimeState.RUNNING))
                self.assertTrue(timeline.opened)
        self.assertTrue(any("timeline_outbox_open_failed" in line for line in logs.output))
        self.assertIs(TimelineFinish.CLOSED, application.state.scene_timeline_finish)
        self.assertEqual(0, self.sessions())

    async def test_shutdown_before_the_outbox_opened_starts_nothing(self):
        application = self.application()
        runtime = application.state.scene_monitoring
        self.refuse_outbox_open(application.state.scene_timeline)
        with self.assertLogs("app", level="ERROR"):
            async with asyncio.timeout(20), application.router.lifespan_context(application):
                pass
        self.assertIs(TimelineFinish.NOT_OPENED, application.state.scene_timeline_finish)
        self.assertIs(SceneRuntimeState.STOPPED, runtime.status().state)
        self.assertFalse(runtime.status().worker_running)
        self.assertEqual(0, self.sessions())

    async def test_scheduled_retention_includes_the_presence_timeline(self):
        application = self.application()
        timeline = application.state.scene_timeline
        retention = application.state.audit_retention
        operations = [getattr(store, "_operation", None) for store in retention.stores]
        self.assertEqual(["expire_history", "expire_audit"], operations[-2:])
        calls = []
        for name in ("expire_history", "expire_audit"):
            real = getattr(timeline.presence, name)
            setattr(timeline.presence, name,
                    lambda real=real, name=name, **options: calls.append((name, options["limit"]))
                    or real(**options))
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            # The startup cleanup ran both before serving.
            self.assertEqual([("expire_history", 1000), ("expire_audit", 1000)], calls)

    async def test_counts_are_flushed_while_running(self):
        application = self.application()
        timeline = application.state.scene_timeline
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            timeline.undelivered(4)
            self.assertTrue(await self._until(lambda: self.gap() == (0, 0, 4, 0)))
            self.assertEqual(0, timeline.state().unpersisted)


if __name__ == "__main__":
    unittest.main()
