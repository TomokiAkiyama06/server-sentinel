"""Issues #21/#23 lifespan wiring with disposable storage, a test clock, a
synthetic hardware probe and an intercepted Slack transport. No real Slack
endpoint, host inventory, block device or network is used."""

import asyncio
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4
from zoneinfo import ZoneInfo
import zlib

import app.__main__ as entry
from app.audit import ActorCategory, AuditAction, AuditOutcome, AuditStorageError, TargetKind
from app.deployment import Deployment
from app.integrity.model import Inventory
from app.main import create_app
from app.media.health.service import HealthState, PipelineStatus, Stage
from app.media.recording import Segment
from app.monitoring.config import MonitoringConfiguration, RecordingFilesystem, parse_monitoring
from app.monitoring.runtime import MonitoringDependencies, RuntimeState
from app.settings import ConfigurationError, Settings
from app.storage.database import Database
from app.storage.policy import FilesystemSpace, StorageLimits, StorageState
from app.storage.schema import APPLICATION_MIGRATIONS
from app.media.recording.model import Limits
from tests.asgi import request
from tests.test_recording import SyntheticValidator
from tests.test_storage_notifications import Transport, endpoint


DAY = timedelta(days=1)
STORAGE_LIMITS = {
    "recording_limit_bytes": 100_000, "critical_allowance_bytes": 10_000,
    "hard_reserve_bytes": 4096, "pressure_free_bytes": 8192,
    "recovery_free_bytes": 16_384, "recovery_allocation_bytes": 90_000,
    "write_overhead_bytes": 4096, "max_request_bytes": 1024, "cleanup_batch_size": 10,
}
RECORDING_LIMITS = {
    "pre_roll_bytes": 4096, "max_segment_bytes": 512, "max_segment_ms": 30_000,
    "max_active_recordings": 8, "max_spool_segments": 16, "max_segments_per_recording": 100,
}
PAYLOAD = b"generated geometric test payload" * 4


class Clock:
    def __init__(self, now):
        self.now = now
        self.monotonic = 1000.0

    def utcnow(self):
        return self.now

    def advance(self, delta: timedelta):
        self.now += delta
        self.monotonic += delta.total_seconds()


class SyntheticProbe:
    """Empty generated inventory; never reads the test runner's hardware."""

    def __init__(self):
        self.calls = 0

    def collect(self):
        self.calls += 1
        return Inventory((), frozenset())


class RuntimeFixture(unittest.IsolatedAsyncioTestCase):
    slack = True
    storage_limits = STORAGE_LIMITS

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sentinel-monitoring-")
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.state = base / "state"
        self.recordings = base / "recordings"
        for path in (self.state, self.recordings):
            path.mkdir(mode=0o700)
        self.device = self.recordings.stat().st_dev
        self.approved_device = self.device
        self.clock = Clock(datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc))
        self.transport = Transport()
        self.probe = SyntheticProbe()
        self.settings = Settings(self.state)

    def configuration(self, **overrides):
        filesystem = RecordingFilesystem(
            self.recordings, "00000000-1111-2222-3333-444444444444",
            (os.major(self.device), os.minor(self.device)), self.recordings.parent,
            lambda uuid: self.approved_device, lambda path: True,
        )
        values = dict(
            time_zone=ZoneInfo("UTC"),
            slack=endpoint() if self.slack else None,
            storage_limits=StorageLimits(**self.storage_limits),
            recording_limits=Limits(**RECORDING_LIMITS),
            recording_filesystem=filesystem,
        )
        values.update(overrides)
        return MonitoringConfiguration(**values)

    def application(self, configuration=None, **dependencies):
        values = dict(
            integrity_probe=self.probe, segment_validator=SyntheticValidator(),
            slack_opener=self.transport, utcnow=self.clock.utcnow,
            monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0,
        )
        values.update(dependencies)
        return create_app(
            self.settings, monitoring=configuration or self.configuration(),
            monitoring_dependencies=MonitoringDependencies(**values),
        )

    async def settle(self, runtime):
        """Let the mock delivery thread finish, then persist on the owner."""
        for _ in range(200):
            await runtime.call(runtime._poll)
            # A completion whose local persistence is refused (hard stop)
            # stays pending for local retry; its delivery has still finished.
            if all(entry[2] is not None
                   for entry in runtime.notifications._pending.values()):
                return
            await asyncio.sleep(0.01)
        self.fail("mock delivery did not finish")

    def events(self):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute(
                "SELECT kind, delivery FROM notification_events ORDER BY at, kind"
            ).fetchall()

    def slack_texts(self):
        return [json.loads(request.data)["text"] for request, _ in self.transport.requests]


class UnconfiguredTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_thresholds_fail_closed_with_explicit_state(self):
        with tempfile.TemporaryDirectory() as directory:
            application = create_app(Settings(Path(directory)))
            async with application.router.lifespan_context(application):
                self.assertEqual(RuntimeState.UNCONFIGURED, application.state.monitoring_state)
                self.assertIsNone(application.state.monitoring)
                self.assertFalse(application.state.audit_storage_admitted)
                with self.assertRaises(AuditStorageError):
                    application.state.audit_store.append(
                        actor_category=ActorCategory.SYSTEM,
                        action=AuditAction.CHANGE_ADMIN_SETTING,
                        target_kind=TargetKind.ADMIN_SETTINGS, target_logical_id=uuid4(),
                        outcome=AuditOutcome.SUCCEEDED,
                    )

    async def test_unconfigured_app_runs_no_schema_migration(self):
        # Migrations are metadata writes; without a verified storage policy or
        # an injected admission the app writes no schema at all.
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory))
            application = create_app(settings)
            async with application.router.lifespan_context(application):
                with closing(sqlite3.connect(settings.database_path)) as db:
                    self.assertEqual([], db.execute("SELECT name FROM sqlite_master").fetchall())

    async def test_configuration_without_storage_sections_stays_unconfigured(self):
        with tempfile.TemporaryDirectory() as directory:
            application = create_app(Settings(Path(directory)), monitoring=MonitoringConfiguration(
                ZoneInfo("UTC")))
            async with application.router.lifespan_context(application):
                self.assertEqual(RuntimeState.UNCONFIGURED, application.state.monitoring_state)
                self.assertFalse(application.state.audit_storage_admitted)


class ProductionEntryTests(unittest.TestCase):
    def test_service_refuses_to_run_without_mandatory_checks(self):
        # Without the storage sections the startup/daily hardware integrity
        # check and daily recording self-test cannot run: the service exits
        # non-zero with a fixed event and never starts a listener.
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory))
            for monitoring in (None, MonitoringConfiguration(ZoneInfo("UTC"))):
                with self.subTest(monitoring=monitoring), patch(
                        "app.__main__.configure_logging"), patch(
                        "app.systemd.build_server") as build_server, self.assertLogs(
                            "app.__main__", "ERROR") as logs:
                    self.assertEqual(1, entry.run(settings, monitoring))
                build_server.assert_not_called()
                self.assertEqual(["monitoring_storage_unconfigured"],
                                 [record.getMessage() for record in logs.records])


class FlakyDatabase(Database):
    """The first `failures` connects raise."""

    def __init__(self, path, failures):
        super().__init__(path)
        self.calls = 0
        self.failures = failures

    def connect(self):
        self.calls += 1
        if self.calls <= self.failures:
            raise OSError("synthetic database fault")
        return super().connect()


class LifespanTests(RuntimeFixture):
    async def test_raising_startup_retry_is_rescheduled_not_repeated_each_tick(self):
        database = FlakyDatabase(self.settings.database_path, failures=2)
        application = create_app(
            self.settings, database=database, monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0,
            ),
        )
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            self.assertEqual(1, database.calls)
            # The first due retry raises again from connect(); it must push the
            # deadline forward instead of retrying on every following tick.
            self.clock.advance(timedelta(minutes=15))
            await runtime.call(runtime.tick)
            self.assertEqual(2, database.calls)
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            for _ in range(5):
                self.clock.advance(timedelta(minutes=1))
                await runtime.call(runtime.tick)
            self.assertEqual(2, database.calls)
            self.clock.advance(timedelta(minutes=10))
            await runtime.call(runtime.tick)
            self.assertEqual(3, database.calls)
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            self.assertEqual(1, self.probe.calls)

    async def test_lifespan_state_snapshots_follow_a_recovered_startup(self):
        self.approved_device = self.device + 1
        application = self.application(tick_seconds=0.01)
        async with application.router.lifespan_context(application):
            self.assertEqual(RuntimeState.FAILED, application.state.monitoring_state)
            self.assertFalse(application.state.audit_storage_admitted)
            self.approved_device = self.device
            self.clock.advance(timedelta(minutes=15))
            for _ in range(300):
                if application.state.monitoring_state == RuntimeState.RUNNING:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(RuntimeState.RUNNING, application.state.monitoring_state)
            self.assertTrue(application.state.audit_storage_admitted)
        self.assertEqual(RuntimeState.STOPPED, application.state.monitoring_state)
        self.assertFalse(application.state.audit_storage_admitted)

    async def test_startup_binds_policy_runs_integrity_and_health_and_alerts(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            self.assertTrue(application.state.audit_storage_admitted)
            self.assertEqual(StorageState.NORMAL, runtime.status.storage_state)
            self.assertEqual(1, self.probe.calls)
            await self.settle(runtime)
            # No approved baseline: storage assurance is UNVERIFIABLE, which is
            # an immediate alert; the missing recorder adapter is a visible
            # local UNAVAILABLE warning, never a healthy verdict.
            self.assertEqual(HealthState.UNAVAILABLE, runtime.status.recording_health)
            events = dict(self.events())
            self.assertEqual("sent", events["hardware_integrity_failure"])
            self.assertEqual("suppressed", events["recording_health_warning"])
            self.assertEqual(["ServerSentinel critical alert: hardware_integrity_failure"],
                             self.slack_texts())
            latest = await runtime.call(runtime.health_status.latest)
            self.assertEqual((HealthState.UNAVAILABLE, (Stage.ADAPTER,)),
                             (latest["state"], latest["stages"]))
            # Audit writes from another thread are admitted through the
            # worker-owned policy reservation.
            record = await asyncio.to_thread(
                application.state.audit_store.append,
                actor_category=ActorCategory.SYSTEM, action=AuditAction.CHANGE_ADMIN_SETTING,
                target_kind=TargetKind.ADMIN_SETTINGS, target_logical_id=uuid4(),
                outcome=AuditOutcome.SUCCEEDED,
            )
            self.assertEqual(AuditOutcome.SUCCEEDED, record.outcome)
            # The human surface stays closed.
            messages = await request(application, "/api/system/health")
            self.assertEqual(404, messages[0]["status"])
            with closing(sqlite3.connect(self.settings.database_path)) as db:
                # Drift never writes a baseline without Owner approval.
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM integrity_baseline").fetchone()[0])
        self.assertEqual(RuntimeState.STOPPED, application.state.monitoring_state)
        self.assertFalse(application.state.audit_storage_admitted)

    async def test_integrity_redelivery_is_deduplicated_and_daily_cadence_holds(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(1, self.probe.calls)
            # Re-sending an already accepted outbox row creates no new event.
            await runtime.call(runtime._integrity_sink, 1, self.clock.now, True, [])
            await self.settle(runtime)
            self.clock.advance(DAY)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(2, self.probe.calls)
            kinds = [kind for kind, _ in self.events()]
            self.assertEqual(2, kinds.count("hardware_integrity_failure"))
            self.assertEqual(2, self.slack_texts().count(
                "ServerSentinel critical alert: hardware_integrity_failure"))

    async def test_daily_summary_sends_once_at_configured_local_time(self):
        self.clock.now = datetime(2026, 3, 10, 22, 30, tzinfo=timezone.utc)
        application = self.application(self.configuration(time_zone=ZoneInfo("Asia/Tokyo")))
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            before = len(self.transport.requests)
            # 07:30 Tokyo: not yet due.
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(before, len(self.transport.requests))
            self.clock.now = datetime(2026, 3, 11, 14, 1, tzinfo=timezone.utc)  # 23:01 JST
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            summaries = [text for text in self.slack_texts() if "daily summary" in text]
            self.assertEqual(1, len(summaries))
            self.assertIn("Person/motion/entry observations: unavailable", summaries[0])
            # Process uptime is never presented as monitored camera coverage.
            self.assertIn("Monitored seconds: unavailable", summaries[0])
            self.assertIn("storage: NORMAL", summaries[0])

    async def test_run_loop_ticks_on_the_owner_worker(self):
        self.clock.now = datetime(2026, 3, 10, 23, 5, tzinfo=timezone.utc)
        application = self.application(tick_seconds=0.01)
        async with application.router.lifespan_context(application):
            self.assertEqual(RuntimeState.RUNNING, application.state.monitoring.status.state)
            for _ in range(300):
                if any("daily summary" in text for text in self.slack_texts()):
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(any("daily summary" in text for text in self.slack_texts()))

    async def test_retention_expires_unstarred_and_keeps_starred(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            old_ms = int((self.clock.now - timedelta(days=25)).timestamp() * 1000)

            def completed(starred):
                store = runtime.recordings
                source = uuid4()
                recording = store.start_manual(source, old_ms, duration_ms=1000)
                store.append(Segment(source, uuid4(), 0, old_ms, old_ms + 1000, "synthetic",
                                     "deflate", zlib.compress(PAYLOAD)))
                store.finish(recording)
                store.release_source(source)
                if starred:
                    store.set_starred(recording, True)
                return recording

            expired = await runtime.call(completed, False)
            starred = await runtime.call(completed, True)
            await runtime.call(runtime.tick)
            remaining = await runtime.call(lambda: [
                row["id"] for row in runtime.recordings.list_recordings(limit=10)])
            self.assertEqual([str(starred)], remaining)
            self.assertNotIn(str(expired), remaining)
            self.assertFalse(runtime.status.retention_degraded)

    async def test_recording_filesystem_substitution_refuses_and_alerts_once(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.recordings.rename(self.recordings.with_name("detached"))
            self.recordings.mkdir(mode=0o700)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            status = runtime.status
            self.assertFalse(status.recording_filesystem_ok)
            self.assertEqual(StorageState.HARD_STOP, status.storage_state)
            self.assertEqual(HealthState.FAILED, status.recording_health)
            self.assertEqual(1, self.slack_texts().count(
                "ServerSentinel critical alert: recording_health_failure"))
            # Nothing was written into the substituted directory.
            self.assertEqual([], list(self.recordings.iterdir()))
            with self.assertRaises(Exception):
                await asyncio.to_thread(
                    application.state.audit_store.append,
                    actor_category=ActorCategory.SYSTEM,
                    action=AuditAction.CHANGE_ADMIN_SETTING,
                    target_kind=TargetKind.ADMIN_SETTINGS, target_logical_id=uuid4(),
                    outcome=AuditOutcome.SUCCEEDED,
                )

    async def test_startup_identity_mismatch_fails_closed_and_alerts(self):
        self.approved_device = self.device + 1
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            self.assertFalse(application.state.audit_storage_admitted)
            await self.settle(runtime)
            self.assertEqual(["ServerSentinel critical alert: recording_health_failure"],
                             self.slack_texts())
            self.assertEqual(0, self.probe.calls)
            self.assertEqual([], list(self.recordings.iterdir()))

    async def test_failed_startup_is_retried_and_recovers_without_restart(self):
        self.approved_device = self.device + 1
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            await self.settle(runtime)
            # Not yet due: no reopen attempt, writes stay refused.
            self.clock.advance(timedelta(minutes=5))
            await runtime.call(runtime.tick)
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            # A due retry that still fails does not repeat the immediate alert.
            self.clock.advance(timedelta(minutes=15))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            self.assertEqual(0, self.probe.calls)
            with self.assertRaises(Exception):
                await asyncio.to_thread(
                    application.state.audit_store.append,
                    actor_category=ActorCategory.SYSTEM,
                    action=AuditAction.CHANGE_ADMIN_SETTING,
                    target_kind=TargetKind.ADMIN_SETTINGS, target_logical_id=uuid4(),
                    outcome=AuditOutcome.SUCCEEDED,
                )
            # The expected filesystem appears (e.g. a late mount): the next due
            # retry opens storage and runs the startup integrity/health checks.
            self.approved_device = self.device
            self.clock.advance(timedelta(minutes=15))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            self.assertTrue(runtime.status.recording_filesystem_ok)
            self.assertEqual(1, self.probe.calls)
            self.assertEqual(HealthState.UNAVAILABLE, runtime.status.recording_health)
            self.assertEqual(1, self.slack_texts().count(
                "ServerSentinel critical alert: recording_health_failure"))
            record = await asyncio.to_thread(
                application.state.audit_store.append,
                actor_category=ActorCategory.SYSTEM, action=AuditAction.CHANGE_ADMIN_SETTING,
                target_kind=TargetKind.ADMIN_SETTINGS, target_logical_id=uuid4(),
                outcome=AuditOutcome.SUCCEEDED,
            )
            self.assertEqual(AuditOutcome.SUCCEEDED, record.outcome)


def schema_tables(path):
    with closing(sqlite3.connect(path)) as db:
        return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


class MigrationAdmissionTests(RuntimeFixture):
    async def test_unverified_filesystem_defers_migrations_until_retry_succeeds(self):
        self.approved_device = self.device + 1
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            await self.settle(runtime)
            # No schema was written before the filesystem identity was verified,
            # and the immediate alert was still attempted.
            self.assertEqual(set(), schema_tables(self.settings.database_path))
            self.assertEqual(["ServerSentinel critical alert: recording_health_failure"],
                             self.slack_texts())
            self.approved_device = self.device
            self.clock.advance(timedelta(minutes=15))
            await runtime.call(runtime.tick)
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            with closing(sqlite3.connect(self.settings.database_path)) as db:
                self.assertEqual(len(APPLICATION_MIGRATIONS), db.execute(
                    "SELECT COUNT(*) FROM schema_migrations").fetchone()[0])

    async def test_invalid_database_still_aborts_startup(self):
        self.settings.database_path.write_bytes(b"SYNTHETIC_PRIVATE_VALUE" * 64)
        self.settings.database_path.chmod(0o600)
        application = self.application()
        with self.assertRaisesRegex(RuntimeError, "^application startup failed$"):
            async with application.router.lifespan_context(application):
                self.fail("must not start")
        self.assertFalse(application.state.ready)
        self.assertIsNone(application.state.monitoring._executor)


class HardReserveMigrationTests(RuntimeFixture):
    # Free space can never cover this hard reserve plus the write overhead.
    storage_limits = dict(STORAGE_LIMITS, hard_reserve_bytes=2**61,
                          pressure_free_bytes=2**62, recovery_free_bytes=2**62 + 1)

    async def test_pending_migrations_are_refused_below_the_hard_reserve(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            self.assertFalse(application.state.audit_storage_admitted)
            await self.settle(runtime)
            self.assertEqual(set(), schema_tables(self.settings.database_path))
            self.assertEqual(["ServerSentinel critical alert: recording_health_failure"],
                             self.slack_texts())


class FailingRecorder:
    """Synthetic adapter whose pipeline is never ready: the self-test FAILS."""

    def cleanup(self):
        pass

    def pipeline_status(self):
        return PipelineStatus((True,), False, True)

    def storage_health(self):
        return ("OK",)


class DeniedHealthStatusTests(RuntimeFixture):
    async def test_failure_alert_is_attempted_when_status_persistence_is_denied(self):
        application = self.application(recorder_probe_factory=lambda store: FailingRecorder())
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            failure = "ServerSentinel critical alert: recording_health_failure"
            self.assertEqual(1, self.slack_texts().count(failure))
            # The disk falls below the hard reserve: every metadata write,
            # including the recording-health status row, is refused.
            runtime._policy._space = lambda: FilesystemSpace(0, 2**40)
            self.clock.advance(DAY)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            status = runtime.status
            self.assertEqual(HealthState.FAILED, status.recording_health)
            self.assertTrue(status.recording_health_degraded)
            self.assertEqual(2, self.slack_texts().count(failure))
            # The denied write is retried, but the same failing verdict does
            # not re-alert on every retry.
            self.clock.advance(timedelta(minutes=15))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(2, self.slack_texts().count(failure))
            self.assertTrue(runtime.status.recording_health_degraded)
            # A still-unpersisted failure a day later alerts again.
            self.clock.advance(DAY)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(3, self.slack_texts().count(failure))


class PressureAuditTests(RuntimeFixture):
    # Free space can never reach this pressure threshold, while the small hard
    # reserve keeps metadata writes admissible: the policy enters and audits
    # STORAGE_PRESSURE on its first sample.
    storage_limits = dict(STORAGE_LIMITS, pressure_free_bytes=2**62,
                          recovery_free_bytes=2**62 + 1)

    async def test_storage_transition_is_written_to_the_state_audit(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(StorageState.PRESSURE, runtime.status.storage_state)
            self.assertFalse(runtime.status.storage_audit_failed)
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            rows = db.execute(
                "SELECT previous_state, current_state FROM storage_state_audit").fetchall()
        self.assertEqual([("NORMAL", "STORAGE_PRESSURE")], rows)


class SlackDisabledTests(RuntimeFixture):
    slack = False

    async def test_faults_persist_locally_without_slack(self):
        with patch("app.notifications.slack.build_opener",
                   side_effect=AssertionError("disabled Slack must not open a transport")):
            application = self.application()
            async with application.router.lifespan_context(application):
                runtime = application.state.monitoring
                await self.settle(runtime)
                self.assertEqual("disabled", dict(self.events())["hardware_integrity_failure"])
        self.assertEqual([], self.transport.requests)


class SlackFailureTests(RuntimeFixture):
    async def test_failed_delivery_keeps_local_fault_and_no_secret_in_logs(self):
        self.transport = Transport(error=RuntimeError("generated private failure"))
        with self.assertLogs(level="DEBUG") as logs:
            application = self.application()
            async with application.router.lifespan_context(application):
                runtime = application.state.monitoring
                await self.settle(runtime)
                self.assertEqual("failed", dict(self.events())["hardware_integrity_failure"])
                self.assertTrue(runtime.status.notification_delivery_failed)
        output = "\n".join(logs.output)
        self.assertNotIn("hooks.slack.com", output)
        self.assertNotIn("generated private failure", output)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.recordings = Path(self.temporary.name) / "recordings"
        self.recordings.mkdir(mode=0o700)
        device = self.recordings.stat().st_dev
        self.device = device
        self.value = {
            "time_zone": "Asia/Tokyo",
            "storage_limits": dict(STORAGE_LIMITS),
            "recording_limits": dict(RECORDING_LIMITS),
            "recording_filesystem": {
                "filesystem_uuid": "00000000-1111-2222-3333-444444444444",
                "device": [os.major(device), os.minor(device)],
                "mount_point": self.temporary.name,
            },
        }

    def parse(self, value=None, *, approved=None, root=None):
        return parse_monitoring(
            self.value if value is None else value, recordings_directory=self.recordings,
            resolve_device=lambda uuid: self.device if approved is None else approved,
            root_device=lambda: self.device + 1 if root is None else root,
            is_mount=lambda path: True,
        )

    def test_valid_configuration_defaults_to_2300_and_disabled_slack(self):
        configuration = self.parse()
        self.assertTrue(configuration.storage_configured)
        self.assertEqual((23, 0), (configuration.summary_hour, configuration.summary_minute))
        self.assertIsNone(configuration.slack)
        self.assertNotIn("0000", repr(configuration))

    def test_storage_sections_are_all_or_nothing(self):
        self.assertFalse(self.parse({"time_zone": "UTC"}).storage_configured)
        for name in ("storage_limits", "recording_limits", "recording_filesystem"):
            value = dict(self.value)
            del value[name]
            with self.assertRaisesRegex(ConfigurationError, "incomplete"):
                self.parse(value)

    def test_invalid_values_are_refused_without_echoing_them(self):
        cases = []
        for key, bad in (("time_zone", "../etc/passwd"), ("daily_summary_time", "24:00"),
                         ("slack_webhook_url", "https://example.invalid/secret-token"),
                         ("unknown", 1)):
            cases.append(dict(self.value, **{key: bad}))
        cases.append(dict(self.value, storage_limits=dict(STORAGE_LIMITS, hard_reserve_bytes=0)))
        cases.append(dict(self.value, storage_limits=dict(STORAGE_LIMITS, extra=1)))
        cases.append(dict(self.value, recording_limits=dict(RECORDING_LIMITS, max_segment_bytes=4096)))
        for value in cases:
            with self.assertRaises(ConfigurationError) as raised:
                self.parse(value)
            self.assertNotIn("secret-token", str(raised.exception))
            self.assertNotIn("passwd", str(raised.exception))

    def test_recording_filesystem_identity_must_match(self):
        with self.assertRaisesRegex(ConfigurationError, "mismatch"):
            self.parse(approved=self.device + 7)
        with self.assertRaisesRegex(ConfigurationError, "mismatch"):
            self.parse(root=self.device)
        value = dict(self.value, recording_filesystem=dict(
            self.value["recording_filesystem"], device=[0, 0]))
        with self.assertRaisesRegex(ConfigurationError, "mismatch"):
            self.parse(value)
        value = dict(self.value, recording_filesystem=dict(
            self.value["recording_filesystem"], mount_point="relative"))
        with self.assertRaises(ConfigurationError):
            self.parse(value)


class DeploymentMonitoringTests(unittest.TestCase):
    def test_deployment_accepts_optional_monitoring_object(self):
        with tempfile.TemporaryDirectory(prefix="server-monitoring-synthetic-") as directory:
            root = Path(directory)
            runtime = root / "runtime"
            for path in (runtime, runtime / "state", runtime / "recordings", runtime / "audit"):
                path.mkdir(mode=0o700)
            (root / "code").mkdir()
            device = runtime.stat().st_dev
            uuid = "00000000-1111-2222-3333-444444444444"
            base = {
                "runtime_root": str(runtime), "runtime_mount_point": str(root),
                "runtime_device": [os.major(device), os.minor(device)],
                "runtime_filesystem_uuid": uuid, "service_uid": os.geteuid(),
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }
            monitoring = {
                "time_zone": "UTC", "storage_limits": STORAGE_LIMITS,
                "recording_limits": RECORDING_LIMITS,
                "recording_filesystem": {"filesystem_uuid": uuid,
                                         "device": [os.major(device), os.minor(device)],
                                         "mount_point": str(root)},
            }
            config = root / "deployment.json"

            def load(value):
                config.write_text(json.dumps(value))
                config.chmod(0o600)
                with patch("app.deployment.ADMINISTRATOR_UID", os.geteuid()), patch(
                        "app.deployment._approved_filesystem_device", return_value=device), patch(
                        "app.deployment.os.path.ismount", return_value=True), patch(
                        "app.deployment._administrator_directory"), patch(
                        "app.deployment._operating_system_root_device",
                        return_value=device + 1):
                    return Deployment.load(config, code_root=root / "code")

            self.assertIsNone(load(base).monitoring)
            deployment = load(dict(base, monitoring=monitoring))
            self.assertTrue(deployment.monitoring.storage_configured)
            self.assertNotIn(uuid, repr(deployment))
            with self.assertRaises(ConfigurationError):
                load(dict(base, monitoring=dict(monitoring, storage_limits={})))
            with self.assertRaises(ConfigurationError):
                load(dict(base, other=1))


class ReservationThreadTests(RuntimeFixture):
    async def test_cross_thread_reservation_serializes_with_owner_work(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            held = threading.Event()
            release = threading.Event()
            order = []

            def writer():
                with runtime.reservation():
                    held.set()
                    release.wait(2)
                    order.append("writer")

            thread = threading.Thread(target=writer)
            thread.start()
            self.assertTrue(held.wait(2))
            owner = asyncio.ensure_future(runtime.call(lambda: order.append("owner")))
            await asyncio.sleep(0.05)
            self.assertEqual([], order)
            release.set()
            await owner
            await asyncio.to_thread(thread.join, 2)
            self.assertEqual(["writer", "owner"], order)
