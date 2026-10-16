"""Issue #232 item 4: human-access faults as immediate, value-free Owner
notifications (Owner decision 2026-10-16).

Synthetic only: the real ``HostnameReservationCheck`` over synthetic
``/proc/net`` rows and Serve status, software authenticators, a temporary
SQLite database and an intercepted Slack transport with a generated dummy
endpoint. No real Slack message, socket, browser or authenticator is used.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from contextlib import closing
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest import TestCase
from unittest.mock import PropertyMock, patch
from uuid import UUID, uuid4, uuid5
from zoneinfo import ZoneInfo

from app.auth.human_surface import (
    AUTHENTICATION_OPTIONS_PATH, AUTHENTICATION_PATH, HumanAccess, HumanAccessConfiguration,
    HumanAccessState, HumanSurface,
)
from app.auth.passkeys import CredentialFinding, PasskeyCeremonies
from app.auth.reservation import (
    DAILY_SECONDS, RETRY_WHILE_CLOSED_SECONDS, CheckKind, Reason, ReservationFault,
)
from app.main import create_app
from app.media.recording.model import Limits
from app.monitoring.config import MonitoringConfiguration, RecordingFilesystem
from app.storage.policy import StorageLimits
from app.monitoring.access import AccessFaultMonitor
from app.monitoring.runtime import EVENT_NAMESPACE, MonitoringDependencies, RuntimeState
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import SlackDelivery

from tests.test_hostname_reservation import HOST, NOW, checker
from tests.test_human_surface import (
    EXPOSED, ORIGIN, HumanSurfaceFixture, call, payload, status,
)
from tests.test_monitoring_runtime import (
    RECORDING_LIMITS, STORAGE_LIMITS, FlakyDatabase, RuntimeFixture,
)
from tests.test_recording import SyntheticValidator
from tests.test_storage_notifications import Transport, drain, endpoint


AT = datetime(2026, 10, 16, 9, 0, tzinfo=timezone.utc)
FAULT = NotificationKind.HUMAN_ACCESS_FAULT
RECOVERED = NotificationKind.HUMAN_ACCESS_RECOVERED
FINDING = NotificationKind.CREDENTIAL_FINDING


class RecordingNotifications:
    """Stands in for ``NotificationService.record``; keeps every argument."""

    def __init__(self):
        self.calls = []

    def record(self, kind, *, at, confirmed=False, event_id=None, on_complete=None):
        self.calls.append({"kind": kind, "at": at, "confirmed": confirmed, "event_id": event_id})

    @property
    def kinds(self):
        return [call["kind"] for call in self.calls]


class MonitoredAccessFixture(HumanSurfaceFixture):
    """The fixture's composition, rebuilt with one monitor as both sinks."""

    monitor_options = {}

    def setUp(self):
        super().setUp()
        self.monitor = AccessFaultMonitor(**self.monitor_options)
        self.check, self.files, _, _ = checker(clock=self.clock, session_revoker=self.revoker,
                                               sink=self.monitor)
        self.assertTrue(self.check.startup().open)
        self.ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                            clock=self.ceremony_clock, findings=self.monitor)
        self.access = HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets,
                                  store=self.store, ceremonies=self.ceremonies,
                                  reservation=self.check, rate_limiter=self.limiter)
        self.access.bind_storage_admission(self.admission, database=self.database)
        self.surface = HumanSurface(self.inner, self.access)
        self.monitor.attach(self.access)
        self.notifications = RecordingNotifications()
        self.now = 5000.0
        self.healthy_files = dict(self.files.files)

    def drain(self, advance=0.0):
        self.now += advance
        return self.monitor.drain(self.notifications, at=AT, monotonic=self.now)

    def fail_check(self):
        self.files.files["tcp"] = EXPOSED
        self.clock.value += DAILY_SECONDS
        self.assertFalse(self.check.tick().open)

    def recover_check(self):
        self.files.files.update(self.healthy_files)
        self.clock.value += RETRY_WHILE_CLOSED_SECONDS
        self.assertTrue(self.check.tick().open)


class ReservationFaultTests(MonitoredAccessFixture):
    async def test_failing_check_notifies_once_marks_degraded_and_recovers(self):
        status = self.drain()
        self.assertEqual(self.notifications.kinds, [])
        self.assertFalse(status.human_access_degraded)
        self.fail_check()
        status = self.drain()
        self.assertEqual(self.notifications.kinds, [FAULT])
        self.assertTrue(status.human_access_degraded)
        # The same fault on later daily and retry checks is not re-notified.
        self.clock.value += DAILY_SECONDS
        self.assertFalse(self.check.tick().open)
        self.clock.value += RETRY_WHILE_CLOSED_SECONDS
        self.check.tick()
        for _ in range(3):
            self.assertTrue(self.drain(60).human_access_degraded)
        self.assertEqual(self.notifications.kinds, [FAULT])
        self.recover_check()
        status = self.drain(60)
        self.assertEqual(self.notifications.kinds, [FAULT, RECOVERED])
        self.assertFalse(status.human_access_degraded)
        self.drain(60)
        self.assertEqual(self.notifications.kinds, [FAULT, RECOVERED])

    async def test_notifications_are_value_free_with_distinct_event_ids(self):
        self.fail_check()
        self.drain()
        self.recover_check()
        self.drain()
        ids = [call["event_id"] for call in self.notifications.calls]
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(isinstance(value, UUID) for value in ids))
        for call_ in self.notifications.calls:
            self.assertEqual(set(call_), {"kind", "at", "confirmed", "event_id"})
            self.assertFalse(call_["confirmed"])
        # Nothing from the fault but fixed reason codes is kept.
        kept = repr(vars(self.monitor))
        self.assertNotIn(HOST, kept)
        self.assertNotIn("100.64.0.10", kept)

    async def test_a_fault_that_ended_before_the_drain_is_still_reported(self):
        self.fail_check()
        self.recover_check()
        self.assertTrue(self.drain().human_access_degraded)
        self.assertFalse(self.drain(60).human_access_degraded)
        self.assertEqual(self.notifications.kinds, [FAULT, RECOVERED])

    async def test_a_new_reason_in_the_episode_notifies_again_once(self):
        self.fail_check()
        self.drain()
        late = ReservationFault((Reason.HOSTNAME_RESOLUTION_TIMEOUT,), CheckKind.RETRY, NOW)
        self.monitor.emit(late)
        self.drain(60)
        self.monitor.emit(late)
        self.drain(60)
        self.assertEqual(self.notifications.kinds, [FAULT, FAULT])

    async def test_a_raising_check_is_a_fault(self):
        await self.stop_serving()
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

        async def idle(_seconds):
            await asyncio.Event().wait()

        with patch.object(self.check, "startup", side_effect=RuntimeError("synthetic")):
            task = asyncio.create_task(self.access.run(sleep=idle))
            self.serving.append((self.access, task))
            await self.until(lambda: self.access.state is HumanAccessState.CHECK_FAILING)
        self.assertTrue(self.drain().human_access_degraded)
        self.assertEqual(self.notifications.kinds, [FAULT])

    async def test_a_restored_episode_announces_recovery_and_not_the_fault_again(self):
        self.monitor.restore_fault_episode()
        self.assertFalse(self.drain().human_access_degraded)
        self.assertEqual(self.notifications.kinds, [RECOVERED])

    async def test_a_restored_persisting_fault_is_not_notified_again(self):
        self.monitor.restore_fault_episode()
        self.fail_check()
        self.assertTrue(self.drain().human_access_degraded)
        self.assertEqual(self.notifications.kinds, [])

    async def test_a_restored_undelivered_fault_is_sent_before_the_recovery(self):
        stored, at = uuid4(), AT - timedelta(minutes=30)
        self.monitor.restore_fault_episode(delivered=False, event_id=stored, at=at)
        self.drain()
        self.drain(60)
        self.assertEqual(self.notifications.kinds, [FAULT, RECOVERED])
        # The retry updates the stored pending row instead of adding a fault.
        self.assertEqual(self.notifications.calls[0]["event_id"], stored)
        self.assertEqual(self.notifications.calls[0]["at"], at)

    async def test_a_restored_pending_recovery_is_sent_again_under_its_row(self):
        stored, at = uuid4(), AT - timedelta(minutes=20)
        self.monitor.restore_pending_recovery(event_id=stored, at=at)
        self.assertFalse(self.drain().human_access_degraded)
        self.assertEqual(self.notifications.kinds, [RECOVERED])
        self.assertEqual(self.notifications.calls[0]["event_id"], stored)
        self.assertEqual(self.notifications.calls[0]["at"], at)

    async def test_starting_or_stopped_composition_is_neither_fault_nor_recovery(self):
        await self.stop_serving()
        self.assertIs(self.access.state, HumanAccessState.STOPPED)
        self.assertFalse(self.drain().human_access_degraded)
        self.assertEqual(self.notifications.kinds, [])


class AccessBudgetTests(MonitoredAccessFixture):
    monitor_options = {"access_budget": 2}

    async def test_flapping_is_bounded_and_an_unreported_episode_is_sent_later(self):
        self.fail_check()
        self.drain()
        self.recover_check()
        self.drain(60)
        self.assertEqual(self.notifications.kinds, [FAULT, RECOVERED])
        # Budget spent: a whole further episode is not sent yet ...
        self.fail_check()
        self.assertTrue(self.drain(60).human_access_degraded)
        self.recover_check()
        self.assertFalse(self.drain(60).human_access_degraded)
        self.assertEqual(self.notifications.kinds, [FAULT, RECOVERED])
        # ... but is reported once the rolling hour allows it.
        self.drain(3600)
        self.drain(60)
        self.assertEqual(self.notifications.kinds, [FAULT, RECOVERED, FAULT, RECOVERED])
        self.drain(60)
        self.assertEqual(len(self.notifications.kinds), 4)


class CredentialFindingTests(MonitoredAccessFixture):
    async def test_findings_are_coalesced_and_hold_degraded(self):
        principal = uuid4()
        for _ in range(3):
            self.monitor.credential_finding(CredentialFinding.SIGN_COUNT_REGRESSION, principal)
        self.assertTrue(self.drain().credential_finding_degraded)
        self.assertEqual(self.notifications.kinds, [FINDING])
        self.assertNotIn(str(principal), repr(vars(self.monitor)))
        self.monitor.credential_finding(CredentialFinding.BACKUP_ELIGIBILITY_CHANGED, uuid4())
        self.assertTrue(self.drain(60).credential_finding_degraded)
        self.assertEqual(self.notifications.kinds, [FINDING])
        self.drain(3600)
        self.assertEqual(self.notifications.kinds, [FINDING, FINDING])
        self.assertTrue(self.drain(3600).credential_finding_degraded)
        self.assertFalse(self.drain(24 * 3600).credential_finding_degraded)
        self.assertEqual(self.notifications.kinds, [FINDING, FINDING])

    async def test_a_real_ceremony_finding_reaches_the_monitor(self):
        _, authenticator, _ = self.enroll()
        await self.sign_in(authenticator)
        options = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        assertion = authenticator.assertion(payload(options), origin=ORIGIN, rp_id=HOST, be=True)
        refused = await call(self.surface, "POST", AUTHENTICATION_PATH,
                             body=json.dumps(assertion).encode())
        self.assertNotEqual(status(refused), 204)
        self.assertEqual(self.ceremonies.finding_delivery_failed, 0)
        self.assertTrue(self.drain().credential_finding_degraded)
        self.assertEqual(self.notifications.kinds, [FINDING])


class CompositionTests(MonitoredAccessFixture):
    def monitoring(self):
        """A storage-configured monitoring section; the runtime is never started."""
        recordings = self.temporary / "recordings"
        recordings.mkdir(mode=0o700, exist_ok=True)
        device = recordings.stat().st_dev
        filesystem = RecordingFilesystem(
            recordings, "00000000-1111-2222-3333-444444444444",
            (os.major(device), os.minor(device)), recordings.parent,
            lambda uuid: device, lambda path: True)
        return MonitoringConfiguration(
            ZoneInfo("UTC"), storage_limits=StorageLimits(**STORAGE_LIMITS),
            recording_limits=Limits(**RECORDING_LIMITS), recording_filesystem=filesystem)

    async def test_a_monitor_without_the_monitoring_runtime_is_refused(self):
        """Codex PR #271 (P2): nothing would drain it, so faults would be lost."""
        monitor = AccessFaultMonitor()
        check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker, sink=monitor)
        access = HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets,
                             store=self.store, reservation=check,
                             ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=check,
                                                          clock=self.ceremony_clock, findings=monitor))
        for monitoring in (None, MonitoringConfiguration(ZoneInfo("UTC"))):
            for human_access in (access, None):
                with self.subTest(monitoring=monitoring, human_access=human_access), \
                        self.assertRaises(TypeError):
                    create_app(self.settings(), database=self.database, human_access=human_access,
                               storage_reservation=self.admission, monitoring=monitoring,
                               monitoring_dependencies=MonitoringDependencies(access_faults=monitor))
        self.assertIsNone(monitor.attached)

    async def test_create_app_requires_the_monitor_as_both_sinks_and_attaches(self):
        other_check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker)
        other_ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=other_check,
                                             clock=self.ceremony_clock)
        other = HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets,
                            store=self.store, ceremonies=other_ceremonies, reservation=other_check)
        monitor = AccessFaultMonitor()
        with self.assertRaises(TypeError):
            create_app(self.settings(), database=self.database, human_access=other,
                       storage_reservation=self.admission, monitoring=self.monitoring(),
                       monitoring_dependencies=MonitoringDependencies(access_faults=monitor))
        self.assertIsNone(monitor.attached)
        # The monitor given to the check only: the findings still bypass it.
        half_check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker, sink=monitor)
        half = HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets,
                           store=self.store, reservation=half_check,
                           ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=half_check,
                                                        clock=self.ceremony_clock))
        with self.assertRaises(TypeError):
            create_app(self.settings(), database=self.database, human_access=half,
                       storage_reservation=self.admission, monitoring=self.monitoring(),
                       monitoring_dependencies=MonitoringDependencies(access_faults=monitor))
        fresh = AccessFaultMonitor()
        check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker, sink=fresh)
        access = HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets,
                             store=self.store, reservation=check,
                             ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=check,
                                                          clock=self.ceremony_clock, findings=fresh))
        create_app(self.settings(), database=self.database, human_access=access,
                   storage_reservation=self.admission, monitoring=self.monitoring(),
                   monitoring_dependencies=MonitoringDependencies(access_faults=fresh))
        self.assertIs(fresh.attached, access)
        with self.assertRaises(ValueError):
            fresh.attach(self.access)

    async def test_a_monitor_left_out_of_the_runtime_is_refused(self):
        """Codex PR #271 (P2): a monitor installed as a sink but not handed to
        the monitoring runtime would never be drained."""
        monitor = AccessFaultMonitor()
        check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker, sink=monitor)
        for findings in (monitor, None):
            access = HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets,
                                 store=self.store, reservation=check,
                                 ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=check,
                                                              clock=self.ceremony_clock,
                                                              findings=findings))
            for dependencies in (None, MonitoringDependencies()):
                with self.subTest(findings=findings, dependencies=dependencies), \
                        self.assertRaises(TypeError):
                    create_app(self.settings(), database=self.database, human_access=access,
                               storage_reservation=self.admission, monitoring=self.monitoring(),
                               monitoring_dependencies=dependencies)
        # Only the check's sink being a monitor is refused too.
        other_check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker)
        only_findings = HumanAccess(
            HumanAccessConfiguration(enabled=True), assets=self.assets, store=self.store,
            reservation=other_check,
            ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=other_check,
                                         clock=self.ceremony_clock, findings=AccessFaultMonitor()))
        with self.assertRaises(TypeError):
            create_app(self.settings(), database=self.database, human_access=only_findings,
                       storage_reservation=self.admission)
        self.assertIsNone(monitor.attached)

    async def test_a_refused_create_app_leaves_the_monitor_unattached(self):
        """PR #271 review: the monitor is attached only after every check passed."""
        monitor = AccessFaultMonitor()
        check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker, sink=monitor)
        access = HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets,
                             store=self.store, reservation=check,
                             ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=check,
                                                          clock=self.ceremony_clock, findings=monitor))
        with self.assertRaises(TypeError):
            create_app(self.settings(), database=self.database, human_access=access,
                       storage_reservation=self.admission, monitoring=self.monitoring(),
                       monitoring_dependencies=MonitoringDependencies(access_faults=monitor),
                       local_uvc="not a configuration")
        self.assertIsNone(monitor.attached)
        create_app(self.settings(), database=self.database, human_access=access,
                   storage_reservation=self.admission, monitoring=self.monitoring(),
                   monitoring_dependencies=MonitoringDependencies(access_faults=monitor))
        self.assertIs(monitor.attached, access)
        # A monitor already attached to another composition: the same TypeError.
        with self.assertRaises(TypeError):
            create_app(self.settings(), database=self.database, human_access=self.access,
                       storage_reservation=self.admission, monitoring=self.monitoring(),
                       monitoring_dependencies=MonitoringDependencies(access_faults=monitor))


class MonitorValidationTests(TestCase):
    def test_settings_and_inputs_are_validated(self):
        for options in ({"access_budget": 0}, {"access_budget": True}, {"access_budget": 2000},
                        {"finding_interval_seconds": 0}, {"finding_hold_seconds": float("nan")}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                AccessFaultMonitor(**options)
        monitor = AccessFaultMonitor()
        with self.assertRaises(ValueError):
            monitor.emit("UNEXPECTED_LISTENER")
        with self.assertRaises(ValueError):
            monitor.credential_finding("sign_count_regression", uuid4())
        with self.assertRaises(ValueError):
            monitor.attach(object())
        with self.assertRaises(ValueError):
            MonitoringDependencies(access_faults=object())

    def test_a_raising_record_loses_no_finding_or_fault(self):
        """PR #271 review: arrivals taken from the latch survive a raising drain."""

        class Flaky(RecordingNotifications):
            def __init__(self):
                super().__init__()
                self.fail = True

            def record(self, kind, **values):
                if self.fail:
                    self.fail = False
                    raise RuntimeError("synthetic")
                super().record(kind, **values)

        monitor = AccessFaultMonitor()
        notifications = Flaky()
        monitor.emit(ReservationFault((Reason.UNEXPECTED_LISTENER,), CheckKind.STARTUP, NOW, 1, 0))
        monitor.credential_finding(CredentialFinding.SIGN_COUNT_REGRESSION, uuid4())
        with self.assertRaises(RuntimeError):
            monitor.drain(notifications, at=AT, monotonic=1.0)
        status = monitor.drain(notifications, at=AT, monotonic=2.0)
        self.assertEqual(notifications.kinds, [FAULT, FINDING])
        self.assertTrue(status.human_access_degraded)
        self.assertTrue(status.credential_finding_degraded)

    def test_a_refused_notification_is_retried_with_the_same_event(self):
        """Codex PR #271: ``FAILED`` means the service kept nothing."""
        from app.notifications.slack import DeliveryResult

        class Refusing(RecordingNotifications):
            def __init__(self):
                super().__init__()
                self.refuse = 2

            def record(self, kind, **values):
                super().record(kind, **values)
                if self.refuse:
                    self.refuse -= 1
                    return DeliveryResult.FAILED
                return DeliveryResult.PENDING

        monitor = AccessFaultMonitor()
        notifications = Refusing()
        monitor.emit(ReservationFault((Reason.UNEXPECTED_LISTENER,), CheckKind.STARTUP, NOW, 1, 0))
        for step in range(3):
            monitor.drain(notifications, at=AT + timedelta(minutes=step), monotonic=1.0 + step)
        monitor.drain(notifications, at=AT + timedelta(minutes=5), monotonic=10.0)
        self.assertEqual(notifications.kinds, [FAULT, FAULT, FAULT])
        self.assertEqual(len({call["event_id"] for call in notifications.calls}), 1)
        self.assertEqual({call["at"] for call in notifications.calls}, {AT})
        # Refusals spent no budget: the accepted send was the first counted one.
        self.assertEqual(len(monitor._sent), 1)

    def test_without_a_composition_an_emitted_fault_still_notifies(self):
        monitor = AccessFaultMonitor()
        notifications = RecordingNotifications()
        monitor.emit(ReservationFault((Reason.UNEXPECTED_LISTENER,), CheckKind.STARTUP, NOW, 1, 0))
        self.assertTrue(monitor.drain(notifications, at=AT, monotonic=1.0).human_access_degraded)
        # Recovery cannot be observed without the composition: stays degraded.
        self.assertTrue(monitor.drain(notifications, at=AT, monotonic=2.0).human_access_degraded)
        self.assertEqual(notifications.kinds, [FAULT])


class StandardLibraryImportTests(TestCase):
    """PR #271 review: the monitoring runtime stays importable without the
    application's dependencies (the installer and lifecycle inventory)."""

    def test_runtime_and_monitor_import_with_the_standard_library_only(self):
        server = Path(__file__).resolve().parents[1]
        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(server)!r})\n"
            "import app.monitoring.access, app.monitoring.runtime\n"
            "loaded = sorted(name for name in sys.modules if name.split('.')[0] in "
            "{'starlette', 'fastapi', 'cryptography', 'uvicorn', 'pydantic'} "
            "or name == 'app.auth' or name.startswith('app.auth.'))\n"
            "assert not loaded, loaded\n"
            "import app.lifecycle_inventory\n"
            "print('stdlib-only')\n")
        # -S: no site-packages, so a third-party import fails as on a host
        # without the application's environment; -I: no user site, no cwd.
        result = subprocess.run([sys.executable, "-S", "-I", "-c", script],
                                capture_output=True, text=True, timeout=60,
                                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "stdlib-only")


class NotificationServiceTests(TestCase):
    def test_access_kinds_are_immediate_fixed_category_messages(self):
        transport, local = Transport(), []
        service = NotificationService(local.append, SlackDelivery(endpoint(), opener=transport))
        for kind in (FAULT, FINDING, RECOVERED):
            service.record(kind, at=AT)
        drain(self, service)
        texts = [json.loads(request.data)["text"] for request, _ in transport.requests]
        self.assertEqual(texts, ["ServerSentinel critical alert: human_access_fault",
                                 "ServerSentinel critical alert: credential_finding",
                                 "ServerSentinel recovery notice: human_access_recovered"])
        self.assertEqual({event.kind for event in local}, {FAULT, FINDING, RECOVERED})


class RuntimeTests(RuntimeFixture):
    async def test_runtime_tick_sends_the_alert_and_marks_health(self):
        monitor = AccessFaultMonitor()
        application = self.application(access_faults=monitor)
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            self.assertFalse(runtime.status.human_access_degraded)
            monitor.emit(ReservationFault((Reason.UNEXPECTED_ROUTE,), CheckKind.DAILY, NOW, 0, 1))
            monitor.credential_finding(CredentialFinding.SIGN_COUNT_REGRESSION, uuid4())
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertTrue(runtime.status.human_access_degraded)
            self.assertTrue(runtime.status.credential_finding_degraded)
            texts = self.slack_texts()
            self.assertIn("ServerSentinel critical alert: human_access_fault", texts)
            self.assertIn("ServerSentinel critical alert: credential_finding", texts)
            self.assertNotIn(HOST, "".join(texts))
            kinds = {kind for kind, _ in self.events()}
            self.assertLessEqual({"human_access_fault", "credential_finding"}, kinds)
            # A repeated check failure with the same reason is not re-sent.
            monitor.emit(ReservationFault((Reason.UNEXPECTED_ROUTE,), CheckKind.DAILY, NOW, 0, 1))
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(1, self.slack_texts().count(
                "ServerSentinel critical alert: human_access_fault"))

    async def test_a_failed_runtime_still_alerts_and_marks_health(self):
        """PR #271 review: while the runtime is not RUNNING (here the database
        cannot be opened, so local persistence is refused) the access faults
        are still drained, sent to Slack and marked degraded."""
        monitor = AccessFaultMonitor()
        database = FlakyDatabase(self.settings.database_path, failures=1000)
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        application = create_app(
            self.settings, database=database, monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0,
                access_faults=monitor))
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            monitor.emit(ReservationFault((Reason.UNEXPECTED_LISTENER,), CheckKind.DAILY, NOW, 1, 0))
            monitor.credential_finding(CredentialFinding.BACKUP_ELIGIBILITY_CHANGED, uuid4())
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            self.assertTrue(runtime.status.human_access_degraded)
            self.assertTrue(runtime.status.credential_finding_degraded)
            texts = self.slack_texts()
            self.assertIn("ServerSentinel critical alert: human_access_fault", texts)
            self.assertIn("ServerSentinel critical alert: credential_finding", texts)


class FindingRecoveryTests(RuntimeFixture):
    """Codex PR #271 (P2): a finding committed (with its audit record) but not
    yet notified when the process stopped is notified after the restart."""

    def setUp(self):
        super().setUp()
        # The audit retention cleanup runs on the real clock: a synthetic
        # finding dated by the fixture's fixed clock would already be expired.
        self.clock.now = datetime.now(timezone.utc).replace(microsecond=0)

    def application_with(self, monitor):
        return self.application(access_faults=monitor)

    def audit_finding(self, at, action="mark_principal_credential_inconsistent"):
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute(
                "INSERT INTO security_admin_audit_records VALUES (?, 'system', ?, 'principal', ?, ?, ?)",
                (str(uuid4()), action, str(uuid4()), (at - epoch) // timedelta(microseconds=1),
                 "succeeded" if action.startswith("mark") else "failed"))
            db.commit()

    async def cycle(self):
        monitor = AccessFaultMonitor()
        application = self.application_with(monitor)
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            return runtime.status

    def finding_texts(self):
        return self.slack_texts().count("ServerSentinel critical alert: credential_finding")

    async def test_an_unnotified_audited_finding_is_notified_once_after_restart(self):
        await self.cycle()
        self.assertEqual(self.finding_texts(), 0)
        self.audit_finding(self.clock.now - timedelta(hours=1))
        status = await self.cycle()
        self.assertEqual(self.finding_texts(), 1)
        self.assertTrue(status.credential_finding_degraded)
        # Already notified: a further restart sends nothing more, but the
        # one-day hold is restored from the finding's time (Codex PR #271 P1).
        self.clock.advance(timedelta(minutes=5))
        status = await self.cycle()
        self.assertEqual(self.finding_texts(), 1)
        self.assertTrue(status.credential_finding_degraded)

    async def test_a_pending_notification_row_is_sent_again(self):
        """Codex PR #271: a delivery the stopped process never finished."""
        await self.cycle()
        self.audit_finding(self.clock.now - timedelta(minutes=10))
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            (audit_id,) = db.execute(
                "SELECT id FROM security_admin_audit_records ORDER BY rowid DESC LIMIT 1").fetchone()
            db.execute("INSERT INTO notification_events VALUES (?, 'credential_finding', ?, 0, 'pending')",
                       (str(uuid5(EVENT_NAMESPACE, f"credential-finding-through:{audit_id}")),
                        (self.clock.now - timedelta(minutes=9)).isoformat()))
            db.commit()
        status = await self.cycle()
        self.assertEqual(self.finding_texts(), 1)
        self.assertTrue(status.credential_finding_degraded)
        await self.cycle()
        self.assertEqual(self.finding_texts(), 1)

    async def test_the_last_access_notification_restores_the_episode(self):
        """Codex PR #271: the newest fault/recovered row (by rowid) decides."""
        calls = []
        # Each later row is stamped earlier: only the insertion (rowid) order counts.
        cases = ((("human_access_fault", "sent"),), [{"delivered": True, "event_id": None, "at": None}]), \
            ((("human_access_fault", "sent"), ("human_access_recovered", "sent")), []), \
            ((("human_access_recovered", "sent"), ("human_access_fault", "pending")), "pending"), \
            ((("human_access_recovered", "pending"),), "recovery")
        await self.cycle()
        for rows, expected in cases:
            with closing(sqlite3.connect(self.settings.database_path)) as db:
                for index, (kind, delivery) in enumerate(rows):
                    at = self.clock.now - timedelta(minutes=10 + index)
                    self.last_event_id, self.last_at = str(uuid4()), at
                    db.execute("INSERT INTO notification_events VALUES (?, ?, ?, 0, ?)",
                               (self.last_event_id, kind, at.isoformat(), delivery))
                db.commit()
            calls.clear()
            with patch.object(AccessFaultMonitor, "attached", new_callable=PropertyMock,
                              return_value=object()), \
                    patch.object(AccessFaultMonitor, "restore_fault_episode",
                                 lambda monitor, **values: calls.append(values)), \
                    patch.object(AccessFaultMonitor, "restore_pending_recovery",
                                 lambda monitor, **values: calls.append({"recovery": values})), \
                    patch.object(AccessFaultMonitor, "_polled", lambda monitor: None):
                await self.cycle()
            with self.subTest(rows=rows):
                if expected == "recovery":
                    (call,) = calls
                    self.assertEqual(str(call["recovery"]["event_id"]), self.last_event_id)
                    self.assertEqual(call["recovery"]["at"], self.last_at)
                elif expected == "pending":
                    # The stored row's own ID and time, so the retry updates it.
                    (call,) = calls
                    self.assertEqual(call["delivered"], False)
                    self.assertEqual(str(call["event_id"]), self.last_event_id)
                    self.assertEqual(call["at"], self.last_at)
                else:
                    self.assertEqual(calls, expected)

    async def test_a_clock_rollback_does_not_hide_a_later_finding(self):
        """Codex PR #271: recovery compares the audit rowid, not wall times."""
        await self.cycle()
        self.audit_finding(self.clock.now - timedelta(hours=1))
        await self.cycle()
        self.assertEqual(self.finding_texts(), 1)
        # Committed later, but stamped earlier than the notification (the
        # wall clock moved back), and the process stopped before notifying.
        self.audit_finding(self.clock.now - timedelta(hours=3))
        self.clock.advance(timedelta(minutes=5))
        status = await self.cycle()
        self.assertEqual(self.finding_texts(), 2)
        self.assertTrue(status.credential_finding_degraded)

    async def test_a_reused_rowid_does_not_hide_a_new_finding(self):
        """Codex PR #271: an emptied audit table reuses rowids; the event is
        named after the record's immutable id instead."""
        await self.cycle()
        self.audit_finding(self.clock.now - timedelta(hours=1))
        await self.cycle()
        self.assertEqual(self.finding_texts(), 1)
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            db.execute("DELETE FROM security_admin_audit_records")
            db.commit()
        self.audit_finding(self.clock.now - timedelta(minutes=30))
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            (rowid,) = db.execute("SELECT MAX(rowid) FROM security_admin_audit_records").fetchone()
        self.assertEqual(rowid, 1)
        self.clock.advance(timedelta(minutes=5))
        await self.cycle()
        self.assertEqual(self.finding_texts(), 2)

    async def test_a_live_notification_is_not_repeated_after_restart(self):
        monitor = AccessFaultMonitor()
        application = self.application_with(monitor)
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await runtime.call(runtime.tick)
            self.audit_finding(self.clock.now)
            monitor.credential_finding(CredentialFinding.BACKUP_ELIGIBILITY_CHANGED, uuid4())
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
        self.assertEqual(self.finding_texts(), 1)
        self.clock.advance(timedelta(minutes=5))
        await self.cycle()
        self.assertEqual(self.finding_texts(), 1)

    async def test_an_old_finding_is_notified_but_not_held_degraded(self):
        await self.cycle()
        self.audit_finding(self.clock.now - timedelta(days=2),
                           action="detect_principal_credential_sign_count_regression")
        status = await self.cycle()
        self.assertEqual(self.finding_texts(), 1)
        self.assertFalse(status.credential_finding_degraded)

    async def test_other_audit_actions_are_ignored(self):
        await self.cycle()
        self.audit_finding(self.clock.now - timedelta(hours=1), action="authenticate_principal")
        status = await self.cycle()
        self.assertEqual(self.finding_texts(), 0)
        self.assertFalse(status.credential_finding_degraded)

    async def test_a_finding_from_a_long_stop_is_still_notified(self):
        """Codex PR #271: no lookback shorter than the audit retention."""
        await self.cycle()
        self.audit_finding(self.clock.now - timedelta(days=8))
        status = await self.cycle()
        self.assertEqual(self.finding_texts(), 1)
        self.assertFalse(status.credential_finding_degraded)
