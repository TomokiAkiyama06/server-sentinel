"""Issue #426 (Owner decision 2026-11-19): capture-node credential expiry notices.

Generated clocks and expiries, synthetic node views, an in-memory sink,
disposable SQLite files, a generated test CA and an intercepted Slack
transport only. No real host, node, credential or network is used.
"""
from contextlib import closing
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.cameras.remote_agent.pairing import active_credential_expiries_on
from app.monitoring.capture_nodes import (
    CREDENTIAL_CRITICAL_SECONDS, CREDENTIAL_NOTICE_KINDS, CREDENTIAL_WARNING_SECONDS,
    HOURLY_LIMIT, NODE_NOTICE_KINDS, CaptureNodeHealthMonitor, notice_id,
)
from app.notifications.service import (
    ATTENTION_KINDS, IMMEDIATE_KINDS, RECOVERY_KINDS, NotificationKind,
)

from tests.test_capture_mtls import CaptureTlsHarness, Owner
from tests.test_capture_node_notices import AT, MonitorFixture, Provider, STORAGE
from tests.test_monitoring_runtime import RuntimeFixture


WARNING = NotificationKind.CAPTURE_CREDENTIAL_WARNING
CRITICAL = NotificationKind.CAPTURE_CREDENTIAL_CRITICAL
RECOVERED = NotificationKind.CAPTURE_CREDENTIAL_RECOVERED
DAY = 24 * 3600.0


def empty_csr(key):
    """The renewal CSR an Agent sends: empty subject, no extension."""
    return (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


class ExpiryProvider(Provider):
    def __init__(self):
        super().__init__()
        # Issue #426: {node: not_after} of the active credentials (None:
        # the ledger could not be read).
        self.expiries = {}

    def __call__(self):
        return self.state, tuple(self.nodes.values()), self.expected, self.expiries


class ExpiryFixture(MonitorFixture):
    def setUp(self):
        super().setUp()
        self.provider = ExpiryProvider()
        self.monitor = CaptureNodeHealthMonitor(self.provider)
        self.monitor.restore_credential_notices(())

    def expires_in(self, seconds, node=None, at=AT):
        self.provider.expiries[node or self.node] = at.timestamp() + seconds

    def credential_kinds(self):
        return [kind for kind in self.kinds() if kind in {k.value for k in CREDENTIAL_NOTICE_KINDS}]


class ExpiryThresholdTests(ExpiryFixture, unittest.TestCase):

    def test_the_owner_decision_is_fourteen_and_three_days(self):
        self.assertEqual(CREDENTIAL_WARNING_SECONDS, 14 * DAY)
        self.assertEqual(CREDENTIAL_CRITICAL_SECONDS, 3 * DAY)

    def test_more_than_fourteen_days_left_is_not_notified(self):
        self.expires_in(14 * DAY + 1)
        status = self.drain()
        self.assertEqual(self.kinds(), [])
        self.assertEqual(status.expiring_credentials, 0)

    def test_exactly_fourteen_days_left_is_one_warning(self):
        self.expires_in(14 * DAY)
        status = self.drain()
        self.assertEqual(self.kinds(), [WARNING.value])
        self.assertEqual(status.expiring_credentials, 1)
        for hours in (1, 2, 24):
            self.advance(3600)
            self.drain(AT + timedelta(hours=hours))
        self.assertEqual(self.kinds(), [WARNING.value])

    def test_three_days_and_one_second_left_is_still_only_the_warning(self):
        self.expires_in(3 * DAY + 1)
        self.drain()
        self.assertEqual(self.kinds(), [WARNING.value])

    def test_exactly_three_days_left_escalates_to_one_critical(self):
        self.expires_in(14 * DAY)
        self.drain()
        later = AT + timedelta(days=11)
        self.advance(11 * DAY)
        self.drain(later - timedelta(seconds=1))
        self.assertEqual(self.kinds(), [WARNING.value])
        self.drain(later)
        self.assertEqual(sorted(self.kinds()), sorted([WARNING.value, CRITICAL.value]))
        self.advance(3600)
        self.drain(later + timedelta(days=4))  # expired: still the one critical
        self.assertEqual(len(self.kinds()), 2)

    def test_a_node_first_seen_inside_three_days_sends_only_the_critical(self):
        self.expires_in(3 * DAY)
        self.drain()
        self.assertEqual(self.kinds(), [CRITICAL.value])

    def test_an_expired_active_credential_is_critical(self):
        self.expires_in(-DAY)
        status = self.drain()
        self.assertEqual(self.kinds(), [CRITICAL.value])
        self.assertEqual(status.expiring_credentials, 1)

    def test_texts_are_fixed_and_value_free(self):
        self.expires_in(10 * DAY)
        self.drain()
        self.advance(3600)
        self.drain(AT + timedelta(days=8))
        self.provider.expiries[self.node] = (AT + timedelta(days=400)).timestamp()
        self.advance(3600)
        self.drain(AT + timedelta(days=8, hours=1))
        texts = self.texts()
        self.assertEqual(texts, [
            "ServerSentinel attention notice: capture_credential_warning",
            "ServerSentinel critical alert: capture_credential_critical",
            "ServerSentinel recovery notice: capture_credential_recovered",
        ])
        self.assertNotIn(str(self.node), "".join(texts))

    def test_the_kinds_are_immediate_with_their_severity(self):
        self.assertTrue({WARNING, CRITICAL, RECOVERED} <= IMMEDIATE_KINDS)
        self.assertIn(WARNING, ATTENTION_KINDS)
        self.assertNotIn(CRITICAL, ATTENTION_KINDS | RECOVERY_KINDS)
        self.assertIn(RECOVERED, RECOVERY_KINDS)
        # Re-seed the per-node hourly cap after a restart.
        self.assertTrue(set(CREDENTIAL_NOTICE_KINDS) <= set(NODE_NOTICE_KINDS))


class ExpiryRecoveryTests(ExpiryFixture, unittest.TestCase):

    def renew(self, at):
        self.provider.expiries[self.node] = (at + timedelta(days=397)).timestamp()

    def test_a_renewal_after_a_warning_sends_one_recovery(self):
        self.expires_in(13 * DAY)
        self.drain()
        later = AT + timedelta(days=1)
        self.renew(later)
        self.advance(3600)
        status = self.drain(later)
        self.assertEqual(sorted(self.kinds()), sorted([WARNING.value, RECOVERED.value]))
        self.assertEqual(status.expiring_credentials, 0)
        for hours in (1, 2, 48):
            self.advance(3600)
            self.drain(later + timedelta(hours=hours))
        self.assertEqual(len(self.kinds()), 2)

    def test_a_renewal_after_a_critical_sends_one_recovery(self):
        self.expires_in(2 * DAY)
        self.drain()
        self.renew(AT)
        self.advance(60)
        self.drain()
        self.assertEqual(sorted(self.kinds()), sorted([CRITICAL.value, RECOVERED.value]))

    def test_nothing_sent_means_no_recovery(self):
        self.expires_in(20 * DAY)
        self.drain()
        self.renew(AT)
        self.advance(60)
        self.drain()
        self.assertEqual(self.kinds(), [])

    def test_a_held_warning_renewed_before_it_was_sent_is_dropped(self):
        for index in range(HOURLY_LIMIT):
            self.monitor._window(self.node, self.clock.value).append(self.clock.value)
        self.expires_in(10 * DAY)
        status = self.drain()
        self.assertEqual(status.held_notices, 1)
        self.renew(AT)
        self.advance(3600)
        status = self.drain(AT + timedelta(hours=1))
        self.assertEqual((self.kinds(), status.held_notices), ([], 0))

    def test_a_new_expiry_window_after_a_recovery_is_a_new_episode(self):
        self.expires_in(10 * DAY)
        self.drain()
        self.renew(AT)
        self.advance(3600)
        self.drain()
        # The renewed credential approaches its own expiry a year later.
        later = AT + timedelta(days=397 - 14)
        self.advance(3600)
        self.drain(later)
        self.assertEqual(sorted(self.kinds()),
                         sorted([WARNING.value, RECOVERED.value, WARNING.value]))

    def test_a_revoked_or_inactive_node_is_dropped_without_a_notice(self):
        self.expires_in(10 * DAY)
        self.drain()
        other = uuid4()
        for index in range(HOURLY_LIMIT):
            self.monitor._window(other, self.clock.value).append(self.clock.value)
        self.expires_in(10 * DAY, node=other)
        status = self.drain()
        self.assertEqual(status.held_notices, 1)
        # Both leave the ledger's active set (revoked, or superseded).
        self.provider.expiries = {}
        self.advance(2 * 3600)
        status = self.drain(AT + timedelta(hours=2))
        self.assertEqual((self.kinds(), status.held_notices), ([WARNING.value], 0))
        self.assertEqual(status.expiring_credentials, 0)
        self.assertEqual(self.monitor._credential_sent, {})

    def test_an_unreadable_ledger_pauses_and_keeps_the_state(self):
        self.expires_in(10 * DAY)
        self.drain()
        self.provider.expiries = None
        self.advance(3600)
        self.drain(AT + timedelta(days=9))
        self.assertEqual(self.kinds(), [WARNING.value])
        # Readable again after a renewal: the recovery still follows.
        self.provider.expiries = {self.node: (AT + timedelta(days=400)).timestamp()}
        self.advance(3600)
        self.drain(AT + timedelta(days=9))
        self.assertEqual(sorted(self.kinds()), sorted([WARNING.value, RECOVERED.value]))

    def test_a_node_without_expiries_in_the_provider_is_not_evaluated(self):
        # A three-element provider (no credential expiry) changes nothing.
        provider = Provider()
        monitor = CaptureNodeHealthMonitor(provider)
        monitor.restore_credential_notices(())
        monitor.drain(self.service, at=AT, monotonic=self.clock.value)
        self.assertEqual(self.kinds(), [])


class ExpiryCapTests(ExpiryFixture, unittest.TestCase):

    def test_credential_notices_share_the_node_cap(self):
        self.provider.set(self.node, "degraded", "storage_unavailable")
        for index in range(HOURLY_LIMIT - 2):
            self.drain(AT + timedelta(seconds=index))
            self.provider.set(self.node, "online")
            self.drain(AT + timedelta(seconds=index))
            self.provider.set(self.node, "degraded", "storage_unavailable")
            self.advance(1)
        self.drain(AT + timedelta(seconds=HOURLY_LIMIT))
        self.assertEqual(self.kinds(), [STORAGE.value] * (HOURLY_LIMIT - 1))
        self.provider.set(self.node, "online")
        self.expires_in(10 * DAY)
        self.drain()
        self.assertEqual(self.kinds().count(WARNING.value), 1)
        # The cap is full now: a further storage failure is held, and so is
        # the critical one.
        self.provider.set(self.node, "degraded", "storage_unavailable")
        self.expires_in(2 * DAY)
        status = self.drain()
        self.assertEqual(status.held_notices, 2)
        self.assertEqual(len(self.kinds()), HOURLY_LIMIT)
        # Another node is not delayed by this one.
        other = uuid4()
        self.expires_in(10 * DAY, node=other)
        self.drain()
        self.assertEqual(self.kinds().count(WARNING.value), 2)
        self.advance(3600)
        self.drain()
        self.assertIn(CRITICAL.value, self.kinds())

    def test_a_held_warning_is_replaced_by_the_critical(self):
        for index in range(HOURLY_LIMIT):
            self.monitor._window(self.node, self.clock.value).append(self.clock.value)
        self.expires_in(10 * DAY)
        self.drain()
        self.expires_in(2 * DAY)
        self.drain()
        self.advance(3600)
        self.drain()
        self.assertEqual(self.credential_kinds(), [CRITICAL.value])

    def test_restored_credential_rows_count_for_the_cap(self):
        rows = []
        for index in range(HOURLY_LIMIT):
            at = AT - timedelta(minutes=10 + index)
            rows.append((notice_id(WARNING, self.node, at), WARNING, at, 600.0 + index))
        self.monitor.restore_window(rows, monotonic=self.clock.value)
        self.expires_in(10 * DAY)
        status = self.drain()
        self.assertEqual((self.kinds(), status.held_notices), ([], 1))

    def test_a_full_queue_keeps_the_notice_owed(self):
        from unittest import mock
        self.expires_in(10 * DAY)
        with mock.patch.object(self.service, "can_accept", return_value=False):
            status = self.drain()
        self.assertEqual((self.kinds(), status.held_notices), ([], 1))
        self.drain()
        self.assertEqual(self.kinds(), [WARNING.value])


class ExpiryRestartTests(ExpiryFixture, unittest.TestCase):

    def restarted(self):
        """A new monitor seeded from this sink's credential rows, as a restart does."""
        rows = [(event.event_id, event.kind, event.at) for event in self.sink.rows.values()
                if event.kind in CREDENTIAL_NOTICE_KINDS]
        monitor = CaptureNodeHealthMonitor(self.provider)
        monitor.restore_credential_notices(rows)
        return monitor

    def drain_with(self, monitor, at=AT):
        status = monitor.drain(self.service, at=at, monotonic=self.clock.value)
        self.service.poll()
        return status

    def test_nothing_is_evaluated_before_the_rows_are_restored(self):
        monitor = CaptureNodeHealthMonitor(self.provider)
        self.assertFalse(monitor.credential_notices_restored)
        self.expires_in(10 * DAY)
        self.drain_with(monitor)
        self.assertEqual(self.kinds(), [])
        monitor.restore_credential_notices(())
        self.assertTrue(monitor.credential_notices_restored)
        self.drain_with(monitor)
        self.assertEqual(self.kinds(), [WARNING.value])

    def test_a_restart_does_not_repeat_a_warning_and_still_recovers(self):
        self.expires_in(10 * DAY)
        self.drain()
        monitor = self.restarted()
        self.advance(3600)
        self.drain_with(monitor, AT + timedelta(hours=1))
        self.assertEqual(self.kinds(), [WARNING.value])
        # The critical still follows, once.
        self.drain_with(monitor, AT + timedelta(days=7))
        self.assertEqual(sorted(self.kinds()), sorted([WARNING.value, CRITICAL.value]))
        monitor = self.restarted()
        self.drain_with(monitor, AT + timedelta(days=7, hours=1))
        self.assertEqual(len(self.kinds()), 2)
        # Renewed while the Main was stopped: one recovery after the start.
        self.provider.expiries[self.node] = (AT + timedelta(days=400)).timestamp()
        monitor = self.restarted()
        self.advance(3600)
        self.drain_with(monitor, AT + timedelta(days=8))
        self.drain_with(monitor, AT + timedelta(days=8, hours=1))
        self.assertEqual(sorted(self.kinds()),
                         sorted([WARNING.value, CRITICAL.value, RECOVERED.value]))
        # The recovery closed it: a further restart sends nothing.
        monitor = self.restarted()
        self.drain_with(monitor, AT + timedelta(days=9))
        self.assertEqual(len(self.kinds()), 3)

    def test_a_node_that_left_the_active_set_is_not_seeded_again(self):
        self.expires_in(10 * DAY)
        self.drain()
        monitor = self.restarted()
        self.drain_with(monitor)
        # Revoked, then paired again under the same UUID near expiry: its
        # earlier rows do not suppress the new credential's warning.
        self.provider.expiries = {}
        self.drain_with(monitor)
        self.expires_in(10 * DAY, at=AT + timedelta(days=1))
        self.advance(3600)
        self.drain_with(monitor, AT + timedelta(days=1))
        self.assertEqual(self.kinds(), [WARNING.value, WARNING.value])

    def test_rows_of_another_node_do_not_seed_this_one(self):
        other = uuid4()
        self.expires_in(10 * DAY, node=other)
        self.drain()
        self.provider.expiries = {}
        monitor = self.restarted()
        self.expires_in(10 * DAY)
        self.drain_with(monitor)
        self.assertEqual(self.kinds(), [WARNING.value, WARNING.value])

    def test_a_restore_is_given_once_and_validated(self):
        monitor = CaptureNodeHealthMonitor(self.provider)
        with self.assertRaises(ValueError):
            monitor.restore_credential_notices([(uuid4(), STORAGE, AT)])
        with self.assertRaises(ValueError):
            monitor.restore_credential_notices([(uuid4(), WARNING, AT.replace(tzinfo=None))])
        monitor.restore_credential_notices(())
        at = AT - timedelta(days=1)
        monitor.restore_credential_notices([(notice_id(WARNING, self.node, at), WARNING, at)])
        self.expires_in(10 * DAY)
        self.drain_with(monitor)
        self.assertEqual(self.kinds(), [WARNING.value])

    def test_an_invalid_expiry_is_refused(self):
        self.provider.expiries = {self.node: float("nan")}
        with self.assertRaises(ValueError):
            self.monitor.drain(self.service, at=AT, monotonic=self.clock.value)


class ActiveCredentialExpiryLedgerTests(CaptureTlsHarness):
    """The expiry Main knows for each active node's current credential."""

    def read(self):
        with closing(self.database.connect()) as connection:
            return active_credential_expiries_on(connection)

    def test_only_active_credentials_with_their_current_expiry(self):
        first, issued, _, _ = self._paired_node("a", validity=timedelta(days=20))
        second = self._paired_node("b")[0].node_id
        pending = self._paired_node("c", activate=False)[0].node_id
        expiries = self.read()
        self.assertEqual(set(expiries), {first.node_id, second})
        self.assertAlmostEqual(expiries[first.node_id], issued.not_after.timestamp(), delta=1)
        self.ledger.revoke(Owner(), "owner", node_id=second)
        self.assertEqual(set(self.read()), {first.node_id})
        self.assertNotIn(pending, self.read())

    def test_a_staged_renewal_counts_only_once_promoted(self):
        claim, issued, _, _ = self._paired_node("a", validity=timedelta(days=20))
        key = ec.generate_private_key(ec.SECP256R1())
        renewed = self.authority.issue_renewal_certificate(
            claim.node_id, empty_csr(key), validity=timedelta(days=200))
        self.ledger.stage_renewal(
            node_id=claim.node_id, current_public_key_digest=issued.public_key_digest,
            current_credential_digest=issued.credential_digest,
            public_key_digest=renewed.public_key_digest,
            credential_serial_digest=renewed.credential_digest,
            not_after=renewed.not_after.timestamp(), certificate_pem=renewed.certificate_pem)
        self.assertAlmostEqual(self.read()[claim.node_id], issued.not_after.timestamp(), delta=1)
        # The Agent presents the renewed certificate: promoted.
        self.assertTrue(self.ledger.admits(node_id=claim.node_id,
                                           public_key_digest=renewed.public_key_digest,
                                           credential_serial_digest=renewed.credential_digest))
        self.assertAlmostEqual(self.read()[claim.node_id], renewed.not_after.timestamp(),
                               delta=1)


class ExpiryRuntimeTests(RuntimeFixture):
    """Through the monitoring runtime: delivery, restore on start, restart."""

    def app(self):
        from tests.test_recording import SyntheticValidator
        from app.main import create_app
        from app.monitoring.runtime import MonitoringDependencies
        values = dict(
            integrity_probe=self.probe, slack_opener=self.transport, utcnow=self.clock.utcnow,
            monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0,
            segment_validator=SyntheticValidator())
        return create_app(self.settings, monitoring=self.configuration(),
                          monitoring_dependencies=MonitoringDependencies(**values),
                          capture_ingest_unavailable=True)

    async def run_once(self, expiries):
        application = self.app()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            monitor = runtime.dependencies.capture_nodes
            self.assertFalse(monitor.credential_notices_restored)
            monitor._provider = lambda: ("running", (), frozenset(expiries), expiries)
            self.clock.advance(timedelta(seconds=60))
            # The first running tick restores the stored credential rows,
            # then evaluates the expiry.
            await runtime.call(runtime.tick)
            self.assertTrue(monitor.credential_notices_restored)
            await self.settle(runtime)

    async def test_a_warning_is_sent_once_across_a_restart_and_recovers_once(self):
        node = uuid4()
        now = self.clock.utcnow()
        await self.run_once({node: (now + timedelta(days=10)).timestamp()})
        await self.run_once({node: (now + timedelta(days=10)).timestamp()})
        await self.run_once({node: (now + timedelta(days=400)).timestamp()})
        await self.run_once({node: (now + timedelta(days=400)).timestamp()})
        texts = [text for text in self.slack_texts() if "capture_credential" in text]
        self.assertEqual(texts, [
            "ServerSentinel attention notice: capture_credential_warning",
            "ServerSentinel recovery notice: capture_credential_recovered",
        ])
        kinds = [kind for kind, _delivery in self.events()]
        self.assertEqual(kinds.count(WARNING.value), 1)
        self.assertEqual(kinds.count(RECOVERED.value), 1)

    async def test_the_daily_summary_counts_the_critical(self):
        node = uuid4()
        application = self.app()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            before = await runtime.call(runtime._summary, self.clock.utcnow())
            now = self.clock.utcnow()
            runtime.dependencies.capture_nodes._provider = lambda: (
                "running", (), frozenset({node}), {node: (now + timedelta(days=1)).timestamp()})
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            after = await runtime.call(runtime._summary, self.clock.utcnow())
        self.assertEqual(after.critical_count, before.critical_count + 1)
        self.assertIn("ServerSentinel critical alert: capture_credential_critical",
                      self.slack_texts())


class ExpiryEndToEndTests(RuntimeFixture):
    """The composition root's provider reads the expiry from the pinned ledger."""

    async def test_a_paired_node_near_expiry_is_warned_and_a_revoked_one_is_not(self):
        import asyncio
        import socket
        from app.cameras.remote_agent.ingest_config import (
            CaptureIngestLimits, CaptureIngestMaterial, IngestListenerConfig,
        )
        from app.main import create_app
        from app.monitoring.runtime import MonitoringDependencies
        from tests.test_recording import SyntheticValidator
        harness = CaptureTlsHarness("setUp")
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        node = harness._paired_node("a", validity=timedelta(days=10))[0].node_id
        revoked = harness._paired_node("b", validity=timedelta(days=2))[0].node_id
        harness.ledger.revoke(Owner(), "owner", node_id=revoked)
        with socket.create_server(("127.0.0.1", 0)) as probe:
            port = probe.getsockname()[1]
        material = CaptureIngestMaterial(
            IngestListenerConfig("127.0.0.1", port, "127.0.0.1", 8000),
            CaptureIngestLimits(idle_timeout_seconds=5), harness.context, harness.deployment)
        # The ledger's expiry is wall-clock; the runtime's clock follows it.
        self.clock.now = datetime.now(timezone.utc)
        values = dict(
            integrity_probe=self.probe, slack_opener=self.transport, utcnow=self.clock.utcnow,
            monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0,
            segment_validator=SyntheticValidator())
        application = create_app(self.settings, database=harness.database,
                                 monitoring=self.configuration(),
                                 monitoring_dependencies=MonitoringDependencies(**values),
                                 capture_ingest=material)
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            for _ in range(250):
                if application.state.capture_ingest_state == "running":
                    break
                await asyncio.sleep(0.02)
            self.assertEqual(application.state.capture_ingest_state, "running")
            await runtime.call(runtime.tick)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
        texts = [text for text in self.slack_texts() if "capture_credential" in text]
        self.assertEqual(texts, ["ServerSentinel attention notice: capture_credential_warning"])
        self.assertNotIn(str(node), "".join(self.slack_texts()))


if __name__ == "__main__":
    unittest.main()
