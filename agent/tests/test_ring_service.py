"""The ring in the service loop: settings, clock trust and the loss trigger (Issue #16 PR C1).

Synthetic sessions and a temporary-filesystem ring only; no camera, encoder
or Main Server.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import unittest
from unittest import mock
from uuid import UUID

from media_capture_agent import cli
from media_capture_agent.config import ConfigurationError, Settings
from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import PRE, POST, SECOND, RingConfig, RingRefused
from media_capture_agent.ring_service import ClockTrust, RingMonitor, ring_profiles
from media_capture_agent.runtime import Agent
from media_capture_agent.storage import MediaStore
from media_capture_agent.uvc_pipeline import PipelineError
from tests import support
from media_capture_agent.health import ClockExchange
from tests.support import SOURCE, MockSession, ring_temporary_directory
from tests.test_ring import LEDGER_BYTES, AllowControls, Quota


OTHER = UUID("00000000-0000-4000-8000-000000000003")


def with_ring(value, **ring_changes):
    value = copy.deepcopy(value)
    value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0",
                        "sources": [{"source_id": str(SOURCE), "profile": "1280x720@30/MJPG"}]}
    value["ring"] = {"segment_seconds": 10, "overhead_bytes": 100, "ledger_maximum_bytes": LEDGER_BYTES,
                     "clock_holdover_seconds": 900,
                     "sources": [{"source_id": str(SOURCE), "target_bitrate": 6000,
                                  "maximum_bitrate": 12000, "expected_bitrate": 6000,
                                  "gop_frames": 60}]}
    value["ring"].update(ring_changes)
    return value


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = ring_temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = support.configuration(self.root)

    def parse(self, value):
        return Settings.parse(value, code_root=self.root / "code")

    def test_valid_ring_section(self):
        settings = self.parse(with_ring(self.base))
        ring = settings.ring
        self.assertEqual((ring.segment_seconds, ring.clock_holdover_seconds), (10, 900))
        self.assertEqual(ring.source(SOURCE).maximum_bitrate, 12000)
        (profile,) = ring_profiles(settings)
        self.assertEqual((profile.source_id, profile.maximum_bitrate, profile.expected_bitrate,
                          profile.segment_duration_us, profile.overhead_bytes),
                         (SOURCE, 12000, 6000, 10 * SECOND, 100))
        self.assertEqual(profile.segment_bytes(), 15100)

    def test_ring_is_optional(self):
        self.assertIsNone(self.parse(self.base).ring)
        self.assertEqual(ring_profiles(self.parse(self.base)), ())

    def test_refusals(self):
        def source(**changes):
            item = {"source_id": str(SOURCE), "target_bitrate": 6000, "maximum_bitrate": 12000,
                    "expected_bitrate": 6000, "gop_frames": 60}
            item.update(changes)
            return [item]

        no_capture = with_ring(self.base)
        del no_capture["capture"]
        extra_key = with_ring(self.base)
        extra_key["ring"]["mode"] = "capacity"
        cases = {
            "no capture": no_capture,
            "unknown key": extra_key,
            "other source": with_ring(self.base, sources=source(source_id=str(OTHER))),
            "two entries": with_ring(self.base, sources=source() + source()),
            "no sources": with_ring(self.base, sources=[]),
            "target above maximum": with_ring(self.base, sources=source(target_bitrate=12001)),
            "expected above maximum": with_ring(self.base, sources=source(expected_bitrate=12001)),
            "GOP does not divide": with_ring(self.base, sources=source(gop_frames=7)),
            "GOP above segment": with_ring(self.base, sources=source(gop_frames=600)),
            # PR #434 review: 60 s at 30 fps is 1800 frames; the encoder caps
            # its GOP at 1000, so 1800 must be refused here, not at start.
            "GOP above encoder limit": with_ring(self.base, segment_seconds=60,
                                                 sources=source(gop_frames=1800,
                                                                maximum_bitrate=2000)),
            "zero GOP": with_ring(self.base, sources=source(gop_frames=0)),
            "bool bitrate": with_ring(self.base, sources=source(maximum_bitrate=True)),
            "segment too long": with_ring(self.base, segment_seconds=601),
            "zero holdover": with_ring(self.base, clock_holdover_seconds=0),
            "float segment": with_ring(self.base, segment_seconds=1.0),
            "segment above write limit": with_ring(self.base, sources=source(maximum_bitrate=13100)),
        }
        for name, value in cases.items():
            with self.subTest(name), self.assertRaises(ConfigurationError):
                self.parse(value)


class ClockTrustTests(unittest.TestCase):
    def test_holdover_after_the_last_good_exchange(self):
        clock = ClockTrust(holdover_seconds=900, step_limit_seconds=5)
        self.assertFalse(clock.observe(None, 1000.0, 10.0))  # never good yet
        self.assertTrue(clock.observe((999.0, 9.0), 1000.0, 10.0))
        self.assertTrue(clock.observe(None, 1600.0, 610.0))
        self.assertTrue(clock.observe(None, 1899.0, 909.0))  # exactly the holdover
        self.assertFalse(clock.observe(None, 1899.5, 909.5))
        # Expired: only a new good exchange trusts the clock again.
        self.assertFalse(clock.observe(None, 1901.0, 911.0))
        self.assertTrue(clock.observe((1901.5, 911.5), 1902.0, 912.0))

    def test_a_wall_clock_step_or_monotonic_regression_ends_the_holdover(self):
        clock = ClockTrust(holdover_seconds=900, step_limit_seconds=5)
        clock.observe((1000.0, 10.0), 1000.0, 10.0)
        self.assertTrue(clock.observe(None, 1104.0, 110.0))   # 4 s drift: within the limit
        self.assertFalse(clock.observe(None, 1200.0, 150.0))  # 50 s step
        self.assertFalse(clock.observe(None, 1201.0, 151.0))
        clock.observe((2000.0, 200.0), 2000.0, 200.0)
        self.assertFalse(clock.observe(None, 2001.0, 199.0))

    def test_a_step_after_the_good_exchange_is_not_trusted(self):
        # PR #433 review (P1): the exchange was good, but the wall clock
        # jumped forward before this heartbeat; its time must not anchor trust.
        clock = ClockTrust(holdover_seconds=900, step_limit_seconds=5)
        self.assertFalse(clock.observe((1000.0, 10.0), 1000.0 + 3600.0 + 2.0, 12.0))
        self.assertFalse(clock.observe(None, 4603.0, 13.0))

    def test_a_sample_from_the_future_is_ignored(self):
        clock = ClockTrust(holdover_seconds=900, step_limit_seconds=5)
        self.assertFalse(clock.observe((1000.0, 20.0), 990.0, 10.0))

    def test_limits_must_be_positive(self):
        with self.assertRaises(ValueError):
            ClockTrust(holdover_seconds=0, step_limit_seconds=1)
        with self.assertRaises(ValueError):
            ClockTrust(holdover_seconds=1, step_limit_seconds=0)


class FakeRing:
    def __init__(self, *, config=None, profiles=None, tick_error=None):
        self.config, self.profiles = config, profiles or {}
        self.observed, self.ticks = [], []
        self.tick_error = tick_error

    def observe_connection(self, **kwargs):
        self.observed.append(kwargs)

    def tick(self, **kwargs):
        self.ticks.append(kwargs)
        if self.tick_error:
            raise RingRefused(self.tick_error)
        return {"state": "healthy", "reason": "protection_ready", "extra": "not reported"}

    def close(self):
        pass


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = ring_temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.settings = Settings.parse(with_ring(support.configuration(root)),
                                       code_root=root / "code")

    def heartbeat(self, monitor, **changes):
        values = dict(clock_sample=(4999.0, 99.0), authenticated=True, connected=True,
                      lost=False, utc=5000.0, monotonic=100.0)
        values.update(changes)
        utc, monotonic = values.pop("utc"), values.pop("monotonic")
        return monitor.after_heartbeat(utc=lambda: utc, monotonic=lambda: monotonic, **values)

    def test_an_unconfigured_ring_is_ticked_but_given_no_loss(self):
        ring = FakeRing()
        status = self.heartbeat(RingMonitor(ring, self.settings), connected=False)
        self.assertEqual(ring.observed, [])
        self.assertEqual(len(ring.ticks), 1)
        self.assertEqual(status, {"state": "healthy", "reason": "protection_ready",
                                  "clock_trusted": True})

    def test_a_configured_ring_sees_every_loss_as_unexpected(self):
        profiles = {profile.source_id: profile for profile in ring_profiles(self.settings)}
        ring = FakeRing(config=RingConfig("duration", 600), profiles=profiles)
        monitor = RingMonitor(ring, self.settings)
        self.heartbeat(monitor)
        self.heartbeat(monitor, connected=False, clock_sample=None, utc=5002.0, monotonic=102.0)
        self.assertEqual([(item["connected"], item["unexpected"], item["clock_trusted"],
                           item["now_us"]) for item in ring.observed],
                         [(True, True, True, 5000 * SECOND), (False, True, True, 5002 * SECOND)])

    def test_a_loss_reconnected_within_one_heartbeat_is_still_a_down_transition(self):
        # PR #433 review (P2).
        profiles = {profile.source_id: profile for profile in ring_profiles(self.settings)}
        ring = FakeRing(config=RingConfig("duration", 600), profiles=profiles)
        monitor = RingMonitor(ring, self.settings)
        self.heartbeat(monitor, lost=True)
        self.assertEqual([item["connected"] for item in ring.observed], [False, True])

    def test_a_ring_refusal_is_reported_not_raised(self):
        status = self.heartbeat(RingMonitor(FakeRing(tick_error="ledger_unavailable"),
                                            self.settings))
        self.assertEqual(status, {"state": "degraded", "reason": "ledger_unavailable",
                                  "clock_trusted": True})

    def test_profiles_that_differ_from_the_deployment_need_reconfiguration(self):
        (profile,) = ring_profiles(self.settings)
        other = type(profile)(SOURCE, 12000, 6000, 5 * SECOND, 100)
        ring = FakeRing(config=RingConfig("duration", 600), profiles={SOURCE: other})
        monitor = RingMonitor(ring, self.settings)
        self.assertTrue(monitor.reconfiguration_required)
        self.assertEqual(self.heartbeat(monitor)["reason"], "ring_reconfiguration_required")


class ClockedSession(MockSession):
    """A synthetic session whose clock exchange matches the test clock."""

    def __init__(self, now):
        super().__init__()
        self.now = now
        self.connection_losses = 0
        self.reconnect_once = False

    def exchange_clock(self):
        if self.fail:
            raise ConnectionError("synthetic outage")
        utc, monotonic = self.now[0], self.now[0] - 7000.0
        return ClockExchange(utc - 0.2, monotonic - 0.2, utc - 0.1, utc - 0.1, utc, monotonic)

    def send_heartbeat(self, heartbeat):
        if self.reconnect_once:
            # The Main restarted: the old connection is dropped and the same
            # call reconnects and sends.
            self.reconnect_once = False
            self.connection_losses += 1
        if self.fail:
            self.connection_losses += 1
        super().send_heartbeat(heartbeat)


class AgentLossTests(unittest.TestCase):
    """A real ring under the Agent loop: up then down protects T-10 .. T+10."""

    def setUp(self):
        self.temporary = ring_temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.settings = Settings.parse(with_ring(support.configuration(root)),
                                       code_root=root / "code")
        self.store = MediaStore(self.settings, space=Quota(self.settings.media_root),
                                stable_device=lambda _expected: True)
        ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=LEDGER_BYTES,
                        authority=AllowControls())
        self.ring = ring
        self.now = [7200.0]
        ring.configure(RingConfig("duration", 600), ring_profiles(self.settings),
                       now_us=int(self.now[0] * SECOND), clock_trusted=True)
        self.session = ClockedSession(self.now)
        self.agent = Agent(self.settings, self.store, session=self.session,
                           ring=RingMonitor(ring, self.settings),
                           utc=lambda: self.now[0], monotonic=lambda: self.now[0] - 7000.0)
        self.addCleanup(self.agent.close)

    def incidents(self):
        return [dict(row) for row in self.ring.db.execute(
            "SELECT reason, start, end, clock_uncertain FROM incidents").fetchall()]

    def test_up_then_down_creates_one_trusted_loss_incident(self):
        self.agent.tick()
        self.assertEqual(self.incidents(), [])
        self.now[0] += 2
        self.session.fail = True
        self.agent.tick()
        loss = int(self.now[0] * SECOND)
        self.assertEqual(self.incidents(), [{"reason": "main_connection_lost",
                                             "start": loss - PRE, "end": loss + POST,
                                             "clock_uncertain": 0}])
        self.assertTrue(self.agent.ring_status["clock_trusted"])
        # Still down: no second incident.
        self.now[0] += 2
        self.agent.tick()
        self.assertEqual(len(self.incidents()), 1)

    def test_a_restart_reconnected_inside_one_heartbeat_is_a_loss(self):
        self.agent.tick()
        self.now[0] += 2
        self.session.reconnect_once = True
        self.agent.tick()
        loss = int(self.now[0] * SECOND)
        self.assertEqual([(row["start"], row["end"]) for row in self.incidents()],
                         [(loss - PRE, loss + POST)])

    def test_a_node_that_never_connected_has_no_loss(self):
        self.session.fail = True
        self.agent.tick()
        self.now[0] += 2
        self.agent.tick()
        self.assertEqual(self.incidents(), [])

    def test_the_agent_closes_the_ring(self):
        with mock.patch.object(self.ring, "close", wraps=self.ring.close) as close:
            self.agent.close()
        close.assert_called_once()
        self.addCleanup(lambda: None)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = ring_temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.parsed = Settings.parse(with_ring(support.configuration(root)), code_root=root / "code")

    def run_cli(self, argv, **patches):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(cli.Settings, "load", return_value=self.parsed))
            media = stack.enter_context(mock.patch.object(cli, "MediaStore"))
            media.return_value.device_numbers_stale = False
            stack.enter_context(mock.patch.object(cli, "_capture_launcher", return_value=None))
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(cli, name, **value))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = cli.main(["--config", "/nonexistent", *argv])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_check_verifies_the_encoder_but_never_opens_the_ring(self):
        code, stdout, _stderr = self.run_cli(
            ["--check", "--json"], _encoder_launcher={"return_value": object()},
            _ring={"side_effect": AssertionError("opened")}, Agent={})
        self.assertEqual((code, json.loads(stdout)), (0, {"ok": True}))

    def test_missing_encoder_plugins_fail_the_check(self):
        code, stdout, _stderr = self.run_cli(
            ["--check", "--json"],
            _encoder_launcher={"side_effect": PipelineError("required GStreamer encoder "
                                                            "plugins are unavailable")},
            Agent={})
        self.assertEqual((code, json.loads(stdout)),
                         (1, {"ok": False, "reason": "capture_pipeline_unavailable"}))

    def test_an_unopenable_ring_fails_the_service_start_with_its_own_code(self):
        code, _stdout, stderr = self.run_cli(
            [], _encoder_launcher={"return_value": object()},
            _ring={"side_effect": RingRefused("ledger_root_ownership")}, Agent={})
        self.assertEqual(code, 1)
        self.assertTrue(stderr.endswith(": ring_state_unavailable\n"))
        self.assertNotIn("ledger_root_ownership", stderr)
        self.assertIn("ring_state_unavailable", cli.CHECK_REASONS)


class SessionLossCounterTests(unittest.TestCase):
    """``IngestSession.connection_losses`` counts lost sessions, not renewals."""

    def test_a_dropped_connection_counts_and_a_renewal_reconnect_does_not(self):
        from media_capture_agent.config import MainIngestEndpoint
        from media_capture_agent.ingest_session import IngestSession
        from media_capture_agent.pairing import NodeCredentialStore
        temporary = ring_temporary_directory()
        self.addCleanup(temporary.cleanup)
        runtime = Path(temporary.name) / "runtime"
        runtime.mkdir(mode=0o700)
        session = IngestSession(NodeCredentialStore(runtime), MainIngestEndpoint("127.0.0.1", 9),
                                support.NODE)
        self.assertEqual(session.connection_losses, 0)
        session._drop()  # nothing established: not a loss
        self.assertEqual(session.connection_losses, 0)
        session._connection = mock.Mock()
        session._drop(keep_exchange=True)  # the renewal's own reconnect
        self.assertEqual(session.connection_losses, 0)
        session._connection = mock.Mock()
        session._drop()
        self.assertEqual(session.connection_losses, 1)


if __name__ == "__main__":
    unittest.main()
