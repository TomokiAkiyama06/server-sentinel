"""No analytics, telemetry or crash reporting in normal and error paths.

Main and Agent cores run under a guard that refuses every outbound socket
attempt from any thread. Only the explicitly configured Slack integration may
try to reach its own endpoint, and even that attempt is refused here.
"""

from contextlib import ExitStack, closing
import errno
import io
import logging
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from uuid import UUID

from app.integrity.service import IntegrityService
from app.logging import Event, SafeJsonFormatter, SafeStreamHandler
from app.media.health.service import HealthState, RecordingHealthService
from app.notifications.service import DailySummary, NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from app.presence.delivery import NotificationAdapter
from app.presence.models import Kind, Observation, Quality
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.policy import StorageState
from app.storage.schema import APPLICATION_MIGRATIONS
from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import PRE, SECOND, RingConfig, RingRefused, SegmentProfile
from media_capture_agent.storage import MediaStore

from tests.e2e.harness import (
    AllowRingControls,
    FaultPlan,
    MixedSourceTopology,
    NetworkGuard,
    OutboundNetworkForbidden,
    SyntheticAccess,
    SyntheticClock,
    SyntheticIntegrityProbe,
    SyntheticRecorder,
    agent_settings,
    storage_reservation,
)
from tests.e2e.test_notification_fault_scenarios import endpoint
from tests.e2e.test_mock_core_harness import IntegrityMemoryPort


# Well-known analytics, telemetry and crash-reporting SDK import names.
REPORTING_MODULES = frozenset({
    "sentry_sdk", "raven", "bugsnag", "rollbar", "honeybadger", "opentelemetry",
    "ddtrace", "datadog", "newrelic", "elasticapm", "posthog", "mixpanel",
    "analytics", "segment", "amplitude", "statsd", "prometheus_client",
    "google.analytics", "firebase_admin",
})


# Every scenario module, and through it every production module it loads at
# import time (including tests.e2e.harness itself).
SCENARIO_MODULES = (
    "tests.e2e.harness",
    "tests.e2e.test_mock_core_harness",
    "tests.e2e.test_agent_ring_scenarios",
    "tests.e2e.test_agent_storage_scenarios",
    "tests.e2e.test_retention_scenarios",
    "tests.e2e.test_notification_fault_scenarios",
    "tests.e2e.test_no_telemetry_scenarios",
)

# The processes users run: the Agent CLI and runtime, and the Main launcher,
# settings and logging. The Main web entry points need the server runtime
# dependencies (FastAPI, from server/requirements.lock), checked separately below.
ENTRY_MODULES = (
    "media_capture_agent.cli",
    "media_capture_agent.runtime",
    "media_capture_agent.config",
    "media_capture_agent.storage",
    "app.deployment",
    "app.settings",
    "app.logging",
)
MAIN_WEB_ENTRY_MODULES = ("app.main", "app.__main__")
# Set by the required CI job, which runs as non-root with the hash-pinned
# server runtime dependencies installed: no entry point path may be skipped.
REQUIRE_FULL_ENTRY_POINTS = "E2E_REQUIRE_FULL_ENTRY_POINTS"

# The module-scope imports above run before any NetworkGuard exists, and a
# socket opened and closed during import leaves nothing for the guard's
# open-descriptor scan. So imports are replayed in a fresh interpreter whose
# very first statement installs a refusing, recording audit hook; only the
# standard library is loaded before it. The report itself is an exit callback
# registered before any import: atexit runs callbacks last-in first-out, so
# every shutdown flush an imported module registers (telemetry, crash reports)
# has already run under the still-active hook when the report is written.
IMPORT_BOOTSTRAP = r"""
import sys
EVENTS = %(events)r
attempts = []
def hook(event, args):
    if event in EVENTS:
        attempts.append(event)
        raise PermissionError("guarded import refused " + event)
if %(guard_first)r:
    sys.addaudithook(hook)
import atexit, importlib, json
preloaded = sorted(name for name in sys.modules
                   if name.split(".")[0] in {"app", "media_capture_agent", "tests"})
failed = []
imported = []
calls = []
def report():
    reporting = sorted(set(%(reporting)r) & set(sys.modules))
    print(json.dumps({"attempts": attempts, "failed": failed, "preloaded": preloaded,
                      "reporting": reporting, "imported": imported, "calls": calls}),
          flush=True)
atexit.register(report)
for name in %(modules)r:
    try:
        importlib.import_module(name)
    except BaseException as error:
        failed.append([name, type(error).__name__])
# Startup/validation entry points run under the same hook as the imports.
for module, function, arguments in %(calls)r:
    try:
        entry = getattr(importlib.import_module(module), function)
        value = entry() if arguments is None else entry(arguments)
    except SystemExit as exit:
        value = exit.code
    except BaseException as error:
        value = type(error).__name__
    calls.append([module, function, value])
if not %(guard_first)r:
    sys.addaudithook(hook)
imported.append(True)
"""


def require_full_entry_points():
    """Whether this run must execute every entry point path (set in required CI)."""
    import os

    return os.environ.get(REQUIRE_FULL_ENTRY_POINTS) == "1"


def guarded_import(modules, *, extra_path=None, guard_first=True, calls=()):
    import json
    import os
    import subprocess

    from tests.e2e.harness import _NETWORK_AUDIT_EVENTS

    # No deployment setting from the invoking shell reaches the entry points.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("SERVERSENTINEL_")}
    if extra_path is not None:
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(None, (str(extra_path), environment.get("PYTHONPATH"))))
    script = IMPORT_BOOTSTRAP % {
        "events": sorted(_NETWORK_AUDIT_EVENTS), "modules": list(modules),
        "reporting": sorted(REPORTING_MODULES), "guard_first": guard_first,
        "calls": [list(call) for call in calls],
    }
    completed = subprocess.run(
        [sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2],
        env=environment, capture_output=True, text=True, timeout=120, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"guarded import bootstrap failed: {completed.stderr}")
    lines = completed.stdout.splitlines()
    if not lines:
        # An exit path that skipped the report (os._exit, a fatal signal in a
        # callback) is a failure, never an empty-attempt result.
        raise AssertionError(f"guarded import wrote no report: {completed.stderr}")
    result = json.loads(lines[-1])
    if result.pop("imported") != [True]:
        raise AssertionError(f"guarded import did not finish: {completed.stderr}")
    return result


class NoTelemetryScenarios(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.faults = FaultPlan()

    def test_guard_refuses_and_records_every_outbound_entry_point(self):
        with NetworkGuard() as guard:
            for attempt in (
                lambda: socket.create_connection(("telemetry.invalid", 443), timeout=1),
                lambda: socket.getaddrinfo("telemetry.invalid", 443),
                lambda: socket.gethostbyname("telemetry.invalid"),
            ):
                with self.assertRaises(OutboundNetworkForbidden):
                    attempt()
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as udp:
                with self.assertRaises(OutboundNetworkForbidden):
                    udp.sendto(b"generated", ("192.0.2.1", 9))
                with self.assertRaises(OutboundNetworkForbidden):
                    udp.connect(("192.0.2.1", 9))
        self.assertEqual(
            [("create_connection", "telemetry.invalid"), ("getaddrinfo", "telemetry.invalid"),
             ("gethostbyname", "telemetry.invalid"), ("sendto", "192.0.2.1"),
             ("connect", "192.0.2.1")],
            guard.attempts)

    def test_guard_refuses_and_records_every_resolver_entry_point(self):
        import _socket

        originals = {(module, name): getattr(module, name)
                     for module in (socket, _socket)
                     for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                                  "gethostbyaddr", "getnameinfo")}
        with NetworkGuard() as guard:
            for module in (socket, _socket):
                for attempt in (
                    lambda: module.getaddrinfo("telemetry.invalid", 443),
                    lambda: module.gethostbyname("telemetry.invalid"),
                    lambda: module.gethostbyname_ex("telemetry.invalid"),
                    lambda: module.gethostbyaddr("192.0.2.1"),
                    lambda: module.getnameinfo(("192.0.2.1", 443), 0),
                ):
                    with self.assertRaises(OutboundNetworkForbidden):
                        attempt()
        expected = [("getaddrinfo", "telemetry.invalid"), ("gethostbyname", "telemetry.invalid"),
                    ("gethostbyname_ex", "telemetry.invalid"), ("gethostbyaddr", "192.0.2.1"),
                    ("getnameinfo", "192.0.2.1")]
        self.assertEqual(expected * 2, guard.attempts)
        # Every patch is reverted on exit.
        for (module, name), original in originals.items():
            self.assertIs(getattr(module, name), original)

    def test_guard_refuses_low_level_socket_and_captured_resolvers(self):
        import _socket
        from socket import gethostbyname_ex as captured_before_guard

        with NetworkGuard() as guard:
            with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)) as raw:
                for attempt in (
                    lambda: raw.connect(("192.0.2.1", 9)),
                    lambda: raw.connect_ex(("192.0.2.2", 9)),
                    lambda: raw.sendto(b"generated", ("192.0.2.3", 9)),
                    lambda: raw.sendmsg([b"generated"], [], 0, ("192.0.2.4", 9)),
                ):
                    with self.assertRaises(OutboundNetworkForbidden):
                        attempt()
            with self.assertRaises(OutboundNetworkForbidden):
                captured_before_guard("telemetry.invalid")
            errors = []

            def worker():
                try:
                    with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)) as other:
                        other.connect(("192.0.2.5", 9))
                except OutboundNetworkForbidden as error:
                    errors.append(error)
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join()
            self.assertEqual(1, len(errors))
        self.assertEqual(
            [("connect", "192.0.2.1"), ("connect", "192.0.2.2"), ("sendto", "192.0.2.3"),
             ("sendmsg", "192.0.2.4"), ("gethostbyname", "telemetry.invalid"),
             ("connect", "192.0.2.5")],
            guard.attempts)
        # The process-wide hook is inert once no guard is active.
        with closing(_socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)) as local:
            with self.assertRaises(OSError) as raised:
                local.connect(str(self.root / "absent.sock"))
            self.assertNotIsInstance(raised.exception, OutboundNetworkForbidden)
        self.assertEqual(6, len(guard.attempts))

    def test_guard_fails_closed_on_sockets_connected_before_it_started(self):
        import _socket

        local_a, local_b = socket.socketpair()
        self.addCleanup(local_a.close)
        self.addCleanup(local_b.close)
        with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)) as early:
            # UDP connect only records the peer; nothing is transmitted. The
            # peer is loopback so the setup never depends on a default route
            # and stays deterministic on offline runners.
            early.connect(("127.0.0.1", 9))
            guard = NetworkGuard()
            with self.assertRaises(OutboundNetworkForbidden):
                guard.__enter__()
            self.assertEqual([("preconnected", "127.0.0.1")], guard.attempts)
            # The failed entry left no patch or active guard behind.
            with self.assertRaises(OSError) as raised:
                socket.getaddrinfo("telemetry.invalid", 443,
                                   flags=getattr(socket, "AI_NUMERICHOST", 0))
            self.assertNotIsInstance(raised.exception, OutboundNetworkForbidden)
        # Local AF_UNIX pairs are not outbound and do not trip the guard.
        with NetworkGuard() as guard:
            local_a.send(b"local")
        self.assertEqual(b"local", local_b.recv(16))
        self.assertEqual([], guard.attempts)

    def test_guard_fails_closed_on_connects_still_in_progress(self):
        # A full accept queue drops the SYN, so a non-blocking connect_ex made
        # before the guard stays in SYN_SENT: getpeername() fails, yet the
        # handshake could complete later and send() carries no audit event.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(0)
        socket.create_connection(listener.getsockname()).close()
        pending = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(pending.close)
        pending.setblocking(False)
        self.assertIn(pending.connect_ex(listener.getsockname()),
                      {errno.EINPROGRESS, errno.EAGAIN})
        with self.assertRaises(OSError):
            pending.getpeername()
        guard = NetworkGuard()
        self.addCleanup(guard.__exit__, None, None, None)  # if entry wrongly succeeds
        with self.assertRaises(OutboundNetworkForbidden):
            guard.__enter__()
        self.assertEqual([("preconnected", "127.0.0.1")], guard.attempts)
        pending.close()
        # The idle listener and an unconnected TCP socket do not trip the guard.
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)):
            with NetworkGuard() as guard:
                pass
        self.assertEqual([], guard.attempts)

    def run_main_paths(self, lifecycle):
        # Hardware integrity: startup success, then a failing daily probe.
        probe = SyntheticIntegrityProbe(self.faults)
        integrity = IntegrityService(IntegrityMemoryPort(probe.inventory), probe, lambda *_: None,
                                     monotonic=self.clock.monotonic, utcnow=self.clock.utcnow)
        integrity.startup()
        self.faults.arm("integrity.collect")
        self.clock.advance(86400)
        self.assertTrue(integrity.tick())

        # Recording health success and failure with Slack left unset.
        local = []
        notifications = NotificationService(local.append)
        lifecycle.callback(notifications.close)

        def record(result, at):
            if result.state != HealthState.OK:
                notifications.record(NotificationKind.RECORDING_HEALTH_FAILURE, at=at)

        health = RecordingHealthService(SyntheticRecorder(self.topology, self.faults), record,
                                        monotonic=self.clock.monotonic, utcnow=self.clock.utcnow)
        self.assertEqual(HealthState.OK, health.startup().state)
        self.faults.arm("recording.decode")
        self.clock.advance(86400)
        self.assertEqual(HealthState.FAILED, health.tick().state)
        for kind in NotificationKind:
            if kind != NotificationKind.DAILY_SUMMARY:
                notifications.record(kind, at=self.clock.utcnow(), confirmed=True)
        self.assertEqual(DeliveryResult.DISABLED, notifications.daily(
            DailySummary(3600, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, StorageState.PRESSURE),
            at=self.clock.utcnow()))

        # Presence, critical dispatch and the owner status snapshot.
        database = Database(self.root / "main.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        presence = PresenceService(
            database, access=SyntheticAccess(), evidence=None,
            notifications=NotificationAdapter(notifications, NotificationKind),
            reservation=storage_reservation, detection=lambda: False, storage_status=lambda: False,
        )
        source = self.topology.sources[1]
        now = self.clock.utcnow()
        presence.record(Observation(Kind.SERVER_MOVEMENT, now, now, source_id=source.source_id,
                                    node_id=source.node_id, confidence=0.99,
                                    quality=Quality.SUFFICIENT, clock_trusted=True, confirmed=True))
        presence.dispatch_pending()
        self.assertTrue(presence.owner_status("owner", now=now, clock_trusted=True)
                        ["critical_paths_degraded"])
        with self.assertRaises(PermissionError):
            presence.owner_status("recordings", now=now, clock_trusted=True)

        # Error logging stays local structured output.
        stream = io.StringIO()
        handler = SafeStreamHandler(stream)
        handler.setFormatter(SafeJsonFormatter())
        logger = logging.getLogger("serversentinel.synthetic.e2e")
        logger.addHandler(handler)
        logger.propagate = False
        try:
            try:
                raise RuntimeError("synthetic startup failure")
            except RuntimeError:
                logger.exception(Event.STARTUP_FAILED)
        finally:
            logger.removeHandler(handler)
        self.assertIn('"event":"application_startup_failed"', stream.getvalue())
        self.assertNotIn("synthetic startup failure", stream.getvalue())

    def run_agent_paths(self, lifecycle):
        settings = agent_settings(self.root / "agent", UUID(int=300))
        store = MediaStore(settings, stable_device=lambda _expected: True)
        lifecycle.callback(store.close)
        ring = DiskRing(settings, store, ledger_maximum_bytes=16 * 1024 * 1024,
                        authority=AllowRingControls())
        lifecycle.callback(ring.close)
        source = UUID(int=400)
        t0 = self.clock.now_us()
        ring.configure(RingConfig("duration", 600),
                       (SegmentProfile(source, 800, 400, 60 * SECOND, 100),),
                       now_us=t0, clock_trusted=True)
        for start in range(t0 - PRE, t0, 60 * SECOND):
            ring.append(source, start, start + 60 * SECOND, b"synthetic-compressed-segment",
                        now_us=start + 60 * SECOND, clock_trusted=True)
        ring.observe_connection(authenticated=True, connected=True, unexpected=False,
                                now_us=t0, clock_trusted=True)
        self.assertIsNotNone(ring.observe_connection(authenticated=True, connected=False,
                                                     unexpected=True, now_us=t0, clock_trusted=True))
        # Error paths: profile violation and a lost mount.
        with self.assertRaises(RingRefused):
            ring.append(source, t0, t0 + SECOND, b"x", now_us=t0 + SECOND, clock_trusted=True)
        store.mounts = lambda: []
        self.assertEqual("STORAGE_HARD_STOP", ring.status(now_us=t0, clock_trusted=True)["state"])

    def test_production_imports_make_no_outbound_connection_under_guard(self):
        result = guarded_import(SCENARIO_MODULES)
        self.assertEqual([], result["preloaded"])
        self.assertEqual([], result["failed"])
        self.assertEqual([], result["attempts"])
        self.assertEqual([], result["reporting"])

    def test_production_entry_points_make_no_outbound_connection_under_guard(self):
        import json
        import os

        from tests.e2e.harness import agent_configuration

        if os.geteuid() == 0:
            # The Agent refuses root by design (config and runtime), so its
            # protected --check success path cannot run here; a required run
            # fails instead of silently covering only the refusal path.
            reason = "media_capture_agent refuses UID 0; run the E2E suite as a non-root user"
            if require_full_entry_points():
                self.fail(reason)
            self.skipTest(reason)
        # A protected synthetic Agent configuration outside the checkout, so
        # the CLI runs its real load/storage validation path.
        configuration = self.root / "agent.json"
        configuration.write_text(json.dumps(agent_configuration(self.root / "agent", UUID(int=300))),
                                 encoding="utf-8")
        os.chmod(configuration, 0o600)
        missing = str(self.root / "absent.json")
        protected = ["--config", str(configuration), "--check"]
        result = guarded_import(ENTRY_MODULES, calls=(
            ("media_capture_agent.cli", "main", ["--config", missing]),
            # Only the /dev/disk/by-uuid lookup is synthetic: the ephemeral
            # filesystem has no Owner-approved stable UUID.
            ("tests.e2e.harness", "agent_cli_with_synthetic_stable_device", protected),
            ("media_capture_agent.cli", "main", protected),
            ("app.deployment", "main", ["--config", missing, "--check"]),
        ))
        self.assertEqual([], result["preloaded"])
        self.assertEqual([], result["failed"])
        self.assertEqual([], result["attempts"])
        self.assertEqual([], result["reporting"])
        # Every entry point ran to its own validation result, not an exception:
        # missing configurations fail closed, the protected synthetic Agent
        # configuration passes --check through MediaStore and Agent construction,
        # and the real stable-device lookup refuses the unapproved synthetic UUID.
        self.assertEqual([
            ["media_capture_agent.cli", "main", 1],
            ["tests.e2e.harness", "agent_cli_with_synthetic_stable_device", 0],
            ["media_capture_agent.cli", "main", 1],
            ["app.deployment", "main", 1],
        ], result["calls"])

    def test_main_web_entry_points_make_no_outbound_connection_under_guard(self):
        import importlib.util

        result = guarded_import(MAIN_WEB_ENTRY_MODULES,
                                calls=(("app.__main__", "main", None),))
        self.assertEqual([], result["attempts"])
        self.assertEqual([], result["reporting"])
        if importlib.util.find_spec("fastapi") is not None:
            # Server runtime dependencies present: the real startup error path
            # (no data directory configured) runs under the hook.
            self.assertEqual([], result["failed"])
            self.assertEqual([["app.__main__", "main", 1]], result["calls"])
        else:
            # The required CI job installs server/requirements.lock, so a
            # missing web stack there is a failure, never partial coverage.
            self.assertFalse(require_full_entry_points(),
                             "server runtime dependencies (server/requirements.lock) are required")
            # Without the web stack (a local run) the import still runs under
            # the hook up to the missing dependency only.
            self.assertEqual({"ModuleNotFoundError"}, {kind for _name, kind in result["failed"]})
            self.assertEqual([["app.__main__", "main", "ModuleNotFoundError"]], result["calls"])

    def test_guarded_import_sees_a_connection_closed_during_import(self):
        # A module that resolves and connects once at import time, closes the
        # socket and swallows every error: nothing stays open for the in-process
        # guard's descriptor scan, so only a guard installed first can see it.
        package = self.root / "import_beacon"
        package.mkdir()
        (package / "synthetic_import_beacon.py").write_text(
            "import socket\n"
            "try:\n"
            "    socket.getaddrinfo('127.0.0.1', 9, flags=socket.AI_NUMERICHOST)\n"
            "except Exception:\n"
            "    pass\n"
            "try:\n"
            "    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as beacon:\n"
            "        beacon.connect(('127.0.0.1', 9))\n"
            "except Exception:\n"
            "    pass\n",
            encoding="ascii")
        guarded = guarded_import(["synthetic_import_beacon"], extra_path=package)
        self.assertEqual(["socket.getaddrinfo", "socket.connect"], guarded["attempts"])
        self.assertEqual([], guarded["failed"])
        # Importing first and guarding afterwards, as a module-scope import
        # before NetworkGuard does, observes nothing.
        late = guarded_import(["synthetic_import_beacon"], extra_path=package,
                              guard_first=False)
        self.assertEqual([], late["attempts"])

    def test_guarded_import_sees_a_connection_made_by_an_exit_callback(self):
        # A module that only registers a shutdown flush at import time: the
        # connection happens after the import loop, in an atexit callback that
        # swallows the refusal, so the process still exits successfully.
        package = self.root / "exit_beacon"
        package.mkdir()
        (package / "synthetic_exit_beacon.py").write_text(
            "import atexit, socket\n"
            "def flush():\n"
            "    try:\n"
            "        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as beacon:\n"
            "            beacon.connect(('127.0.0.1', 9))\n"
            "    except Exception:\n"
            "        pass\n"
            "atexit.register(flush)\n",
            encoding="ascii")
        for guard_first in (True, False):
            with self.subTest(guard_first=guard_first):
                guarded = guarded_import(["synthetic_exit_beacon"], extra_path=package,
                                         guard_first=guard_first)
                self.assertEqual(["socket.connect"], guarded["attempts"])
                self.assertEqual([], guarded["failed"])

    def test_guarded_import_fails_when_an_exit_path_skips_the_report(self):
        package = self.root / "abrupt_exit"
        package.mkdir()
        (package / "synthetic_abrupt_exit.py").write_text(
            "import atexit, os\n"
            "atexit.register(os._exit, 0)\n",
            encoding="ascii")
        with self.assertRaises(AssertionError):
            guarded_import(["synthetic_abrupt_exit"], extra_path=package)

    def run_guarded_paths(self):
        # The lifecycle stack is exited before the guard, so every service's
        # shutdown (a flush in close()) runs while egress is still refused.
        with NetworkGuard() as guard, ExitStack() as lifecycle:
            self.run_main_paths(lifecycle)
            self.run_agent_paths(lifecycle)
        return guard

    def test_shutdown_cleanups_run_while_the_guard_is_active(self):
        from unittest import mock

        for owner in (NotificationService, MediaStore, DiskRing):
            with self.subTest(owner=owner.__name__):
                original = owner.close

                def flushing_close(instance, _original=original):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as beacon:
                            beacon.connect(("127.0.0.1", 9))
                    except Exception:
                        pass  # a flush that swallows the refusal still shows up
                    _original(instance)

                self.setUp()
                with mock.patch.object(owner, "close", flushing_close):
                    guard = self.run_guarded_paths()
                self.assertIn(("connect", "127.0.0.1"), guard.attempts)

    def test_normal_and_error_paths_make_no_outbound_connection(self):
        import atexit

        # A shutdown flush registered while the paths run would execute after
        # the guard is gone, so the paths must leave no new exit callback.
        registered = atexit._ncallbacks()
        guard = self.run_guarded_paths()
        self.assertEqual(registered, atexit._ncallbacks())
        self.assertEqual([], guard.attempts)
        self.assertEqual(set(), REPORTING_MODULES & set(sys.modules))

    def test_opt_in_slack_is_the_only_destination_and_is_not_telemetry(self):
        with NetworkGuard() as guard, ExitStack() as lifecycle:
            local = []
            service = NotificationService(local.append, SlackDelivery(endpoint(), timeout_seconds=1))
            lifecycle.callback(service.close)
            self.assertEqual(DeliveryResult.PENDING, service.record(
                NotificationKind.RECORDING_HEALTH_FAILURE, at=self.clock.utcnow()))
            while service.pending_count:
                self.assertTrue(service._worker.ready.wait(5))
                service.poll()
        self.assertEqual(DeliveryResult.FAILED, service.last_delivery)
        self.assertEqual(["pending", "failed"], [event.delivery.value for event in local])
        self.assertTrue(guard.attempts)
        self.assertEqual({"hooks.slack.com"}, {host for _name, host in guard.attempts})


if __name__ == "__main__":
    unittest.main()
