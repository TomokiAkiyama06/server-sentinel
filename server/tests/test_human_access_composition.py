"""Issue #10: the ``human_access`` deployment key and the production composition.

Synthetic only: invented ``.invalid`` / documentation values, synthetic
``/proc/net`` rows and Serve status, a temporary SQLite database, a synthetic
Web build and small generated stand-in executables for the Tailscale CLI. No
real ``tailscale``, tailscaled, socket, browser or authenticator is involved,
and nothing reads the host's ``/proc/net``.
"""

import asyncio
from dataclasses import replace
from uuid import uuid4
import json
import logging
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from app.auth.access_config import (
    ISOLATION_MODES, SERVE_STATUS_ARGUMENTS, HumanAccessDeployment, HumanAccessRefused,
    parse_human_access,
)
from app.auth.composition import (
    MAX_PROC_NET_BYTES, ServeStatusCommand, build_human_access, read_proc_net, reservation_config,
)
from app.auth.human_surface import HumanAccess, HumanAccessUnavailable, SHELL_PATH
from app.auth.reservation import (
    IsolationMode, ProcNetListeners, Reason, ReservationConfig, ReservationEnumerationError,
    ServeStatusRoutes,
)
from app.auth.session_binding import SessionBindingKey
from app.deployment import _tailscale_executable, main as deployment_main
from app.logging import Event
from app.main import ClosedHumanSurface, create_app
from app.monitoring.access import AccessFaultMonitor
from app.monitoring.runtime import MonitoringDependencies
from app.settings import ConfigurationError, Settings
from app.storage.database import Database
from app.storage.policy import StorageLimits

from tests.test_hostname_reservation import HOST, V4, V6, Files, Owners, Resolver, Status
from tests import test_release_web_assets as web_setting
from tests.test_monitoring_runtime import STORAGE_LIMITS, RuntimeFixture, SyntheticValidator
from tests.web_asset_fakes import write_build


SECTION = {
    "enabled": True,
    "hostname": HOST,
    "reserved_addresses": [str(V4), str(V6)],
    "isolation": "dedicated_network_identity",
    "tailscale_executable": "/usr/bin/tailscale",
}
LOOPBACK = ("127.0.0.1", 40000)
UPSTREAM = ("127.0.0.1", 8080)


def section(**changes):
    value = dict(SECTION)
    for key, item in changes.items():
        if item is ...:
            value.pop(key, None)
        else:
            value[key] = item
    return value


async def get(application, path, *, host=HOST):
    messages = []
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
        "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "", "client": LOOPBACK, "server": UPSTREAM,
        "headers": [(b"host", host.encode()),
                    (b"tailscale-user-login", b"synthetic-room-account@example.invalid")],
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await application(scope, receive, send)
    return messages


class SectionParsingTests(unittest.TestCase):
    def test_minimal_section_takes_the_documented_defaults(self):
        parsed = parse_human_access(section())
        self.assertIs(parsed.enabled, True)
        self.assertEqual(parsed.hostname, HOST)
        self.assertEqual(parsed.port, 443)
        self.assertEqual(parsed.reserved_addresses, frozenset({V4, V6}))
        self.assertEqual(parsed.isolation, "dedicated_network_identity")
        self.assertEqual(parsed.tailscale_executable, Path("/usr/bin/tailscale"))
        self.assertEqual(parsed.proxy_listeners, frozenset())
        self.assertIsNone(parsed.proxy_owner)
        self.assertIs(parsed.require_device_bound, False)

    def test_both_isolation_modes_and_null_are_accepted(self):
        self.assertEqual(set(ISOLATION_MODES), {mode.value for mode in IsolationMode})
        for mode in (*ISOLATION_MODES, None):
            with self.subTest(mode=mode):
                self.assertEqual(parse_human_access(section(isolation=mode)).isolation, mode)

    def test_full_section(self):
        parsed = parse_human_access(section(
            port=8443, proxy_listeners=[str(V4)],
            proxy_owner={"unit": "tailscaled.service", "uid": 0}, require_device_bound=True,
            enabled=False))
        self.assertIs(parsed.enabled, False)
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.proxy_listeners, frozenset({V4}))
        self.assertEqual((parsed.proxy_owner.unit, parsed.proxy_owner.uid), ("tailscaled.service", 0))
        self.assertIs(parsed.require_device_bound, True)

    def test_invalid_sections_are_refused_without_values(self):
        cases = {
            "not an object": ["enabled"],
            "unknown key": section(extra=1),
            "missing enabled": section(enabled=...),
            "missing hostname": section(hostname=...),
            "missing addresses": section(reserved_addresses=...),
            "missing isolation": section(isolation=...),
            "missing executable": section(tailscale_executable=...),
            "enabled not bool": section(enabled=1),
            "upper-case hostname": section(hostname=HOST.upper()),
            "trailing dot": section(hostname=HOST + "."),
            "ip hostname": section(hostname="100.64.0.10"),
            "hostname with port": section(hostname=HOST + ":443"),
            "port zero": section(port=0),
            "port bool": section(port=True),
            "port text": section(port="443"),
            "unknown isolation": section(isolation="shared_host"),
            "no addresses": section(reserved_addresses=[]),
            "address not list": section(reserved_addresses=str(V4)),
            "duplicate address": section(reserved_addresses=[str(V4), str(V4)]),
            "loopback address": section(reserved_addresses=["127.0.0.1"]),
            "unspecified address": section(reserved_addresses=["0.0.0.0"]),
            "mapped address": section(reserved_addresses=["::ffff:100.64.0.10"]),
            "zone id": section(reserved_addresses=["fe80::1%eth0"]),
            "address not text": section(reserved_addresses=[1]),
            "too many addresses": section(reserved_addresses=[f"100.64.0.{n}" for n in range(1, 18)]),
            "proxy not reserved": section(proxy_listeners=["100.64.0.99"],
                                          proxy_owner={"unit": "tailscaled.service", "uid": 0}),
            "proxy without owner": section(proxy_listeners=[str(V4)]),
            "owner without proxy": section(proxy_owner={"unit": "tailscaled.service", "uid": 0}),
            "scope owner": section(proxy_listeners=[str(V4)],
                                   proxy_owner={"unit": "run-x.scope", "uid": 0}),
            "owner uid": section(proxy_listeners=[str(V4)],
                                 proxy_owner={"unit": "tailscaled.service", "uid": -1}),
            "owner extra key": section(proxy_listeners=[str(V4)],
                                       proxy_owner={"unit": "tailscaled.service", "uid": 0, "x": 1}),
            "relative executable": section(tailscale_executable="usr/bin/tailscale"),
            "dotdot executable": section(tailscale_executable="/usr/../usr/bin/tailscale"),
            "unnormalized executable": section(tailscale_executable="/usr/bin//tailscale"),
            "root executable": section(tailscale_executable="/"),
            "nul executable": section(tailscale_executable="/usr/bin/tail\0scale"),
            "device bound text": section(require_device_bound="false"),
        }
        for name, value in cases.items():
            with self.subTest(name), self.assertRaises(HumanAccessRefused) as refused:
                parse_human_access(value)
            self.assertEqual(refused.exception.reason, "setting")
            self.assertIsInstance(refused.exception, ConfigurationError)
            for secret in (HOST, str(V4), "tailscale", "100.64"):
                self.assertNotIn(secret, str(refused.exception))

    def test_repr_keeps_private_values_out(self):
        text = repr(parse_human_access(section(proxy_listeners=[str(V4)],
                                               proxy_owner={"unit": "tailscaled.service", "uid": 0})))
        for secret in (HOST, str(V4), str(V6), "tailscale"):
            self.assertNotIn(secret, text)

    def test_reservation_config_follows_the_section(self):
        settings = Settings(Path(tempfile.gettempdir()), human_port=880)
        parsed = parse_human_access(section(
            isolation="single_purpose_node", proxy_listeners=[str(V6)],
            proxy_owner={"unit": "tailscaled.service", "uid": 0}))
        config = reservation_config(parsed, settings.human_host, settings.human_port)
        self.assertEqual(config.isolation, IsolationMode.SINGLE_PURPOSE_NODE)
        self.assertEqual(config.upstream, "http://127.0.0.1:880")
        self.assertEqual({item.address for item in config.proxy_listeners}, {V6})
        self.assertEqual({item.port for item in config.proxy_listeners}, {443})
        self.assertEqual(config.proxy_owner.unit, "tailscaled.service")
        self.assertIsNone(reservation_config(parse_human_access(section(isolation=None)),
                                             "127.0.0.1", 880).isolation)
        # Unset upstream (not loaded through a deployment): refused, value-free.
        with self.assertRaises(HumanAccessRefused):
            parsed.reservation_config()


class DeploymentKeyTests(unittest.TestCase):
    """The key in ``Deployment.load`` and the release's own ``--check``."""

    # The synthetic installation, runtime tree and loaders of the Web build
    # setting tests (borrowed, so those tests are not collected twice here).
    UUID = web_setting.WebAssetsDirectorySettingTests.UUID
    write = web_setting.WebAssetsDirectorySettingTests.write
    load = web_setting.WebAssetsDirectorySettingTests.load
    check = web_setting.WebAssetsDirectorySettingTests.check

    def setUp(self):
        web_setting.WebAssetsDirectorySettingTests.setUp(self)
        self.web = str(self.installation / "current/web")
        write_build(self.release / "web")
        bin_directory = self.root / "bin"
        bin_directory.mkdir(mode=0o755)
        self.executable = bin_directory / "tailscale"
        self.executable.write_text("#!/bin/sh\nexit 0\n")
        self.executable.chmod(0o755)

    def access(self, **changes):
        return section(**{"tailscale_executable": str(self.executable), **changes})

    def test_absent_key_keeps_human_access_unconfigured(self):
        self.assertIsNone(self.load().human_access)
        self.assertIsNone(self.load(web_assets_directory=self.web).human_access)

    def test_present_key_is_parsed(self):
        loaded = self.load(web_assets_directory=self.web, human_access=self.access())
        self.assertIsInstance(loaded.human_access, HumanAccessDeployment)
        self.assertEqual(loaded.human_access.hostname, HOST)
        # The listener-exception CLI (PR #275) reads the stated reservation
        # through this zero-argument call, with the deployment's upstream.
        config = loaded.human_access.reservation_config()
        self.assertIsInstance(config, ReservationConfig)
        self.assertEqual(config.upstream, "http://127.0.0.1:8000")
        self.assertEqual(config.reserved_addresses, frozenset({V4, V6}))
        self.assertEqual(config.isolation, IsolationMode.DEDICATED_NETWORK_IDENTITY)

    def test_enabled_without_web_assets_is_refused(self):
        with self.assertRaises(HumanAccessRefused) as refused:
            self.load(human_access=self.access())
        self.assertEqual(refused.exception.reason, "web_assets")
        # Disabled, the section is still validated but needs no Web build.
        self.assertIs(self.load(human_access=self.access(enabled=False)).human_access.enabled, False)
        with self.assertRaises(HumanAccessRefused):
            self.load(human_access=self.access(enabled=False, port=0))

    def test_check_prints_one_value_free_reason(self):
        cases = (
            ({"human_access": self.access(hostname="Upper.example.invalid")}, "setting"),
            ({"human_access": self.access()}, "web_assets"),
            ({"human_access": self.access(tailscale_executable=str(self.root / "missing")),
              "web_assets_directory": self.web}, "executable"),
        )
        for extra, reason in cases:
            with self.subTest(reason=reason):
                code, stdout, stderr = self.check(**extra)
                self.assertEqual(code, 1)
                self.assertEqual(stderr, "ServerSentinel deployment validation failed: human "
                                         f"access refused (reason={reason})\n")
                self.assertNotIn(str(self.root), stderr)
        code, stdout, _ = self.check(human_access=self.access(), web_assets_directory=self.web)
        self.assertEqual((code, stdout), (0, "ServerSentinel deployment validation passed\n"))

    def test_launcher_passes_the_checked_section_to_run(self):
        link = self.root / "bin/tailscale-link"
        link.symlink_to(self.executable)
        self.write(human_access=self.access(tailscale_executable=str(link)),
                   web_assets_directory=self.web)
        with patch("app.deployment.__file__", str(self.module)), patch(
                "app.__main__.run", return_value=0) as run:
            self.assertEqual(deployment_main(["--config", str(self.config)]), 0)
        passed = run.call_args.kwargs["human_access"]
        # The symbolic link is resolved and its target is what runs.
        self.assertEqual(passed.tailscale_executable, self.executable.resolve())

    def test_executable_must_be_administrator_controlled(self):
        self.assertEqual(_tailscale_executable(self.executable), self.executable.resolve())
        for mode in (0o775, 0o757, 0o644):
            with self.subTest(mode=oct(mode)):
                self.executable.chmod(mode)
                with self.assertRaises(HumanAccessRefused) as refused:
                    _tailscale_executable(self.executable)
                self.assertEqual(refused.exception.reason, "executable")
        self.executable.chmod(0o755)
        with self.assertRaises(HumanAccessRefused):
            _tailscale_executable(self.executable.parent)
        with patch("app.deployment.ADMINISTRATOR_UID", os.geteuid() + 1):
            if os.geteuid() != 0:
                with self.assertRaises(HumanAccessRefused):
                    _tailscale_executable(self.executable)
        (self.executable.parent).chmod(0o777)
        self.addCleanup((self.executable.parent).chmod, 0o755)
        with self.assertRaises(HumanAccessRefused):
            _tailscale_executable(self.executable)

    def test_standalone_installer_validates_the_section_with_stdlib_only(self):
        from build_installer import build
        with tempfile.TemporaryDirectory(prefix="server-access-installer-") as directory:
            target = Path(directory) / "installer.pyz"
            build(target)
            code = ("import json, sys; sys.path.insert(0, sys.argv[1]); "
                    "from app.deployment import parse_human_access; "
                    "print(parse_human_access(json.loads(sys.argv[2])).port)")
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(target), json.dumps(SECTION)],
                cwd="/", capture_output=True, text=True, check=True, timeout=60,
            )
        self.assertEqual("443", result.stdout.strip())


# Generated stand-ins for the Tailscale CLI: each runs this interpreter.
STAND_INS = {
    "ok": "import sys\nsys.stdout.write('{\"TCP\": {}}')\n",
    "argv": "import json, sys\nprint(json.dumps(sys.argv[1:]))\n",
    "environment": "import json, os\nprint(json.dumps(sorted(os.environ)))\n",
    "fail": "import sys\nsys.stdout.write('{}')\nsys.exit(3)\n",
    "hang": "import time\ntime.sleep(60)\n",
    "flood": "import sys\nsys.stdout.write('x' * 4096)\nsys.stdout.flush()\nimport time\ntime.sleep(60)\n",
    "binary": "import sys\nsys.stdout.buffer.write(b'\\xff\\xfe')\n",
    "stdin": "import sys\nsys.stdout.write(repr(sys.stdin.read()))\n",
}


class ServeStatusCommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="server-serve-status-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = {}
        for name, body in STAND_INS.items():
            path = self.root / name
            path.write_text(f"#!{sys.executable}\n{body}")
            path.chmod(0o755)
            self.paths[name] = path

    def test_runs_only_the_fixed_read_only_query(self):
        self.assertEqual(json.loads(ServeStatusCommand(self.paths["argv"])()),
                         list(SERVE_STATUS_ARGUMENTS))
        self.assertEqual(SERVE_STATUS_ARGUMENTS, ("serve", "status", "--json"))

    def test_output_is_returned_for_the_parser(self):
        self.assertEqual(ServeStatusCommand(self.paths["ok"])(), '{"TCP": {}}')

    def test_environment_is_empty_and_stdin_closed(self):
        with patch.dict(os.environ, {"SYNTHETIC_SECRET": "value"}):
            variables = json.loads(ServeStatusCommand(self.paths["environment"])())
        # The interpreter itself may add LC_CTYPE; nothing is inherited.
        self.assertNotIn("SYNTHETIC_SECRET", variables)
        self.assertLessEqual(set(variables), {"LC_CTYPE"})
        self.assertEqual(ServeStatusCommand(self.paths["stdin"])(), "''")

    def test_failures_are_enumeration_errors(self):
        cases = {
            "fail": dict(),
            "hang": dict(timeout=0.5),
            "flood": dict(max_bytes=1024),
            "binary": dict(),
        }
        for name, options in cases.items():
            with self.subTest(name):
                with self.assertRaises(ReservationEnumerationError):
                    ServeStatusCommand(self.paths[name], **options)()
        with self.assertRaises(ReservationEnumerationError):
            ServeStatusCommand(self.root / "missing")()

    def test_timeout_kills_the_child(self):
        started = []
        real = subprocess.Popen

        def popen(*arguments, **options):
            process = real(*arguments, **options)
            started.append(process)
            return process

        with self.assertRaises(ReservationEnumerationError):
            ServeStatusCommand(self.paths["hang"], timeout=0.3, popen=popen)()
        self.assertEqual(len(started), 1)
        # Killed and reaped: nothing outlives the refused check.
        self.assertIsNotNone(started[0].returncode)

    def test_popen_options(self):
        calls = []

        def popen(argv, **options):
            calls.append((argv, options))
            raise OSError("synthetic")

        with self.assertRaises(ReservationEnumerationError):
            ServeStatusCommand(Path("/synthetic/tailscale"), popen=popen)()
        argv, options = calls[0]
        self.assertEqual(argv, ["/synthetic/tailscale", "serve", "status", "--json"])
        self.assertEqual(options["env"], {})
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertIs(options["close_fds"], True)
        self.assertIs(options["start_new_session"], True)
        self.assertNotIn("shell", options)

    def test_construction_is_validated(self):
        for kwargs in (dict(executable=Path("relative")), dict(timeout=0), dict(timeout=10.0),
                       dict(timeout=True), dict(max_bytes=0), dict(max_bytes=2 * 1024 * 1024)):
            arguments = dict(executable=Path("/synthetic/tailscale"))
            arguments.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ServeStatusCommand(arguments.pop("executable"), **arguments)

    def test_routes_from_the_command_are_parsed(self):
        status = self.root / "serve"
        document = {"TCP": {"443": {"HTTPS": True}},
                    "Web": {f"{HOST}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:880"}}}}}
        status.write_text(f"#!{sys.executable}\nprint({json.dumps(json.dumps(document))})\n")
        status.chmod(0o755)
        routes = ServeStatusRoutes(ServeStatusCommand(status)).routes()
        self.assertEqual([(route.host, route.port, route.target) for route in routes],
                         [(HOST, 443, "http://127.0.0.1:880")])


class ProcNetReaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="server-proc-net-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_reads_only_the_four_tables(self):
        files = Files()
        for name in ("tcp", "tcp6", "udp", "udp6"):
            (self.root / name).write_text(files.raw[name])
        self.assertEqual(read_proc_net("tcp", root=str(self.root)), files.raw["tcp"])
        self.assertEqual(len(ProcNetListeners(lambda name: read_proc_net(name, root=str(self.root)),
                                              byteorder="little").listeners()), 1)
        for name in ("tcp4", "../tcp", "unix", ""):
            with self.subTest(name=name), self.assertRaises(ReservationEnumerationError):
                read_proc_net(name, root=str(self.root))

    def test_missing_large_or_non_ascii_tables_fail_closed(self):
        with self.assertRaises(ReservationEnumerationError):
            read_proc_net("tcp6", root=str(self.root))
        (self.root / "tcp").write_bytes(b"x" * 65)
        with self.assertRaises(ReservationEnumerationError):
            read_proc_net("tcp", root=str(self.root), limit=64)
        self.assertEqual(len(read_proc_net("tcp", root=str(self.root), limit=65)), 65)
        (self.root / "udp").write_bytes(b"\xff")
        with self.assertRaises(ReservationEnumerationError):
            read_proc_net("udp", root=str(self.root))
        self.assertGreaterEqual(MAX_PROC_NET_BYTES, 1_000_000 * 64)


class CompositionTests(RuntimeFixture):
    """``build_human_access`` with synthetic enumerators, served through ``create_app``
    with a storage-configured monitoring runtime (synthetic probe, intercepted
    Slack transport), as the launcher composes it."""

    def setUp(self):
        super().setUp()
        self.root = self.state.parent
        self.web = write_build(self.root / "web")
        self.settings = Settings(self.root / "state", human_port=8080, web_assets_dir=self.web)
        self.database = Database(self.settings.database_path)

    def build(self, configuration=None, **overrides):
        options = dict(
            faults=AccessFaultMonitor(),
            listeners=ProcNetListeners(Files(), byteorder="little"),
            routes=ServeStatusRoutes(Status()), resolver=Resolver(), socket_owners=Owners(),
            own_sockets=lambda: frozenset(range(1000, 5000)),
            unprivileged_port_start=lambda: 10000,
            session_binding=SessionBindingKey.generate(),
        )
        options.update(overrides)
        configuration = configuration or parse_human_access(section(isolation="single_purpose_node"))
        return build_human_access(configuration, self.settings, self.database, **options)

    def test_the_composition_wires_one_fault_monitor_and_the_section(self):
        faults = AccessFaultMonitor()
        access = self.build(faults=faults, configuration=parse_human_access(
            section(require_device_bound=True)))
        self.assertIsInstance(access, HumanAccess)
        self.assertIs(access.reservation.fault_sink, faults)
        self.assertIs(access.ceremonies.findings, faults)
        self.assertIs(access.ceremonies.require_device_bound, True)
        self.assertEqual(access.origin, f"https://{HOST}")
        self.assertEqual(access.ceremonies.rp.rp_id, HOST)
        self.assertEqual(access.store.invitation_lifetime, self.settings.invitation_lifetime)
        self.assertEqual(access.store.database, self.database)
        self.assertEqual(access.assets.directory, self.web.resolve())
        self.assertEqual(access.reservation.exception_store.database.path, self.database.path)
        self.assertTrue(access.reservation.opening_configured)
        self.assertEqual(access.reservation.config.isolation, IsolationMode.DEDICATED_NETWORK_IDENTITY)

    def test_production_inputs_are_the_default(self):
        from app.auth.composition import ServeStatusCommand as Command
        from app.auth.reservation import GetaddrinfoResolver
        from app.auth.sock_diag import SockDiagOwners
        from app.auth import composition as composition_module
        captured = {}

        class Capture(composition_module.HostnameReservationCheck):
            def __init__(self, config, listeners, routes, sink, **options):
                captured.update(listeners=listeners, routes=routes, **options)
                super().__init__(config, listeners, routes, sink, **options)

        with patch("app.auth.composition.HostnameReservationCheck", Capture):
            build_human_access(parse_human_access(section()), self.settings, self.database,
                               faults=AccessFaultMonitor(),
                               session_binding=SessionBindingKey.generate())
        self.assertIsInstance(captured["listeners"], ProcNetListeners)
        self.assertIsInstance(captured["routes"], ServeStatusRoutes)
        self.assertIsInstance(captured["routes"]._status, Command)
        self.assertEqual(captured["routes"]._status._argv,
                         ("/usr/bin/tailscale", "serve", "status", "--json"))
        self.assertIsInstance(captured["resolver"], GetaddrinfoResolver)
        self.assertIsInstance(captured["socket_owners"], SockDiagOwners)

    def test_session_binding_key_is_loaded_from_the_state_directory(self):
        self.build(session_binding=None, monitoring=self.configuration())
        info = self.settings.session_binding_key_path.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        # A restart loads the same key under the same check.
        self.build(session_binding=None, monitoring=self.configuration())

    def test_session_binding_key_is_created_only_on_verified_storage(self):
        """Codex PR #282: the key is written before the monitoring runtime binds
        the storage admission, so it gets the database's own fresh check:
        never past the hard reserve, never on a missing or replaced mount."""
        path = self.settings.session_binding_key_path
        cases = {
            "no monitoring configuration": dict(monitoring=None),
            "storage thresholds missing": dict(monitoring=self.configuration(
                storage_limits=None, recording_limits=None, recording_filesystem=None)),
            "hard reserve would be spent": dict(monitoring=self.configuration(
                storage_limits=StorageLimits(**{
                    **STORAGE_LIMITS, "hard_reserve_bytes": 2 ** 62,
                    "pressure_free_bytes": 2 ** 62 + 1, "recovery_free_bytes": 2 ** 62 + 2}))),
        }
        for name, change in cases.items():
            with self.subTest(name), self.assertRaises(HumanAccessUnavailable):
                self.build(session_binding=None, **change)
            self.assertFalse(path.exists())
            self.assertEqual([entry for entry in path.parent.iterdir()
                              if entry.name.startswith(".session-binding")], [])
        # The approved filesystem is no longer the mounted one.
        configuration = self.configuration()
        self.approved_device = self.device + 1
        with self.assertRaises(HumanAccessUnavailable):
            self.build(session_binding=None, monitoring=configuration)
        self.assertFalse(path.exists())
        # An existing key is not used while the mount is replaced either.
        self.approved_device = self.device
        self.build(session_binding=None, monitoring=configuration)
        self.assertTrue(path.exists())
        self.approved_device = self.device + 1
        with self.assertRaises(HumanAccessUnavailable):
            self.build(session_binding=None, monitoring=configuration)

    def test_any_missing_or_invalid_piece_refuses_without_values(self):
        configuration = parse_human_access(section())
        disabled = parse_human_access(section(enabled=False))
        cases = {
            "disabled": dict(configuration=disabled),
            "no monitor": dict(faults=None),
            "other monitor type": dict(faults=object()),
            "other database": dict(database=Database(self.root / "other.sqlite3")),
            "no web assets": dict(settings=Settings(self.root / "state", human_port=8080)),
            "other upstream": dict(configuration=replace(configuration, upstream_host="127.0.0.1",
                                                         upstream_port=8081)),
            "invalid web assets": dict(settings=Settings(self.root / "state", human_port=8080,
                                                         web_assets_dir=self.root / "missing")),
        }
        for name, change in cases.items():
            with self.subTest(name):
                arguments = dict(configuration=configuration, settings=self.settings,
                                 database=self.database, faults=AccessFaultMonitor(),
                                 session_binding=SessionBindingKey.generate())
                arguments.update(change)
                with self.assertRaises(HumanAccessUnavailable) as refused:
                    build_human_access(arguments.pop("configuration"), arguments.pop("settings"),
                                       arguments.pop("database"), **arguments)
                self.assertNotIn(HOST, str(refused.exception))
                self.assertNotIn(str(self.root), str(refused.exception))
        # The binding key directory is not the service's own: refused.
        (self.root / "state").chmod(0o777)
        self.addCleanup((self.root / "state").chmod, 0o700)
        with self.assertRaises(HumanAccessUnavailable):
            self.build(session_binding=None, monitoring=self.configuration())

    async def serve(self, access, **options):
        return create_app(
            self.settings, database=self.database, human_access=access,
            monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0,
                access_faults=access.reservation.fault_sink),
            **options)

    async def wait_serving(self, access):
        for _ in range(500):
            if not access.stopped:
                return
            await asyncio.sleep(0.01)
        self.fail("composition did not start serving")

    async def test_a_passing_check_serves_the_shell(self):
        access = self.build()
        application = await self.serve(access)
        async with application.router.lifespan_context(application):
            await self.wait_serving(access)
            self.assertTrue(access.reservation.access_open)
            messages = await get(application, SHELL_PATH)
            self.assertEqual(messages[0]["status"], 200)

    async def test_unstated_isolation_keeps_access_closed(self):
        access = self.build(configuration=parse_human_access(section(isolation=None)))
        application = await self.serve(access)
        async with application.router.lifespan_context(application):
            await self.wait_serving(access)
            self.assertFalse(access.reservation.access_open)
            self.assertIn(Reason.ISOLATION_UNSTATED, access.reservation.verdict.reasons)
            self.assertEqual((await get(application, SHELL_PATH))[0]["status"], 404)

    async def test_a_failing_serve_status_keeps_access_closed(self):
        access = self.build(routes=ServeStatusRoutes(
            Status(ReservationEnumerationError("SERVE_STATUS_UNAVAILABLE"))))
        application = await self.serve(access)
        async with application.router.lifespan_context(application):
            await self.wait_serving(access)
            self.assertFalse(access.reservation.access_open)
            self.assertEqual((await get(application, SHELL_PATH))[0]["status"], 404)

    async def test_live_frame_pull_is_attached_for_the_local_sources(self):
        """#277: the launcher's create_app attaches the S7 frame pull over the
        preview hub of the deployment's local UVC sources."""
        from app.cameras.uvc.config import LocalUvcConfiguration
        source = uuid4()
        access = self.build()
        application = await self.serve(access, local_uvc=LocalUvcConfiguration((source,)))
        self.assertIsNotNone(access.live)
        self.assertEqual(tuple(application.state.local_preview.source_ids), (source,))

    def test_absent_composition_keeps_the_closed_surface(self):
        application = create_app(self.settings, database=self.database)
        self.assertIsNone(application.state.human_access)
        self.assertTrue(any(item.cls is ClosedHumanSurface for item in application.user_middleware))


class LauncherCompositionTests(unittest.TestCase):
    def setUp(self):
        self.handlers = logging.getLogger().handlers[:]
        self.level = logging.getLogger().level
        self.addCleanup(lambda: (setattr(logging.getLogger(), "handlers", self.handlers),
                                 logging.getLogger().setLevel(self.level)))
        temporary = tempfile.TemporaryDirectory(prefix="server-launcher-access-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = Settings(self.root, web_assets_dir=self.root / "web")

    def run_launcher(self, human_access, **patches):
        from types import SimpleNamespace
        from app.__main__ import run
        monitoring = SimpleNamespace(storage_configured=True)
        with patch("app.__main__.create_app") as create, patch(
                "app.systemd.build_server") as build:
            for name, value in patches.items():
                patcher = patch(name, value)
                patcher.start()
                self.addCleanup(patcher.stop)
            code = run(self.settings, monitoring, None, human_access=human_access)
        return code, create, build

    def test_absent_or_disabled_section_builds_nothing(self):
        for value in (None, parse_human_access(section(enabled=False))):
            with self.subTest(value=value):
                code, create, _ = self.run_launcher(value)
                self.assertEqual(code, 0)
                self.assertNotIn("human_access", create.call_args.kwargs)
                self.assertNotIn("monitoring_dependencies", create.call_args.kwargs)

    def test_enabled_section_passes_one_monitor_everywhere(self):
        built = {}

        def fake_build(configuration, settings, database, *, faults, monitoring):
            built.update(faults=faults, database=database, monitoring=monitoring)
            return "composition"

        code, create, build = self.run_launcher(
            parse_human_access(section()),
            **{"app.auth.composition.build_human_access": fake_build})
        self.assertEqual(code, 0)
        kwargs = create.call_args.kwargs
        self.assertEqual(kwargs["human_access"], "composition")
        self.assertIs(kwargs["monitoring_dependencies"].access_faults, built["faults"])
        self.assertIs(kwargs["database"], built["database"])
        self.assertEqual(built["database"].path, self.settings.database_path)
        # The key is created under the deployment's storage check.
        self.assertTrue(built["monitoring"].storage_configured)
        build.return_value.run.assert_called_once_with()

    def test_a_refused_composition_does_not_start(self):
        def refuse(*_arguments, **_options):
            raise HumanAccessUnavailable()

        with self.assertLogs("app.__main__", level="ERROR") as logs:
            code, create, build = self.run_launcher(
                parse_human_access(section()), **{"app.auth.composition.build_human_access": refuse})
        self.assertEqual(code, 1)
        create.assert_not_called()
        build.assert_not_called()
        self.assertEqual([record.msg for record in logs.records],
                         [Event.HUMAN_ACCESS_COMPOSITION_FAILED])

    def test_create_app_refusal_does_not_start(self):
        from types import SimpleNamespace
        from app.__main__ import run
        with patch("app.auth.composition.build_human_access", return_value="composition"), patch(
                "app.__main__.create_app", side_effect=TypeError("human access composition is invalid")), patch(
                "app.systemd.build_server") as build, self.assertLogs("app.__main__", level="ERROR"):
            code = run(self.settings, SimpleNamespace(storage_configured=True), None,
                       human_access=parse_human_access(section()))
        self.assertEqual(code, 1)
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
