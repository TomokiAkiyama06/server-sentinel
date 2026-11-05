"""Issue #321 item 2: the start-failure notice (systemd ``OnFailure=``).

The notifier is tested with a fake transport only; nothing here opens a
network connection. The installer tests reuse the synthetic release
lifecycle of ``tests/test_release.py``.
"""

import io
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError, URLError
import zipfile

from app.notifications.slack import SlackEndpoint
from build_installer import build as build_installer
import failure_notice
import install
from tests import test_release


SERVER = Path(__file__).resolve().parents[1]
# Synthetic, and deliberately shorter than a real webhook's segments so the
# repository secret guard does not mistake it for one.
WEBHOOK = "https://hooks.slack.com/services/T0SYN/B0SYN/synthetic-webhook_secret"
SECRET = "synthetic-webhook_secret"


class Response:
    def __init__(self, status=200, body=b"ok"):
        self.status, self.body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size):
        return self.body[:size]


class Opener:
    """A fake transport: each attempt pops one outcome (a Response or an exception)."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def http_error(code):
    return HTTPError(WEBHOOK, code, "synthetic " + SECRET, {}, io.BytesIO(SECRET.encode()))


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class NotifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="failure-notice-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / "deployment.json"
        self.state = self.root / "run"
        self.state.mkdir(mode=0o700)
        self.environ = {"RUNTIME_DIRECTORY": str(self.state)}
        self.write_config({"runtime_root": "/srv/synthetic-runtime", "service_uid": 4242,
                           "monitoring": {"time_zone": "Asia/Tokyo",
                                          "slack_webhook_url": WEBHOOK}})
        self.sleeps = []

    def write_config(self, value):
        self.config.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        self.config.chmod(0o640)

    def run_notice(self, opener, clock=None):
        stderr = io.StringIO()
        code = failure_notice.run(str(self.config), environ=self.environ, opener=opener,
                                  clock=clock or Clock(), sleep=self.sleeps.append, stderr=stderr)
        output = stderr.getvalue()
        # Nothing but the fixed prefix and fixed words: no URL, token, path
        # or configuration value.
        for leaked in (SECRET, "hooks.slack.com", "T0SYN", str(self.config),
                       str(self.state), "synthetic-runtime", "4242", "Asia/Tokyo"):
            self.assertNotIn(leaked, output)
        self.assertRegex(output, r"\AServerSentinel failure notice: [a-z_ ()=]+\n\Z")
        return code, output

    def test_sends_exactly_the_fixed_text_once(self):
        opener = Opener(Response())
        code, output = self.run_notice(opener)
        self.assertEqual((code, output), (0, "ServerSentinel failure notice: sent\n"))
        self.assertEqual(len(opener.requests), 1)
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, WEBHOOK)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(timeout, 10)
        self.assertEqual(json.loads(request.data), {"text": failure_notice.MESSAGE})
        self.assertEqual(failure_notice.MESSAGE,
                         "ServerSentinel critical alert: service_start_failed")
        # Same shape as the in-service critical alerts.
        self.assertRegex(failure_notice.MESSAGE, r"\AServerSentinel critical alert: [a-z_]+\Z")
        self.assertEqual(self.sleeps, [])

    def test_one_notice_per_episode_within_a_boot(self):
        clock = Clock(5000.0)
        self.assertEqual(self.run_notice(Opener(Response()), clock)[0], 0)
        self.assertEqual((self.state / "last-notice").read_text(), "5000")
        self.assertEqual(stat.S_IMODE((self.state / "last-notice").stat().st_mode), 0o600)
        for later in (5000.0, 5001.0, 5000.0 + failure_notice.COOLDOWN_SECONDS - 1):
            clock.now = later
            opener = Opener()
            self.assertEqual(self.run_notice(opener, clock),
                             (0, "ServerSentinel failure notice: suppressed (reason=recent_notice)\n"))
            self.assertEqual(opener.requests, [])
        clock.now = 5000.0 + failure_notice.COOLDOWN_SECONDS
        opener = Opener(Response())
        self.assertEqual(self.run_notice(opener, clock)[0], 0)
        self.assertEqual(len(opener.requests), 1)

    def test_untrusted_or_missing_state_never_suppresses(self):
        for content in ("9999999", "garbage", "", "1" * 40, "-5"):
            with self.subTest(content=content):
                (self.state / "last-notice").write_text(content)
                opener = Opener(Response())
                self.assertEqual(self.run_notice(opener, Clock(1000.0))[0], 0)
                self.assertEqual(len(opener.requests), 1)
        (self.state / "last-notice").unlink()
        (self.state / "last-notice").symlink_to(self.root / "elsewhere")
        (self.root / "elsewhere").write_text("1000")
        opener = Opener(Response())
        self.assertEqual(self.run_notice(opener, Clock(1000.0))[0], 0)
        self.assertEqual(len(opener.requests), 1)
        # Without a RuntimeDirectory the notice is still sent.
        for environ in ({}, {"RUNTIME_DIRECTORY": "relative"},
                        {"RUNTIME_DIRECTORY": str(self.state) + ":/other"}):
            with self.subTest(environ=environ):
                self.environ = environ
                opener = Opener(Response())
                self.assertEqual(self.run_notice(opener)[0], 0)
                self.assertEqual(len(opener.requests), 1)

    def test_unremembered_state_directory_still_sends(self):
        self.state.chmod(0o500)
        self.addCleanup(self.state.chmod, 0o700)
        opener = Opener(Response())
        self.assertEqual(self.run_notice(opener)[0], 0)
        self.assertEqual(len(opener.requests), 1)

    def test_retries_only_what_a_later_attempt_can_fix_and_stays_bounded(self):
        for outcomes, attempts, code, reason in (
                ((URLError("no route " + SECRET),) * 3, 3, 1, "delivery_failed"),
                ((TimeoutError(SECRET), http_error(503), Response()), 3, 0, None),
                ((http_error(429), Response()), 2, 0, None),
                ((http_error(404),), 1, 1, "delivery_rejected"),
                ((http_error(403),), 1, 1, "delivery_rejected"),
                ((Response(200, b"invalid_token"),), 1, 1, "delivery_rejected"),
                ((Response(200, b"ok" * 40),), 1, 1, "delivery_rejected"),
                ((Response(204, b""),), 1, 1, "delivery_rejected"),
                ((ValueError(WEBHOOK),) * 3, 3, 1, "delivery_failed")):
            with self.subTest(outcomes=outcomes):
                self.sleeps.clear()
                (self.state / "last-notice").unlink(missing_ok=True)
                opener = Opener(*outcomes)
                result, output = self.run_notice(opener)
                self.assertEqual(result, code)
                self.assertEqual(len(opener.requests), attempts)
                self.assertLessEqual(attempts, failure_notice.ATTEMPTS)
                self.assertEqual(self.sleeps, [failure_notice.RETRY_SECONDS] * (attempts - 1))
                if reason:
                    self.assertEqual(output, "ServerSentinel failure notice: not sent "
                                             f"(reason={reason})\n")
                    # A notice that was not delivered is not remembered.
                    self.assertFalse((self.state / "last-notice").exists())
        # The worst case fits inside the unit's TimeoutStartSec=90.
        self.assertLess(failure_notice.ATTEMPTS * failure_notice.TIMEOUT_SECONDS
                        + (failure_notice.ATTEMPTS - 1) * failure_notice.RETRY_SECONDS, 90)

    def test_reads_only_the_webhook_and_tolerates_the_rest(self):
        # A configuration the release refuses for another reason still names
        # the webhook (the 2026-10-24 outage: a device-number mismatch).
        self.write_config({"runtime_device": [8, 0], "unknown_key": True,
                           "monitoring": {"slack_webhook_url": WEBHOOK, "time_zone": 7}})
        self.assertEqual(failure_notice.read_webhook(str(self.config)), ("configured", WEBHOOK))

    def test_unconfigured_slack_is_not_an_error(self):
        for value in ({"runtime_root": "/srv/x"}, {"monitoring": {"time_zone": "UTC"}},
                      {"monitoring": None}):
            with self.subTest(value=value):
                self.write_config(value)
                opener = Opener()
                self.assertEqual(self.run_notice(opener), (
                    0, "ServerSentinel failure notice: not sent (reason=slack_not_configured)\n"))
                self.assertEqual(opener.requests, [])

    def test_unreadable_or_invalid_webhook_is_refused_without_a_request(self):
        invalid_urls = (
            "http://hooks.slack.com/services/A/B/C", "https://hooks.slack.com.evil/services/A/B/C",
            "https://evil.example/services/A/B/C", "https://hooks.slack.com:8443/services/A/B/C",
            "https://evil-slack.com/services/A/B/C", "https://hooks.evilslack.com/services/A/B/C",
            "https://slack.com/services/A/B/C",
            "https://user@hooks.slack.com/services/A/B/C", WEBHOOK + "?x=1", WEBHOOK + "#f",
            WEBHOOK + "/extra", WEBHOOK + " ", "https://hooks.slack.com/services/A/B/" + "c" * 3000,
            7, None, ["x"])
        values = [{"monitoring": {"slack_webhook_url": url}} for url in invalid_urls]
        values += [b"{not json", b"[]", json.dumps({"monitoring": []}).encode(),
                   json.dumps({"monitoring": {"slack_webhook_url": WEBHOOK},
                               "pad": "x" * (16 * 1024)}).encode()]
        for value in values:
            with self.subTest(value=str(value)[:80]):
                self.write_config(value)
                opener = Opener()
                self.assertEqual(self.run_notice(opener), (
                    1, "ServerSentinel failure notice: not sent (reason=webhook_unavailable)\n"))
                self.assertEqual(opener.requests, [])
        self.config.unlink()
        self.assertEqual(self.run_notice(Opener())[0], 1)
        (self.root / "real.json").write_text(json.dumps({"monitoring": {"slack_webhook_url": WEBHOOK}}))
        self.config.symlink_to(self.root / "real.json")
        self.assertEqual(failure_notice.read_webhook(str(self.config)), ("unavailable", None))
        self.config.unlink()
        self.config.mkdir()
        self.assertEqual(failure_notice.read_webhook(str(self.config)), ("unavailable", None))

    def test_endpoint_rules_match_the_service_sender(self):
        samples = [WEBHOOK, "https://hooks.slack.com:443/services/A/B/C",
                   "https://hooks.slack.com/services/A/B/C", "https://HOOKS.slack.com/services/A/B/C",
                   "https://hooks.slack.com/services/A/B", "https://hooks.slack.com/services/A/B/C/",
                   "https://hooks.slack.com/services/A/B/C?", "https://hooks.slack.com/services/A/B/C#",
                   "https://:@hooks.slack.com/services/A/B/C", "https://[::1]/services/A/B/C",
                   "https://hooks.slack.com:0/services/A/B/C", "https://hooks.slack.com:99999/services/A/B/C",
                   "ftp://hooks.slack.com/services/A/B/C", "https://hooks.slack.com/services/A/B/C\n",
                   "https://hooks.slack.com/services/A/B/é", "", "https://hooks.slack.com/services/a.b/B/C"]
        for url in samples:
            with self.subTest(url=url):
                try:
                    SlackEndpoint(url)
                    expected = True
                except ValueError:
                    expected = False
                self.assertEqual(failure_notice.valid_endpoint(url), expected)

    def test_default_transport_uses_no_proxy_and_no_redirect(self):
        captured = []

        def fake_build_opener(*handlers):
            captured.extend(handlers)
            return Opener(Response())

        with patch("failure_notice.build_opener", side_effect=fake_build_opener), \
                patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:1"}):
            self.assertEqual(failure_notice.send(WEBHOOK), "sent")
        proxies = [handler for handler in captured
                   if isinstance(handler, failure_notice.ProxyHandler)]
        self.assertEqual([handler.proxies for handler in proxies], [{}])
        self.assertTrue(any(isinstance(handler, failure_notice.NoRedirect) for handler in captured))
        self.assertIsNone(failure_notice.NoRedirect().redirect_request(None, None, 302, "", {}, ""))

    def test_command_line_is_fixed(self):
        for arguments in ([], ["--config"], ["--config", "relative.json"],
                          ["--config", "/x", "--extra"], ["--other", "/x"]):
            with self.subTest(arguments=arguments), patch("sys.stderr", io.StringIO()) as stderr:
                self.assertEqual(failure_notice.main(arguments), 2)
                self.assertEqual(stderr.getvalue(),
                                 "ServerSentinel failure notice: not sent (reason=usage)\n")

    def test_runs_isolated_without_the_application(self):
        # As the unit runs it: the host interpreter, -I -S, from outside the
        # source tree. The configuration names no webhook, so nothing is sent
        # (the container has no network either).
        self.write_config({"runtime_root": "/srv/x"})
        script = self.root / "failure_notice.py"
        script.write_bytes((SERVER / "failure_notice.py").read_bytes())
        probe = ("import runpy, sys; runpy.run_path(sys.argv[1], run_name='probe'); "
                 "print(sorted(name for name in sys.modules if name == 'app' "
                 "or name.startswith('app.')))")
        result = subprocess.run([sys.executable, "-I", "-S", "-c", probe, str(script)],
                                cwd=self.root, capture_output=True, text=True, timeout=60,
                                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(SERVER)})
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "[]\n", ""))
        result = subprocess.run([sys.executable, "-I", "-S", str(script), "--config", str(self.config)],
                                cwd=self.root, capture_output=True, text=True, timeout=60,
                                env={"PATH": "/usr/bin:/bin", "RUNTIME_DIRECTORY": str(self.state)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr,
                         "ServerSentinel failure notice: not sent (reason=slack_not_configured)\n")

    def test_imports_only_the_standard_library(self):
        source = (SERVER / "failure_notice.py").read_text()
        modules = set(re.findall(r"^(?:from|import) ([a-z_.]+)", source, re.MULTILINE))
        self.assertEqual({module.split(".")[0] for module in modules},
                         {"json", "os", "re", "ssl", "stat", "subprocess", "sys", "time",
                          "urllib"})

    def test_unless_active_sends_nothing_while_the_service_is_active(self):
        calls = []

        def runner(arguments, **options):
            calls.append((arguments, options))
            return SimpleNamespace(returncode=0, stdout=b"active\n")

        opener = Opener()
        stderr = io.StringIO()
        code = failure_notice.run(str(self.config), environ=self.environ, opener=opener,
                                  stderr=stderr, unless_active=True, runner=runner)
        self.assertEqual((code, stderr.getvalue()),
                         (0, "ServerSentinel failure notice: not sent (reason=service_active)\n"))
        self.assertEqual(opener.requests, [])
        [(arguments, options)] = calls
        self.assertEqual(arguments, ["/usr/bin/systemctl", "show", "--property=ActiveState",
                                     "--value", "server-sentinel.service"])
        self.assertEqual(options["timeout"], 10)
        self.assertEqual(options["env"]["PATH"], "/usr/bin:/bin")
        self.assertNotIn(str(self.config), repr(options))

    def test_unless_active_sends_when_the_service_is_not_active_or_unknown(self):
        for outcome in ((0, b"inactive\n"), (0, b"failed\n"), (0, b"activating\n"),
                        (0, b"active-ish\n"), (0, b""), (1, b"active\n"),
                        subprocess.TimeoutExpired("systemctl", 10), OSError("no systemctl")):
            with self.subTest(outcome=outcome):
                (self.state / "last-notice").unlink(missing_ok=True)

                def runner(arguments, **options):
                    if isinstance(outcome, BaseException):
                        raise outcome
                    return SimpleNamespace(returncode=outcome[0], stdout=outcome[1])

                opener = Opener(Response())
                stderr = io.StringIO()
                code = failure_notice.run(str(self.config), environ=self.environ,
                                          opener=opener, clock=Clock(), sleep=self.sleeps.append,
                                          stderr=stderr, unless_active=True, runner=runner)
                self.assertEqual((code, stderr.getvalue()),
                                 (0, "ServerSentinel failure notice: sent\n"))
                self.assertEqual(len(opener.requests), 1)

    def test_the_on_failure_notice_never_asks_systemd(self):
        # OnFailure= already means failed; a racing restart must not hide it.
        queried = []

        def runner(*arguments, **options):
            queried.append(arguments)
            return SimpleNamespace(returncode=0, stdout=b"active\n")

        opener = Opener(Response())
        stderr = io.StringIO()
        code = failure_notice.run(str(self.config), environ=self.environ, opener=opener,
                                  stderr=stderr, runner=runner)
        self.assertEqual((code, stderr.getvalue()), (0, "ServerSentinel failure notice: sent\n"))
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(queried, [])

    def test_the_notice_and_the_watch_share_one_episode(self):
        # OnFailure= reported it; the watch 15 minutes later in the same boot does not repeat it.
        self.assertEqual(self.run_notice(Opener(Response()), Clock(100.0))[0], 0)
        opener = Opener()
        stderr = io.StringIO()
        failure_notice.run(str(self.config), environ=self.environ, opener=opener,
                           clock=Clock(100.0 + 900), stderr=stderr, unless_active=True,
                           runner=lambda *a, **k: SimpleNamespace(returncode=0, stdout=b"failed"))
        self.assertEqual(stderr.getvalue(),
                         "ServerSentinel failure notice: suppressed (reason=recent_notice)\n")
        self.assertEqual(opener.requests, [])

    def test_command_line_accepts_only_the_watch_flag(self):
        with patch("failure_notice.run", return_value=0) as run:
            self.assertEqual(failure_notice.main(["--config", "/x", "--unless-active"]), 0)
            self.assertEqual(failure_notice.main(["--config", "/x"]), 0)
        self.assertEqual([call.kwargs["unless_active"] for call in run.call_args_list],
                         [True, False])
        for arguments in (["--config", "/x", "--unless-active", "x"],
                          ["--config", "/x", "--unless-activ"], ["--unless-active", "/x"]):
            with self.subTest(arguments=arguments), patch("sys.stderr", io.StringIO()):
                self.assertEqual(failure_notice.main(arguments), 2)


class FailureNoticeInstallerTests(unittest.TestCase):
    setUp = test_release.ReleaseLifecycleTests.setUp
    artifact = test_release.ReleaseLifecycleTests.artifact
    arguments = test_release.ReleaseLifecycleTests.arguments
    perform = test_release.ReleaseLifecycleTests.perform
    approved_device_lookup = test_release.ReleaseLifecycleTests.approved_device_lookup

    @property
    def notice_unit(self):
        return self.unit.with_name("server-sentinel-failure-notice.service")

    @property
    def watch_unit(self):
        return self.unit.with_name("server-sentinel-start-watch.service")

    @property
    def watch_timer(self):
        return self.unit.with_name("server-sentinel-start-watch.timer")

    @property
    def notice_files(self):
        return (self.notice_unit, self.watch_unit, self.watch_timer, self.notice_script)

    @property
    def notice_script(self):
        return self.installation / "failure_notice.py"

    def service_unit(self):
        return self.unit.read_text().splitlines()

    def test_install_places_both_files_and_names_the_unit(self):
        self.perform(self.arguments("install", "1.0.0"))
        account = pwd.getpwuid(self.uid)
        script = self.notice_script
        self.assertEqual(script.read_bytes(), (SERVER / "failure_notice.py").read_bytes())
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o444)
        unit_info = self.notice_unit.stat()
        self.assertEqual(stat.S_IMODE(unit_info.st_mode), 0o644)
        text = self.notice_unit.read_text()
        lines = text.splitlines()
        self.assertEqual(lines[0], install.FAILURE_NOTICE_MARKER)
        self.assertEqual(text, install.render_failure_notice_unit(
            self.installation, self.config, account, Path(sys.executable)))
        # The interpreter as given (not the release's venv), isolated.
        self.assertIn(f'ExecStart="{sys.executable}" -I -S "{script}" --config "{self.config}"',
                      lines)
        # (the test interpreter itself may live in a venv, as on CI)
        without_python = text.replace(sys.executable, "<python>")
        self.assertNotIn("venv", without_python)
        self.assertNotIn("releases", without_python)
        self.assertNotIn("current", without_python)
        for expected in ("Type=oneshot", "User=" + account.pw_name, f"Group={account.pw_gid}",
                         "Wants=network-online.target", "After=network-online.target",
                         "TimeoutStartSec=90", "RuntimeDirectory=server-sentinel-failure-notice",
                         "RuntimeDirectoryMode=0700", "RuntimeDirectoryPreserve=yes",
                         "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true",
                         "PrivateTmp=true", "PrivateDevices=true", "CapabilityBoundingSet=",
                         "AmbientCapabilities=", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                         "RestrictSUIDSGID=true", "SystemCallFilter=@system-service"):
            self.assertIn(expected, lines)
        # Only OnFailure= starts it; it depends on nothing of the service.
        for absent in ("[Install]", "WantedBy", "RequiresMountsFor", "\nOnFailure",
                       "ReadWritePaths", "Restart=", str(self.runtime)):
            self.assertNotIn(absent, text)
        service = self.service_unit()
        unit_section = service[:service.index("[Service]")]
        service_section = service[service.index("[Service]"):service.index("[Install]")]
        self.assertIn("OnFailure=server-sentinel-failure-notice.service", unit_section)
        for expected in ("Restart=on-failure", "RestartMode=direct", "RestartSec=5"):
            self.assertIn(expected, service_section)
        # PR #392 P1: a start that a failed dependency never runs is caught by the watch.
        self.assertIn("Wants=server-sentinel-start-watch.timer", unit_section)
        watch = self.watch_unit.read_text()
        self.assertEqual(watch, install.render_failure_notice_unit(
            self.installation, self.config, account, Path(sys.executable), watch=True))
        self.assertIn(f'ExecStart="{sys.executable}" -I -S "{script}" --config "{self.config}"'
                      " --unless-active", watch.splitlines())
        # The same unit otherwise: same hardening, same runtime directory.
        self.assertEqual([line for line in watch.splitlines()
                          if not line.startswith(("#", "Description=", "ExecStart="))],
                         [line for line in lines
                          if not line.startswith(("#", "Description=", "ExecStart="))])
        timer = self.watch_timer.read_text()
        timer_lines = timer.splitlines()
        self.assertEqual(timer_lines[0], install.FAILURE_NOTICE_MARKER)
        for expected in ("OnActiveSec=15min", "RemainAfterElapse=true",
                         "Unit=server-sentinel-start-watch.service"):
            self.assertIn(expected, timer_lines)
        for absent in ("[Install]", "OnBootSec", "OnCalendar", "Persistent"):
            self.assertNotIn(absent, timer)
        for path in (self.watch_unit, self.watch_timer):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertNotIn(b"--unless-active", self.notice_unit.read_bytes())

    def test_start_limit_is_always_reached_by_a_start_that_keeps_failing(self):
        self.perform(self.arguments("install", "1.0.0"))
        service = self.service_unit()
        unit_section = service[:service.index("[Service]")]

        def value(lines, key):
            [line] = [line for line in lines if line.startswith(key + "=")]
            return int(line.split("=", 1)[1])

        burst = value(unit_section, "StartLimitBurst")
        interval = value(unit_section, "StartLimitIntervalSec")
        start = value(service, "TimeoutStartSec")
        stop = value(service, "TimeoutStopSec")
        restart = value(service, "RestartSec")
        self.assertEqual((burst, interval, start, stop, restart), (5, 1200, 60, 90, 5))
        # The refused (burst + 1)-th start comes at most burst attempts after
        # the first. An attempt that hangs lasts TimeoutStartSec, then (it
        # ignores SIGTERM) TimeoutStopSec before SIGKILL, then RestartSec
        # (PR #392 P2): still inside the window.
        self.assertFalse(any(line.startswith(("TimeoutStartFailureMode=", "TimeoutSec=",
                                              "ExecStopPost=", "ExecStop="))
                             for line in service))
        self.assertLess(burst * (start + stop + restart), interval)

    def test_update_repairs_and_rollback_leaves_the_notice_alone(self):
        self.perform(self.arguments("install", "1.0.0"))
        expected_unit = self.notice_unit.read_bytes()
        expected_script = self.notice_script.read_bytes()
        # An installation from before Issue #321: update adds them.
        expected = {path: path.read_bytes() for path in self.notice_files}
        for path in self.notice_files:
            path.unlink()
        self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual({path: path.read_bytes() for path in self.notice_files}, expected)
        # An installer-placed file with other text or a widened mode is rewritten.
        self.notice_script.chmod(0o644)
        self.notice_script.write_bytes(expected_script + b"# edited\n")
        self.notice_script.chmod(0o666)
        self.notice_unit.write_bytes(expected_unit + b"ExecStartPre=/bin/true\n")
        self.perform(self.arguments("update", "1.2.0"))
        self.assertEqual(self.notice_unit.read_bytes(), expected_unit)
        self.assertEqual(self.notice_script.read_bytes(), expected_script)
        self.assertEqual(stat.S_IMODE(self.notice_script.stat().st_mode), 0o444)
        inodes = (self.notice_unit.stat().st_ino, self.notice_script.stat().st_ino)
        self.perform(self.arguments("update", "1.3.0"))  # unchanged: left alone
        self.perform(self.arguments("rollback"))
        self.assertEqual((self.notice_unit.stat().st_ino, self.notice_script.stat().st_ino), inodes)

    def test_foreign_files_are_refused_before_any_change(self):
        arguments = self.arguments("install", "1.0.0")
        for path_name in ("notice_unit", "watch_unit", "watch_timer", "notice_script"):
            for kind in ("text", "symlink", "directory"):
                with self.subTest(path=path_name, kind=kind):
                    path = getattr(self, path_name)
                    # An existing installation root holds releases/.
                    (self.installation / "releases").mkdir(parents=True, exist_ok=True)
                    if kind == "text":
                        path.write_text("[Service]\nExecStart=/usr/bin/owner-helper\n")
                    elif kind == "symlink":
                        path.symlink_to(self.root / "deployment.json")
                    else:
                        path.mkdir()
                    calls = len(self.runner.calls)
                    with self.assertRaises(install.FailureNoticeConflict) as refused:
                        self.perform(arguments)
                    message = str(refused.exception)
                    self.assertIn("refused before any change", message)
                    self.assertIn(str(path), message)
                    self.assertFalse(self.unit.exists())
                    self.assertFalse((self.installation / "releases/1.0.0").exists())
                    self.assertEqual(len(self.runner.calls), calls)
                    if kind == "directory":
                        path.rmdir()
                    else:
                        self.assertTrue(path.is_symlink() or "owner-helper" in path.read_text())
                        path.unlink()
        self.perform(arguments)
        self.notice_unit.unlink()
        self.notice_unit.write_text("# the Owner's own unit\n")
        before = self.unit.read_text()
        with self.assertRaises(install.FailureNoticeConflict):
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(self.notice_unit.read_text(), "# the Owner's own unit\n")
        self.assertEqual(self.unit.read_text(), before)
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertFalse((self.installation / "releases/1.1.0").exists())

    def test_a_placed_file_not_owned_by_root_is_rewritten(self):
        self.perform(self.arguments("install", "1.0.0"))
        arguments = self.arguments("update", "1.1.0")
        for path, mode in ((self.notice_unit, 0o644), (self.notice_script, 0o444)):
            with self.subTest(path=path.name):
                with patch("install.RELEASE_OWNER_UID", self.uid):
                    self.assertEqual(install._existing_failure_notice(arguments, path, mode),
                                     path.read_bytes())
                # The patched "root" is the test account; any other owner differs.
                with patch("install.RELEASE_OWNER_UID", self.uid + 1):
                    self.assertEqual(install._existing_failure_notice(arguments, path, mode), b"")

    def test_failed_install_removes_only_notice_files_it_created(self):
        self.runner.fail_version = "1.0.0"
        arguments = self.arguments("install", "1.0.0")
        with self.assertRaises(OSError):
            self.perform(arguments)
        for path in self.notice_files:
            self.assertFalse(path.exists())
        self.assertFalse(self.unit.exists())
        # A placed file from an earlier attempt stays.
        script = (SERVER / "failure_notice.py").read_bytes()
        self.notice_script.write_bytes(script)
        self.notice_script.chmod(0o444)
        with self.assertRaises(OSError):
            self.perform(arguments)
        self.assertEqual(self.notice_script.read_bytes(), script)
        self.assertFalse(self.notice_unit.exists())

    def test_failed_notice_fsync_leaves_no_created_file_behind(self):
        real_fsync = install._fsync_directory

        def fail_for_script(path):
            if Path(path) == self.installation:
                raise OSError("synthetic fsync failure")
            real_fsync(path)

        arguments = self.arguments("install", "1.0.0")
        with patch("install._fsync_directory", side_effect=fail_for_script):
            with self.assertRaises(OSError):
                self.perform(arguments)
        for path in self.notice_files:
            self.assertFalse(path.exists())
        self.assertFalse(self.unit.exists())
        self.perform(arguments)
        self.assertTrue(self.notice_script.exists())

    def test_failed_update_keeps_the_notice(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.notice_unit.unlink()
        self.runner.fail_version = "1.1.0"
        with self.assertRaises(OSError):
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertTrue(self.notice_unit.exists())
        self.assertIn("OnFailure=server-sentinel-failure-notice.service", self.service_unit())

    def test_notice_is_placed_before_systemd_reloads(self):
        order = []
        real = install._place_failure_notice

        def place(files):
            order.append("place")
            return real(files)

        original = self.runner.__call__

        def runner(arguments, **options):
            if arguments[:2] == ["systemctl", "daemon-reload"]:
                order.append("reload")
            return original(arguments, **options)

        self.runner = runner
        with patch("install._place_failure_notice", side_effect=place):
            self.perform(self.arguments("install", "1.0.0"))
        self.assertEqual(order[:2], ["place", "reload"])

    def test_unrenderable_values_are_refused(self):
        account = pwd.getpwuid(self.uid)
        for root, python in (("relative", "/usr/bin/python3"), ("/opt/../etc", "/usr/bin/python3"),
                             ("/opt/x", "python3"), ("/opt/$x", "/usr/bin/python3"),
                             ("/opt/x", "/usr/bin/python3\n")):
            with self.subTest(root=root, python=python), self.assertRaises(ValueError):
                install.render_failure_notice_unit(Path(root), self.config, account, Path(python))
        bad = pwd.struct_passwd(("bad name",) + tuple(account)[1:])
        with self.assertRaises(ValueError):
            install.render_failure_notice_unit(self.installation, self.config, bad,
                                               Path("/usr/bin/python3"))

    def test_standalone_installer_ships_the_script_unchanged(self):
        installer = self.root / "server-sentinel-installer.pyz"
        with patch("build_installer.REPOSITORY", self.root):
            build_installer(installer)
        with zipfile.ZipFile(installer) as archive:
            shipped = archive.read("failure_notice.py")
        self.assertEqual(shipped, (SERVER / "failure_notice.py").read_bytes())
        # The installer reads it from inside the zipapp, as it does on a host.
        probe = ("import sys; sys.path.insert(0, sys.argv[1]); import install; "
                 "sys.stdout.buffer.write(install.failure_notice_source())")
        result = subprocess.run([sys.executable, "-I", "-c", probe, str(installer)], cwd="/",
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, shipped)

    def test_source_marker_is_the_first_line(self):
        source = install.failure_notice_source()
        self.assertEqual(source.split(b"\n", 1)[0], install.FAILURE_NOTICE_MARKER.encode())
        with patch.object(install.failure_notice.__loader__, "get_data",
                          return_value=b"# other\n"), self.assertRaises(ValueError):
            install.failure_notice_source()


if __name__ == "__main__":
    unittest.main()
