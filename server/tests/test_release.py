import argparse
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch
import zipfile

from app.deployment import (
    Deployment, _approved_filesystem_device, main as deployment_main,
)
from app.settings import ConfigurationError
from build_artifact import _required_wheels, build
from build_installer import build as build_installer
import install
from install import (
    _extract, _protected_parent, _release_lock, _trusted_python, _unit_path, execute,
    render_unit,
)


def _hold_release_lock(unit, acquired, release):
    with _release_lock(Path(unit)):
        acquired.set()
        release.wait(5)


class Runner:
    """Synthetic subprocess runner that models the dedicated-account preflight.

    The installer drops to a different, unprivileged account for its preflight.
    A test process cannot actually become that account, so model the part that
    matters here: every directory the installer asks that account to enter must
    be readable and traversable by an account that is neither the owner nor a
    member of the owning group.
    """

    def __init__(self, root: Path):
        self.root = root
        self.calls = []
        self.fail_version = None
        # ``systemctl show -p <property> --value server-sentinel-upstream.socket``:
        # a value (exit 0), an ``(exit code, output)`` pair, or an exception.
        # By default no unit file and not running.
        self.socket_state = {"LoadState": "not-found", "ActiveState": "inactive"}

    def _check_foreign_account_access(self, options) -> None:
        if options.get("user") is None:
            return
        working_directory = Path(options["cwd"]).resolve()
        installation = self.root.resolve()
        if not working_directory.is_relative_to(installation):
            raise OSError("preflight working directory escaped the installation root")
        candidates = [installation, working_directory]
        candidates.extend(
            parent for parent in working_directory.parents
            if parent.is_relative_to(installation)
        )
        for candidate in candidates:
            if candidate.stat().st_mode & 0o005 != 0o005:
                raise OSError(
                    "dedicated account cannot traverse the installation tree"
                )

    def __call__(self, arguments, **options):
        self.calls.append((arguments, options))
        self._check_foreign_account_access(options)
        if arguments[1:4] == ["-I", "-m", "venv"]:
            python = Path(arguments[4]) / "bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("synthetic")
        if (arguments[:3] == ["systemctl", "show", "-p"] and arguments[3] in self.socket_state
                and arguments[4:] == ["--value", install.UPSTREAM_SOCKET_UNIT]):
            value = self.socket_state[arguments[3]]
            if isinstance(value, BaseException):
                raise value
            code, output = value if isinstance(value, tuple) else (0, value + "\n")
            return SimpleNamespace(returncode=code, stdout=output)
        if arguments[:2] == ["systemctl", "restart"] and self.fail_version:
            current = os.readlink(self.root / "current")
            if current == "releases/" + self.fail_version:
                raise OSError("synthetic service startup failure")
        return object()


class ReleaseLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="server-release-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.installation = self.root / "installation"
        self.unit = self.root / "server-sentinel.service"
        self.runtime = self.root / "runtime"
        self.uid = os.geteuid()
        self.gid = os.getegid()
        for path in (self.runtime, self.runtime / "state", self.runtime / "recordings",
                     self.runtime / "audit"):
            path.mkdir(mode=0o700)
        self.config = self.root / "deployment.json"
        device = self.runtime.stat().st_dev
        self.filesystem_uuid = "00000000-1111-2222-3333-444444444444"
        self.config.write_text(json.dumps({
            "runtime_root": str(self.runtime),
            "runtime_mount_point": str(self.root),
            "runtime_device": [os.major(device), os.minor(device)],
            "runtime_filesystem_uuid": self.filesystem_uuid, "capture_ca_directory": None,
            "service_uid": self.uid,
            "human_host": "127.0.0.1",
            "human_port": 8000,
            "log_level": "INFO",
        }))
        self.config.chmod(0o600)
        self.wheelhouse = self.root / "wheels"
        self.wheelhouse.mkdir()
        (self.root / "LICENSE").write_text("synthetic Apache-2.0 fixture")
        (self.root / "NOTICE").write_text("synthetic notice fixture")
        for line in (Path(__file__).parents[1] / "requirements.lock").read_text().splitlines():
            if "==" in line and line.endswith(" \\"):
                name, version = line[:-2].split("==")
                name = name.replace("-", "_").replace(".", "_")
                (self.wheelhouse / f"{name}-{version}-py3-none-any.whl").write_bytes(
                    (name + version).encode()
                )
        self.runner = Runner(self.installation)
        # Issue #180: a fake root prefix for /usr/local/sbin; nothing is
        # written outside the temporary tree.
        self.wrapper = self.root / "usr/local/sbin/serversentinel-pairing"
        self.wrapper.parent.mkdir(parents=True)

    def artifact(self, version):
        path = self.root / ("server-sentinel-" + version + ".tar.gz")
        wheels = sorted(self.wheelhouse.glob("*.whl"))
        with patch("build_artifact.REPOSITORY", self.root), patch(
                "build_artifact._required_wheels", return_value=wheels):
            digest = build(path, version, self.wheelhouse)
        return path, digest

    def arguments(self, command, version=None):
        values = dict(command=command, destination=self.installation, config=self.config,
                      unit=self.unit, version=version)
        if command in {"install", "update"}:
            artifact, digest = self.artifact(version)
            values.update(artifact=artifact, sha256=digest, python=Path(sys.executable))
        return argparse.Namespace(**values)

    def perform(self, arguments, *, mount=True, root_device=None, approved_device=None,
                private_tmp=(Path("/nonexistent-private-temporary-root"),),
                protected_home=(Path("/nonexistent-protected-home-root"),)):
        account = pwd.getpwuid(self.uid)
        if root_device is None:
            # The fixture's temporary runtime directory ordinarily shares the
            # test runner's filesystem.  Model the separately mounted runtime
            # volume that a real installation requires.
            root_device = self.runtime.stat().st_dev + 1
        # A test process cannot create a block device node, so resolve the
        # Owner-approved filesystem UUID through an injected lookup.  By default
        # it still carries the fixture's runtime filesystem.
        uuid_lookup = self.approved_device_lookup(approved_device)
        with patch("install.os.geteuid", return_value=0), patch(
                "install.SYSTEMD_UNIT", self.unit), patch("install._protected_parent"), patch(
                "install._trusted_python", side_effect=lambda path: path.resolve()), patch(
                "install._installed_unit", side_effect=lambda path: path.read_text()), patch(
                "app.deployment.os.path.ismount", return_value=mount), patch(
                "app.deployment._operating_system_root_device", return_value=root_device), patch(
                "app.deployment.ADMINISTRATOR_UID", self.uid), patch(
                "app.deployment._approved_filesystem_device", side_effect=uuid_lookup), patch(
                "install.PRIVATE_TMP_ROOTS", private_tmp), patch(
                "install.PROTECTED_HOME_ROOTS", protected_home), patch(
                "install.pwd.getpwuid", return_value=account), patch(
                "install.PAIRING_WRAPPER", self.wrapper), patch(
                "install.PAIRING_WRAPPER_OWNER", (self.uid, self.gid)):
            execute(arguments, runner=self.runner)

    def approved_device_lookup(self, approved_device=None):
        expected = self.filesystem_uuid
        device = self.runtime.stat().st_dev if approved_device is None else approved_device

        def lookup(uuid):
            if uuid != expected:
                raise ConfigurationError("approved runtime filesystem is unavailable")
            return device

        return lookup

    def test_install_update_and_rollback_preserve_external_runtime_data(self):
        markers = []
        for directory in (self.runtime / "state", self.runtime / "recordings",
                          self.runtime / "audit"):
            marker = directory / "preserved.synthetic"
            marker.write_text(directory.name)
            markers.append(marker)

        with patch("install._release_lock", wraps=_release_lock) as release_lock:
            self.perform(self.arguments("install", "1.0.0"))
            self.perform(self.arguments("update", "1.1.0"))
            self.perform(self.arguments("rollback"))
        self.assertEqual(
            release_lock.call_args_list,
            [call(self.unit), call(self.unit), call(self.unit)],
        )
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        unit = self.unit.read_text()
        self.assertIn("User=" + pwd.getpwuid(self.uid).pw_name, unit)
        self.assertIn(
            "\nWorkingDirectory=" + str(self.installation / "current") + "\n", unit
        )
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("Type=notify", unit)
        self.assertIn("NotifyAccess=main", unit)
        self.assertNotIn("Type=simple", unit)
        self.assertNotIn("0.0.0.0", unit)

        self.assertEqual(os.readlink(self.installation / "previous"), "releases/1.1.0")
        self.assertEqual(
            [marker.read_text() for marker in markers], ["state", "recordings", "audit"]
        )

    def test_release_lock_excludes_an_overlapping_process(self):
        context = multiprocessing.get_context("fork")
        acquired = context.Event()
        release = context.Event()
        process = context.Process(
            target=_hold_release_lock,
            args=(str(self.unit), acquired, release),
        )
        try:
            with _release_lock(self.unit):
                process.start()
                self.assertFalse(acquired.wait(0.2))
            self.assertTrue(acquired.wait(5))
        finally:
            release.set()
            if process.pid is not None:
                process.join(5)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
        self.assertEqual(process.exitcode, 0)

    def test_same_unit_serializes_destinations_and_restart_state(self):
        first_entered = threading.Event()
        allow_first_to_finish = threading.Event()
        second_entered = threading.Event()
        errors = []
        restart_states = []
        active = 0
        state_lock = threading.Lock()

        def operation(arguments, _runner):
            nonlocal active
            with state_lock:
                active += 1
                overlap = active > 1
                first = not first_entered.is_set()
            if overlap:
                errors.append(AssertionError("release operations overlapped"))
            current = arguments.destination / "synthetic-current"
            arguments.unit.write_text(str(arguments.destination))
            current.write_text(str(arguments.destination))
            try:
                if first:
                    first_entered.set()
                    allow_first_to_finish.wait(5)
                else:
                    second_entered.set()
                restart_states.append((arguments.unit.read_text(), current.read_text()))
                _runner(["systemctl", "restart", "server-sentinel.service"], check=True)
            finally:
                with state_lock:
                    active -= 1

        first_arguments = self.arguments("rollback")
        second_arguments = self.arguments("rollback")
        second_arguments.destination = self.root / "other-installation"

        def invoke(arguments):
            try:
                execute(arguments, runner=self.runner)
            except Exception as error:
                errors.append(error)

        first = threading.Thread(target=invoke, args=(first_arguments,))
        second = threading.Thread(target=invoke, args=(second_arguments,))
        with patch("install.os.geteuid", return_value=0), patch(
                "install.SYSTEMD_UNIT", self.unit), patch(
                "install._protected_parent"), patch("install._execute_locked",
                                                    side_effect=operation):
            first.start()
            try:
                self.assertTrue(first_entered.wait(5))
                second.start()
                self.assertFalse(second_entered.wait(0.2))
            finally:
                allow_first_to_finish.set()
                first.join(5)
                if second.ident is not None:
                    second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(second_entered.is_set())
        self.assertEqual(restart_states, [
            (str(first_arguments.destination), str(first_arguments.destination)),
            (str(second_arguments.destination), str(second_arguments.destination)),
        ])

    def test_alternate_systemd_unit_path_is_rejected_before_mutation(self):
        arguments = self.arguments("rollback")
        arguments.unit = self.root / "alternate" / "server-sentinel.service"
        arguments.unit.parent.mkdir()
        with patch("install.os.geteuid", return_value=0), self.assertRaisesRegex(
                ValueError, "supported system path"):
            execute(arguments, runner=self.runner)
        self.assertFalse(self.installation.exists())
        self.assertEqual(list(arguments.unit.parent.iterdir()), [])

    def test_release_lock_rejects_unsafe_files_and_does_not_reenter(self):
        lock = self.root / ".server-sentinel.service.release.lock"
        target = self.root / "lock-target"
        target.write_text("")
        lock.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            with _release_lock(self.unit):
                self.fail("unsafe lock acquired")
        lock.unlink()

        lock.write_text("")
        lock.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "invalid"):
            with _release_lock(self.unit):
                self.fail("unsafe lock acquired")
        lock.chmod(0o600)

        with _release_lock(self.unit):
            with self.assertRaisesRegex(ValueError, "still running"):
                with _release_lock(self.unit, timeout=0):
                    self.fail("release lock reentered")

    def test_release_lock_checks_owner_and_releases_after_failure(self):
        lock = self.root / ".server-sentinel.service.release.lock"
        lock.write_text("")
        lock.chmod(0o600)
        actual = lock.stat()
        unsafe = type("UnsafeLock", (), {
            "st_mode": actual.st_mode,
            "st_nlink": actual.st_nlink,
            "st_uid": actual.st_uid + 1,
        })()
        with patch("install.os.fstat", return_value=unsafe):
            with self.assertRaisesRegex(ValueError, "invalid"):
                with _release_lock(self.unit):
                    self.fail("wrong-owner lock acquired")

        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            with _release_lock(self.unit):
                raise RuntimeError("synthetic")
        with _release_lock(self.unit, timeout=0):
            pass

    def test_failed_update_restores_running_release_and_runtime_data(self):
        marker = self.runtime / "state/preserved.synthetic"
        marker.write_text("unchanged")
        self.perform(self.arguments("install", "1.0.0"))
        self.runner.fail_version = "2.0.0"
        with self.assertRaises(OSError):
            self.perform(self.arguments("update", "2.0.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertFalse((self.installation / "previous").exists())
        self.assertEqual(marker.read_text(), "unchanged")
        restarts = [call for call, _ in self.runner.calls if call[:2] == ["systemctl", "restart"]]
        self.assertGreaterEqual(len(restarts), 3)

    def test_update_replaces_service_definition_and_restores_it_on_failed_activation(self):
        self.perform(self.arguments("install", "1.0.0"))
        original = self.unit.read_text()
        with patch("install.render_unit", return_value="[Service]\nProtectSystem=strict\n"):
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(self.unit.read_text(), "[Service]\nProtectSystem=strict\n")
        self.perform(self.arguments("rollback"))
        self.assertEqual(self.unit.read_text(), original)

        with patch("install.render_unit", return_value="[Service]\nProtectSystem=strict\n"):
            self.perform(self.arguments("update", "1.2.0"))

        self.runner.fail_version = "1.3.0"
        with patch("install.render_unit", return_value="[Service]\nProtectHome=true\n"):
            with self.assertRaises(OSError):
                self.perform(self.arguments("update", "1.3.0"))
        self.assertEqual(self.unit.read_text(), "[Service]\nProtectSystem=strict\n")
        self.assertNotEqual(self.unit.read_text(), original)

    def test_missing_runtime_tree_and_public_listener_fail_before_artifact_install(self):
        (self.runtime / "recordings").rmdir()
        with self.assertRaises(ConfigurationError):
            self.perform(self.arguments("install", "1.0.0"))
        self.assertFalse((self.runtime / "recordings").exists())
        self.assertFalse((self.installation / "releases").exists())

        (self.runtime / "recordings").mkdir(mode=0o700)
        value = json.loads(self.config.read_text())
        value["runtime_device"][1] += 1
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        with self.assertRaisesRegex(ConfigurationError, "filesystem identity"):
            self.perform(self.arguments("install", "1.0.1"))

        value = json.loads(self.config.read_text())
        device = self.runtime.stat().st_dev
        value["runtime_device"] = [os.major(device), os.minor(device)]
        value["human_host"] = "0.0.0.0"
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        with self.assertRaises(ConfigurationError):
            self.perform(self.arguments("install", "1.0.2"))
        self.assertFalse((self.installation / "releases").exists())

    def test_configuration_and_runtime_cannot_live_in_release_tree(self):
        # Model runtime data placed inside a real installation root, so the
        # containment check runs rather than the destination adoption guard.
        self.installation.mkdir(mode=0o755)
        (self.installation / "releases").mkdir(mode=0o755)
        internal = self.installation / "runtime"
        for path in (internal, internal / "state", internal / "recordings", internal / "audit"):
            path.mkdir(mode=0o700)
        value = json.loads(self.config.read_text())
        value["runtime_root"] = str(internal)
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        with self.assertRaises(ConfigurationError):
            self.perform(self.arguments("install", "1.0.0"))

        value["runtime_root"] = str(self.runtime)
        internal_config = self.installation / "deployment.json"
        internal_config.write_text(json.dumps(value))
        internal_config.chmod(0o600)
        self.config = internal_config
        with self.assertRaises(ConfigurationError):
            self.perform(self.arguments("install", "1.0.1"))

    def test_runtime_subdirectory_symlink_cannot_escape_approved_root(self):
        state = self.runtime / "state"
        state.rmdir()
        outside = self.root / "external-state"
        outside.mkdir(mode=0o700)
        state.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ConfigurationError, "escapes"):
            self.perform(self.arguments("install", "1.0.0"))
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.installation / "releases").exists())

    def test_runtime_mount_point_must_be_an_actual_mount(self):
        with self.assertRaisesRegex(ConfigurationError, "filesystem identity"):
            self.perform(self.arguments("install", "1.0.0"), mount=False)
        self.assertFalse((self.installation / "releases").exists())

    def test_runtime_mount_point_cannot_be_the_root_filesystem(self):
        value = json.loads(self.config.read_text())
        value["runtime_mount_point"] = "/"
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        with self.assertRaisesRegex(ConfigurationError, "must not be root"):
            self.perform(self.arguments("install", "1.0.0"))
        self.assertFalse((self.installation / "releases").exists())

    def test_runtime_mount_cannot_be_backed_by_the_root_filesystem_device(self):
        with self.assertRaisesRegex(ConfigurationError, "root filesystem device"):
            self.perform(
                self.arguments("install", "1.0.0"),
                root_device=self.runtime.stat().st_dev,
            )
        self.assertFalse((self.installation / "releases").exists())

    def test_artifact_is_versioned_allow_list_without_tests_or_private_config(self):
        artifact, digest = self.artifact("1.2.3")
        self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), digest)
        with tarfile.open(artifact, "r:gz") as archive:
            names = archive.getnames()
        self.assertIn("manifest.json", names)
        self.assertIn("app/deployment.py", names)
        self.assertTrue(any(name.startswith("wheels/fastapi-") for name in names))
        self.assertFalse(any("test" in name or name.endswith("deployment.json") for name in names))

    def test_builder_rejects_wheel_not_approved_by_lock_hash(self):
        with self.assertRaisesRegex(ValueError, "unreviewed"):
            _required_wheels(self.wheelhouse)

    def test_standalone_installer_does_not_require_checkout(self):
        installer = self.root / "server-sentinel-installer.pyz"
        with patch("build_installer.REPOSITORY", self.root):
            digest = build_installer(installer)
        self.assertEqual(hashlib.sha256(installer.read_bytes()).hexdigest(), digest)
        result = subprocess.run(
            ["python3", str(installer), "--help"], cwd="/", text=True,
            capture_output=True, check=True,
        )
        self.assertIn("Install, update or roll back", result.stdout)
        with zipfile.ZipFile(installer) as archive:
            names = archive.namelist()
        self.assertIn("install.py", names)
        self.assertIn("app/deployment.py", names)
        self.assertFalse(any("test" in name or name.endswith(".pyc") for name in names))

    def test_explicit_rollback_target_must_already_be_installed(self):
        self.perform(self.arguments("install", "1.0.0"))
        with self.assertRaises(ValueError):
            self.perform(self.arguments("rollback", "9.9.9"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")

    def test_rollback_version_rejects_path_traversal_before_switch(self):
        self.perform(self.arguments("install", "1.0.0"))
        calls = len(self.runner.calls)
        for version in ("../1.0.0", "1.0.0/..", "/tmp/release", ".", "1.0"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "version"):
                self.perform(self.arguments("rollback", version))
            self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
            self.assertEqual(len(self.runner.calls), calls)

    def test_relative_configuration_path_is_rejected_before_release_staging(self):
        arguments = self.arguments("install", "1.0.0")
        arguments.config = Path("deployment.json")
        with self.assertRaisesRegex(ValueError, "absolute"):
            self.perform(arguments)
        self.assertFalse((self.installation / "releases").exists())

    def test_archive_total_expansion_is_bounded(self):
        first, second = b"a" * 600, b"b" * 600
        manifest = {
            "format": 1,
            "name": "server-sentinel-main",
            "version": "1.0.0",
            "files": {
                "first": hashlib.sha256(first).hexdigest(),
                "second": hashlib.sha256(second).hexdigest(),
            },
        }
        archive_data = io.BytesIO()
        with tarfile.open(fileobj=archive_data, mode="w:gz") as archive:
            for name, content in (("manifest.json", json.dumps(manifest).encode()),
                                  ("first", first), ("second", second)):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        with tempfile.TemporaryDirectory() as temporary, patch("install.MAX_ARTIFACT_BYTES", 1024):
            with self.assertRaisesRegex(ValueError, "contents exceed"):
                _extract(archive_data.getvalue(), Path(temporary), "1.0.0")

    def test_untrusted_or_symlinked_installation_ancestor_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(private, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "root-controlled"):
                _protected_parent(link)

    def test_root_python_helpers_are_isolated_from_invocation_directory(self):
        shadow = self.root / "venv.py"
        shadow.write_text("raise RuntimeError('must not execute')")
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            self.perform(self.arguments("install", "1.0.0"))
        finally:
            os.chdir(previous)
        root_helpers = [entry for entry in self.runner.calls
                        if "venv" in entry[0] or "pip" in entry[0]]
        self.assertEqual(len(root_helpers), 2)
        for arguments, options in root_helpers:
            self.assertIn("-I", arguments)
            self.assertEqual(options["cwd"], "/")
            self.assertEqual(options["env"]["PATH"], "/usr/bin:/bin")
            self.assertNotIn("PYTHONPATH", options["env"])
            self.assertNotIn("PYTHONHOME", options["env"])

    def test_release_build_uses_safe_umask_and_restores_the_administrator_setting(self):
        previous = os.umask(0o077)
        try:
            self.perform(self.arguments("install", "1.0.0"))
            observed = os.umask(0o077)
            os.umask(observed)
        finally:
            os.umask(previous)
        self.assertEqual(observed, 0o077)
        self.assertEqual(self.installation.stat().st_mode & 0o777, 0o755)
        release = self.installation / "releases/1.0.0"
        self.assertEqual(release.stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.installation / "releases").stat().st_mode & 0o777, 0o755)

    def test_single_path_directives_are_rendered_without_command_line_quoting(self):
        account = pwd.getpwuid(self.uid)
        code_root = self.root / "code"
        code_root.mkdir()
        with patch("app.deployment.ADMINISTRATOR_UID", self.uid), patch(
                "app.deployment._approved_filesystem_device",
                side_effect=self.approved_device_lookup()), patch(
                "app.deployment.os.path.ismount", return_value=True), patch(
                "app.deployment._operating_system_root_device",
                return_value=self.runtime.stat().st_dev + 1):
            deployment = Deployment.load(self.config, code_root=code_root)
        unit = render_unit(self.installation, self.config, deployment, account,
                           socket_activation=True)
        working = [line for line in unit.splitlines()
                   if line.startswith("WorkingDirectory=")]
        self.assertEqual(working, ["WorkingDirectory=" + str(self.installation / "current")])
        # Write access is granted to the runtime subdirectories only, so the
        # service account cannot replace or remove them or the runtime root.
        writable = [line for line in unit.splitlines()
                    if line.startswith("ReadWritePaths=")]
        self.assertEqual(writable, ['ReadWritePaths="' + str(self.runtime / "state")
                                    + '" "' + str(self.runtime / "recordings")
                                    + '" "' + str(self.runtime / "audit") + '"'])
        self.assertNotIn('ReadWritePaths="' + str(self.runtime) + '"', unit)
        self.assertIn('RequiresMountsFor="' + str(self.runtime) + '"', unit)
        # Issue #126: the upstream is passed by its .socket unit, and the
        # unprivileged sock_diag lookup needs AF_NETLINK, the host network
        # namespace and the host cgroup view.
        lines = unit.splitlines()
        self.assertIn("Sockets=server-sentinel-upstream.socket", lines)
        # Only for a release that accepts the socket (PR #153 review): Sockets=
        # implies Wants=/After= on the socket unit.
        legacy = render_unit(self.installation, self.config, deployment, account)
        self.assertNotIn("server-sentinel-upstream.socket", legacy)
        self.assertEqual([line for line in lines if "server-sentinel-upstream.socket" not in line],
                         legacy.splitlines())
        with self.assertRaises(ValueError):
            render_unit(self.installation, self.config, deployment, account, socket_activation=1)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", lines)
        self.assertIn("ProtectControlGroups=true", lines)
        self.assertFalse(any(line.startswith(("PrivateNetwork=", "NetworkNamespacePath=", "PrivateUsers="))
                             for line in lines))
        self.assertIn("CapabilityBoundingSet=", lines)
        self.assertIn("AmbientCapabilities=", lines)
        # systemd would keep command-line quotes as part of this single path and
        # reject the unit with "path is not absolute".
        self.assertNotIn('"', working[0])
        self.assertTrue(working[0].partition("=")[2].startswith("/"))

        for unsafe in ("relative/current", "/srv/current\n[Service]", "/srv/current ",
                       "/srv/current\\"):
            with self.subTest(path=unsafe), self.assertRaisesRegex(ValueError, "systemd path"):
                _unit_path(unsafe)
        # The specifier character is the only escaping this directive needs.
        self.assertEqual(_unit_path("/srv/100%/current"), "/srv/100%%/current")

    def test_restrictive_umask_keeps_the_installation_root_account_traversable(self):
        previous = os.umask(0o077)
        try:
            self.perform(self.arguments("install", "1.0.0"))
            self.perform(self.arguments("update", "1.1.0"))
        finally:
            os.umask(previous)
        preflights = [options for arguments, options in self.runner.calls
                      if options.get("user") is not None]
        self.assertEqual(len(preflights), 2)
        for options in preflights:
            self.assertEqual(options["user"], self.uid)
            self.assertEqual(options["extra_groups"], [])
        for path in (self.installation, self.installation / "releases",
                     self.installation / "releases/1.0.0",
                     self.installation / "releases/1.1.0"):
            self.assertEqual(path.stat().st_mode & 0o005, 0o005, path)

    def test_failed_release_pointer_write_restores_both_pointers_and_the_unit(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.1.0")
        self.assertEqual(os.readlink(self.installation / "previous"), "releases/1.0.0")
        installed_unit = self.unit.read_text()
        restarts = len([call for call, _ in self.runner.calls
                        if call[:2] == ["systemctl", "restart"]])

        real_set_link = install._set_link

        def failing_set_link(root, name, target):
            if name == "current":
                raise OSError("synthetic pointer write failure")
            return real_set_link(root, name, target)

        with patch("install._set_link", side_effect=failing_set_link):
            with patch("install.render_unit", return_value="[Service]\nProtectHome=true\n"):
                with self.assertRaises(OSError):
                    self.perform(self.arguments("update", "1.2.0"))

        # The rollback history must not be corrupted by the failed transaction.
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.1.0")
        self.assertEqual(os.readlink(self.installation / "previous"), "releases/1.0.0")
        self.assertEqual(self.unit.read_text(), installed_unit)
        self.assertGreater(
            len([call for call, _ in self.runner.calls
                 if call[:2] == ["systemctl", "restart"]]),
            restarts,
        )

    def test_recovery_continues_after_an_individual_restoration_failure(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.perform(self.arguments("update", "1.1.0"))
        real_set_link = install._set_link
        attempts = []

        def failing_set_link(root, name, target):
            attempts.append((name, target))
            if name == "current" and target == "releases/1.2.0":
                raise OSError("synthetic pointer write failure")
            if name == "current" and target == "releases/1.1.0":
                raise OSError("synthetic restoration failure")
            return real_set_link(root, name, target)

        with patch("install._set_link", side_effect=failing_set_link):
            with self.assertRaises(OSError):
                self.perform(self.arguments("update", "1.2.0"))
        # A failure restoring `current` must not skip `previous` restoration.
        self.assertIn(("previous", "releases/1.0.0"), attempts)
        self.assertEqual(os.readlink(self.installation / "previous"), "releases/1.0.0")

    def test_fresh_install_never_creates_a_writable_service_unit(self):
        created_modes = {}
        real_open = install.os.open

        def recording_open(path, flags, mode=0o777, **options):
            if str(path) == str(self.unit) and flags & os.O_CREAT:
                created_modes[str(path)] = mode
            return real_open(path, flags, mode, **options)

        previous = os.umask(0o000)
        try:
            with patch("install.os.open", side_effect=recording_open):
                self.perform(self.arguments("install", "1.0.0"))
        finally:
            os.umask(previous)
        # Under a permissive administrator umask the creation mode itself has to
        # be restrictive; a later chmod would leave a writable-descriptor window.
        self.assertEqual(created_modes.get(str(self.unit)), 0o644)
        self.assertEqual(self.unit.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.unit.stat().st_mode & 0o022, 0)

    def test_fresh_install_does_not_clobber_an_existing_service_unit(self):
        self.unit.write_text("[Service]\nExecStart=/bin/false\n")
        with self.assertRaisesRegex(ValueError, "already installed"):
            self.perform(self.arguments("install", "1.0.0"))
        self.assertEqual(self.unit.read_text(), "[Service]\nExecStart=/bin/false\n")

    def test_replaced_runtime_filesystem_is_refused_by_the_approved_uuid(self):
        self.perform(self.arguments("install", "1.0.0"))
        # A reformatted or swapped disk keeps the mount path, directory layout
        # and Linux major/minor pair, but never the approved filesystem UUID.
        with self.assertRaisesRegex(ConfigurationError, "filesystem identity mismatch"):
            self.perform(
                self.arguments("update", "1.1.0"),
                approved_device=self.runtime.stat().st_dev + 7,
            )
        self.assertFalse((self.installation / "releases/1.1.0").exists())
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")

        value = json.loads(self.config.read_text())
        value["runtime_filesystem_uuid"] = "99999999-8888-7777-6666-555555555555"
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        with self.assertRaisesRegex(ConfigurationError, "unavailable"):
            self.perform(self.arguments("update", "1.1.1"))
        self.assertFalse((self.installation / "releases/1.1.1").exists())

    def test_approved_filesystem_uuid_lookup_rejects_unsafe_and_missing_entries(self):
        directory = self.root / "by-uuid"
        directory.mkdir()
        impostor = directory / "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        impostor.write_text("not a block device")
        with patch("app.deployment.FILESYSTEM_UUID_ROOT", directory):
            for uuid in ("../../etc/passwd", "/dev/sda1", "ab", "uuid with space",
                         "uuid\x00", 42, None):
                with self.subTest(uuid=uuid), self.assertRaisesRegex(
                        ConfigurationError, "invalid runtime filesystem identity"):
                    _approved_filesystem_device(uuid)
            with self.assertRaisesRegex(ConfigurationError, "unavailable"):
                _approved_filesystem_device("11111111-2222-3333-4444-555555555555")
            # A regular file standing in for the approved device is refused.
            with self.assertRaisesRegex(ConfigurationError, "unavailable"):
                _approved_filesystem_device(impostor.name)

    def test_dot_segment_installation_paths_are_refused_before_mutation(self):
        # abspath() strips ".." lexically, so a validated normalized path would
        # not be the location the kernel reaches through an intermediate
        # symbolic link.  Refuse dot segments outright.
        for field in ("destination", "config", "unit"):
            arguments = self.arguments("rollback")
            original = getattr(arguments, field)
            setattr(arguments, field, original.parent / ".." / original.parent.name
                    / original.name)
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "absolute installation paths required"):
                self.perform(arguments)
            self.assertFalse((self.installation / "releases").exists())
        with self.assertRaisesRegex(ValueError, "absolute installation paths required"):
            _protected_parent(self.root / "installation" / ".." / "installation")
        with self.assertRaisesRegex(ValueError, "absolute installation paths required"):
            _protected_parent(Path("relative/installation"))

    def test_configuration_under_a_private_temporary_directory_is_refused(self):
        # The unit sets PrivateTmp=true, so ExecStartPre could never reopen it.
        with self.assertRaisesRegex(ValueError, "private temporary directory"):
            self.perform(self.arguments("install", "1.0.0"), private_tmp=(self.root,))
        self.assertFalse((self.installation / "releases").exists())
        self.assertFalse(self.unit.exists())

    def test_deployment_paths_under_a_protected_home_are_refused(self):
        # ProtectHome=true empties /home, /root and /run/user inside the
        # service mount namespace, so each required path is checked separately.
        for root in (self.root, self.installation, self.runtime):
            with self.subTest(root=root):
                with self.assertRaisesRegex(ValueError, "protected home directory"):
                    self.perform(self.arguments("rollback"), protected_home=(root,))
        self.assertFalse((self.installation / "releases").exists())
        self.assertFalse(self.unit.exists())

    def test_existing_destination_that_is_not_an_installation_is_not_relaxed(self):
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        (foreign / "private.synthetic").write_text("unrelated administrator data")
        arguments = self.arguments("rollback")
        arguments.destination = foreign
        with self.assertRaisesRegex(ValueError, "not a ServerSentinel installation root"):
            self.perform(arguments)
        # The mistyped destination keeps its original restrictive mode.
        self.assertEqual(foreign.stat().st_mode & 0o777, 0o700)
        self.assertEqual((foreign / "private.synthetic").read_text(),
                         "unrelated administrator data")
        self.assertFalse((foreign / "releases").exists())
        self.assertFalse(self.unit.exists())

    def test_existing_empty_or_installed_destination_is_normalized(self):
        self.installation.mkdir(mode=0o700)
        self.perform(self.arguments("install", "1.0.0"))
        self.assertEqual(self.installation.stat().st_mode & 0o777, 0o755)
        # An existing installation root that the service cannot traverse is
        # reported instead of being silently widened.
        self.installation.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "unreachable by the service account"):
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(self.installation.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.installation / "releases/1.1.0").exists())
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")

    def test_runtime_directories_must_stay_usable_by_the_service_account(self):
        # Owner-only modes such as 0o000 or 0o500 pass a group/other check but
        # make later recording or audit writes fail, so readiness would be
        # announced for a runtime tree the service cannot actually use.
        for name in ("state", "recordings", "audit"):
            for mode in (0o000, 0o500, 0o600):
                directory = self.runtime / name
                directory.chmod(mode)
                try:
                    with self.subTest(directory=name, mode=oct(mode)):
                        with self.assertRaisesRegex(
                                ConfigurationError, "readable and writable by the service"):
                            self.perform(self.arguments("rollback"))
                        self.assertFalse((self.installation / "releases").exists())
                finally:
                    directory.chmod(0o700)
        self.runtime.chmod(0o500)
        try:
            with self.assertRaisesRegex(
                    ConfigurationError, "readable and writable by the service"):
                self.perform(self.arguments("rollback"))
        finally:
            self.runtime.chmod(0o700)
        self.assertFalse((self.installation / "releases").exists())

    def test_relative_runtime_mount_point_is_rejected_before_resolution(self):
        # resolve() would anchor a relative value to whichever directory the
        # caller happens to be in, which differs between the administrator and
        # the service resolving it from the release tree.
        value = json.loads(self.config.read_text())
        value["runtime_mount_point"] = os.path.relpath(self.root, "/")
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        previous = Path.cwd()
        try:
            os.chdir("/")
            with self.assertRaisesRegex(ConfigurationError, "must be absolute"):
                self.perform(self.arguments("rollback"))
        finally:
            os.chdir(previous)
        self.assertFalse((self.installation / "releases").exists())

    def test_failed_unit_directory_fsync_leaves_no_unit_behind(self):
        arguments = self.arguments("install", "1.0.0")
        with patch("install._fsync_directory", side_effect=OSError("synthetic fsync failure")):
            with self.assertRaises(OSError):
                self.perform(arguments)
        # A retry must not be rejected as already installed.
        self.assertFalse(self.unit.exists())
        self.assertFalse((self.installation / "releases/1.0.0").exists())
        self.perform(arguments)
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertEqual(self.unit.stat().st_mode & 0o777, 0o644)

    def test_python_interpreter_must_be_absolute_and_root_controlled(self):
        candidate = self.root / "python"
        candidate.write_text("synthetic")
        candidate.chmod(0o755)
        for path in (Path("python3"), candidate):
            with self.subTest(path=path), self.assertRaises(ValueError):
                _trusted_python(path)


class DeploymentConfigurationTests(unittest.TestCase):
    def test_runtime_launcher_rejects_install_tree_config_and_accepts_external_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "installation"
            release = install / "releases/1.0.0"
            module = release / "app/deployment.py"
            module.parent.mkdir(parents=True)
            module.write_text("synthetic")
            (install / "current").symlink_to("releases/1.0.0", target_is_directory=True)

            runtime = root / "runtime"
            for path in (runtime, runtime / "state", runtime / "recordings", runtime / "audit"):
                path.mkdir(mode=0o700)
            device = runtime.stat().st_dev
            uuid = "00000000-1111-2222-3333-444444444444"
            value = {
                "runtime_root": str(runtime), "service_uid": os.geteuid(),
                "runtime_mount_point": str(root),
                "runtime_device": [os.major(device), os.minor(device)],
                "runtime_filesystem_uuid": uuid, "capture_ca_directory": None,
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }

            # The launcher requires the storage-configured monitoring section:
            # without it the mandatory hardware integrity check and recording
            # self-test could not run.
            monitored = dict(value, monitoring={
                "time_zone": "UTC",
                "storage_limits": {
                    "recording_limit_bytes": 100_000, "critical_allowance_bytes": 10_000,
                    "hard_reserve_bytes": 4096, "pressure_free_bytes": 8192,
                    "recovery_free_bytes": 16_384, "recovery_allocation_bytes": 90_000,
                    "write_overhead_bytes": 4096, "max_request_bytes": 1024,
                    "cleanup_batch_size": 10,
                },
                "recording_limits": {
                    "pre_roll_bytes": 4096, "max_segment_bytes": 512, "max_segment_ms": 30_000,
                    "max_active_recordings": 8, "max_spool_segments": 16,
                    "max_segments_per_recording": 100,
                },
                "recording_filesystem": {
                    "filesystem_uuid": uuid, "device": [os.major(device), os.minor(device)],
                    "mount_point": str(root),
                },
            })
            external = root / "etc/deployment.json"
            external.parent.mkdir(mode=0o755)
            unmonitored = root / "etc/unmonitored.json"
            internal = install / "deployment.json"
            release_internal = install / "current/deployment.json"
            for config in (external, internal, release_internal):
                config.write_text(json.dumps(monitored))
                config.chmod(0o600)
            unmonitored.write_text(json.dumps(value))
            unmonitored.chmod(0o600)

            with patch("app.deployment.__file__", str(module)), patch(
                    "app.deployment.ADMINISTRATOR_UID", os.geteuid()), patch(
                    "app.deployment._approved_filesystem_device", return_value=device):
                for config in (internal, release_internal):
                    with self.subTest(config=config), patch(
                            "sys.stderr", new_callable=io.StringIO) as stderr, self.assertRaises(
                                SystemExit) as stopped:
                        deployment_main(["--config", str(config), "--check"])
                    self.assertEqual(stopped.exception.code, 1)
                    self.assertEqual(
                        stderr.getvalue(), "ServerSentinel deployment validation failed\n"
                    )

                with patch("app.deployment.os.path.ismount", return_value=True), patch(
                        "app.deployment._operating_system_root_device",
                        return_value=device + 1):
                    # A structurally valid external configuration without the
                    # monitoring storage sections is refused by --check (the
                    # unit's ExecStartPre) and by the launcher itself.
                    for arguments in (["--check"], []):
                        with self.subTest(arguments=arguments), patch(
                                "sys.stderr", new_callable=io.StringIO) as stderr, patch(
                                "app.__main__.run") as run, self.assertRaises(
                                    SystemExit) as stopped:
                            deployment_main(["--config", str(unmonitored), *arguments])
                        self.assertEqual(stopped.exception.code, 1)
                        self.assertEqual(
                            stderr.getvalue(), "ServerSentinel deployment validation failed\n"
                        )
                        run.assert_not_called()
                    with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                        self.assertEqual(
                            deployment_main(["--config", str(external), "--check"]), 0
                        )
                self.assertEqual(
                    stdout.getvalue(), "ServerSentinel deployment validation passed\n"
                )

            source_module = root / "releases/server/app/deployment.py"
            source_module.parent.mkdir(parents=True)
            source_module.write_text("synthetic")
            with patch("app.deployment.__file__", str(source_module)), patch(
                    "app.deployment.ADMINISTRATOR_UID", os.geteuid()), patch(
                    "app.deployment._approved_filesystem_device", return_value=device), patch(
                    "app.deployment.os.path.ismount", return_value=True), patch(
                    "app.deployment._operating_system_root_device",
                    return_value=device + 1), patch(
                        "sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(
                    deployment_main(["--config", str(external), "--check"]), 0
                )
            self.assertEqual(
                stdout.getvalue(), "ServerSentinel deployment validation passed\n"
            )

    def test_configuration_is_private_bounded_and_owned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in (root / "runtime", root / "runtime/state",
                         root / "runtime/recordings", root / "runtime/audit"):
                path.mkdir(mode=0o700)
            config = root / "deployment.json"
            device = (root / "runtime").stat().st_dev
            config.write_text(json.dumps({
                "runtime_root": str(root / "runtime"), "service_uid": os.geteuid(),
                "runtime_mount_point": str(root),
                "runtime_device": [os.major(device), os.minor(device)],
                "runtime_filesystem_uuid": "00000000-1111-2222-3333-444444444444", "capture_ca_directory": None,
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }))
            config.chmod(0o644)
            with self.assertRaises(ConfigurationError):
                Deployment.load(config, code_root=root / "code")

    def test_configuration_must_be_administrator_owned_and_not_runtime_writable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            for path in (runtime, runtime / "state", runtime / "recordings",
                         runtime / "audit"):
                path.mkdir(mode=0o700)
            device = runtime.stat().st_dev
            value = {
                "runtime_root": str(runtime), "service_uid": os.geteuid(),
                "runtime_mount_point": str(root),
                "runtime_device": [os.major(device), os.minor(device)],
                "runtime_filesystem_uuid": "00000000-1111-2222-3333-444444444444", "capture_ca_directory": None,
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }
            (root / "code").mkdir()
            administrator = root / "etc"
            administrator.mkdir(mode=0o755)
            config = administrator / "deployment.json"
            config.write_text(json.dumps(value))
            config.chmod(0o640)

            def load(path):
                return Deployment.load(path, code_root=root / "code")

            environment = (
                patch("app.deployment.os.path.ismount", return_value=True),
                patch("app.deployment._operating_system_root_device",
                      return_value=device + 1),
                patch("app.deployment._approved_filesystem_device", return_value=device),
            )
            for context in environment:
                self.enterContext(context)

            with patch("app.deployment.ADMINISTRATOR_UID", os.geteuid()):
                # An administrator-owned, group-readable configuration is accepted.
                self.assertEqual(load(config).service_uid, os.geteuid())

                # The runtime account must never be able to rewrite it.
                config.chmod(0o660)
                with self.assertRaisesRegex(ConfigurationError, "unavailable"):
                    load(config)
                config.chmod(0o640)

                administrator.chmod(0o777)
                with self.assertRaisesRegex(
                        ConfigurationError, "directory must be administrator-controlled"):
                    load(config)
                # A sticky shared directory cannot have its entries replaced by
                # non-owners, so it stays acceptable.
                administrator.chmod(0o1777)
                self.assertEqual(load(config).service_uid, os.geteuid())
                administrator.chmod(0o755)

                # An ancestor above the immediate parent must be controlled too.
                nested = administrator / "nested"
                nested.mkdir(mode=0o755)
                deeper = nested / "deployment.json"
                deeper.write_text(json.dumps(value))
                deeper.chmod(0o640)
                self.assertEqual(load(deeper).service_uid, os.geteuid())
                administrator.chmod(0o777)
                with self.assertRaisesRegex(
                        ConfigurationError, "directory must be administrator-controlled"):
                    load(deeper)
                administrator.chmod(0o755)

                # Configuration inside the service-writable runtime tree is refused
                # even when its own mode is correct.
                inside = runtime / "deployment.json"
                inside.write_text(json.dumps(value))
                inside.chmod(0o640)
                with self.assertRaisesRegex(
                        ConfigurationError, "outside runtime-writable data"):
                    load(inside)

            # A configuration owned by the runtime account rather than the
            # administrator is refused.
            with patch("app.deployment.ADMINISTRATOR_UID", os.geteuid() + 1):
                with self.assertRaisesRegex(
                        ConfigurationError, "must be administrator-owned"):
                    load(config)


def drop_socket_capability(release: Path) -> None:
    """Model a release from before socket activation, keeping its other capabilities.

    These socket-activation tests isolate that boundary; the
    ``capture_ca_directory`` boundary (Issue #109) has its own tests.
    """
    path = release / install.RELEASE_CAPABILITIES
    text = path.read_text()
    path.chmod(0o644)
    path.write_text(text.replace("HUMAN_UPSTREAM_SOCKET_ACTIVATION = True\n", ""))


class ActivationBoundaryTests(unittest.TestCase):
    """Issue #126 / PR #153: an update or rollback never switches to a release
    from before socket activation while the host could not start it."""

    # Reuse the lifecycle fixture without re-running its tests.
    setUp_lifecycle = ReleaseLifecycleTests.setUp
    artifact = ReleaseLifecycleTests.artifact
    arguments = ReleaseLifecycleTests.arguments
    perform = ReleaseLifecycleTests.perform
    approved_device_lookup = ReleaseLifecycleTests.approved_device_lookup

    def setUp(self):
        self.setUp_lifecycle()
        port_start = patch("install._unprivileged_port_start", return_value=1024)
        self.port_start = port_start.start()
        self.addCleanup(port_start.stop)

    def legacy(self, *versions):
        """Model releases built before app/release_capabilities.py existed."""
        real = install._supports_socket_activation

        def capability(release):
            name = Path(release).name.lstrip(".").removesuffix(".staging")
            return False if name in versions else real(release)

        return patch("install._supports_socket_activation", side_effect=capability)

    def installed_old_then_new(self):
        with self.legacy("1.0.0"):
            self.perform(self.arguments("install", "1.0.0"))
        drop_socket_capability(self.installation / "releases/1.0.0")
        self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.1.0")

    def state(self):
        return (os.readlink(self.installation / "current"), os.readlink(self.installation / "previous"),
                self.unit.read_text())

    def restarts(self):
        return [arguments for arguments, _ in self.runner.calls if arguments[:2] == ["systemctl", "restart"]]

    def test_artifact_release_declares_socket_activation(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.assertTrue(install._supports_socket_activation(self.installation / "releases/1.0.0"))

    # (LoadState, ActiveState) as systemd 259 reported them for a socket unit
    # (throwaway user units, PR #153 round 5).
    IN_USE = {
        "enabled and running": ("loaded", "active"),
        "disabled, file still present": ("loaded", "inactive"),
        "file moved, no daemon-reload yet": ("loaded", "active"),
        "file moved and reloaded, still running (stale)": ("not-found", "active"),
        "masked": ("masked", "inactive"),
        "failed": ("not-found", "failed"),
    }

    def test_rollback_refuses_while_the_socket_unit_is_present_or_running(self):
        for name, (load, active) in self.IN_USE.items():
            with self.subTest(name):
                self.setUp()
                self.installed_old_then_new()
                self.runner.socket_state.update(LoadState=load, ActiveState=active)
                before, restarts = self.state(), len(self.restarts())
                with self.assertRaises(install.ActivationBoundaryRefused) as refused:
                    self.perform(self.arguments("rollback"))
                # Nothing changed: pointers, unit and running release stay.
                self.assertEqual(self.state(), before)
                self.assertEqual(len(self.restarts()), restarts)
                message = str(refused.exception)
                for phrase in ("before any change", "releases/1.0.0",
                               "server-sentinel-upstream.socket is installed or running",
                               "sudo systemctl disable --now server-sentinel-upstream.socket",
                               str(self.config), '"human_port"', "run the same command again: ... rollback"):
                    self.assertIn(phrase, message)
                # The installer only queried the Owner's socket unit.
                for arguments, _ in self.runner.calls:
                    if install.UPSTREAM_SOCKET_UNIT in arguments:
                        self.assertEqual(arguments[:3], ["systemctl", "show", "-p"])

    def test_rollback_refuses_a_privileged_port_the_old_launcher_cannot_bind(self):
        for start in (9000, None):
            with self.subTest(start=start):
                self.setUp()
                self.installed_old_then_new()
                self.port_start.return_value = start
                before = self.state()
                with self.assertRaises(install.ActivationBoundaryRefused) as refused:
                    self.perform(self.arguments("rollback", "1.0.0"))
                self.assertEqual(self.state(), before)
                self.assertIn("human_port 8000 is below ip_unprivileged_port_start", str(refused.exception))
                self.assertIn("rollback --version 1.0.0", str(refused.exception))

    def test_rollback_proceeds_once_the_owner_steps_are_done(self):
        self.installed_old_then_new()
        self.runner.socket_state.update(LoadState="loaded", ActiveState="active")
        with self.assertRaises(install.ActivationBoundaryRefused):
            self.perform(self.arguments("rollback"))
        # Owner: disable --now, only the stop done: still refused.
        self.runner.socket_state.update(ActiveState="inactive")
        with self.assertRaises(install.ActivationBoundaryRefused):
            self.perform(self.arguments("rollback"))
        # Owner: unit file parked and daemon-reload done.
        self.runner.socket_state.update(LoadState="not-found")
        self.perform(self.arguments("rollback"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")

    def test_activation_releases_are_not_blocked(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.perform(self.arguments("update", "1.1.0"))
        self.runner.socket_state.update(LoadState="loaded", ActiveState="active")
        self.port_start.return_value = 9000
        self.perform(self.arguments("rollback"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")

    def test_update_to_a_pre_activation_release_is_refused_and_unstaged(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.runner.socket_state.update(LoadState="loaded", ActiveState="active")
        before = (os.readlink(self.installation / "current"), self.unit.read_text())
        with patch("install._supports_socket_activation", return_value=False), \
                self.assertRaises(install.ActivationBoundaryRefused) as refused:
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual((os.readlink(self.installation / "current"), self.unit.read_text()), before)
        self.assertFalse((self.installation / "releases/1.1.0").exists())
        self.assertIn("run the same command again: ... update ...", str(refused.exception))

    def unit_names_socket(self, path=None):
        return "Sockets=server-sentinel-upstream.socket" in (path or self.unit).read_text().splitlines()

    def test_unit_names_the_socket_only_for_an_activation_release(self):
        # PR #153 review: Sockets= implies Wants=/After= on the socket unit, so
        # a release that cannot accept the socket must not pull it back in.
        with self.legacy("1.0.0"):
            self.perform(self.arguments("install", "1.0.0"))
        self.assertFalse(self.unit_names_socket())
        self.assertFalse(self.unit_names_socket(self.installation / "releases/1.0.0/.server-sentinel.service"))
        self.perform(self.arguments("update", "1.1.0"))
        self.assertTrue(self.unit_names_socket())
        self.assertTrue(self.unit_names_socket(self.installation / "releases/1.1.0/.server-sentinel.service"))

    def test_activation_legacy_activation_cycle_renders_the_matching_unit(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.assertTrue(self.unit_names_socket())
        # Owner steps done (socket unit file parked: not-found, inactive; an
        # unprivileged human_port), then forward to a release without the capability.
        with self.legacy("1.1.0"):
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.1.0")
        drop_socket_capability(self.installation / "releases/1.1.0")
        self.assertFalse(self.unit_names_socket())
        # Back to an activation release.
        self.perform(self.arguments("update", "1.2.0"))
        self.assertTrue(self.unit_names_socket())
        # Rollbacks restore each release's own snapshot.
        self.perform(self.arguments("rollback", "1.1.0"))
        self.assertFalse(self.unit_names_socket())
        self.perform(self.arguments("rollback", "1.0.0"))
        self.assertTrue(self.unit_names_socket())

    def test_rollback_refuses_a_legacy_snapshot_that_names_the_socket(self):
        self.installed_old_then_new()
        snapshot = self.installation / "releases/1.0.0/.server-sentinel.service"
        snapshot.chmod(0o644)
        snapshot.write_text(snapshot.read_text().replace(
            "[Service]\n", "[Service]\nSockets=server-sentinel-upstream.socket\n", 1))
        before = self.state()
        with self.assertRaisesRegex(ValueError, "installed service configuration differs"):
            self.perform(self.arguments("rollback"))
        self.assertEqual(self.state(), before)

    def test_unclear_socket_state_counts_as_in_use(self):
        for prop, value in (("LoadState", (1, "")), ("LoadState", (0, None)), ("ActiveState", "")
                            , ("LoadState", "bad-setting"), ("ActiveState", "activating")):
            with self.subTest(prop=prop, value=value):
                self.setUp()
                self.installed_old_then_new()
                self.runner.socket_state[prop] = value
                with self.assertRaises(install.ActivationBoundaryRefused):
                    self.perform(self.arguments("rollback"))

    def test_failed_socket_query_counts_as_in_use_with_the_owner_steps(self):
        # PR #153 review: a query that times out or cannot run is unknown, so
        # in use; the refusal still carries the Owner procedure.
        failures = {"timeout": subprocess.TimeoutExpired(["systemctl"], 30),
                    "no systemctl": FileNotFoundError("systemctl"),
                    "os error": PermissionError("synthetic"),
                    "subprocess error": subprocess.SubprocessError("synthetic")}
        for name, failure in failures.items():
            for prop in ("LoadState", "ActiveState"):
                with self.subTest(name=name, prop=prop):
                    self.setUp()
                    self.installed_old_then_new()
                    self.runner.socket_state[prop] = failure
                    before = self.state()
                    with self.assertRaises(install.ActivationBoundaryRefused) as refused:
                        self.perform(self.arguments("rollback"))
                    self.assertEqual(self.state(), before)
                    self.assertIn("server-sentinel-upstream.socket is installed or running", str(refused.exception))
                    self.assertIn("sudo systemctl disable --now", str(refused.exception))

    def test_printed_steps_are_in_a_working_order(self):
        # PR #153 review: starting the socket unit cannot hand its socket to a
        # running service, so returning needs an explicit restart, and both
        # directions restore the Tailscale Serve target.
        self.installed_old_then_new()
        self.runner.socket_state.update(LoadState="loaded")
        with self.assertRaises(install.ActivationBoundaryRefused) as refused:
            self.perform(self.arguments("rollback"))
        message = str(refused.exception)
        switch, _, back = message.partition("To return to socket activation later")
        self.assertTrue(back)

        def ordered(text, phrases):
            positions = [text.find(phrase) for phrase in phrases]
            self.assertNotIn(-1, positions, phrases)
            self.assertEqual(positions, sorted(positions), phrases)

        ordered(switch, ['set "human_port" to the port that release used',
                         "sudo systemctl disable --now server-sentinel-upstream.socket",
                         "sudo mv /etc/systemd/system/server-sentinel-upstream.socket /etc/server-sentinel/disabled/",
                         "sudo systemctl daemon-reload",
                         "run the same command again: ... rollback",
                         "point the Tailscale Serve target at", "verify:"])
        ordered(back, ["update to a release that supports it",
                       'set "human_port" back to the ListenStream port',
                       "sudo mv /etc/server-sentinel/disabled/server-sentinel-upstream.socket"
                       " /etc/systemd/system/server-sentinel-upstream.socket",
                       "sudo systemctl daemon-reload",
                       "sudo systemctl enable --now server-sentinel-upstream.socket",
                       "sudo systemctl restart server-sentinel.service",
                       "point the Tailscale Serve target back at", "verify:"])
        self.assertNotIn("restart server-sentinel.service", switch)
        # Round 5: mask fails for a unit file in /etc/systemd/system and a
        # masked socket can still report active, so the steps never use it.
        self.assertNotIn("mask", message)

    def test_capability_file_is_read_as_text_strictly(self):
        release = self.root / "release"
        (release / "app").mkdir(parents=True)
        path = release / install.RELEASE_CAPABILITIES
        self.assertFalse(install._supports_socket_activation(release))
        for text, expected in (("HUMAN_UPSTREAM_SOCKET_ACTIVATION = True\n", True),
                               ("x = 1\nHUMAN_UPSTREAM_SOCKET_ACTIVATION = True\n", True),
                               ("# HUMAN_UPSTREAM_SOCKET_ACTIVATION = True\n", False),
                               ("HUMAN_UPSTREAM_SOCKET_ACTIVATION = False\n", False),
                               ("HUMAN_UPSTREAM_SOCKET_ACTIVATION = True  # no\n", False)):
            with self.subTest(text=text):
                path.write_text(text)
                self.assertEqual(install._supports_socket_activation(release), expected)
        path.unlink()
        path.symlink_to(self.root / "elsewhere.py")
        (self.root / "elsewhere.py").write_text("HUMAN_UPSTREAM_SOCKET_ACTIVATION = True\n")
        with self.assertRaises(OSError):
            install._supports_socket_activation(release)
        path.unlink()
        path.write_bytes(b"\xff" * 10)
        with self.assertRaises(ValueError):
            install._supports_socket_activation(release)

    def test_refusal_prints_the_owner_steps(self):
        refusal = install.ActivationBoundaryRefused("synthetic owner steps\n")
        stderr = io.StringIO()
        with patch("install.execute", side_effect=refusal), patch.object(
                sys, "argv", ["install.py", "--destination", "/opt/x", "--config", "/etc/x.json", "--unit",
                              "/etc/systemd/system/server-sentinel.service", "rollback"]), \
                patch("sys.stderr", stderr), self.assertRaises(SystemExit) as exited:
            install.main()
        self.assertEqual(exited.exception.code, 1)
        self.assertIn("synthetic owner steps", stderr.getvalue())


class CaptureCaSettingBoundaryTests(unittest.TestCase):
    """Issue #109 (review of PR #177): ``capture_ca_directory`` is required by
    releases with ``CAPTURE_CA_DIRECTORY_SETTING`` and refused as an unknown
    key by earlier ones, so update and rollback check the configuration
    against the release they switch to, before any change."""

    setUp_lifecycle = ReleaseLifecycleTests.setUp
    artifact = ReleaseLifecycleTests.artifact
    arguments = ReleaseLifecycleTests.arguments
    perform = ReleaseLifecycleTests.perform
    approved_device_lookup = ReleaseLifecycleTests.approved_device_lookup

    def setUp(self):
        self.setUp_lifecycle()
        port_start = patch("install._unprivileged_port_start", return_value=1024)
        port_start.start()
        self.addCleanup(port_start.stop)
        self.legacy_versions = set()
        real = getattr(install, "_supports_capture_ca_setting", None)
        if real is None:
            return  # an installer without the boundary (fail-before runs)

        def capability(release):
            name = Path(release).name.lstrip(".").removesuffix(".staging")
            return False if name in self.legacy_versions else real(release)
        supports = patch("install._supports_capture_ca_setting", side_effect=capability)
        supports.start()
        self.addCleanup(supports.stop)

    def configure(self, present):
        value = json.loads(self.config.read_text())
        value.pop("capture_ca_directory", None)
        if present:
            value["capture_ca_directory"] = None
        self.config.chmod(0o600)
        self.config.write_text(json.dumps(value))

    def state(self):
        previous = self.installation / "previous"
        return (os.readlink(self.installation / "current"),
                os.readlink(previous) if previous.is_symlink() else None, self.unit.read_text())

    def refused(self, arguments, *phrases):
        before = self.state()
        with self.assertRaises(install.ActivationBoundaryRefused) as refused:
            self.perform(arguments)
        self.assertEqual(before, self.state(), "nothing may change")
        message = str(refused.exception)
        self.assertIn("before any change", message)
        for phrase in phrases:
            self.assertIn(phrase, message)
        return message

    def test_artifact_release_declares_the_capture_ca_setting(self):
        self.perform(self.arguments("install", "1.0.0"))
        capabilities = (self.installation / "releases/1.0.0" / install.RELEASE_CAPABILITIES)
        self.assertIn("\nCAPTURE_CA_DIRECTORY_SETTING = True\n", capabilities.read_text())

    def test_setting_capable_legacy_capable_cycle(self):
        # A deployment on a release from before Issue #109 (no key).
        self.legacy_versions.add("1.0.0")
        self.configure(present=False)
        self.perform(self.arguments("install", "1.0.0"))
        # Updating to a release that requires the key is refused with the steps.
        update = self.arguments("update", "1.1.0")
        self.refused(update, "requires \"capture_ca_directory\"",
                     "add \"capture_ca_directory\"", "rerun the same command (update ...)")
        self.assertFalse((self.installation / "releases/1.1.0").exists())
        self.configure(present=True)
        self.perform(update)
        self.assertEqual("releases/1.1.0", os.readlink(self.installation / "current"))
        # Rolling back to the legacy release with the key is refused before
        # any change, with the exact steps for both directions.
        self.refused(self.arguments("rollback"), "predates the \"capture_ca_directory\"",
                     "remove the \"capture_ca_directory\" entry",
                     "rerun the same command (rollback)", "first add the entry back")
        self.configure(present=False)
        self.perform(self.arguments("rollback"))
        self.assertEqual("releases/1.0.0", os.readlink(self.installation / "current"))
        # And forward again to the capable release.
        self.refused(self.arguments("rollback", "1.1.0"), "requires \"capture_ca_directory\"",
                     "rerun the same command (rollback --version 1.1.0)")
        self.configure(present=True)
        self.perform(self.arguments("rollback", "1.1.0"))
        self.assertEqual("releases/1.1.0", os.readlink(self.installation / "current"))

    def test_update_to_a_legacy_artifact_with_the_key_is_refused_before_its_check(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.legacy_versions.add("1.1.0")
        checks = len([call for call, _ in self.runner.calls if "--check" in call])
        self.refused(self.arguments("update", "1.1.0"), "remove the \"capture_ca_directory\" entry")
        self.assertEqual(checks, len([call for call, _ in self.runner.calls if "--check" in call]),
                         "the release's own --check never ran")
        self.assertFalse((self.installation / "releases/1.1.0").exists())
        self.assertFalse((self.installation / "releases/.1.1.0.staging").exists())


PAIRING_PROBE = '''import json, os, sys
print(json.dumps({"argv": sys.argv[1:], "file": __file__, "executable": sys.executable,
                  "path0": sys.path[0], "cwd": os.getcwd(), "environ": dict(os.environ),
                  "isolated": sys.flags.isolated, "name": __name__}))
'''


class PairingWrapperTests(unittest.TestCase):
    """Issue #180: the installer places ``serversentinel-pairing`` (root:root
    0755). It runs the pairing CLI of the release ``current`` names, with that
    release's interpreter and code, whatever the caller's environment."""

    setUp_lifecycle = ReleaseLifecycleTests.setUp
    artifact = ReleaseLifecycleTests.artifact
    arguments = ReleaseLifecycleTests.arguments
    perform = ReleaseLifecycleTests.perform
    approved_device_lookup = ReleaseLifecycleTests.approved_device_lookup

    def setUp(self):
        self.setUp_lifecycle()
        port_start = patch("install._unprivileged_port_start", return_value=1024)
        port_start.start()
        self.addCleanup(port_start.stop)
        # What an untrusted caller environment could offer instead of the
        # release: an ``app`` package, ``python``, ``readlink`` and ``env``.
        self.hostile = self.root / "hostile"
        module = self.hostile / "app/cameras/remote_agent/pairing_cli.py"
        module.parent.mkdir(parents=True)
        (self.hostile / "app/__init__.py").write_text("")
        (self.hostile / "app/cameras/remote_agent/__init__.py").write_text("")
        module.write_text("print('HOSTILE')\n")
        (self.hostile / "bin").mkdir()
        for name in ("python", "python3", "readlink", "env"):
            tool = self.hostile / "bin" / name
            tool.write_text("#!/bin/sh\necho HOSTILE\n")
            tool.chmod(0o755)
        (self.hostile / "sitecustomize.py").write_text("print('HOSTILE')\n")

    def probe(self, version):
        """Let an installed release run: the test interpreter stands for its
        venv interpreter, and its pairing CLI reports how it was started."""
        release = self.installation / "releases" / version
        python = release / "venv/bin/python"
        python.unlink()
        python.symlink_to(sys.executable)
        module = release / "app/cameras/remote_agent/pairing_cli.py"
        module.unlink()
        module.write_text(PAIRING_PROBE)
        return release

    def run_wrapper(self, *arguments):
        environment = {
            "PATH": str(self.hostile / "bin") + ":/usr/bin:/bin",
            "PYTHONPATH": str(self.hostile), "PYTHONHOME": str(self.hostile),
            "PYTHONSTARTUP": str(self.hostile / "sitecustomize.py"),
            "PYTHONUSERBASE": str(self.hostile), "PYTHONSAFEPATH": "",
            "ENV": str(self.hostile / "sitecustomize.py"), "IFS": "/",
            "SYNTHETIC_SECRET": "not-for-the-cli",
        }
        return subprocess.run([str(self.wrapper), *arguments], cwd=self.hostile, env=environment,
                              capture_output=True, text=True, timeout=60)

    def ran(self, *arguments):
        result = self.run_wrapper(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("HOSTILE", result.stdout + result.stderr)
        return json.loads(result.stdout)

    def assert_runs(self, version, arguments=("list", "--database", "state.sqlite3")):
        release = self.installation / "releases" / version
        report = self.ran(*arguments)
        self.assertEqual(report["executable"], str(release / "venv/bin/python"))
        self.assertEqual(report["file"], str(release / "app/cameras/remote_agent/pairing_cli.py"))
        self.assertEqual(report["path0"], str(release))
        self.assertEqual(report["argv"], list(arguments))
        self.assertEqual(report["name"], "__main__")
        self.assertEqual(report["isolated"], 1)
        # env -i: only the fixed PATH (plus the locale Python itself may set).
        self.assertEqual(report["environ"].get("PATH"), "/usr/bin:/bin")
        self.assertLessEqual(set(report["environ"]), {"PATH", "LC_CTYPE"})
        # The working directory is kept, so relative arguments keep meaning.
        self.assertEqual(Path(report["cwd"]).resolve(), self.hostile.resolve())
        return report

    def test_wrapper_owner_is_root(self):
        self.assertEqual(install.PAIRING_WRAPPER, Path("/usr/local/sbin/serversentinel-pairing"))
        self.assertEqual(install.PAIRING_WRAPPER_OWNER, (0, 0))
        with patch("install.os.fchown") as fchown:
            install._root_owned(7)
        fchown.assert_called_once_with(7, 0, 0)

    def test_install_places_a_root_owned_wrapper_for_the_installation(self):
        self.perform(self.arguments("install", "1.0.0"))
        info = self.wrapper.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o755)
        self.assertEqual((info.st_uid, info.st_gid), (self.uid, self.gid))  # the patched root:root
        text = self.wrapper.read_text()
        self.assertTrue(text.startswith("#!/bin/sh\n" + install.PAIRING_WRAPPER_MARKER + "\n"))
        self.assertIn("root='" + str(self.installation) + "'\n", text)
        self.assertIn("/usr/bin/env -i PATH=/usr/bin:/bin", text)
        self.assertIn('"$release/venv/bin/python" -I -c', text)
        self.assertIn(install.PAIRING_MODULE, text)
        self.assertEqual(text, install.render_pairing_wrapper(self.installation))
        self.assertEqual(list(self.wrapper.parent.iterdir()), [self.wrapper])

    def test_wrapper_follows_current_across_update_and_rollback(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.probe("1.0.0")
        inode = self.wrapper.stat().st_ino
        self.assert_runs("1.0.0")
        self.perform(self.arguments("update", "1.1.0"))
        self.probe("1.1.0")
        self.assert_runs("1.1.0")
        self.perform(self.arguments("rollback"))
        self.assert_runs("1.0.0")
        self.perform(self.arguments("rollback", "1.1.0"))
        self.assert_runs("1.1.0")
        # One release-independent file: never rewritten by a switch.
        self.assertEqual(self.wrapper.stat().st_ino, inode)

    def test_arguments_pass_through_unchanged(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.probe("1.0.0")
        tricky = ("approve", "--request", "relative/request.json", "two words", "$HOME",
                  "*", "'", '"', "--", "-c", "", "-I", "a\nb")
        self.assert_runs("1.0.0", tricky)

    def test_wrapper_refuses_without_a_valid_release(self):
        self.perform(self.arguments("install", "1.0.0"))
        release = self.probe("1.0.0")
        current = self.installation / "current"
        refusal = "serversentinel-pairing: refused: no_installed_release\n"
        for target in ("releases/..", "releases/1.0.0/../../hostile", "hostile",
                       "releases/1.0.0/", "releases/../releases/1.0.0", None):
            with self.subTest(target=target):
                current.unlink(missing_ok=True)
                if target is not None:
                    current.symlink_to(target)
                result = self.run_wrapper("list")
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (2, "", refusal))
        current.symlink_to("releases/1.0.0")
        (release / "app/cameras/remote_agent/pairing_cli.py").unlink()
        result = self.run_wrapper("list")
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, "", "serversentinel-pairing: refused: release_without_pairing_cli\n"))

    def test_foreign_wrapper_is_refused_before_any_change(self):
        arguments = self.arguments("install", "1.0.0")
        for kind in ("script", "symlink", "directory"):
            with self.subTest(kind=kind):
                if kind == "script":
                    self.wrapper.write_text("#!/bin/sh\nexec something-else \"$@\"\n")
                elif kind == "symlink":
                    self.wrapper.symlink_to(self.hostile / "bin/python")
                else:
                    self.wrapper.mkdir()
                with self.assertRaises(install.PairingWrapperConflict) as refused:
                    self.perform(arguments)
                message = str(refused.exception)
                self.assertIn("before any change", message)
                self.assertIn(str(self.wrapper), message)
                self.assertFalse((self.installation / "current").is_symlink())
                self.assertFalse((self.installation / "releases").exists())
                self.assertFalse(self.unit.exists())
                if kind == "symlink":
                    self.assertTrue(self.wrapper.is_symlink())
                    self.wrapper.unlink()
                elif kind == "directory":
                    self.wrapper.rmdir()
                else:
                    self.assertIn("something-else", self.wrapper.read_text())
                    self.wrapper.unlink()

    def test_update_refuses_a_foreign_wrapper_and_keeps_the_running_release(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.wrapper.unlink()
        self.wrapper.write_text("#!/bin/sh\n# Owner's own helper\n")
        unit = self.unit.read_text()
        with self.assertRaises(install.PairingWrapperConflict):
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertFalse((self.installation / "releases/1.1.0").exists())
        self.assertEqual(self.unit.read_text(), unit)
        self.assertEqual(self.wrapper.read_text(), "#!/bin/sh\n# Owner's own helper\n")

    def test_update_adds_a_missing_wrapper_and_repairs_a_stale_one(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.wrapper.unlink()  # an installation made before Issue #180
        self.perform(self.arguments("update", "1.1.0"))
        expected = install.render_pairing_wrapper(self.installation)
        self.assertEqual(self.wrapper.read_text(), expected)
        # An installer-generated wrapper with other text, or a widened mode,
        # is replaced by a new root-owned 0755 file.
        stale = install.render_pairing_wrapper(self.root / "elsewhere")
        for text, mode, version in ((stale, 0o755, "1.2.0"), (expected, 0o775, "1.3.0")):
            with self.subTest(mode=oct(mode)):
                self.wrapper.unlink()
                self.wrapper.write_text(text)
                self.wrapper.chmod(mode)
                inode = self.wrapper.stat().st_ino
                self.perform(self.arguments("rollback"))  # rollback leaves it alone
                self.assertEqual(self.wrapper.stat().st_ino, inode)
                self.perform(self.arguments("update", version))
                self.assertEqual(self.wrapper.read_text(), expected)
                self.assertEqual(stat.S_IMODE(self.wrapper.stat().st_mode), 0o755)
                self.assertNotEqual(self.wrapper.stat().st_ino, inode)
        self.assertEqual(list(self.wrapper.parent.iterdir()), [self.wrapper])

    def test_failed_install_removes_only_a_wrapper_it_created(self):
        self.runner.fail_version = "1.0.0"
        arguments = self.arguments("install", "1.0.0")
        with self.assertRaises(OSError):
            self.perform(arguments)
        self.assertFalse(self.wrapper.exists())
        self.assertFalse(self.unit.exists())
        expected = install.render_pairing_wrapper(self.installation)
        self.wrapper.write_text(expected)
        self.wrapper.chmod(0o755)
        with self.assertRaises(OSError):
            self.perform(arguments)
        self.assertEqual(self.wrapper.read_text(), expected)

    def test_failed_update_keeps_a_wrapper_that_runs_the_restored_release(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.wrapper.unlink()
        self.probe("1.0.0")
        self.runner.fail_version = "1.1.0"
        with self.assertRaises(OSError):
            self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assert_runs("1.0.0")

    def test_unrenderable_installation_root_is_refused(self):
        for root in ("/opt/it's", "/opt/line\nbreak", "/opt/tab\there", "relative", "/opt/../etc"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                install.render_pairing_wrapper(Path(root))

    def test_conflict_prints_the_owner_steps(self):
        conflict = install.PairingWrapperConflict("refused before any change: steps\n")
        stderr = io.StringIO()
        with patch("install.execute", side_effect=conflict), patch.object(
                sys, "argv", ["install.py", "--destination", "/opt/x", "--config", "/etc/x.json",
                              "--unit", str(install.SYSTEMD_UNIT), "rollback"]), \
                patch("sys.stderr", stderr), self.assertRaises(SystemExit) as exited:
            install.main()
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "refused before any change: steps\n")


if __name__ == "__main__":
    unittest.main()
