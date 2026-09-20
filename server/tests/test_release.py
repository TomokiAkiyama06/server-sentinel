import argparse
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import call, patch
import zipfile

from app.deployment import Deployment, main as deployment_main
from app.settings import ConfigurationError
from build_artifact import _required_wheels, build
from build_installer import build as build_installer
from install import _extract, _protected_parent, _release_lock, _trusted_python, execute


def _hold_release_lock(unit, acquired, release):
    with _release_lock(Path(unit)):
        acquired.set()
        release.wait(5)


class Runner:
    def __init__(self, root: Path):
        self.root = root
        self.calls = []
        self.fail_version = None

    def __call__(self, arguments, **options):
        self.calls.append((arguments, options))
        if arguments[1:4] == ["-I", "-m", "venv"]:
            python = Path(arguments[4]) / "bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("synthetic")
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
        self.config.write_text(json.dumps({
            "runtime_root": str(self.runtime),
            "runtime_mount_point": str(self.root),
            "runtime_device": [os.major(device), os.minor(device)],
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

    def perform(self, arguments, *, mount=True, root_device=None):
        account = pwd.getpwuid(self.uid)
        if root_device is None:
            # The fixture's temporary runtime directory ordinarily shares the
            # test runner's filesystem.  Model the separately mounted runtime
            # volume that a real installation requires.
            root_device = self.runtime.stat().st_dev + 1
        with patch("install.os.geteuid", return_value=0), patch(
                "install.SYSTEMD_UNIT", self.unit), patch("install._protected_parent"), patch(
                "install._trusted_python", side_effect=lambda path: path.resolve()), patch(
                "install._installed_unit", side_effect=lambda path: path.read_text()), patch(
                "app.deployment.os.path.ismount", return_value=mount), patch(
                "app.deployment._operating_system_root_device", return_value=root_device), patch(
                "install.pwd.getpwuid", return_value=account):
            execute(arguments, runner=self.runner)

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
        self.assertIn('WorkingDirectory="' + str(self.installation / "current") + '"', unit)
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
        self.installation.mkdir()
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
            value = {
                "runtime_root": str(runtime), "service_uid": os.geteuid(),
                "runtime_mount_point": str(root),
                "runtime_device": [os.major(device), os.minor(device)],
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }

            external = root / "etc/deployment.json"
            external.parent.mkdir()
            internal = install / "deployment.json"
            release_internal = install / "current/deployment.json"
            for config in (external, internal, release_internal):
                config.write_text(json.dumps(value))
                config.chmod(0o600)

            with patch("app.deployment.__file__", str(module)):
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
                        return_value=device + 1), patch(
                            "sys.stdout", new_callable=io.StringIO) as stdout:
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
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }))
            config.chmod(0o644)
            with self.assertRaises(ConfigurationError):
                Deployment.load(config, code_root=root / "code")


if __name__ == "__main__":
    unittest.main()
