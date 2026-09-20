import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from app.deployment import Deployment
from app.settings import ConfigurationError
from build_artifact import _required_wheels, build
from build_installer import build as build_installer
from install import _extract, _protected_parent, _trusted_python, execute


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

    def perform(self, arguments, *, mount=True):
        account = pwd.getpwuid(self.uid)
        with patch("install.os.geteuid", return_value=0), patch(
                "install._protected_parent"), patch(
                "install._trusted_python", side_effect=lambda path: path.resolve()), patch(
                "install._installed_unit", side_effect=lambda path: path.read_text()), patch(
                "app.deployment.os.path.ismount", return_value=mount), patch(
                "install.pwd.getpwuid", return_value=account):
            execute(arguments, runner=self.runner)

    def test_install_update_and_rollback_preserve_external_runtime_data(self):
        markers = []
        for directory in (self.runtime / "state", self.runtime / "recordings",
                          self.runtime / "audit"):
            marker = directory / "preserved.synthetic"
            marker.write_text(directory.name)
            markers.append(marker)

        self.perform(self.arguments("install", "1.0.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertFalse((self.installation / "previous").exists())
        unit = self.unit.read_text()
        self.assertIn("User=" + pwd.getpwuid(self.uid).pw_name, unit)
        self.assertIn('WorkingDirectory="' + str(self.installation / "current") + '"', unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("Type=notify", unit)
        self.assertIn("NotifyAccess=main", unit)
        self.assertNotIn("Type=simple", unit)
        self.assertNotIn("0.0.0.0", unit)

        self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.1.0")
        self.assertEqual(os.readlink(self.installation / "previous"), "releases/1.0.0")
        self.perform(self.arguments("rollback"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertEqual(os.readlink(self.installation / "previous"), "releases/1.1.0")
        self.assertEqual(
            [marker.read_text() for marker in markers], ["state", "recordings", "audit"]
        )

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

        self.runner.fail_version = "1.2.0"
        with patch("install.render_unit", return_value="[Service]\nProtectHome=true\n"):
            with self.assertRaises(OSError):
                self.perform(self.arguments("update", "1.2.0"))
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
