"""Issue #10 phase 2 S5c: the Web build in the release, installer and deployment.

The release archive carries ``web/dist`` under ``web/`` with every file's
SHA-256 in the release manifest; the installer places it root-owned with
explicit modes, never through a hard link and whatever the administrator
umask, and checks it against that manifest at install and before a
rollback; the deployment key ``web_assets_directory`` points
``Settings.web_assets_dir`` at the release's own build, which the release's
``--check`` loads. Every build here is synthetic (``tests.web_asset_fakes``).
"""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from app import deployment as deployment_module
from app.deployment import Deployment, main as deployment_main
from app.settings import ConfigurationError
import build_artifact
from build_artifact import WebBuildRefused, build
import install
from install import ReleaseFilesDiffer, _extract, verify_release_web
from tests import test_release as lifecycle
from tests.web_asset_fakes import APP, SHELL, write_build


def _build_files(directory: Path) -> dict[str, bytes]:
    return {str(path.relative_to(directory)): path.read_bytes()
            for path in sorted(directory.rglob("*")) if path.is_file()}


class ReleaseFixture(unittest.TestCase):
    # The lifecycle fixture (``tests.test_release``) without its tests.
    setUp = lifecycle.ReleaseLifecycleTests.setUp
    artifact = lifecycle.ReleaseLifecycleTests.artifact
    arguments = lifecycle.ReleaseLifecycleTests.arguments
    perform = lifecycle.ReleaseLifecycleTests.perform
    approved_device_lookup = lifecycle.ReleaseLifecycleTests.approved_device_lookup

    def members(self, artifact):
        with tarfile.open(artifact, "r:gz") as archive:
            manifest = json.loads(archive.extractfile("manifest.json").read())
            data = {member.name: (archive.extractfile(member).read(), member.mode)
                    for member in archive.getmembers() if member.name != "manifest.json"}
        return manifest, data

    def state(self):
        return (os.readlink(self.installation / "current"),
                os.readlink(self.installation / "previous"), self.unit.read_text())

    def daemon_reloads(self):
        return len([c for c, _ in self.runner.calls if c[:2] == ["systemctl", "daemon-reload"]])

    def verify(self, release):
        """``verify_release_web`` with the test account standing for root."""
        with patch("install.RELEASE_OWNER_UID", self.uid):
            return verify_release_web(release)


class ArtifactWebBuildTests(ReleaseFixture):
    def test_the_web_build_is_archived_with_every_digest_in_the_release_manifest(self):
        artifact, _ = self.artifact("1.0.0")
        manifest, members = self.members(artifact)
        expected = {"web/" + name: data for name, data in _build_files(self.web_dist).items()}
        self.assertEqual(set(expected), {name for name in members if name.startswith("web/")})
        self.assertIn("web/manifest.json", expected)
        self.assertIn("web/shell/s.js", expected)
        self.assertIn("web/app/index.html", expected)
        for name, data in expected.items():
            with self.subTest(name=name):
                self.assertEqual(members[name], (data, 0o444))
                self.assertEqual(manifest["files"][name], hashlib.sha256(data).hexdigest())

    def test_rebuilding_from_the_same_build_records_the_same_release_manifest(self):
        first, _ = self.artifact("1.0.0")
        copy = self.root / "web-dist-copy"
        shutil.copytree(self.web_dist, copy)
        self.web_dist = copy
        second = self.root / "again.tar.gz"
        wheels = sorted(self.wheelhouse.glob("*.whl"))
        with patch("build_artifact.REPOSITORY", self.root), patch(
                "build_artifact._required_wheels", return_value=wheels):
            build(second, "1.0.0", self.wheelhouse, copy)
        self.assertEqual(self.members(first), self.members(second))

    def refused_build(self, reason_text=None):
        destination = self.root / "refused.tar.gz"
        with self.assertRaises(WebBuildRefused) as refused:
            with patch("build_artifact.REPOSITORY", self.root), patch(
                    "build_artifact._required_wheels",
                    return_value=sorted(self.wheelhouse.glob("*.whl"))):
                build(destination, "1.0.0", self.wheelhouse, self.web_dist)
        self.assertFalse(destination.exists())
        self.assertNotIn(str(self.root), str(refused.exception))
        if reason_text is not None:
            self.assertIn(reason_text, str(refused.exception))

    def test_a_missing_modified_or_extra_build_file_is_refused(self):
        for change, reason in (("missing", "reason=set"), ("modified", "reason=digest"),
                               ("extra", "reason=set"), ("manifest", "reason=set")):
            with self.subTest(change=change):
                self.web_dist = write_build(self.root / ("web-" + change))
                if change == "missing":
                    (self.web_dist / "app" / "app.js").unlink()
                elif change == "modified":
                    (self.web_dist / "shell" / "s.js").write_bytes(SHELL["s.js"][:-2] + b"//")
                elif change == "extra":
                    (self.web_dist / "app" / "unlisted.js").write_bytes(b"synthetic\n")
                else:
                    (self.web_dist / "manifest.json").unlink()
                self.refused_build(reason)

    def test_links_special_files_and_unusable_directories_are_refused(self):
        outside = self.root / "outside.js"
        outside.write_bytes(APP["app.js"])
        linked = write_build(self.root / "web-link")
        (linked / "app" / "app.js").unlink()
        (linked / "app" / "app.js").symlink_to(outside)
        whole = self.root / "web-whole-link"
        whole.symlink_to(write_build(self.root / "web-target"), target_is_directory=True)
        fifo = write_build(self.root / "web-fifo")
        (fifo / "app" / "app.js").unlink()
        os.mkfifo(fifo / "app" / "app.js")
        nested = write_build(self.root / "web-nested")
        (nested / "app" / "deep").mkdir()
        (nested / "app" / "deep" / "x.js").write_bytes(b"synthetic\n")
        for directory in (linked, whole, fifo, nested, self.root / "absent", Path("web/dist")):
            with self.subTest(directory=directory.name):
                self.web_dist = directory
                self.refused_build()

    def test_the_build_copy_does_not_depend_on_the_builder_umask(self):
        # The builder's own tree may be group-writable (umask 0002); the
        # release still carries exactly the bytes, and the loader check runs
        # on a private copy with explicit modes.
        for path in [self.web_dist, *self.web_dist.rglob("*")]:
            path.chmod(0o775 if path.is_dir() else 0o664)
        previous = os.umask(0o002)
        try:
            artifact, _ = self.artifact("1.0.0")
        finally:
            os.umask(previous)
        _, members = self.members(artifact)
        self.assertEqual(members["web/app/app.js"], (APP["app.js"], 0o444))

    def test_the_command_line_requires_the_web_build(self):
        with patch("sys.argv", ["build_artifact.py", "--output", str(self.root / "x.tar.gz"),
                                "--version", "1.0.0", "--wheelhouse", str(self.wheelhouse)]), \
                patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as stopped:
            build_artifact.main()
        self.assertEqual(stopped.exception.code, 2)


class InstalledWebBuildTests(ReleaseFixture):
    def assert_release_web(self, release: Path):
        web = release / "web"
        source_inodes = {path.stat().st_ino for path in self.web_dist.rglob("*") if path.is_file()}
        for path in [web, *web.rglob("*")]:
            info = os.lstat(path)
            with self.subTest(path=str(path.relative_to(release))):
                self.assertEqual(info.st_uid, self.uid)
                if path.is_dir():
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o755)
                else:
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o444)
                    self.assertEqual(info.st_nlink, 1)
                    self.assertNotIn(info.st_ino, source_inodes)
        self.assertEqual(_build_files(web), _build_files(self.web_dist))
        copy = release / install.RELEASE_MANIFEST
        self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o444)
        self.assertTrue(json.loads(copy.read_text())["files"]["web/manifest.json"])

    def test_install_places_the_build_root_owned_read_only_under_a_permissive_umask(self):
        # Ubuntu's default administrator umask is 0002.
        previous = os.umask(0o002)
        try:
            self.perform(self.arguments("install", "1.0.0"))
        finally:
            os.umask(previous)
        release = self.installation / "releases/1.0.0"
        self.assert_release_web(release)
        self.assertTrue(self.verify(release))

    def test_extraction_sets_explicit_modes_whatever_the_umask(self):
        artifact, _ = self.artifact("1.0.0")
        for mask in (0o002, 0o000, 0o077, 0o277):
            with self.subTest(umask=oct(mask)):
                destination = Path(tempfile.mkdtemp(dir=self.root))
                os.chmod(destination, 0o755)
                previous = os.umask(mask)
                try:
                    _extract(artifact.read_bytes(), destination, "1.0.0")
                finally:
                    os.umask(previous)
                self.assert_release_web(destination)
                self.assertEqual(stat.S_IMODE((destination / "app/deployment.py").stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((destination / "app").stat().st_mode), 0o755)
                self.assertTrue(self.verify(destination))

    def test_the_installer_never_uses_hard_link_tooling(self):
        source = Path(install.__file__).read_text()
        for tool in ("os.link", "link-dest", "cp -al", "copytree", "copy2", "hardlink"):
            self.assertNotIn(tool, source)

    def test_an_artifact_may_not_carry_the_installer_manifest_copy(self):
        artifact, _ = self.artifact("1.0.0")
        with tarfile.open(artifact, "r:gz") as source:
            members = [(member, source.extractfile(member).read()) for member in source.getmembers()]
        forged = io.BytesIO()
        with tarfile.open(fileobj=forged, mode="w:gz") as archive:
            for member, data in members:
                archive.addfile(member, io.BytesIO(data))
            extra = tarfile.TarInfo(install.RELEASE_MANIFEST)
            extra.size = 2
            archive.addfile(extra, io.BytesIO(b"{}"))
        destination = Path(tempfile.mkdtemp(dir=self.root))
        with self.assertRaises(ValueError):
            _extract(forged.getvalue(), destination, "1.0.0")
        self.assertEqual(list(destination.iterdir()), [])

    def test_a_staged_build_that_differs_is_refused_and_unstaged(self):
        self.perform(self.arguments("install", "1.0.0"))
        state = self.state() if (self.installation / "previous").is_symlink() else None
        real = install._release_mode
        with patch("install._release_mode",
                   side_effect=lambda name: 0o644 if name.startswith("web/") else real(name)):
            with self.assertRaises(ValueError):
                self.perform(self.arguments("update", "1.1.0"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")
        self.assertFalse((self.installation / "releases/1.1.0").exists())
        self.assertFalse((self.installation / "releases/.1.1.0.staging").exists())
        if state is not None:
            self.assertEqual(state, self.state())

    def installed_two(self):
        self.perform(self.arguments("install", "1.0.0"))
        self.perform(self.arguments("update", "1.1.0"))
        return self.installation / "releases/1.0.0"

    def test_rollback_refuses_a_target_whose_build_differs_before_any_change(self):
        outside = self.root / "outside.js"
        outside.write_bytes(APP["app.js"])

        def modify(web):
            path = web / "app" / "app.js"
            path.chmod(0o644)
            path.write_bytes(APP["app.js"] + b"//")
            path.chmod(0o444)

        def extra(web):
            (web / "app").chmod(0o755)
            (web / "app" / "extra.js").write_bytes(b"synthetic\n")
            (web / "app" / "extra.js").chmod(0o444)

        def remove(web):
            (web / "shell" / "s.css").unlink()

        def writable(web):
            (web / "app" / "app.js").chmod(0o644)

        def linked(web):
            os.link(web / "app" / "app.js", self.root / "alias.js")

        def symlinked(web):
            (web / "app" / "app.js").unlink()
            (web / "app" / "app.js").symlink_to(outside)

        def directory_mode(web):
            (web / "shell").chmod(0o775)

        def manifest_copy(web):
            copy = web.parent / install.RELEASE_MANIFEST
            document = json.loads(copy.read_text())
            document["files"]["web/app/app.js"] = "0" * 64
            copy.chmod(0o644)
            copy.write_text(json.dumps(document))
            copy.chmod(0o444)

        def no_manifest_copy(web):
            (web.parent / install.RELEASE_MANIFEST).unlink()

        for change in (modify, extra, remove, writable, linked, symlinked, directory_mode,
                       manifest_copy, no_manifest_copy):
            with self.subTest(change=change.__name__):
                self.setUp()
                target = self.installed_two()
                change(target / "web")
                state, reloads = self.state(), self.daemon_reloads()
                checks = len([c for c, _ in self.runner.calls if "--check" in c])
                for version in (None, "1.0.0"):
                    with self.assertRaises(ReleaseFilesDiffer) as refused, patch(
                            "install._replace_unit", wraps=install._replace_unit) as replace_unit:
                        self.perform(self.arguments("rollback", version))
                    replace_unit.assert_not_called()
                    message = str(refused.exception)
                    for phrase in ("before any change", "releases/1.0.0", "release manifest",
                                   "move its directory out of releases/"):
                        self.assertIn(phrase, message)
                    self.assertNotIn("app.js", message)
                self.assertEqual(state, self.state())
                self.assertEqual(reloads, self.daemon_reloads())
                # Refused as root before the target's own check runs.
                self.assertEqual(checks, len([c for c, _ in self.runner.calls if "--check" in c]))

    def test_rollback_to_a_release_from_before_the_web_build_proceeds(self):
        target = self.installed_two()
        shutil.rmtree(target / "web")
        (target / install.RELEASE_MANIFEST).unlink()
        self.assertFalse(self.verify(target))
        self.perform(self.arguments("rollback"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")

    def test_an_intact_target_build_is_rolled_back_to(self):
        target = self.installed_two()
        self.assertTrue(self.verify(target))
        self.perform(self.arguments("rollback"))
        self.assertEqual(os.readlink(self.installation / "current"), "releases/1.0.0")

    def test_a_build_owned_by_another_account_is_refused(self):
        target = self.installed_two()
        with patch("install.RELEASE_OWNER_UID", self.uid + 1), self.assertRaises(ValueError):
            verify_release_web(target)


def _monitoring(uuid, device, mount):
    return {
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
            "mount_point": str(mount),
        },
    }


class WebAssetsDirectorySettingTests(unittest.TestCase):
    UUID = "00000000-1111-2222-3333-444444444444"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="server-web-setting-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.installation = self.root / "installation"
        self.release = self.installation / "releases/1.0.0"
        self.module = self.release / "app/deployment.py"
        self.module.parent.mkdir(parents=True)
        self.module.write_text("synthetic")
        (self.installation / "current").symlink_to("releases/1.0.0", target_is_directory=True)
        self.runtime = self.root / "runtime"
        for path in (self.runtime, self.runtime / "state", self.runtime / "recordings",
                     self.runtime / "audit"):
            path.mkdir(mode=0o700)
        self.device = self.runtime.stat().st_dev
        self.base = {
            "runtime_root": str(self.runtime), "service_uid": os.geteuid(),
            "runtime_mount_point": str(self.root),
            "runtime_device": [os.major(self.device), os.minor(self.device)],
            "runtime_filesystem_uuid": self.UUID, "capture_ca_directory": None,
            "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            "monitoring": _monitoring(self.UUID, self.device, self.root),
        }
        self.config = self.root / "etc/deployment.json"
        self.config.parent.mkdir(mode=0o755)
        for patcher in (patch("app.deployment.ADMINISTRATOR_UID", os.geteuid()),
                        patch("app.deployment._approved_filesystem_device", return_value=self.device),
                        patch("app.deployment.os.path.ismount", return_value=True),
                        patch("app.deployment._operating_system_root_device",
                              return_value=self.device + 1)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, **extra):
        self.config.write_text(json.dumps({**self.base, **extra}))
        self.config.chmod(0o600)

    def load(self, code_root=None, install_root=None, **extra):
        self.write(**extra)
        return Deployment.load(self.config, code_root=code_root or self.release,
                               install_root=self.installation if install_root is None else install_root)

    def check(self, module=None, **extra):
        """``python -m app.deployment --check`` of the release; ``(code, stdout, stderr)``."""
        self.write(**extra)
        with patch("app.deployment.__file__", str(module or self.module)), patch(
                "sys.stdout", new_callable=io.StringIO) as stdout, patch(
                "sys.stderr", new_callable=io.StringIO) as stderr:
            try:
                code = deployment_main(["--config", str(self.config), "--check"])
            except SystemExit as stopped:
                code = stopped.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_the_key_names_the_running_release_build(self):
        current = str(self.installation / "current/web")
        settings = self.load(web_assets_directory=current).settings
        self.assertEqual(settings.web_assets_dir, self.release / "web")
        # Another release (a rollback or staging check) resolves its own build.
        other = self.installation / "releases/1.1.0"
        other.mkdir()
        self.assertEqual(self.load(code_root=other, web_assets_directory=current).settings.web_assets_dir,
                         other / "web")
        # Absent: no build, so no human composition can be mounted.
        self.assertIsNone(self.load().settings.web_assets_dir)

    def test_a_source_tree_build_must_lie_inside_the_code_root(self):
        code = self.root / "checkout/server"
        code.mkdir(parents=True)
        self.write(web_assets_directory=str(code / "web"))
        deployment = Deployment.load(self.config, code_root=code)
        self.assertEqual(deployment.settings.web_assets_dir, code / "web")
        self.write(web_assets_directory=str(self.root / "checkout/web/dist"))
        with self.assertRaises(ConfigurationError):
            Deployment.load(self.config, code_root=code)

    def test_invalid_values_are_refused_value_free(self):
        current = self.installation / "current"
        for value in ("", "web", "relative/web", str(current), str(current) + "/../web",
                      str(current / "web/../../web"), str(self.release / "web"),
                      str(self.root / "web"), "/", None, 1, True, ["/x"], {"path": "/x"},
                      str(current / "web") + "\0"):
            with self.subTest(value=value), self.assertRaises(ConfigurationError) as refused:
                self.load(web_assets_directory=value)
            if isinstance(value, str) and "/" in value:
                self.assertNotIn(value, str(refused.exception))

    def test_the_staging_check_resolves_the_installation(self):
        staging = self.installation / "releases/.1.1.0.staging"
        module = staging / "app/deployment.py"
        module.parent.mkdir(parents=True)
        module.write_text("synthetic")
        with patch("app.deployment.__file__", str(module)):
            self.assertEqual(deployment_module._runtime_roots(), (staging, self.installation))
        for name in (".1.1.0", "1.1.0.staging", ".x.staging", "..staging"):
            other = self.installation / "releases" / name / "app/deployment.py"
            other.parent.mkdir(parents=True)
            other.write_text("synthetic")
            with self.subTest(name=name), patch("app.deployment.__file__", str(other)):
                self.assertIsNone(deployment_module._runtime_roots()[1])

    def test_the_release_check_loads_the_build_and_names_the_refusal(self):
        current = str(self.installation / "current/web")
        code, _, error = self.check(web_assets_directory=current)
        self.assertEqual((code, error),
                         (1, "ServerSentinel deployment validation failed: web assets refused (reason=path)\n"))
        web = write_build(self.release / "web")
        code, output, error = self.check(web_assets_directory=current)
        self.assertEqual((code, output, error), (0, "ServerSentinel deployment validation passed\n", ""))

        def refused(reason):
            code, _, error = self.check(web_assets_directory=current)
            self.assertEqual(code, 1)
            self.assertEqual(
                error, f"ServerSentinel deployment validation failed: web assets refused (reason={reason})\n")

        (web / "app" / "app.js").write_bytes(APP["app.js"][:-2] + b"//")
        refused("digest")
        (web / "app" / "app.js").write_bytes(APP["app.js"] + b"//")
        refused("size")
        (web / "app" / "app.js").write_bytes(APP["app.js"])
        (web / "app" / "app.js").chmod(0o666)
        refused("mode")
        (web / "app" / "app.js").chmod(0o644)
        os.link(web / "app" / "app.js", self.root / "alias.js")
        refused("nlink")
        (self.root / "alias.js").unlink()
        (web / "app" / "extra.js").write_bytes(b"synthetic\n")
        refused("set")
        (web / "app" / "extra.js").unlink()
        self.assertEqual(self.check(web_assets_directory=current)[0], 0)
        # A link inside the release must not lead to a build elsewhere.
        shutil.rmtree(web)
        (self.release / "web").symlink_to(write_build(self.root / "elsewhere"), target_is_directory=True)
        refused("path")
        # Without the key nothing is loaded, as before S5c.
        self.assertEqual(self.check()[0], 0)


if __name__ == "__main__":
    unittest.main()
