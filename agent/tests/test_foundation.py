import argparse
import dataclasses
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from build_artifact import build
from install import MAX_ARTIFACT_BYTES, install, read_artifact, render_unit
from media_capture_agent.cli import main
from media_capture_agent.config import ConfigurationError, Settings, MAX_CONFIGURATION_BYTES
from media_capture_agent.health import ClockExchange, assess_clock
from media_capture_agent.runtime import Agent
from media_capture_agent.storage import MediaStore, Mount, StorageRefused, parse_mounts
from tests.support import MockSession, SyntheticCapture, configuration, settings


class DeploymentCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agent-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.settings = settings(self.root)

    def store(self, **kwargs):
        store = MediaStore(self.settings, **kwargs)
        self.addCleanup(store.close)
        return store


class StorageTests(DeploymentCase):
    def test_bounded_private_write_never_replaces_existing(self):
        store = self.store()
        identity = uuid4()
        name = store.write_segment(identity, b"synthetic video bytes")
        path = self.settings.media_root / name
        self.assertEqual(path.read_bytes(), b"synthetic video bytes")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(StorageRefused):
            store.write_segment(identity, b"different data")
        self.assertEqual(path.read_bytes(), b"synthetic video bytes")
        for data in (b"", b"x" * (self.settings.max_segment_bytes + 1)):
            with self.assertRaises(StorageRefused):
                store.write_segment(uuid4(), data)
        with self.assertRaises(StorageRefused):
            store.write_segment("../escape", b"x")

    def test_missing_or_substituted_mount_blocks_startup(self):
        for mounts in ([], [Mount(dataclasses.replace(self.settings.expected_mount,
                                                     source="synthetic-other-device"), 1, False)]):
            with self.subTest(mounts=bool(mounts)), self.assertRaises(StorageRefused):
                self.store(mounts=lambda: mounts)
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_runtime_remount_same_device_is_refused(self):
        current = [Mount(self.settings.expected_mount, 1, False)]
        store = self.store(mounts=lambda: current, mount_id=lambda _: current[0].mount_id)
        current[0] = dataclasses.replace(current[0], mount_id=2)
        with self.assertRaisesRegex(StorageRefused, "mount_replaced"):
            store.write_segment(uuid4(), b"synthetic")
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_disappearance_creates_no_fallback(self):
        store = self.store()
        self.settings.media_root.rmdir()
        with self.assertRaises(StorageRefused):
            store.write_segment(uuid4(), b"synthetic")
        self.assertFalse(self.settings.media_root.exists())

    def test_directory_replacement_cannot_redirect_pinned_descriptor(self):
        store = self.store()
        old = self.root / "old-mounted-media"
        self.settings.media_root.rename(old)
        self.settings.media_root.mkdir(mode=0o700)
        with self.assertRaisesRegex(StorageRefused, "media_root_replaced"):
            store.write_segment(uuid4(), b"synthetic")
        self.assertEqual(list(old.iterdir()), [])
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_replacement_between_admission_and_open_stays_on_original_descriptor(self):
        store = self.store()
        original_open = os.open
        old = self.root / "old-mounted-media"

        def replace_at_open(path, flags, *args, **kwargs):
            if str(path).endswith(".segment"):
                self.settings.media_root.rename(old)
                self.settings.media_root.mkdir(mode=0o700)
            return original_open(path, flags, *args, **kwargs)

        with patch("media_capture_agent.storage.os.open", side_effect=replace_at_open):
            with self.assertRaisesRegex(StorageRefused, "media_root_replaced"):
                store.write_segment(uuid4(), b"synthetic")
        self.assertEqual(list(old.iterdir()), [])
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_symlink_ancestors_and_media_root_refused(self):
        original = self.settings.media_root
        moved = self.root / "original"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(StorageRefused):
            self.store()
        original.unlink()
        moved.rename(original)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.settings = dataclasses.replace(self.settings, media_root=alias / "media")
        with self.assertRaises(StorageRefused):
            self.store()

    def test_readonly_or_shared_writable_root_rejected(self):
        for mode in (0o500, 0o777):
            self.settings.media_root.chmod(mode)
            try:
                with self.assertRaises(StorageRefused):
                    self.store()
            finally:
                self.settings.media_root.chmod(0o700)

    def test_reserve_uses_available_blocks_and_rounding(self):
        value = os.statvfs(self.settings.media_root)
        fake = type("Space", (), {"f_bavail": 1, "f_frsize": 4096, "f_flag": value.f_flag})()
        store = self.store(space=lambda _: fake)
        with self.assertRaisesRegex(StorageRefused, "STORAGE_HARD_STOP"):
            store.write_segment(uuid4(), b"synthetic")
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_failed_allocation_never_uses_sparse_fallback(self):
        store = self.store()
        with patch("media_capture_agent.storage.os.posix_fallocate", side_effect=OSError):
            with self.assertRaises(StorageRefused):
                store.write_segment(uuid4(), b"synthetic")
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_failed_sync_removes_only_owned_partial(self):
        store = self.store()
        existing = store.write_segment(uuid4(), b"earlier synthetic")
        with patch("media_capture_agent.storage.os.fsync", side_effect=OSError):
            with self.assertRaises(StorageRefused):
                store.write_segment(uuid4(), b"synthetic")
        self.assertEqual([entry.name for entry in self.settings.media_root.iterdir()], [existing])

    def test_inventory_verification_and_cleanup_at_hard_stop(self):
        store = self.store()
        identity, data = uuid4(), b"synthetic complete segment"
        store.write_segment(identity, data)
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(store.list_segments(), {identity: len(data)})
        self.assertGreaterEqual(store.segment_allocations()[identity], len(data))
        self.assertGreater(store.allocation_unit, 0)
        self.assertTrue(store.verify_segment(identity, len(data), digest))
        self.assertFalse(store.verify_segment(identity, len(data), "0" * 64))
        self.assertFalse(store.verify_segment(identity, len(data) - 1, digest))
        self.assertFalse(store.verify_segment(uuid4(), len(data), digest))
        fake = type("Space", (), {"f_bavail": 0, "f_frsize": 4096, "f_flag": 0})()
        store.space = lambda _: fake
        with self.assertRaisesRegex(StorageRefused, "STORAGE_HARD_STOP"):
            store.check()
        self.assertEqual(store.check(require_reserve=False), 0)
        self.assertTrue(store.verify_segment(identity, len(data), digest))
        self.assertTrue(store.delete_segment(identity))
        self.assertFalse(store.delete_segment(identity))
        self.assertEqual(store.list_segments(), {})

    def test_recovery_rejects_fullsize_but_partial_zeroed_content(self):
        store = self.store()
        identity, data = uuid4(), b"synthetic expected content"
        path = self.settings.media_root / (str(identity) + ".segment")
        descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        try:
            os.posix_fallocate(descriptor, 0, len(data))
            os.write(descriptor, data[:5])
        finally:
            os.close(descriptor)
        self.assertEqual(store.list_segments()[identity], len(data))
        self.assertFalse(store.verify_segment(identity, len(data), hashlib.sha256(data).hexdigest()))

    def test_inventory_rejects_symlinks_without_reading_or_deleting_target(self):
        store = self.store()
        target = self.root / "unrelated"
        target.write_bytes(b"keep")
        identity = uuid4()
        (self.settings.media_root / (str(identity) + ".segment")).symlink_to(target)
        for operation in (store.list_segments, store.segment_allocations,
                          lambda: store.delete_segment(identity),
                          lambda: store.verify_segment(identity, 4, "0" * 64)):
            with self.assertRaises(StorageRefused):
                operation()
        self.assertEqual(target.read_bytes(), b"keep")

    def test_stacked_bind_mount_identity_change_is_detected(self):
        store = self.store()
        pinned = store.mount_id(store._fd)
        store.mount_id = lambda fd: pinned if fd == store._fd else pinned + 1
        with self.assertRaisesRegex(StorageRefused, "mount_replaced"):
            store.check()

    def test_systemd_narrow_writable_bind_preserves_approved_backing_identity(self):
        expected = self.settings.expected_mount
        relative = self.settings.media_root.relative_to(expected.mount_point)
        namespace = dataclasses.replace(expected, mount_point=self.settings.media_root,
                                        filesystem_root=expected.filesystem_root / relative)
        mounts = [Mount(expected, 10, True), Mount(namespace, 11, False)]
        store = self.store(mounts=lambda: mounts, mount_id=lambda _: 11)
        identity = uuid4()
        store.write_segment(identity, b"synthetic namespace capture")
        self.assertIn(identity, store.list_segments())
        mounts.pop(0)
        with self.assertRaisesRegex(StorageRefused, "mount_identity_mismatch"):
            store.write_segment(uuid4(), b"missing approved parent")

    def test_same_device_bind_of_unapproved_backing_directory_is_rejected(self):
        expected = self.settings.expected_mount
        substituted = dataclasses.replace(expected, mount_point=self.settings.media_root,
                                          filesystem_root=Path("/synthetic-unapproved"))
        mounts = [Mount(expected, 10, True), Mount(substituted, 11, False)]
        with self.assertRaisesRegex(StorageRefused, "mount_identity_mismatch"):
            self.store(mounts=lambda: mounts, mount_id=lambda _: 11)
        same_point_wrong_root = dataclasses.replace(expected, filesystem_root=Path("/substitute"))
        with self.assertRaisesRegex(StorageRefused, "mount_identity_mismatch"):
            self.store(mounts=lambda: [Mount(same_point_wrong_root, 11, False)],
                       mount_id=lambda _: 11)

    def test_mount_parser_escapes_and_readonly_superblock(self):
        mount = parse_mounts("31 20 8:1 / /synthetic\\040mount rw - ext4 /dev/synthetic ro\n")[0]
        self.assertEqual(mount.identity.mount_point, Path("/synthetic mount"))
        self.assertTrue(mount.readonly)
        with self.assertRaises(StorageRefused):
            parse_mounts("malformed")


class HealthTests(DeploymentCase):
    def test_clock_offset_uncertainty_wall_step(self):
        healthy = ClockExchange(100, 50, 100.1, 100.1, 100.2, 50.2)
        self.assertEqual(assess_clock(healthy, self.settings).state, "online")
        for exchange, reason in (
            (None, "clock_unavailable"),
            (dataclasses.replace(healthy, remote_receive_utc=110.1,
                                 remote_send_utc=110.1), "clock_offset"),
            (dataclasses.replace(healthy, local_receive_utc=104,
                                 local_receive_monotonic=54), "clock_uncertain"),
            (dataclasses.replace(healthy, local_receive_utc=120), "clock_step"),
            (dataclasses.replace(healthy, local_receive_monotonic=49), "clock_invalid"),
            (dataclasses.replace(healthy, remote_send_utc=float("nan")), "clock_invalid"),
        ):
            with self.subTest(reason=reason):
                self.assertEqual(assess_clock(exchange, self.settings).reason, reason)

    def test_unplug_keeps_node_online(self):
        capture, session = SyntheticCapture(), MockSession()
        agent = Agent(self.settings, self.store(), capture=capture, session=session)
        self.addCleanup(agent.close)
        healthy = agent.tick()
        capture.online = False
        unplugged = agent.tick()
        self.assertEqual(healthy["node_state"], "online")
        self.assertEqual(unplugged["node_state"], "online")
        self.assertEqual(unplugged["sources"][0]["state"], "offline")
        self.assertEqual(len(session.heartbeats), 2)
        self.assertEqual(unplugged["sequence"], 2)

    def test_clock_main_mount_failures_report_degradation(self):
        capture, session = SyntheticCapture(), MockSession()
        agent = Agent(self.settings, self.store(), capture=capture, session=session)
        self.addCleanup(agent.close)
        session.offset = 20
        self.assertIn("clock_offset", agent.tick()["node_reasons"])
        session.fail = True
        self.assertIn("main_unavailable", agent.tick()["node_reasons"])
        self.settings.media_root.rmdir()
        heartbeat = agent.tick()
        self.assertEqual(heartbeat["storage"]["state"], "failed")
        self.assertEqual(heartbeat["node_state"], "degraded")
        self.assertFalse(self.settings.media_root.exists())

    def test_unpaired_service_closed_and_close_releases_resources(self):
        agent = Agent(self.settings, self.store())
        heartbeat = agent.tick()
        self.assertIn("pairing_required", heartbeat["node_reasons"])
        self.assertIn("capture_unconfigured", heartbeat["node_reasons"])
        self.assertEqual(heartbeat["node_state"], "degraded")
        agent.close()
        self.assertIsNone(agent.store._fd)

    def test_root_or_other_account_cannot_run_service(self):
        for uid in (0, os.geteuid() + 1):
            with patch("media_capture_agent.runtime.os.geteuid", return_value=uid):
                with self.assertRaisesRegex(StorageRefused, "nonroot"):
                    Agent(self.settings, self.store())


class ConfigurationTests(unittest.TestCase):
    def test_no_audio_or_resource_defaults_or_code_tree_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = configuration(root)
            for key, bad in (("audio", True), ("service_uid", 0),
                             ("clock_offset_limit_seconds", float("nan")),
                             ("safety_reserve_bytes", 0), ("media_root", str(root / "code/media"))):
                with self.subTest(key=key), self.assertRaises(ConfigurationError):
                    Settings.parse(dict(value, **{key: bad}), code_root=root / "code")

    def test_fifo_configuration_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "configuration.fifo"
            os.mkfifo(fifo, mode=0o600)
            script = """
import sys
from pathlib import Path
from media_capture_agent.config import ConfigurationError, Settings, MAX_CONFIGURATION_BYTES
try:
    Settings.load(Path(sys.argv[1]), code_root=Path(sys.argv[1]).parent / "code")
except ConfigurationError:
    raise SystemExit(0)
raise SystemExit(1)
"""
            subprocess.run([sys.executable, "-c", script, str(fifo)],
                           check=True, timeout=2, capture_output=True)

    def test_installer_rejects_fifo_before_parsing_or_deployment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "synthetic-artifact"
            artifact.write_bytes(b"synthetic-not-executable")
            fifo = root / "configuration.fifo"
            os.mkfifo(fifo, mode=0o600)
            script = """
import argparse
import hashlib
from pathlib import Path
import sys
from unittest.mock import patch
from install import install
artifact, fifo = Path(sys.argv[1]), Path(sys.argv[2])
args = argparse.Namespace(artifact=artifact, config=fifo, version="0.1.0",
                          destination=fifo.parent / "installation",
                          sha256=hashlib.sha256(artifact.read_bytes()).hexdigest())
with patch("install.os.geteuid", return_value=0):
    try:
        install(args)
    except ValueError:
        raise SystemExit(0)
raise SystemExit(1)
"""
            subprocess.run([sys.executable, "-c", script, str(artifact), str(fifo)],
                           check=True, timeout=2, capture_output=True)

    def test_configuration_growth_is_bounded_in_agent_and_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "deployment.json"
            value = configuration(root)
            original_fdopen = os.fdopen
            reads = []

            def growing_reader(fd, mode):
                stream = original_fdopen(fd, mode)

                class Reader:
                    def __enter__(self):
                        return self

                    def __exit__(self, *_):
                        stream.close()

                    def fileno(self):
                        return stream.fileno()

                    def read(self, size=-1):
                        reads.append(size)
                        if not 0 <= size <= MAX_CONFIGURATION_BYTES + 1:
                            raise AssertionError("unbounded configuration read")
                        with config.open("ab") as writer:
                            writer.truncate(MAX_CONFIGURATION_BYTES * 2)
                        return stream.read(size)

                return Reader()

            for caller in ("agent", "installer"):
                config.write_text(json.dumps(value))
                config.chmod(0o600)
                args = argparse.Namespace(artifact=root / "unused-artifact", config=config,
                                          version="0.1.0", destination=root / "install",
                                          sha256=hashlib.sha256(b"synthetic").hexdigest())
                with self.subTest(caller=caller), patch("os.fdopen", side_effect=growing_reader):
                    with self.assertRaises(ConfigurationError):
                        if caller == "agent":
                            Settings.load(config, code_root=root / "code")
                        else:
                            with patch("install.os.geteuid", return_value=0), patch(
                                "install.read_artifact", return_value=b"synthetic"
                            ):
                                install(args)
            self.assertEqual(reads, [MAX_CONFIGURATION_BYTES + 1] * 2)

    def test_configuration_in_source_or_installation_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = root / "code"
            destination = root / "installation"
            code.mkdir()
            destination.mkdir()
            alias = root / "external-alias"
            alias.symlink_to(code, target_is_directory=True)
            value = configuration(root)
            for parent in (code, destination, root):
                config = parent / "deployment.json"
                config.write_text(json.dumps(value))
                config.chmod(0o600)
            for path in (code / "deployment.json", alias / "deployment.json"):
                with self.subTest(path=path.name), self.assertRaises(ConfigurationError):
                    Settings.load(path, code_root=code)
            self.assertEqual(Settings.load(root / "deployment.json", code_root=code).service_uid,
                             os.geteuid())
            for parent in (code, destination, alias):
                args = argparse.Namespace(artifact=root / "unused", version="0.1.0",
                                          config=parent / "deployment.json", destination=destination,
                                          sha256=hashlib.sha256(b"synthetic").hexdigest())
                with self.subTest(parent=parent.name), patch("install.os.geteuid", return_value=0), patch(
                    "install.read_artifact", return_value=b"synthetic"
                ), patch("install.__file__", str(code / "agent/install.py")), patch(
                    "install.protected_parent"
                ) as deployment:
                    with self.assertRaises(ConfigurationError):
                        install(args)
                    deployment.assert_not_called()

    def test_config_owner_only_and_redacted_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text(json.dumps(configuration(root)))
            config.chmod(0o600)
            self.assertEqual(Settings.load(config, code_root=root / "code").service_uid,
                             os.geteuid())
            config.chmod(0o644)
            with self.assertRaises(ConfigurationError):
                Settings.load(config, code_root=root / "code")
            error = io.StringIO()
            with patch("sys.stderr", error):
                self.assertEqual(main(["--config", str(config), "--check"]), 1)
            self.assertNotIn(str(root), error.getvalue())


class DistributionTests(DeploymentCase):
    def test_ci_container_context_is_allow_listed(self):
        rules = (Path(__file__).parents[1] / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("\n*\n", "\n" + rules)
        for path in ("!media_capture_agent/**", "!tests/**", "**/__pycache__/", "**/*.pyc"):
            self.assertIn(path, rules)

    def test_versioned_artifact_accepts_only_config_outside_installation(self):
        version = self.root / "installation" / "0.1.0"
        version.mkdir(parents=True)
        artifact = version / "media-capture-agent"
        digest = build(artifact)
        self.assertEqual(len(digest), 64)
        result = subprocess.run([sys.executable, str(artifact), "--help"], capture_output=True,
                                text=True, check=True, cwd="/")
        self.assertIn("media-capture-agent", result.stdout)
        config = self.root / "deployment.json"
        values = dataclasses.asdict(self.settings)
        values["node_id"] = str(values["node_id"])
        values["runtime_root"] = str(values["runtime_root"])
        values["media_root"] = str(values["media_root"])
        values["expected_mount"]["mount_point"] = str(values["expected_mount"]["mount_point"])
        values["expected_mount"]["filesystem_root"] = str(values["expected_mount"]["filesystem_root"])
        config.write_text(json.dumps(values))
        config.chmod(0o600)
        checked = subprocess.run([sys.executable, str(artifact), "--config", str(config), "--check"],
                                 capture_output=True, text=True, check=True, cwd="/")
        self.assertIn("validation passed", checked.stdout)
        for parent in (version, version.parent):
            internal = parent / "deployment.json"
            internal.write_text(config.read_text())
            internal.chmod(0o600)
            rejected = subprocess.run([sys.executable, str(artifact), "--config", str(internal),
                                       "--check"], capture_output=True, text=True, cwd="/", timeout=5)
            self.assertEqual(rejected.returncode, 1)
            self.assertNotIn("validation passed", rejected.stdout)
        for key in ("runtime_root", "media_root"):
            internal = version.parent / key
            internal.mkdir(mode=0o700)
            config.write_text(json.dumps(dict(values, **{key: str(internal)})))
            rejected = subprocess.run([sys.executable, str(artifact), "--config", str(config),
                                       "--check"], capture_output=True, text=True, cwd="/", timeout=5)
            self.assertEqual(rejected.returncode, 1)
            self.assertNotIn("validation passed", rejected.stdout)
        import zipfile
        with zipfile.ZipFile(artifact) as archive:
            self.assertIn("LICENSE", archive.namelist())
            self.assertFalse(any("test" in name or name.endswith(".pyc")
                                 for name in archive.namelist()))

    def test_artifact_fifo_device_symlink_and_oversize_are_rejected_before_read(self):
        fifo = self.root / "artifact.fifo"
        os.mkfifo(fifo, mode=0o600)
        script = """
import sys
from pathlib import Path
from install import read_artifact
try:
    read_artifact(Path(sys.argv[1]))
except ValueError:
    raise SystemExit(0)
raise SystemExit(1)
"""
        subprocess.run([sys.executable, "-c", script, str(fifo)],
                       check=True, timeout=2, capture_output=True)
        with self.assertRaises(ValueError):
            read_artifact(Path("/dev/zero"))
        large = self.root / "oversized-artifact"
        with large.open("wb") as stream:
            stream.truncate(MAX_ARTIFACT_BYTES + 1)
        with self.assertRaises(ValueError):
            read_artifact(large)
        valid = self.root / "bounded-artifact"
        valid.write_bytes(b"bounded synthetic artifact")
        self.assertEqual(read_artifact(valid), valid.read_bytes())
        alias = self.root / "artifact-alias"
        alias.symlink_to(valid)
        with self.assertRaises(OSError):
            read_artifact(alias)

    def test_installer_release_is_traversable_under_restrictive_umask(self):
        destination = self.root / "installation"
        destination.mkdir()
        config = self.root / "deployment.json"
        value = dataclasses.asdict(self.settings)
        for key in ("node_id", "runtime_root", "media_root"):
            value[key] = str(value[key])
        for key in ("mount_point", "filesystem_root"):
            value["expected_mount"][key] = str(value["expected_mount"][key])
        config.write_text(json.dumps(value))
        config.chmod(0o600)
        artifact = self.root / "bounded-artifact"
        artifact.write_bytes(b"synthetic-artifact-not-executed")
        args = argparse.Namespace(artifact=artifact, config=Path(os.path.relpath(config)), version="0.1.0",
                                  destination=destination, video_device=[],
                                  unit=self.root / "media-capture-agent.service",
                                  sha256=hashlib.sha256(artifact.read_bytes()).hexdigest())
        previous = os.umask(0o077)
        try:
            # Files are synthetic/non-root-owned here; actual privileged preflight
            # remains manual. Assert installation modes without running any code.
            with patch("install.os.geteuid", return_value=0), patch("install.protected_parent"), patch(
                "install.subprocess.run"
            ) as preflight:
                install(args)
            self.assertTrue(preflight.called)
        finally:
            os.umask(previous)
        self.assertEqual((destination / "0.1.0").stat().st_mode & 0o777, 0o755)
        self.assertEqual((destination / "0.1.0/media-capture-agent").stat().st_mode & 0o777, 0o555)
        self.assertEqual(preflight.call_args.args[0][2], str(config.absolute()))
        self.assertIn(str(config.absolute()), args.unit.read_text(encoding="utf-8"))

    def test_checkout_named_agent_accepts_external_sibling_data(self):
        component = self.root / "agent" / "agent"
        component.mkdir(parents=True)
        shutil.copytree(Path(__file__).resolve().parents[1] / "media_capture_agent",
                        component / "media_capture_agent",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        config = self.root / "deployment.json"
        value = dataclasses.asdict(self.settings)
        for key in ("node_id", "runtime_root", "media_root"):
            value[key] = str(value[key])
        for key in ("mount_point", "filesystem_root"):
            value["expected_mount"][key] = str(value["expected_mount"][key])
        config.write_text(json.dumps(value))
        config.chmod(0o600)
        result = subprocess.run([sys.executable, "-m", "media_capture_agent.cli",
                                 "--config", str(config), "--check"], cwd=component,
                                capture_output=True, text=True, timeout=5, check=True)
        self.assertIn("validation passed", result.stdout)

    def test_unit_dedicated_account_and_video_only_devices(self):
        unit = render_unit(Path("/opt/example/0.1.0/media-capture-agent"),
                           Path("/etc/example/config.json"), self.settings, "synthetic", 123,
                           ["/dev/video0"])
        self.assertIn("User=synthetic", unit)
        self.assertIn("Group=123", unit)
        self.assertIn("DevicePolicy=closed", unit)
        self.assertIn('DeviceAllow="/dev/video0" rw', unit)
        self.assertIn("--check", unit)
        self.assertNotIn("/dev/snd", unit)
        with self.assertRaises(ValueError):
            render_unit(Path("/opt/example/agent"), Path("/etc/example/config.json"),
                        self.settings, "synthetic", 123, ["/dev/snd/pcmC0D0c"])
