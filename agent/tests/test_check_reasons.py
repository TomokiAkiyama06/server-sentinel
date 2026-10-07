"""`--check` reports exactly one fixed, identifier-free reason code per failure."""

import contextlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from media_capture_agent import cli, storage
from media_capture_agent.cli import CHECK_REASONS, main
from media_capture_agent.config import ExpectedMount
from media_capture_agent.pairing import NodeCredentialMaterial, NodeCredentialStore
from media_capture_agent.storage import MediaStore, Mount, StorageRefused
from tests.support import configuration

PASSED = "media-capture-agent: local deployment validation passed\n"
FAILED = "media-capture-agent: local deployment validation failed: "


@unittest.skipIf(os.geteuid() == 0, "the Agent refuses root by design")
class CheckReasonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-check-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.value = configuration(self.root)
        self.media = Path(self.value["media_root"])
        self.runtime = Path(self.value["runtime_root"])
        for directory in (self.media, self.runtime):
            # Restore traversal so the temporary tree can always be removed.
            self.addCleanup(lambda path=directory: path.exists() and path.chmod(0o700))
        self.store_options = {"stable_device": lambda _expected: True}

    def write(self, **changes):
        value = json.loads(json.dumps(self.value))
        mount = changes.pop("expected_mount", {})
        value.update(changes)
        value["expected_mount"].update(mount)
        self.value = value
        config = self.root / "deployment.json"
        config.write_text(json.dumps(value), encoding="utf-8")
        config.chmod(0o600)
        return config

    def forbidden(self):
        """Every configured identifier/value that must never be printed."""
        mount = self.value["expected_mount"]
        values = {str(self.root), self.value["media_root"], self.value["runtime_root"],
                  self.value["node_id"], mount["filesystem_uuid"], mount["source"],
                  f"{mount['major']}:{mount['minor']}", str(self.value["safety_reserve_bytes"]),
                  str(self.value["max_segment_bytes"])}
        if mount["mount_point"] != "/":
            values.add(mount["mount_point"])
        try:
            import pwd
            values.add(pwd.getpwuid(os.geteuid()).pw_name)
        except KeyError:
            pass
        return values

    def run_check(self, config=None, *, json_output=False):
        config = config or self.write()
        options = self.store_options
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--config", str(config), "--check"] + (["--json"] if json_output else [])
        with patch.object(cli, "MediaStore",
                          lambda settings: MediaStore(settings, **options)), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_reason(self, reason, config=None):
        self.assertIn(reason, CHECK_REASONS)
        code, stdout, stderr = self.run_check(config)
        self.assertEqual((code, stdout, stderr), (1, "", FAILED + reason + "\n"))
        code, stdout, stderr = self.run_check(config, json_output=True)
        self.assertEqual((code, stderr), (1, ""))
        self.assertEqual(json.loads(stdout), {"ok": False, "reason": reason})
        for output in (stdout, stderr):
            self.assertNotIn("Traceback", output)
            for value in self.forbidden():
                self.assertNotIn(value, output)

    def fake_mounts(self, *entries, mount_id=1):
        self.store_options.update(mounts=lambda: list(entries), mount_id=lambda _fd: mount_id)

    def identity(self, **changes):
        mount = dict(self.value["expected_mount"], **changes)
        return ExpectedMount(Path(mount["mount_point"]), mount["filesystem"], mount["source"],
                             mount["major"], mount["minor"], Path(mount["filesystem_root"]))

    # Success path is unchanged; --json success prints only {"ok": true}.

    def test_success_output_unchanged(self):
        self.assertEqual(self.run_check(), (0, PASSED, ""))
        code, stdout, stderr = self.run_check(json_output=True)
        self.assertEqual((code, json.loads(stdout), stderr), (0, {"ok": True}, ""))

    def test_json_requires_check(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--config", str(self.write()), "--json"])

    # Configuration.

    def test_config_invalid(self):
        config = self.write()
        config.chmod(0o644)
        self.assert_reason("config_invalid", config)
        self.assert_reason("config_invalid", self.write(audio=True))
        self.assert_reason("config_invalid", self.write(safety_reserve_bytes=-1))
        self.assert_reason("config_invalid", self.root / "absent.json")

    # Mount identity.

    def test_filesystem_uuid_mismatch(self):
        # Real /dev/disk/by-uuid lookup: the synthetic UUID never resolves.
        self.store_options = {}
        self.assert_reason("filesystem_uuid_mismatch")

    def test_mount_device_mismatch(self):
        minor = self.value["expected_mount"]["minor"]
        self.assert_reason("mount_device_mismatch",
                           self.write(expected_mount={"minor": minor + 1}))
        major = self.value["expected_mount"]["major"]
        self.assert_reason("mount_device_mismatch",
                           self.write(expected_mount={"minor": minor, "major": major + 1}))

    def test_mount_source_mismatch(self):
        self.assert_reason("mount_source_mismatch",
                           self.write(expected_mount={"source": "synthetic-other-source"}))

    def test_mount_identity_mismatch(self):
        self.assert_reason("mount_identity_mismatch",
                           self.write(expected_mount={"filesystem": "synthetic-fs"}))

    def test_media_root_on_root_filesystem(self):
        config = self.write(expected_mount={"mount_point": str(self.root),
                                            "filesystem_root": "/"})
        self.fake_mounts(Mount(ExpectedMount(Path("/"), "synthetic-rootfs", "synthetic-root",
                                             250, 1, Path("/")), 1, False))
        self.assert_reason("media_root_on_root_filesystem", config)

    def test_mount_point_is_root(self):
        config = self.write(expected_mount={"mount_point": "/", "filesystem_root": "/"})
        self.fake_mounts(
            Mount(ExpectedMount(Path("/"), "synthetic-rootfs", "synthetic-root", 250, 1,
                                Path("/")), 2, False),
            Mount(self.identity(mount_point=str(self.root)), 1, False),
        )
        self.assert_reason("mount_point_is_root", config)

    def test_mount_missing(self):
        # Approved mount absent from the inventory and media root absent.
        config = self.write(expected_mount={"mount_point": str(self.root),
                                            "filesystem_root": "/"})
        self.media.rmdir()
        self.fake_mounts(Mount(ExpectedMount(Path("/"), "synthetic-rootfs", "synthetic-root",
                                             250, 1, Path("/")), 1, False))
        self.assert_reason("mount_missing", config)
        # Mount inventory has no entry for the pinned directory's mount ID.
        self.media.mkdir(mode=0o700)
        self.fake_mounts(mount_id=7)
        self.assert_reason("mount_missing", config)

    def test_media_root_unavailable_while_mount_present(self):
        self.media.rmdir()
        self.assert_reason("media_root_unavailable")

    def test_mount_readonly(self):
        self.fake_mounts(Mount(self.identity(), 1, True))
        self.assert_reason("mount_readonly")
        self.fake_mounts(Mount(self.identity(), 1, False))
        readonly = type("Space", (), {"f_flag": os.ST_RDONLY, "f_bavail": 10**6,
                                      "f_frsize": 4096})()
        self.store_options["space"] = lambda _fd: readonly
        self.assert_reason("mount_readonly")

    def test_mount_replaced(self):
        calls = iter(range(1000))
        self.store_options["mount_id"] = lambda _fd: next(calls)
        self.assert_reason("mount_replaced")

    def test_mount_inventory_unavailable(self):
        def unavailable():
            raise StorageRefused("mount_inventory_unavailable")
        self.store_options["mounts"] = unavailable
        self.assert_reason("mount_inventory_unavailable")

    def test_mount_inventory_io_error_maps_to_inventory_reason(self):
        # Real read_mounts/descriptor_mount_id: /proc mountinfo/fdinfo unreadable.
        self.store_options = {"stable_device": lambda _expected: True}
        with patch.object(storage, "open", create=True,
                          side_effect=OSError(13, "synthetic " + str(self.root))):
            self.assert_reason("mount_inventory_unavailable")
        # Only mountinfo unreadable while fdinfo still resolves the mount ID.
        self.store_options = {"stable_device": lambda _expected: True,
                              "mount_id": lambda _fd: 1}
        with patch.object(storage, "open", create=True,
                          side_effect=OSError(5, "synthetic " + str(self.root))):
            self.assert_reason("mount_inventory_unavailable")

    def test_mount_inventory_io_error_at_startup_root_diagnostic(self):
        # Media root cannot be opened and the inventory is unreadable: the
        # startup helper must not report media_root_unavailable instead.
        self.media.rmdir()
        self.store_options = {"stable_device": lambda _expected: True}
        with patch.object(storage, "open", create=True,
                          side_effect=OSError(13, "synthetic " + str(self.root))):
            self.assert_reason("mount_inventory_unavailable")

        def unreadable():
            raise OSError(5, "synthetic " + str(self.root))
        self.store_options["mounts"] = unreadable
        self.assert_reason("mount_inventory_unavailable")

    def test_mount_inventory_io_error_keeps_runtime_reason(self):
        # Heartbeat/ring contract: str(exc) stays storage_unavailable.
        with patch.object(storage, "open", create=True, side_effect=OSError(5, "synthetic")):
            with self.assertRaises(StorageRefused) as raised:
                storage.read_mounts()
        self.assertEqual((str(raised.exception), raised.exception.diagnostic),
                         ("storage_unavailable", "mount_inventory_unavailable"))
        with patch.object(storage, "open", create=True, side_effect=OSError(5, "synthetic")):
            with self.assertRaises(StorageRefused) as raised:
                storage.descriptor_mount_id(0)
        self.assertEqual((str(raised.exception), raised.exception.diagnostic),
                         ("storage_unavailable", "mount_inventory_unavailable"))

    # Media root ownership, permissions and space.

    def test_media_root_owner_mismatch(self):
        self.assert_reason("media_root_owner_mismatch",
                           self.write(service_uid=os.geteuid() + 1))

    def test_media_root_permissions_too_open(self):
        self.media.chmod(0o770)
        self.assert_reason("media_root_permissions_too_open")

    def test_not_writable_by_service_account(self):
        self.media.chmod(0o500)
        self.assert_reason("not_writable_by_service_account")

    def test_insufficient_free_space(self):
        # A reserve larger than any free space (and the filesystem) fails closed.
        self.assert_reason("insufficient_free_space", self.write(safety_reserve_bytes=2**62))

    def test_storage_unavailable(self):
        def failing(_fd):
            raise OSError(5, "synthetic " + str(self.root))
        self.store_options["space"] = failing
        self.assert_reason("storage_unavailable")

    # Service account and runtime root.

    def test_service_account_mismatch(self):
        class RootOs:
            """Only the Agent's account check sees UID 0; config/storage stay real."""

            def __getattr__(self, name):
                return getattr(os, name)

            @staticmethod
            def geteuid():
                return 0

        with patch("media_capture_agent.runtime.os", RootOs()):
            self.assert_reason("service_account_mismatch")

    def test_runtime_root_reasons(self):
        self.runtime.chmod(0o750)
        self.assert_reason("runtime_root_permissions_unsafe")
        self.runtime.chmod(0o500)
        self.assert_reason("runtime_root_not_writable")
        self.runtime.chmod(0o700)
        self.runtime.rmdir()
        try:
            self.assert_reason("runtime_root_unavailable")
        finally:
            self.runtime.mkdir(mode=0o700)

    # Installed node credential vs configured node_id (#116 re-pairing).

    def install_credential(self, node):
        NodeCredentialStore(self.runtime).install(NodeCredentialMaterial(
            deployment_id=uuid4(), node_id=node, server_name="main.example.invalid",
            private_key=b"synthetic-private", client_certificate=b"synthetic-client",
            ca_certificate=b"synthetic-ca"))

    def test_matching_installed_credential_passes(self):
        self.install_credential(UUID(self.value["node_id"]))
        self.assertEqual(self.run_check(), (0, PASSED, ""))

    def test_node_identity_mismatch_refuses_check_and_start(self):
        # After ``enroll pair --repair revoked`` the credential names a new node
        # while the configuration still names the revoked one.
        new_node = uuid4()
        self.install_credential(new_node)
        self.assert_reason("node_identity_mismatch")
        config = self.write()
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "MediaStore",
                          lambda settings: MediaStore(settings, **self.store_options)), \
                patch.object(cli.Agent, "tick", side_effect=AssertionError("started")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--config", str(config)])
        self.assertEqual((1, "", FAILED + "node_identity_mismatch\n"),
                         (code, stdout.getvalue(), stderr.getvalue()))
        self.assertNotIn(str(new_node), stdout.getvalue() + stderr.getvalue())
        # The manual configuration update clears the refusal.
        self.write(node_id=str(new_node))
        self.assertEqual(self.run_check(), (0, PASSED, ""))

    def test_damaged_installed_credential_is_not_treated_as_unpaired(self):
        self.install_credential(UUID(self.value["node_id"]))
        for entry in (self.runtime / "node-credentials").glob("client-certificate-*.pem"):
            entry.write_bytes(b"tampered")
        self.assert_reason("node_credential_unavailable")

    def test_lost_credential_commit_is_not_treated_as_unpaired(self):
        self.install_credential(UUID(self.value["node_id"]))
        (self.runtime / "node-credentials" / "current.json").unlink()
        self.assert_reason("node_credential_unavailable")

    def test_check_backfills_evidence_for_an_identity_paired_before_it_existed(self):
        self.install_credential(UUID(self.value["node_id"]))
        (self.runtime / "node-identity-installed").unlink()
        self.assertEqual(self.run_check(), (0, PASSED, ""))
        self.assertTrue((self.runtime / "node-identity-installed").exists())
        (self.runtime / "node-credentials" / "current.json").unlink()
        self.assert_reason("node_credential_unavailable")

    # Unexpected internal errors.

    def test_unexpected_error_is_check_failed_without_exception_text(self):
        secret = "synthetic-secret " + str(self.root) + " " + self.value["node_id"]
        for error in (RuntimeError(secret), KeyError(secret), OSError(2, secret),
                      StorageRefused("unmapped_internal_" + secret)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(cli, "Agent", side_effect=error):
                self.assert_reason("check_failed")
                _code, stdout, stderr = self.run_check()
                self.assertNotIn("synthetic-secret", stdout + stderr)


class ReasonTableTests(unittest.TestCase):
    def test_codes_are_fixed_identifier_free_words(self):
        for reason in CHECK_REASONS:
            self.assertRegex(reason, re.compile(r"^[a-z][a-z_]*[a-z]$"))
        tables = cli._STORAGE_REASONS | cli._RUNTIME_REASONS
        self.assertLessEqual(set(cli._STORAGE_REASONS.values()), CHECK_REASONS)
        self.assertLessEqual(set(cli._RUNTIME_REASONS.values()), CHECK_REASONS)
        self.assertTrue(tables)

    def test_documented_table_matches_enum(self):
        readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
        documented = set(re.findall(r"^\| `([a-z_]+)` \|", readme, re.MULTILINE))
        self.assertEqual(documented & CHECK_REASONS, CHECK_REASONS)


if __name__ == "__main__":
    unittest.main()
