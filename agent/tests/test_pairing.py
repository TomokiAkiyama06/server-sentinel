import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from media_capture_agent.pairing import (
    NodeCredentialMaterial,
    NodeCredentialStore,
    PairingCode,
    PairingRefused,
    prompt_pairing_code,
)


DEPLOYMENT = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NODE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


class PairingPromptTests(unittest.TestCase):
    def test_code_and_secret_material_repr_are_redacted(self):
        code = PairingCode("A" * 26)
        material = self.material(private_key=b"synthetic-private-marker")
        self.assertNotIn(code.value, repr(code))
        self.assertNotIn("synthetic-private-marker", repr(material))

    def test_prompt_refuses_without_controlling_terminal_before_reading(self):
        reader_called = False

        def reader(*_args, **_kwargs):
            nonlocal reader_called
            reader_called = True
            return "A" * 26

        with self.assertRaisesRegex(PairingRefused, "secure_pairing_input_unavailable"):
            prompt_pairing_code(opener=lambda *_args: (_ for _ in ()).throw(OSError()),
                                reader=reader)
        self.assertFalse(reader_called)

    def test_prompt_uses_tty_and_validates_exact_base32(self):
        descriptor = os.open("/dev/null", os.O_RDWR)
        with patch("media_capture_agent.pairing.os.isatty", return_value=True):
            code = prompt_pairing_code(opener=lambda *_args: descriptor,
                                       reader=lambda *_args, **_kwargs: "A234567" + "B" * 19)
        self.assertEqual(code.value, "A234567" + "B" * 19)
        descriptor = os.open("/dev/null", os.O_RDWR)
        with patch("media_capture_agent.pairing.os.isatty", return_value=True):
            with self.assertRaisesRegex(PairingRefused, "invalid_pairing_code"):
                prompt_pairing_code(opener=lambda *_args: descriptor,
                                    reader=lambda *_args, **_kwargs: "lowercase-is-rejected-000")

    @staticmethod
    def material(**changes):
        values = {
            "deployment_id": DEPLOYMENT,
            "node_id": NODE,
            "server_name": "main.example.invalid",
            "private_key": b"synthetic-private",
            "client_certificate": b"synthetic-client-certificate",
            "ca_certificate": b"synthetic-ca-certificate",
        }
        values.update(changes)
        return NodeCredentialMaterial(**values)


class NodeCredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "runtime"
        self.root.mkdir(mode=0o700)
        self.store = NodeCredentialStore(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def material(self, **changes):
        return PairingPromptTests.material(**changes)

    def test_install_commits_one_private_generation(self):
        material = self.material()
        self.store.install(material)
        self.assertTrue(self.store.installed())

        credentials = self.root / "node-credentials"
        self.assertEqual(credentials.stat().st_mode & 0o777, 0o700)
        manifest_path = credentials / "current.json"
        self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o600)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest_path.stat().st_nlink, 2)
        self.assertEqual(manifest["deployment_id"], str(DEPLOYMENT))
        self.assertEqual(manifest["node_id"], str(NODE))
        for kind, expected in {
            "private_key": material.private_key,
            "client_certificate": material.client_certificate,
            "ca_certificate": material.ca_certificate,
        }.items():
            path = credentials / manifest["files"][kind]["name"]
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_bytes(), expected)

    def test_existing_identity_is_never_replaced(self):
        first = self.material()
        self.store.install(first)
        manifest = (self.root / "node-credentials" / "current.json").read_bytes()
        with self.assertRaisesRegex(PairingRefused, "node_identity_already_exists"):
            self.store.install(self.material(private_key=b"replacement"))
        self.assertEqual((self.root / "node-credentials" / "current.json").read_bytes(), manifest)

    def test_identity_replacement_swaps_only_to_a_new_node_of_the_same_deployment(self):
        self.store.install(self.material())
        credentials = self.root / "node-credentials"
        before = set(path.name for path in credentials.iterdir())
        other = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        for material, reason in (
                (self.material(private_key=b"same-node"), "repair_identity_rejected"),
                (self.material(node_id=other, deployment_id=other), "renewal_identity_mismatch")):
            with self.assertRaisesRegex(PairingRefused, reason):
                self.store.replace_identity(material)
        with self.assertRaisesRegex(PairingRefused, "renewal_identity_mismatch"):
            self.store.rotate(self.material(node_id=other))
        self.assertEqual(before, set(path.name for path in credentials.iterdir()))
        self.store.replace_identity(self.material(node_id=other, private_key=b"new-node-key"))
        self.assertTrue(self.store.installed())
        manifest = json.loads((credentials / "current.json").read_text(encoding="utf-8"))
        self.assertEqual(str(other), manifest["node_id"])
        after = set(path.name for path in credentials.iterdir())
        self.assertEqual({".pairing.lock", "current.json"}, before & after,
                         "the old generation is deleted after the swap commits")

    def test_symlinked_credential_directory_and_marker_are_refused(self):
        target = self.root / "target"
        target.mkdir(mode=0o700)
        (self.root / "node-credentials").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(PairingRefused, "credential_storage_unavailable"):
            self.store.install(self.material())
        self.assertEqual(list(target.iterdir()), [])

        (self.root / "node-credentials").unlink()
        credentials = self.root / "node-credentials"
        credentials.mkdir(mode=0o700)
        outside = self.root / "outside"
        outside.write_text("untouched", encoding="utf-8")
        (credentials / "current.json").symlink_to(outside)
        with self.assertRaisesRegex(PairingRefused, "node_identity_already_exists"):
            self.store.install(self.material())
        self.assertEqual(outside.read_text(encoding="utf-8"), "untouched")

    def test_shared_runtime_or_credential_permissions_are_refused(self):
        self.root.chmod(0o750)
        with self.assertRaisesRegex(PairingRefused, "runtime_root_rejected"):
            self.store.install(self.material())
        self.root.chmod(0o700)
        credentials = self.root / "node-credentials"
        credentials.mkdir(mode=0o750)
        with self.assertRaisesRegex(PairingRefused, "credential_directory_rejected"):
            self.store.install(self.material())

    def test_invalid_or_oversized_material_is_rejected_before_writing(self):
        with self.assertRaisesRegex(PairingRefused, "invalid_credential_material"):
            self.material(private_key=b"")
        with self.assertRaisesRegex(PairingRefused, "invalid_credential_material"):
            self.material(client_certificate=b"x" * (256 * 1024 + 1))
        with self.assertRaisesRegex(PairingRefused, "invalid_credential_metadata"):
            self.material(server_name="bad/name")
        self.assertFalse((self.root / "node-credentials").exists())

    def test_incomplete_generation_is_not_an_installed_identity(self):
        credentials = self.root / "node-credentials"
        credentials.mkdir(mode=0o700)
        (credentials / "private-key-orphan.pem").write_bytes(b"orphan")
        (credentials / "private-key-orphan.pem").chmod(0o600)
        self.assertFalse(self.store.installed())

    def test_lost_commit_marker_after_install_fails_closed(self):
        # PR #139 review: once an identity was installed, losing current.json
        # (or the whole credential directory) is corruption, never "unpaired".
        self.store.install(self.material())
        marker = self.root / "node-identity-installed"
        self.assertEqual(0o600, marker.stat().st_mode & 0o777)
        credentials = self.root / "node-credentials"
        (credentials / "current.json").unlink()
        with self.assertRaisesRegex(PairingRefused, "credential_commit_missing"):
            self.store.installed_node_id()
        with self.assertRaisesRegex(PairingRefused, "credential_commit_missing"):
            self.store.install(self.material(private_key=b"replacement"))
        self.assertFalse((credentials / "current.json").exists())
        for entry in credentials.iterdir():
            entry.unlink()
        credentials.rmdir()
        with self.assertRaisesRegex(PairingRefused, "credential_commit_missing"):
            self.store.installed()

    def test_interrupted_first_install_stays_unpaired_and_can_retry(self):
        with patch("media_capture_agent.pairing.os.link", side_effect=OSError("synthetic")):
            with self.assertRaisesRegex(PairingRefused, "credential_storage_unavailable"):
                self.store.install(self.material())
        self.assertFalse((self.root / "node-identity-installed").exists())
        self.assertIsNone(self.store.installed_node_id())
        self.store.install(self.material())
        self.assertEqual(NODE, self.store.installed_node_id())

    def test_swaps_keep_or_restore_the_installed_evidence(self):
        self.store.install(self.material())
        marker = self.root / "node-identity-installed"
        marker.unlink()  # e.g. a crash between the commit and the evidence write
        other = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        self.store.replace_identity(self.material(node_id=other, private_key=b"new-node-key"))
        self.assertTrue(marker.exists())
        self.store.rotate(self.material(node_id=other, private_key=b"renewed-key"))
        self.assertTrue(marker.exists())
        (self.root / "node-credentials" / "current.json").unlink()
        with self.assertRaisesRegex(PairingRefused, "credential_commit_missing"):
            self.store.installed()

    def test_validating_a_committed_generation_backfills_the_evidence(self):
        # PR #139 review: an identity paired before the evidence existed (or a
        # crash between the commit and the evidence write) has a valid commit
        # but no marker; validation must backfill it before anything is lost.
        self.store.install(self.material())
        marker = self.root / "node-identity-installed"
        marker.unlink()
        self.assertEqual(NODE, self.store.installed_node_id())
        self.assertTrue(marker.exists())
        self.assertEqual(0o600, marker.stat().st_mode & 0o777)
        (self.root / "node-credentials" / "current.json").unlink()
        with self.assertRaisesRegex(PairingRefused, "credential_commit_missing"):
            self.store.installed_node_id()

    def test_evidence_that_cannot_be_backfilled_fails_closed(self):
        self.store.install(self.material())
        (self.root / "node-identity-installed").unlink()
        real_open = os.open

        def refuse_marker(path, *args, **kwargs):
            if path == "node-identity-installed":
                raise OSError(28, "synthetic no space")
            return real_open(path, *args, **kwargs)
        with patch("media_capture_agent.pairing.os.open", refuse_marker):
            with self.assertRaisesRegex(PairingRefused, "credential_storage_unavailable"):
                self.store.installed_node_id()
        self.assertFalse((self.root / "node-identity-installed").exists())

    def test_committed_manifest_generation_survives_without_cleanup_step(self):
        self.store.install(self.material())
        credentials = self.root / "node-credentials"
        current = credentials / "current.json"
        companion = next(credentials.glob("manifest-*.json"))
        self.assertEqual((current.stat().st_dev, current.stat().st_ino),
                         (companion.stat().st_dev, companion.stat().st_ino))
        self.assertTrue(self.store.installed())

    def test_corrupt_or_replaced_committed_material_fails_closed(self):
        self.store.install(self.material())
        credentials = self.root / "node-credentials"
        manifest = json.loads((credentials / "current.json").read_text(encoding="utf-8"))
        key = credentials / manifest["files"]["private_key"]["name"]
        key.write_bytes(b"changed")
        key.chmod(0o600)
        with self.assertRaises(PairingRefused):
            self.store.installed()

    def test_missing_committed_material_is_not_treated_as_unpaired(self):
        self.store.install(self.material())
        credentials = self.root / "node-credentials"
        manifest = json.loads((credentials / "current.json").read_text(encoding="utf-8"))
        (credentials / manifest["files"]["private_key"]["name"]).unlink()

        with self.assertRaisesRegex(PairingRefused, "credential_storage_unavailable"):
            self.store.installed()

    def test_missing_companion_manifest_is_not_treated_as_unpaired(self):
        self.store.install(self.material())
        credentials = self.root / "node-credentials"
        next(credentials.glob("manifest-*.json")).unlink()

        with self.assertRaisesRegex(PairingRefused, "credential_file_rejected"):
            self.store.installed()

    def test_invalid_committed_marker_is_never_treated_as_identity(self):
        credentials = self.root / "node-credentials"
        credentials.mkdir(mode=0o700)
        marker = credentials / "current.json"
        marker.write_text('{"format_version":1}', encoding="utf-8")
        marker.chmod(0o600)
        with self.assertRaises(PairingRefused):
            self.store.installed()


if __name__ == "__main__":
    unittest.main()
