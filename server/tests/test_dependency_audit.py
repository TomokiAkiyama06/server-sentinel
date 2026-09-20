"""Keep every installable artifact within the reviewed inventory."""

import json
from pathlib import Path
import re
import tempfile
import unittest
from urllib.parse import urlsplit


def locked_artifacts(root):
    """Follow the same local includes that pip installs, rejecting escapes/cycles."""
    root = root.resolve()
    permitted, active, visited = set(), set(), set()

    def read(name):
        if name in active:
            raise ValueError("cyclic requirement include")
        if name in visited:
            return
        path = root / name
        if path.is_symlink() or path.resolve().parent != root:
            raise ValueError("requirement include escapes component")
        active.add(name)
        for raw in path.read_text().replace("\\\n", " ").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "--requirement")):
                include = re.fullmatch(r"(?:-r|--requirement)\s+([a-zA-Z0-9_.-]+\.lock)", line)
                if include is None:
                    raise ValueError("unsupported requirement include")
                read(include.group(1))
                continue
            pin = re.match(r"([a-z0-9-]+)==([^\s]+)\s+", line)
            hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?=\s|$)", line)
            if pin is None or not hashes:
                raise ValueError("unhashed or unsupported requirement")
            permitted.update((pin.group(1), pin.group(2), digest) for digest in hashes)
        active.remove(name)
        visited.add(name)

    read("requirements.lock")
    read("requirements-ci.lock")
    return permitted


class DependencyAuditTests(unittest.TestCase):
    def test_every_locked_artifact_has_complete_audit_provenance(self):
        root = Path(__file__).resolve().parents[1]
        permitted = locked_artifacts(root)
        records = (json.loads((root / "docs/wheel-audit.json").read_text())
                   + json.loads((root / "docs/detector-wheel-audit.json").read_text()))
        audited = {(row["name"], row["version"], row["sha256"])
                   for row in records}
        self.assertEqual(len(audited), len(records), "duplicate audit artifact")
        self.assertEqual(permitted, audited, "unreviewed or obsolete wheel hash")
        for row in records:
            with self.subTest(wheel=row["wheel"]):
                download = urlsplit(row["download_url"])
                self.assertEqual(download.scheme, "https")
                self.assertEqual(download.hostname, "files.pythonhosted.org")
                self.assertEqual(download.path.rsplit("/", 1)[-1], row["wheel"])
                self.assertEqual(row["release_metadata_url"],
                                 "https://pypi.org/pypi/" + row["name"] + "/"
                                 + row["version"] + "/json")
                self.assertTrue(row["license"])
                self.assertTrue(row["license_files"])
                self.assertEqual(set(row["license_files"]), set(row["license_sha256"]))
                for digest in row["license_sha256"].values():
                    self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_nested_lock_addition_and_hash_change_are_not_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.lock").write_text("# no base packages\n")
            (root / "requirements-ci.lock").write_text("-r optional.lock\n")
            (root / "optional.lock").write_text("-r nested.lock\n")
            (root / "nested.lock").write_text("example==1 --hash=sha256:" + "a" * 64 + "\n")
            expected = {("example", "1", "a" * 64)}
            self.assertEqual(locked_artifacts(root), expected)
            (root / "nested.lock").write_text("example==1 --hash=sha256:" + "b" * 64 + "\n")
            self.assertNotEqual(locked_artifacts(root), expected)

    def test_include_cycles_and_escapes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.lock").write_text("# no base packages\n")
            for include in ("-r requirements-ci.lock\n", "-r ../outside.lock\n"):
                (root / "requirements-ci.lock").write_text(include)
                with self.assertRaises(ValueError):
                    locked_artifacts(root)
