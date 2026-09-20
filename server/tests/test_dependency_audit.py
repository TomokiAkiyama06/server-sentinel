"""Keep every installable artifact within the reviewed inventory."""

import json
from pathlib import Path
import re
import unittest
from urllib.parse import urlsplit


class DependencyAuditTests(unittest.TestCase):
    def test_every_locked_artifact_has_complete_audit_provenance(self):
        root = Path(__file__).resolve().parents[1]
        permitted = set()
        for name in ("requirements.lock", "requirements-ci.lock"):
            logical_lines = (root / name).read_text().replace("\\\n", " ")
            for line in logical_lines.splitlines():
                if not line.strip() or line.startswith(("#", "-r ")):
                    continue
                pin = re.match(r"([a-z0-9-]+)==([^\s]+)\s+", line)
                self.assertIsNotNone(pin, name)
                hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?=\s|$)", line)
                self.assertTrue(hashes, pin.group(1))
                permitted.update((pin.group(1), pin.group(2), value)
                                 for value in hashes)

        records = json.loads((root / "docs/wheel-audit.json").read_text())
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
