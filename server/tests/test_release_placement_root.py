"""Issue #10 phase 2 S5c: release placement as real root, without patching the owner.

The other release tests stand in for root with the test account
(``install.RELEASE_OWNER_UID`` patched). This one runs ``_extract`` and
``verify_release_web`` as root itself, under the Ubuntu default umask
``0002``, and checks the root-owned, read-only, singly linked result. It is
skipped unless the process is root, and fails instead when
``RELEASE_PLACEMENT_REQUIRE_ROOT=1`` (the CI root step). Every build is
synthetic (``tests.web_asset_fakes``).
"""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest

import install
from install import _extract, verify_release_web
from tests.web_asset_fakes import write_build


def _artifact(web: Path) -> bytes:
    files = {"app/__init__.py": b""}
    for path in sorted(web.rglob("*")):
        if path.is_file():
            files["web/" + str(path.relative_to(web))] = path.read_bytes()
    manifest = {"format": 1, "name": "server-sentinel-main", "version": "1.0.0",
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as archive:
        for name, data in (("manifest.json", json.dumps(manifest).encode()), *files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            archive.addfile(info, io.BytesIO(data))
    return content.getvalue()


class RootPlacementTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            if os.environ.get("RELEASE_PLACEMENT_REQUIRE_ROOT") == "1":
                self.fail("RELEASE_PLACEMENT_REQUIRE_ROOT=1 but the test is not running as root")
            raise unittest.SkipTest("release placement as root needs root")
        temporary = tempfile.TemporaryDirectory(prefix="server-placement-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_the_build_is_placed_root_owned_read_only_and_verified(self):
        self.assertEqual(install.RELEASE_OWNER_UID, 0)
        content = _artifact(write_build(self.root / "web-dist"))
        destination = self.root / "release"
        destination.mkdir()
        destination.chmod(0o755)
        previous = os.umask(0o002)
        try:
            _extract(content, destination, "1.0.0")
        finally:
            os.umask(previous)
        web = destination / "web"
        for path in [web, *web.rglob("*")]:
            info = os.lstat(path)
            with self.subTest(path=str(path.relative_to(destination))):
                self.assertEqual(info.st_uid, 0)
                if stat.S_ISDIR(info.st_mode):
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o755)
                else:
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o444, 1))
        self.assertTrue(verify_release_web(destination))
        # A file handed to another account is refused without any patching.
        os.chown(web / "app" / "app.js", 65534, -1)
        with self.assertRaises(ValueError):
            verify_release_web(destination)


if __name__ == "__main__":
    unittest.main()
