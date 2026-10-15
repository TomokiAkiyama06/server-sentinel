"""Issue #10 phase 2 S5b: the server's asset policy against the real Web build.

``app.auth.web_assets`` copies the response policies and content types of
``web/scripts/policy.mjs`` instead of reading ``web/`` at run time. These
tests read that file (a small, fixed-shape parser that fails on any other
shape) and compare it with the server's constants, so a change on one side
alone fails here.

``RealBuildTests`` loads an actual ``web/dist`` (S5a ``npm run build``)
through ``WebAssets.load``. Without a build, or without ``policy.mjs`` (a
copy of ``server/`` alone), these tests are skipped, unless
``WEB_DIST_REQUIRED=1`` (the CI ``web-browser`` job, right after building),
where either one missing fails instead (Issue #10 S5c). Standard library
only: that job installs no Main Server dependency.
"""

import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
import unittest.mock

from app.auth import web_assets
from app.auth.web_assets import WebAssets


REPOSITORY = Path(__file__).resolve().parents[2]
POLICY = REPOSITORY / "web" / "scripts" / "policy.mjs"
DIST = REPOSITORY / "web" / "dist"
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def web_required() -> bool:
    """Whether a missing Web source or build must fail instead of skip (CI)."""
    return os.environ.get("WEB_DIST_REQUIRED") == "1"


def _policy_source() -> str:
    if not POLICY.is_file():
        if web_required():
            raise AssertionError("WEB_DIST_REQUIRED=1 but web/scripts/policy.mjs is missing")
        raise unittest.SkipTest("web/scripts/policy.mjs is not part of this checkout")
    return POLICY.read_text(encoding="utf-8")


def _joined_array(source: str, name: str) -> str:
    """``export const NAME = ["a", "b"].join('; ');`` as ``"a; b"``."""
    match = re.search(r"^export const " + name + r" = \[(.*?)\]\.join\('; '\);$", source, re.S | re.M)
    if match is None:
        raise AssertionError(f"{name} in policy.mjs no longer has the parsed shape")
    body = match.group(1)
    items = [json.loads('"' + item + '"') for item in _STRING.findall(body)]
    if not items or _STRING.sub("", body).replace(",", "").strip():
        raise AssertionError(f"{name} in policy.mjs is not a list of string literals")
    return "; ".join(items)


def _content_types(source: str) -> dict[str, str]:
    match = re.search(r"^export const CONTENT_TYPES = new Map\(\[(.*?)\]\);$", source, re.S | re.M)
    if match is None:
        raise AssertionError("CONTENT_TYPES in policy.mjs no longer has the parsed shape")
    body = match.group(1)
    pairs = re.findall(r"\['\.([a-z0-9]+)', '([^'\\]*)'\]", body)
    if not pairs or re.sub(r"\['\.[a-z0-9]+', '[^'\\]*'\]", "", body).replace(",", "").strip():
        raise AssertionError("CONTENT_TYPES in policy.mjs is not a list of literal pairs")
    return dict(pairs)


class PolicyCrossCheckTests(unittest.TestCase):
    def setUp(self):
        self.source = _policy_source()

    def test_the_shell_policy_is_the_web_shell_policy(self):
        self.assertEqual(web_assets.SHELL_CSP, _joined_array(self.source, "SHELL_CSP"))

    def test_the_application_policies_are_the_web_policies(self):
        self.assertEqual(web_assets.APP_META_CSP, _joined_array(self.source, "APP_META_CSP"))
        # policy.mjs: APP_CSP = `${APP_META_CSP}; frame-ancestors 'none'`.
        self.assertRegex(self.source, r"(?m)^export const APP_CSP = `\$\{APP_META_CSP\}; frame-ancestors 'none'`;$")
        self.assertEqual(web_assets.APP_CSP, web_assets.APP_META_CSP + "; frame-ancestors 'none'")

    def test_the_content_types_are_the_web_content_types(self):
        self.assertEqual(dict(web_assets.CONTENT_TYPES), _content_types(self.source))

    def test_the_parser_rejects_a_changed_shape(self):
        # The parser must fail rather than silently read a partial value.
        changed = (self.source.replace(".join('; ')", ".join(';')"),
                   self.source.replace('"script-src \'self\'",', "SCRIPT,", 1))
        for index, source in enumerate(changed):
            self.assertNotEqual(source, self.source)
            with self.subTest(change=index):
                with self.assertRaises(AssertionError):
                    _joined_array(source, "SHELL_CSP")
        with self.assertRaises(AssertionError):
            _content_types(self.source.replace("['.svg', 'image/svg+xml'],", "[SVG, TYPE],"))


class RealBuildTests(unittest.TestCase):
    """The loader accepts what ``npm run build`` actually writes."""

    def setUp(self):
        if not (DIST / "manifest.json").is_file():
            if web_required():
                self.fail("WEB_DIST_REQUIRED=1 but web/dist/manifest.json is missing")
            raise unittest.SkipTest("no web/dist build in this checkout")
        # A private copy with release-like modes: the loader refuses group- or
        # world-writable entries, and a checkout's umask is not a deployment's.
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.build = Path(temporary.name) / "build"
        shutil.copytree(DIST, self.build, symlinks=True)
        for path in [self.build, *self.build.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)

    def test_the_real_build_loads_and_is_served_byte_for_byte(self):
        assets = WebAssets.load(self.build)
        manifest = json.loads((DIST / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(assets.shell_index.body, (DIST / "shell" / "index.html").read_bytes())
        self.assertEqual(assets.shell_script.body, (DIST / "shell" / "s.js").read_bytes())
        self.assertEqual(assets.shell_style.body, (DIST / "shell" / "s.css").read_bytes())
        self.assertEqual(assets.app_index.body, (DIST / "app" / "index.html").read_bytes())
        for path in manifest["files"]:
            directory, _, name = path.partition("/")
            if directory == "app" and name != "index.html":
                with self.subTest(path=path):
                    self.assertEqual(assets.app_file(name).body, (DIST / path).read_bytes())
                    self.assertEqual(assets.app_file(name).sha256, manifest["files"][path]["sha256"])
        self.assertIsNotNone(assets.app_file("app.js"))

    def test_the_real_application_document_carries_the_meta_policy(self):
        document = (self.build / "app" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(document.count("Content-Security-Policy"), 1)
        self.assertIn(f'<meta http-equiv="Content-Security-Policy" content="{web_assets.APP_META_CSP}">',
                      document)
        header = dict(WebAssets.load(self.build).app_index.headers)[b"content-security-policy"]
        self.assertEqual(header.decode(), web_assets.APP_CSP)


class RequiredBuildTests(unittest.TestCase):
    """Issue #10 S5c: ``WEB_DIST_REQUIRED=1`` turns every skip into a failure."""

    def run_case(self, case, required):
        missing = Path(tempfile.mkdtemp()) / "missing"
        self.addCleanup(shutil.rmtree, missing.parent)
        result = unittest.TestResult()
        with unittest.mock.patch(__name__ + ".POLICY", missing / "policy.mjs"), \
                unittest.mock.patch(__name__ + ".DIST", missing / "dist"), \
                unittest.mock.patch.dict(os.environ, {"WEB_DIST_REQUIRED": required}):
            case.run(result)
        return len(result.failures), len(result.skipped), len(result.errors)

    def test_a_missing_policy_or_build_fails_only_when_required(self):
        for case in (lambda: PolicyCrossCheckTests("test_the_content_types_are_the_web_content_types"),
                     lambda: RealBuildTests("test_the_real_build_loads_and_is_served_byte_for_byte")):
            with self.subTest(case=case().id()):
                self.assertEqual(self.run_case(case(), "1"), (1, 0, 0))
                self.assertEqual(self.run_case(case(), ""), (0, 1, 0))


if __name__ == "__main__":
    unittest.main()
