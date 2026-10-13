"""Synthetic Web builds for the human surface tests (Issue #10 phase 2 S5b).

Every file is invented text; no real build output, name or person is used.
The layout is the one ``web/dist`` has after S5a: ``manifest.json``,
``shell/`` (exactly three files) and ``app/``.
"""

import hashlib
import json
from pathlib import Path

from app.auth.web_assets import WebAssets


SHELL = {
    "index.html": b"<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">"
                  b"<link rel=\"stylesheet\" href=\"/s.css\"><script type=\"module\" src=\"/s.js\"></script>"
                  b"</head><body><main id=\"s\"></main></body></html>\n",
    "s.js": b"document.getElementById('s').textContent = 'synthetic shell';\n",
    "s.css": b"main{font-family:sans-serif}\n",
}
APP = {
    "index.html": b"<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">"
                  b"<script type=\"module\" src=\"/app/app.js\"></script></head>"
                  b"<body><div id=\"root\"></div></body></html>\n",
    "app.js": b"export const synthetic = 1;\n",
    "app.css": b"#root{margin:0}\n",
    "icon.svg": b"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1 1\"></svg>\n",
    "synthetic-license.txt": b"Synthetic licence text for tests.\n",
    # The S5a build's mixed-case names (esbuild's external legal comments).
    "app.js.LEGAL.txt": b"Synthetic legal comments.\n",
    "synthetic-LICENSE.txt": b"Synthetic licence text for tests.\n",
}
# The content types S5a writes into its manifest (web/scripts/policy.mjs).
TYPES = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
         "css": "text/css; charset=utf-8", "svg": "image/svg+xml", "txt": "text/plain; charset=utf-8"}


def manifest_for(shell: dict, app: dict) -> dict:
    files = {}
    for directory, contents in (("shell", shell), ("app", app)):
        for name, body in contents.items():
            files[f"{directory}/{name}"] = {
                "sha256": hashlib.sha256(body).hexdigest(), "size": len(body),
                "type": TYPES.get(name.rpartition(".")[2], "application/octet-stream"),
            }
    return {"files": files}


def write_build(directory: Path, *, shell: dict | None = None, app: dict | None = None,
                manifest: dict | None = None) -> Path:
    """Write a synthetic build to ``directory`` (created) and return it."""
    shell = dict(SHELL if shell is None else shell)
    app = dict(APP if app is None else app)
    # Explicit modes: the loader refuses group- or world-writable entries,
    # so the fixture must not depend on the umask of whoever runs the tests.
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    for name, contents in (("shell", shell), ("app", app)):
        (directory / name).mkdir(exist_ok=True)
        (directory / name).chmod(0o755)
        for file, body in contents.items():
            (directory / name / file).write_bytes(body)
            (directory / name / file).chmod(0o644)
    document = manifest_for(shell, app) if manifest is None else manifest
    (directory / "manifest.json").write_text(json.dumps(document))
    (directory / "manifest.json").chmod(0o644)
    return directory


def synthetic_assets(directory: Path) -> WebAssets:
    """A verified ``WebAssets`` over a fresh synthetic build in ``directory``."""
    return WebAssets.load(write_build(directory))
