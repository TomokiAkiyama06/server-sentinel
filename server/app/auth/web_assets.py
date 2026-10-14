"""The Web assets the human listener serves (Issue #10 phase 2 S5b).

ADR-0003 forbids a separate static host, and the reservation check accepts
exactly one Serve proxy route to the backend (``HostnameReservationConfig.
expected_route``), so the sign-in shell and the application bundle are served
by ``HumanSurface`` from bytes this module loaded once, at composition time.

``WebAssets.load(directory)`` reads a build's ``manifest.json``::

    {"files": {"<relative path>": {"sha256": "<64 hex>", "size": N, "type": "<content type>"}}}

and refuses (``WebAssetsUnavailable``, value-free) unless all of the
following hold:

- the directory holds exactly ``manifest.json``, ``shell/`` and ``app/``;
  ``shell/`` holds exactly ``index.html``, ``s.js`` and ``s.css``; ``app/``
  holds ``index.html`` and otherwise only flat files whose names fully match
  ``APP_NAME`` (so each is reachable as ``/app/<name>``); the
  listed files are exactly the files on disk, with no extra, missing or
  nested entry;
- every entry below the directory is a regular file or directory, opened
  relative to its parent with ``O_NOFOLLOW`` (a symlink, device, FIFO or
  socket is refused). The configured directory itself is resolved once (a
  deployment may point its setting through a symlink it controls);
- neither the resolved directory nor any directory or file below it is
  group- or world-writable, and no file has a second hard link
  (``st_nlink`` must be 1);
- every extension is in ``CONTENT_TYPES`` (``html``, ``js``, ``css``,
  ``svg``, ``txt``) and the manifest's ``type`` is exactly that extension's
  content type in ``CONTENT_TYPES``;
- every file's size and SHA-256 equal the manifest's, it is valid UTF-8, and
  the per-file, total, count and manifest caps hold.

A refusal carries one value-free word of ``REFUSAL_REASONS`` (``mode``,
``nlink``, ``digest``, ``set``, ``size``, ``type``, ``utf8``, ...) in
``WebAssetsUnavailable.reason``, which the deployment check prints for the
operator (Issue #10 S5c); its message stays one generic sentence and no
client ever sees either.

The bytes are then frozen in memory with their complete response headers: a
later change on disk is never served, and no request ever builds a
filesystem path (a request only selects one of the fixed shell entries or
looks a validated name up in the in-memory map).

The manifest is written by the same build as the files, so these checks
catch an accidental, partial or mixed deployment, not a deliberate one: an
account that can write the directory can rewrite the manifest too.
Protection against the service account comes from ownership and modes: the
release places the build root-owned and read-only, never hard-linked
(Issue #10 S5c, ``install.py``), so it cannot write it; the permission and
hard-link checks here refuse the layouts that would make such a directory
writable by another account or alias a file from elsewhere. The installer
also compares the build with the release manifest copy at install and
before a rollback; that copy is unsigned and in the same root-owned tree,
so it detects accidental or partial changes, not a change by root, and it
is not compared at every start.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping


MANIFEST_NAME = "manifest.json"
SHELL_DIRECTORY = "shell"
APP_DIRECTORY = "app"
SHELL_FILES = ("index.html", "s.js", "s.css")
APP_INDEX = "index.html"
# One ``/app/<name>`` path segment: ASCII letters, digits, dots and hyphens,
# starting with a letter or digit. Upper case is allowed because the S5a
# build ships ``app.js.LEGAL.txt`` and ``react-LICENSE.txt``; the lookup is
# exact, so ``/app/App.js`` is simply a miss.
APP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,63}")
MAX_MANIFEST_BYTES = 64 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES = 64
CONTENT_TYPES: Mapping[str, str] = MappingProxyType({
    "html": "text/html; charset=utf-8",
    "js": "text/javascript; charset=utf-8",
    "css": "text/css; charset=utf-8",
    "svg": "image/svg+xml",
    "txt": "text/plain; charset=utf-8",
})
# The content types and policies below are the values of
# ``web/scripts/policy.mjs`` (Issue #10 phase 2 S5a), copied, not read at
# run time, so ``server/`` does not depend on ``web/``; a change there must
# change these. ``tests/test_web_build_contract.py`` parses ``policy.mjs``
# and compares, and CI loads the freshly built ``web/dist`` with this loader.
#
# The sign-in shell (Owner decisions D1, S5-1): its own script and style,
# same-origin API calls only, no image, font, frame, form, base or
# embedding, and DOM injection sinks closed by Trusted Types.
SHELL_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
             "img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'; "
             "frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'")
# The application (S5-2). Its index.html also carries ``APP_META_CSP`` in a
# meta element as defence in depth (the S5a build refuses a document whose
# meta policy differs); the header is that policy plus ``frame-ancestors``,
# which a meta element cannot carry.
APP_META_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'")
APP_CSP = APP_META_CSP + "; frame-ancestors 'none'"
_COMMON_HEADERS = (
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LOADER = object()


# Value-free reasons a load is refused (Issue #10 S5c), for the operator: the
# deployment check prints one of these words, never a path, name or value.
# The exception message itself stays the one generic sentence.
REFUSAL_REASONS = frozenset({
    "path",      # the configured directory is not an absolute, existing directory
    "type",      # not a regular file/directory, or an unknown extension or content type
    "mode",      # an entry is group- or world-writable
    "nlink",     # a file has a second hard link
    "set",       # the files on disk are not exactly the manifest's, or the layout differs
    "manifest",  # manifest.json is not the strict format
    "size",      # a size differs from the manifest or a cap is exceeded
    "digest",    # a SHA-256 differs from the manifest
    "utf8",      # a file is not valid UTF-8
    "io",        # the filesystem refused a read
    "invalid",   # anything else (an asset set not built by the loader)
})


class WebAssetsUnavailable(ValueError):
    """The asset directory cannot be served; carries no path or value.

    ``reason`` is one word of ``REFUSAL_REASONS`` for operator diagnosis; the
    message is always the same generic sentence.
    """

    def __init__(self, reason: str = "invalid") -> None:
        super().__init__("web assets are unavailable")
        self.reason = reason if reason in REFUSAL_REASONS else "invalid"


@dataclass(frozen=True)
class WebAsset:
    """One frozen response: the exact header list and body."""

    body: bytes
    headers: tuple[tuple[bytes, bytes], ...]
    sha256: str


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite number")


def _extension(name: str) -> str | None:
    stem, dot, extension = name.rpartition(".")
    return extension if dot and stem else None


def _entry(value: object) -> tuple[str, int, str]:
    if not isinstance(value, dict) or set(value) != {"sha256", "size", "type"}:
        raise WebAssetsUnavailable("manifest")
    digest, size, kind = value["sha256"], value["size"], value["type"]
    if (not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            or type(size) is not int or not isinstance(kind, str)):
        raise WebAssetsUnavailable("manifest")
    if not 0 <= size <= MAX_FILE_BYTES:
        raise WebAssetsUnavailable("size")
    return digest, size, kind


def _parse_manifest(raw: bytes) -> dict[str, dict[str, tuple[str, int, str]]]:
    """``{"shell": {name: entry}, "app": {name: entry}}`` from strict manifest JSON."""
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                              parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise WebAssetsUnavailable("manifest") from None
    if not isinstance(document, dict) or set(document) != {"files"} or not isinstance(document["files"], dict):
        raise WebAssetsUnavailable("manifest")
    files = document["files"]
    if len(files) > MAX_FILES:
        raise WebAssetsUnavailable("size")
    layout: dict[str, dict[str, tuple[str, int, str]]] = {SHELL_DIRECTORY: {}, APP_DIRECTORY: {}}
    for path, value in files.items():
        directory, slash, name = path.partition("/")
        if not slash or directory not in layout or "/" in name:
            raise WebAssetsUnavailable("set")
        if directory == SHELL_DIRECTORY and name not in SHELL_FILES:
            raise WebAssetsUnavailable("set")
        if directory == APP_DIRECTORY and not APP_NAME.fullmatch(name):
            raise WebAssetsUnavailable("set")
        extension = _extension(name)
        if extension not in CONTENT_TYPES:
            raise WebAssetsUnavailable("type")
        digest, size, kind = _entry(value)
        expected = CONTENT_TYPES[extension]
        if kind != expected:
            raise WebAssetsUnavailable("type")
        layout[directory][name] = (digest, size, expected)
    if set(layout[SHELL_DIRECTORY]) != set(SHELL_FILES) or APP_INDEX not in layout[APP_DIRECTORY]:
        raise WebAssetsUnavailable("set")
    return layout


def _open_below(parent: int, name: str, *, directory: bool) -> int:
    """Open ``name`` relative to ``parent`` without following a symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        _check_mode(os.fstat(descriptor), directory=directory)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _check_mode(info: os.stat_result, *, directory: bool) -> None:
    """A directory or a singly linked regular file nobody else may write."""
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise WebAssetsUnavailable("type")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise WebAssetsUnavailable("mode")
    if not directory and info.st_nlink != 1:
        raise WebAssetsUnavailable("nlink")


def _read_file(parent: int, name: str, limit: int) -> bytes:
    """The bytes of one regular file of at most ``limit`` bytes."""
    descriptor = _open_below(parent, name, directory=False)
    try:
        if os.fstat(descriptor).st_size > limit:
            raise WebAssetsUnavailable("size")
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, min(limit + 1 - total, 1024 * 1024))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise WebAssetsUnavailable("size")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _entries(descriptor: int) -> set[str]:
    return set(os.listdir(descriptor))


def _response(body: bytes, content_type: str, csp: str, digest: str) -> WebAsset:
    headers = ((b"content-type", content_type.encode("ascii")),
               (b"content-length", str(len(body)).encode("ascii")),
               *_COMMON_HEADERS,
               (b"content-security-policy", csp.encode("ascii")))
    return WebAsset(body, headers, digest)


class WebAssets:
    """The frozen, verified asset set; built only by ``WebAssets.load``."""

    def __init__(self, token: object, directory: Path, shell: Mapping[str, WebAsset],
                 app: Mapping[str, WebAsset]) -> None:
        if token is not _LOADER:
            raise WebAssetsUnavailable()
        self._directory = directory
        self._shell = MappingProxyType(dict(shell))
        self._app = MappingProxyType(dict(app))

    @property
    def directory(self) -> Path:
        """The resolved directory the set was loaded from (read-only)."""
        return self._directory

    @classmethod
    def load(cls, directory: object) -> "WebAssets":
        """Verify and freeze the build in ``directory``; see the module docstring."""
        if not isinstance(directory, Path) or not directory.is_absolute():
            raise WebAssetsUnavailable("path")
        try:
            root_path = directory.resolve(strict=True)
            root = os.open(root_path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
        except (OSError, RuntimeError, ValueError):
            raise WebAssetsUnavailable("path") from None
        try:
            _check_mode(os.fstat(root), directory=True)
            return cls._load(root, root_path)
        except WebAssetsUnavailable:
            raise
        except (NotADirectoryError, IsADirectoryError):
            raise WebAssetsUnavailable("type") from None
        except OSError as error:
            # O_NOFOLLOW on a symbolic link fails with ELOOP; a missing
            # entry is a layout that differs from the expected one.
            reason = {errno.ELOOP: "type", errno.ENOENT: "set"}.get(error.errno, "io")
            raise WebAssetsUnavailable(reason) from None
        except (ValueError, RecursionError):
            raise WebAssetsUnavailable("io") from None
        finally:
            os.close(root)

    @classmethod
    def _load(cls, root: int, root_path: Path) -> "WebAssets":
        if _entries(root) != {MANIFEST_NAME, SHELL_DIRECTORY, APP_DIRECTORY}:
            raise WebAssetsUnavailable("set")
        layout = _parse_manifest(_read_file(root, MANIFEST_NAME, MAX_MANIFEST_BYTES))
        if sum(size for entries in layout.values() for _, size, _ in entries.values()) > MAX_TOTAL_BYTES:
            raise WebAssetsUnavailable("size")
        frozen: dict[str, dict[str, WebAsset]] = {}
        for directory, entries in layout.items():
            csp = SHELL_CSP if directory == SHELL_DIRECTORY else APP_CSP
            descriptor = _open_below(root, directory, directory=True)
            try:
                if _entries(descriptor) != set(entries):
                    raise WebAssetsUnavailable("set")
                frozen[directory] = {}
                for name, (digest, size, content_type) in entries.items():
                    body = _read_file(descriptor, name, size)
                    if len(body) != size:
                        raise WebAssetsUnavailable("size")
                    if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), digest):
                        raise WebAssetsUnavailable("digest")
                    try:
                        body.decode("utf-8")
                    except UnicodeDecodeError:
                        raise WebAssetsUnavailable("utf8") from None
                    frozen[directory][name] = _response(body, content_type, csp, digest)
            finally:
                os.close(descriptor)
        return cls(_LOADER, root_path, frozen[SHELL_DIRECTORY], frozen[APP_DIRECTORY])

    # -- lookups (no filesystem access) ---------------------------------

    @property
    def shell_index(self) -> WebAsset:
        return self._shell["index.html"]

    @property
    def shell_script(self) -> WebAsset:
        return self._shell["s.js"]

    @property
    def shell_style(self) -> WebAsset:
        return self._shell["s.css"]

    @property
    def app_index(self) -> WebAsset:
        return self._app[APP_INDEX]

    def app_file(self, name: object) -> WebAsset | None:
        """The ``/app/<name>`` asset, or ``None``.

        ``index.html`` is served only as ``/app/`` (one URL per asset), and a
        name outside ``APP_NAME`` never matches.
        """
        if not isinstance(name, str) or name == APP_INDEX or not APP_NAME.fullmatch(name):
            return None
        return self._app.get(name)
