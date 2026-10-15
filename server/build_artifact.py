#!/usr/bin/env python3
"""Build a versioned Main Server release archive from reviewed local inputs."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile

from app.auth.web_assets import MAX_FILES, MAX_TOTAL_BYTES, WebAssets, WebAssetsUnavailable


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent
# Issue #10 phase 2 S5c: the release carries the Web build (``web/dist`` of
# ``npm ci && npm run build``) under this directory; every file's SHA-256 is
# in the release manifest, which the installer checks at install and rollback.
WEB_DIRECTORY = "web"
# The copy of the release manifest the installer keeps in each release.
RESERVED_NAMES = frozenset({"manifest.json", "release-manifest.json"})
# Entries a Web build may hold: the loader's files plus manifest.json, shell/ and app/.
MAX_WEB_ENTRIES = MAX_FILES + 3


class WebBuildRefused(ValueError):
    """The Web build cannot be released; the message is fixed and value-free."""


def _web_files(web_dist: Path) -> list[tuple[str, bytes]]:
    """``(relative path, bytes)`` of a Web build the server's own loader accepts.

    The build directory is read without following any symbolic link: only
    regular files and directories, bounded by the loader's caps. The bytes
    are then written to a private copy with explicit modes (the builder's
    umask is not the deployment's) and must load through
    ``WebAssets.load``, so a release never ships a build the service would
    refuse. The archive carries exactly these bytes.
    """
    if not isinstance(web_dist, Path) or not web_dist.is_absolute():
        raise WebBuildRefused("web build directory must be absolute")
    files: list[tuple[str, bytes]] = []
    total = 0
    # Every directory entry (files and directories alike, empty ones too)
    # counts against one bound before anything else is done with it: the
    # loader's files plus manifest.json, shell/ and app/.
    entries = 0

    def walk(descriptor: int, prefix: PurePosixPath) -> None:
        nonlocal total, entries
        names = []
        with os.scandir(descriptor) as listing:
            for entry in listing:
                entries += 1
                if entries > MAX_WEB_ENTRIES:
                    raise WebBuildRefused("web build exceeds the asset caps")
                names.append(entry.name)
        # Sorted only after the bounded collection: the output stays deterministic.
        for name in sorted(names):
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            relative = prefix / name
            if stat.S_ISDIR(info.st_mode):
                if len(relative.parts) > 1:
                    raise WebBuildRefused("web build is nested too deeply")
                child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                try:
                    walk(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if len(files) >= MAX_FILES + 1 or info.st_size > MAX_TOTAL_BYTES - total:
                    raise WebBuildRefused("web build exceeds the asset caps")
                file = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=descriptor)
                with os.fdopen(file, "rb") as stream:
                    data = stream.read(MAX_TOTAL_BYTES - total + 1)
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    raise WebBuildRefused("web build exceeds the asset caps")
                files.append((str(relative), data))
            else:
                raise WebBuildRefused("web build holds an entry that is not a regular file")

    try:
        root = os.open(web_dist, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise WebBuildRefused("web build directory is unavailable") from None
    try:
        walk(root, PurePosixPath())
    except OSError:
        raise WebBuildRefused("web build could not be read") from None
    finally:
        os.close(root)
    with tempfile.TemporaryDirectory(prefix="server-sentinel-web-") as temporary:
        copy = Path(temporary) / "web"
        copy.mkdir()
        os.chmod(copy, 0o755)
        for name, data in files:
            target = copy.joinpath(*PurePosixPath(name).parts)
            if not target.parent.exists():
                target.parent.mkdir()
                os.chmod(target.parent, 0o755)
            target.write_bytes(data)
            os.chmod(target, 0o644)
        try:
            WebAssets.load(copy)
        except WebAssetsUnavailable as refused:
            raise WebBuildRefused("web build refused by the asset loader (reason="
                                  + refused.reason + ")") from None
    return files


def _required_wheels(wheelhouse: Path) -> list[Path]:
    requirements = []
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    approved_hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", lock))
    for line in lock.splitlines():
        match = re.match(r"([A-Za-z0-9_.-]+)==([^ \\]+) [\\]$", line)
        if match:
            requirements.append((re.sub(r"[-_.]+", "_", match.group(1)).lower(), match.group(2)))
    wheels = sorted(wheelhouse.glob("*.whl"))
    represented = set()
    for wheel in wheels:
        if hashlib.sha256(wheel.read_bytes()).hexdigest() not in approved_hashes:
            raise ValueError("wheelhouse contains an unreviewed artifact")
        normalized = re.sub(r"[-_.]+", "_", wheel.name).lower()
        matches = {
            (name, version) for name, version in requirements
            if normalized.startswith(
                name + "_" + re.sub(r"[-_.]+", "_", version).lower() + "_"
            )
        }
        if len(matches) != 1:
            raise ValueError("wheelhouse contains an unreviewed artifact")
        represented.update(matches)
    if represented != set(requirements):
        raise ValueError("wheelhouse is incomplete")
    return wheels


def _files(wheelhouse: Path, web_dist: Path):
    """``(archive name, bytes)`` of every release member; each is read once.

    The manifest digest and the archived bytes therefore come from the same
    read, so a file changing during the build cannot make them differ.
    """
    for path in sorted((ROOT / "app").rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield str(Path("app") / path.relative_to(ROOT / "app")), path.read_bytes()
    for name in ("requirements.lock", "pyproject.toml"):
        yield name, (ROOT / name).read_bytes()
    for name in ("LICENSE", "NOTICE"):
        yield name, (REPOSITORY / name).read_bytes()
    yield "BACKEND_THIRD_PARTY_LICENSE_TEXTS.md", (
        ROOT / "docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md").read_bytes()
    for path in _required_wheels(wheelhouse):
        yield "wheels/" + path.name, path.read_bytes()
    for name, data in _web_files(web_dist):
        yield WEB_DIRECTORY + "/" + name, data


def build(destination: Path, version: str, wheelhouse: Path, web_dist: Path) -> str:
    """Write the release archive; return its SHA-256.

    ``web_dist`` is the output of ``npm ci && npm run build`` in ``web/``
    (Owner decision S5-5). Its files go under ``web/`` with their SHA-256 in
    the release manifest; that build is deterministic, so the same sources
    give the same manifest entries.
    """
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?", version):
        raise ValueError("invalid release version")
    if destination.exists() or not wheelhouse.is_dir():
        raise ValueError("artifact destination or wheelhouse is invalid")
    entries = list(_files(wheelhouse, web_dist))
    names = [name for name, _ in entries]
    if len(names) != len(set(names)) or RESERVED_NAMES & set(names):
        raise ValueError("release members collide")
    manifest = {
        "format": 1,
        "name": "server-sentinel-main",
        "version": version,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in entries},
    }
    # The outer archive is reproducible too: no file name and a zero time in
    # the gzip header, fixed member metadata, sorted members.
    with open(destination, "xb") as raw, gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0) as compressed, tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size, info.mode, info.mtime = len(payload), 0o444, 0
        archive.addfile(info, io.BytesIO(payload))
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o555 if name.endswith(".py") else 0o444
            archive.addfile(info, io.BytesIO(data))
    destination.chmod(0o444)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--web-dist", type=Path, required=True,
                        help="absolute path of web/dist after npm ci && npm run build")
    args = parser.parse_args()
    try:
        digest = build(args.output, args.version, args.wheelhouse, args.web_dist)
    except WebBuildRefused as refused:
        # A fixed, value-free text (no path or file name): see _web_files.
        parser.exit(1, "Main Server artifact build failed: " + str(refused) + "\n")
    except (OSError, ValueError, tarfile.TarError):
        parser.exit(1, "Main Server artifact build failed\n")
    print("sha256=" + digest)


if __name__ == "__main__":
    main()
