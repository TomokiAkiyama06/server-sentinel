#!/usr/bin/env python3
"""Build a versioned Main Server release archive from reviewed local inputs."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent


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


def _files(wheelhouse: Path):
    for path in sorted((ROOT / "app").rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield path, Path("app") / path.relative_to(ROOT / "app")
    for name in ("requirements.lock", "pyproject.toml"):
        yield ROOT / name, Path(name)
    for name in ("LICENSE", "NOTICE"):
        yield REPOSITORY / name, Path(name)
    yield ROOT / "docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md", Path(
        "BACKEND_THIRD_PARTY_LICENSE_TEXTS.md"
    )
    for path in _required_wheels(wheelhouse):
        yield path, Path("wheels") / path.name


def build(destination: Path, version: str, wheelhouse: Path) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?", version):
        raise ValueError("invalid release version")
    if destination.exists() or not wheelhouse.is_dir():
        raise ValueError("artifact destination or wheelhouse is invalid")
    entries = list(_files(wheelhouse))
    manifest = {
        "format": 1,
        "name": "server-sentinel-main",
        "version": version,
        "files": {str(name): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path, name in entries},
    }
    with tarfile.open(destination, "x:gz", format=tarfile.PAX_FORMAT) as archive:
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size, info.mode, info.mtime = len(payload), 0o444, 0
        archive.addfile(info, io.BytesIO(payload))
        for path, name in entries:
            info = archive.gettarinfo(path, arcname=str(name))
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.mode = 0o555 if name.suffix == ".py" else 0o444
            with path.open("rb") as stream:
                archive.addfile(info, stream)
    destination.chmod(0o444)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = build(args.output, args.version, args.wheelhouse)
    except (OSError, ValueError, tarfile.TarError):
        parser.exit(1, "Main Server artifact build failed\n")
    print("sha256=" + digest)


if __name__ == "__main__":
    main()
