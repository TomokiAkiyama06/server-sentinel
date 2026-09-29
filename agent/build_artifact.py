#!/usr/bin/env python3
"""Build an executable versioned zipapp; includes only reviewed runtime sources."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import zipapp


ROOT = Path(__file__).resolve().parent
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
RELEASE_METADATA = "MEDIA_CAPTURE_AGENT_RELEASE.json"


def build(destination, *, version="0.1.0", source_commit="0" * 40):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("artifact destination already exists")
    if (not VERSION.fullmatch(version) or not SOURCE_COMMIT.fullmatch(source_commit)
            or set(source_commit) == {"0"}):
        raise ValueError("invalid release provenance")
    with tempfile.TemporaryDirectory(prefix="media-capture-agent-build-") as temporary:
        stage = Path(temporary)
        shutil.copytree(ROOT / "media_capture_agent", stage / "media_capture_agent",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(ROOT / "LICENSE", stage / "LICENSE")
        (stage / "__main__.py").write_text(
            "from media_capture_agent.cli import main\nraise SystemExit(main())\n",
            encoding="utf-8",
        )
        (stage / RELEASE_METADATA).write_text(json.dumps({
            "format": 1,
            "name": "media-capture-agent",
            "version": version,
            "source_commit": source_commit,
        }, sort_keys=True) + "\n", encoding="utf-8")
        zipapp.create_archive(stage, destination, interpreter="/usr/bin/env python3",
                              compressed=True)
    destination.chmod(0o555)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True,
                        help="full lowercase Git commit recorded in the artifact")
    args = parser.parse_args()
    try:
        digest = build(args.output, version=args.version, source_commit=args.source_commit)
    except (OSError, ValueError):
        parser.exit(1, "artifact build failed\n")
    print(f"version={args.version} source_commit={args.source_commit} sha256={digest}")


if __name__ == "__main__":
    main()
