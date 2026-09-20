#!/usr/bin/env python3
"""Build an executable versioned zipapp; includes only reviewed runtime sources."""

import argparse
import hashlib
from pathlib import Path
import shutil
import tempfile
import zipapp


ROOT = Path(__file__).resolve().parent


def build(destination):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("artifact destination already exists")
    with tempfile.TemporaryDirectory(prefix="media-capture-agent-build-") as temporary:
        stage = Path(temporary)
        shutil.copytree(ROOT / "media_capture_agent", stage / "media_capture_agent",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(ROOT / "LICENSE", stage / "LICENSE")
        (stage / "__main__.py").write_text(
            "from media_capture_agent.cli import main\nraise SystemExit(main())\n",
            encoding="utf-8",
        )
        zipapp.create_archive(stage, destination, interpreter="/usr/bin/env python3",
                              compressed=True)
    destination.chmod(0o555)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = build(args.output)
    except (OSError, ValueError):
        parser.exit(1, "artifact build failed\n")
    print("sha256=" + digest)


if __name__ == "__main__":
    main()
