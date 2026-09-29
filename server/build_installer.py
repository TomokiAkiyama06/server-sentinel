#!/usr/bin/env python3
"""Build the standalone Main Server release installer zipapp."""

import argparse
import hashlib
from pathlib import Path
import shutil
import tempfile
import zipapp


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent
INSTALLER_MODULES = (
    "__init__.py", "deployment.py", "settings.py",
    "cameras/uvc/config.py",
    "monitoring/__init__.py", "monitoring/config.py",
    "media/recording/__init__.py", "media/recording/model.py", "media/recording/store.py",
    "notifications/__init__.py", "notifications/slack.py",
    "storage/__init__.py", "storage/policy.py",
    # The optional detection section; these modules import only the standard
    # library at import time (the person runtime is imported inside a worker).
    "detection/foundation/__init__.py",
    "detection/foundation/config.py", "detection/foundation/contracts.py",
    "detection/foundation/feed.py", "detection/foundation/isolation.py",
    "detection/foundation/motion.py", "detection/foundation/person.py",
    "detection/foundation/scheduler.py",
)


def build(destination: Path) -> str:
    if destination.exists():
        raise ValueError("installer destination already exists")
    with tempfile.TemporaryDirectory(prefix="server-sentinel-installer-") as temporary:
        stage = Path(temporary)
        shutil.copyfile(ROOT / "install.py", stage / "install.py")
        # Deployment validation, including the optional monitoring section,
        # needs only these standard-library modules; no third-party package.
        for name in INSTALLER_MODULES:
            (stage / "app" / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "app" / name, stage / "app" / name)
        shutil.copyfile(REPOSITORY / "LICENSE", stage / "LICENSE")
        shutil.copyfile(REPOSITORY / "NOTICE", stage / "NOTICE")
        (stage / "__main__.py").write_text(
            "from install import main\nmain()\n", encoding="utf-8"
        )
        zipapp.create_archive(
            stage, destination, interpreter="/usr/bin/env python3", compressed=True
        )
    destination.chmod(0o555)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = build(args.output)
    except (OSError, ValueError):
        parser.exit(1, "Main Server installer build failed\n")
    print("sha256=" + digest)


if __name__ == "__main__":
    main()
