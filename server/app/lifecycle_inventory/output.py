"""Private output files of the lifecycle inventory (#47, split in #256).

Baselines and reports are created exclusively with mode 0600, refused
inside the runtime root, the installed package / virtual environment, the
whole installation destination or any Git checkout, and read back only
while still as private as they were written.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

from ._common import InventoryError, _absolute


def _inside_git_checkout(path: Path) -> bool:
    # Same marker rule as the recording store: a worktree's ``.git`` file or a
    # clone's ``.git/HEAD``.
    return any((parent / ".git").is_file() or (parent / ".git" / "HEAD").is_file()
               for parent in (path, *path.parents))


def _installation_root(prefix: Path) -> Path | None:
    """The whole installed tree containing this interpreter's venv, if any.

    The installer lays out ``<destination>/releases/<version>/venv`` with
    ``<destination>/current`` pointing at a release, so the destination covers
    every release and the ``current`` / ``previous`` links. Other venvs (e.g.
    a development one) only refuse themselves, never their parent directory.
    """
    release = prefix.parent
    if prefix.name == "venv" and release.parent.name == "releases":
        return release.parent.parent
    return None


def _refused_roots(runtime_root: Path) -> tuple[Path, ...]:
    # The installed package's parent (``releases/<version>``): this module is
    # ``<that>/app/lifecycle_inventory/output.py``.
    roots = [runtime_root, Path(__file__).resolve().parents[2]]
    if sys.prefix != sys.base_prefix:
        prefix = Path(sys.prefix)
        try:
            prefix = prefix.resolve(strict=False)
        except (OSError, RuntimeError):
            pass
        roots.append(prefix)
        installation = _installation_root(prefix)
        if installation is not None:
            roots.append(installation)
    resolved = []
    for root in roots:
        try:
            resolved.append(root.resolve(strict=False))
        except (OSError, RuntimeError):
            resolved.append(root)
    return tuple(resolved)


def safe_output_path(output: Path, runtime_root: Path) -> Path:
    """Return the destination, refusing runtime, installation and checkout trees."""
    output = _absolute(output, "output")
    runtime_root = _absolute(runtime_root, "runtime root")
    try:
        parent = output.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise InventoryError("output directory is unavailable") from None
    if not parent.is_dir():
        raise InventoryError("output directory is unavailable")
    target = parent / output.name
    for root in _refused_roots(runtime_root):
        if target == root or root in target.parents:
            raise InventoryError(
                "output must be outside the runtime root and the installed release")
    if _inside_git_checkout(parent):
        raise InventoryError("output must be outside any repository checkout")
    return target


def write_private(output: Path, runtime_root: Path, document: dict) -> Path:
    target = safe_output_path(output, runtime_root)
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        raise InventoryError("output already exists; choose a new file") from None
    except OSError:
        raise InventoryError("output could not be created") from None
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target


def read_private(path: Path) -> dict:
    """Read a baseline only if it is still as private as write_private() left it.

    A regular file, not a symlink, owned by the invoking user or root, with no
    group/other access; anything else may have been read or replaced.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY)
    except OSError:
        raise InventoryError("baseline could not be read") from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (os.geteuid(), 0)
                or info.st_mode & 0o077):
            raise InventoryError("baseline is not private (expected a 0600 regular file "
                                 "owned by this user or root)")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return json.loads(handle.read())
    except (OSError, ValueError):
        raise InventoryError("baseline could not be read") from None
    finally:
        os.close(descriptor)
