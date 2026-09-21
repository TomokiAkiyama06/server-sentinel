#!/usr/bin/env python3
"""Explicit local installer; never create accounts, change mounts, or start units."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import stat
import zipfile

from media_capture_agent.config import ConfigurationError, Settings, read_protected_configuration
from media_capture_agent.storage import StorageRefused, open_directory


MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 4096
MAX_UNIT_BYTES = 64 * 1024
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
RELEASE_METADATA = "MEDIA_CAPTURE_AGENT_RELEASE.json"


class ReleaseRestorationError(ValueError):
    """A pointer failure left state uncertain; retain every referenced release."""


class UnitReplacementError(ValueError):
    """The new unit may be durable; retain its current release target."""


def read_artifact(path):
    """Never block on a special file or read an unbounded root-owned input."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARTIFACT_BYTES:
            raise ValueError("artifact must be a bounded regular file")
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("artifact changed during verification")
        return data


def release_metadata(artifact, expected_version):
    """Read provenance already bound by the separately verified outer digest."""
    try:
        with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
            matches = [entry for entry in archive.infolist()
                       if entry.filename == RELEASE_METADATA]
            if (len(matches) != 1 or matches[0].is_dir()
                    or matches[0].file_size > MAX_METADATA_BYTES):
                raise ValueError("release metadata missing")
            content = archive.read(matches[0])
        value = json.loads(content)
    except (OSError, KeyError, UnicodeError, ValueError, zipfile.BadZipFile):
        raise ValueError("release metadata invalid") from None
    if (not isinstance(value, dict)
            or set(value) != {"format", "name", "version", "source_commit"}
            or value["format"] != 1 or value["name"] != "media-capture-agent"
            or value["version"] != expected_version
            or not SOURCE_COMMIT.fullmatch(str(value["source_commit"]))
            or set(value["source_commit"]) == {"0"}):
        raise ValueError("release provenance mismatch")
    return value


def quote(value):
    value = str(value)
    if any(ord(char) < 32 for char in value) or "$" in value:
        raise ValueError("invalid unit argument")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def render_unit(executable, config, settings, account, group, devices=()):
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", account):
        raise ValueError("invalid dedicated account")
    if type(group) is not int or group < 0:
        raise ValueError("invalid dedicated group")
    for device in devices:
        if not re.fullmatch(r"/dev/video[0-9]+", device):
            raise ValueError("only explicit video device nodes are supported")
    device_rules = "\n".join("DeviceAllow=" + quote(device) + " rw" for device in devices)
    return f"""[Unit]
Description=ServerSentinel media-capture-agent
After=local-fs.target network.target
RequiresMountsFor={quote(settings.media_root)} {quote(settings.runtime_root)}

[Service]
Type=simple
User={account}
Group={group}
ExecStartPre={quote(executable)} --config {quote(config)} --check
ExecStart={quote(executable)} --config {quote(config)}
Restart=on-failure
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={quote(settings.media_root)} {quote(settings.runtime_root)}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
DevicePolicy=closed
{device_rules}
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
Environment=PYTHONDONTWRITEBYTECODE=1

[Install]
WantedBy=multi-user.target
"""


def protected_parent(path):
    for parent in (path, *path.parents):
        fd = open_directory(parent)
        try:
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("installation ancestors must be root-controlled")
        finally:
            os.close(fd)


def _pointer_target(destination, name):
    pointer = destination / name
    if not pointer.exists() and not pointer.is_symlink():
        return None
    if not pointer.is_symlink():
        raise ValueError("release pointer must be a symbolic link")
    target = os.readlink(pointer)
    if not VERSION.fullmatch(target):
        raise ValueError("release pointer is invalid")
    return target


def _sync_directory(path):
    descriptor = open_directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _set_pointer(destination, name, target):
    pointer = destination / name
    temporary = destination / ("." + name + ".new")
    temporary.unlink(missing_ok=True)
    if target is None:
        pointer.unlink(missing_ok=True)
        _sync_directory(destination)
        return
    temporary.symlink_to(target)
    os.replace(temporary, pointer)
    _sync_directory(destination)


def _switch_pointers(destination, *, current, previous):
    old_current = _pointer_target(destination, "current")
    old_previous = _pointer_target(destination, "previous")
    try:
        # Publish the recovery target before changing the active release.
        _set_pointer(destination, "previous", previous)
        _set_pointer(destination, "current", current)
    except BaseException:
        restoration_errors = []
        for name, target in (("current", old_current), ("previous", old_previous)):
            try:
                _set_pointer(destination, name, target)
            except BaseException as error:
                restoration_errors.append(error)
        if restoration_errors:
            raise ReleaseRestorationError(
                "release pointer restoration failed"
            ) from restoration_errors[0]
        raise


def _validate_release(destination, version):
    try:
        root = (destination / version).lstat()
        executable = (destination / version / "media-capture-agent").lstat()
        owner = destination.stat().st_uid
    except OSError:
        raise ValueError("release is unavailable") from None
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != owner or root.st_mode & 0o022
            or not stat.S_ISREG(executable.st_mode) or executable.st_uid != owner
            or executable.st_nlink != 1 or executable.st_mode & 0o222
            or executable.st_mode & 0o111 == 0):
        raise ValueError("release is unavailable")


def _installed_unit(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            parent = path.parent.stat()
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != parent.st_uid
                    or before.st_nlink != 1 or before.st_mode & 0o022
                    or before.st_size > MAX_UNIT_BYTES):
                raise ValueError("installed service configuration differs")
            content = stream.read(MAX_UNIT_BYTES + 1)
            after = os.fstat(stream.fileno())
    except OSError:
        raise ValueError("installed service configuration differs") from None
    if len(content) != before.st_size or (
            before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("installed service configuration differs")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("installed service configuration differs") from None


def _replace_unit(path, content):
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_UNIT_BYTES:
        raise ValueError("service configuration is too large")
    temporary = path.with_name("." + path.name + ".new")
    descriptor = None
    replaced = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_CLOEXEC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            os.fchmod(stream.fileno(), 0o644)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        replaced = True
        _sync_directory(path.parent)
    except BaseException as error:
        if descriptor is not None:
            os.close(descriptor)
        if not replaced:
            temporary.unlink(missing_ok=True)
            raise
        raise UnitReplacementError("service configuration replacement is uncertain") from error


def _legacy_release(destination, installed_unit, config, settings, account, devices):
    """Identify legacy active code by exact regeneration, never unit parsing."""
    matches = []
    try:
        entries = tuple(destination.iterdir())
    except OSError:
        raise ValueError("legacy release is unavailable") from None
    for entry in entries:
        if not VERSION.fullmatch(entry.name):
            continue
        try:
            _validate_release(destination, entry.name)
        except ValueError:
            continue
        expected = render_unit(entry / "media-capture-agent", config, settings,
                               account.pw_name, account.pw_gid, devices)
        if installed_unit == expected:
            matches.append(entry.name)
    if len(matches) != 1:
        raise ValueError("legacy release cannot be adopted safely")
    return matches[0]


@contextmanager
def release_lock(destination):
    path = destination / ".release.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        parent = destination.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != parent.st_uid
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError("release lock is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _stage(args, artifact, settings, account, config):
    version_root = args.destination / args.version
    version_root.mkdir(mode=0o755)
    version_root.chmod(0o755)
    executable = version_root / "media-capture-agent"
    try:
        with executable.open("xb") as stream:
            stream.write(artifact)
            stream.flush()
            os.fchmod(stream.fileno(), 0o555)
            os.fsync(stream.fileno())
        subprocess.run([str(executable), "--config", str(config), "--check"],
                       check=True, timeout=30, user=account.pw_uid, group=account.pw_gid,
                       extra_groups=[], env={"PATH": "/usr/bin:/bin",
                                             "PYTHONDONTWRITEBYTECODE": "1"},
                       cwd="/", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _sync_directory(version_root)
        _sync_directory(args.destination)
        return executable
    except BaseException:
        executable.unlink(missing_ok=True)
        version_root.rmdir()
        raise


def _remove_staged(executable):
    executable.unlink(missing_ok=True)
    executable.parent.rmdir()


def rollback(args):
    if os.geteuid() != 0:
        raise ValueError("rollback requires explicit administrator execution")
    if not args.destination.is_absolute():
        raise ValueError("absolute installation paths required")
    protected_parent(args.destination)
    with release_lock(args.destination):
        current = _pointer_target(args.destination, "current")
        previous = _pointer_target(args.destination, "previous")
        if current is None or previous is None:
            raise ValueError("previous release is unavailable")
        _validate_release(args.destination, previous)
        _switch_pointers(args.destination, current=previous, previous=current)


def install(args):
    operation = getattr(args, "operation", "install")
    if operation == "rollback":
        rollback(args)
        return
    if os.geteuid() != 0:
        raise ValueError("installation requires explicit administrator execution")
    if not VERSION.fullmatch(args.version):
        raise ValueError("invalid release version")
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        raise ValueError("verified artifact digest required")
    artifact = read_artifact(args.artifact)
    if hashlib.sha256(artifact).hexdigest() != args.sha256:
        raise ValueError("artifact digest mismatch")
    # Bind a relative deployment path to the administrator's invocation
    # directory before the preflight changes cwd and before writing the unit.
    # Do not resolve it: read_protected_configuration must retain its final
    # symlink refusal when it opens the configuration.
    config = Path(os.path.abspath(args.config))
    code_root = Path(__file__).resolve().parents[1]
    value, config_owner = read_protected_configuration(
        config, forbidden_roots=(args.destination, code_root)
    )
    settings = Settings.parse(value, code_root=args.destination)
    release_metadata(artifact, args.version)
    if any(root.is_relative_to(code_root) for root in (settings.runtime_root, settings.media_root)):
        raise ValueError("runtime data must be outside the checkout")
    if config_owner != settings.service_uid:
        raise ValueError("configuration must belong to dedicated account")
    account = pwd.getpwuid(settings.service_uid)
    if pwd.getpwnam(account.pw_name).pw_uid == 0:
        raise ValueError("dedicated non-root account required")
    if not args.destination.is_absolute() or not args.unit.is_absolute():
        raise ValueError("absolute installation paths required")
    if args.unit.name != "media-capture-agent.service":
        raise ValueError("service must retain its functional name")
    protected_parent(args.destination)
    protected_parent(args.unit.parent)
    with release_lock(args.destination):
        current = _pointer_target(args.destination, "current")
        previous = _pointer_target(args.destination, "previous")
        if operation == "install" and (current is not None or previous is not None):
            raise ValueError("release is already installed")
        content = render_unit(args.destination / "current/media-capture-agent", config, settings,
                              account.pw_name, account.pw_gid, args.video_device)
        installed_unit = _installed_unit(args.unit) if operation == "update" else None
        if operation == "update" and current is not None:
            _validate_release(args.destination, current)
        if operation == "update" and current is None and previous is not None:
            raise ValueError("release pointers are inconsistent")
        executable = _stage(args, artifact, settings, account, config)
        adopted = False
        if operation == "update" and current is None:
            try:
                legacy = _legacy_release(args.destination, installed_unit, config, settings,
                                         account, args.video_device)
                _switch_pointers(args.destination, current=legacy, previous=None)
                try:
                    _replace_unit(args.unit, content)
                except UnitReplacementError:
                    # The current pointer deliberately remains on the legacy
                    # executable so either durable unit version stays valid.
                    raise
                except BaseException:
                    _switch_pointers(args.destination, current=None, previous=None)
                    raise
            except (ReleaseRestorationError, UnitReplacementError):
                # State is uncertain. Retain every release that may be named.
                raise
            except BaseException:
                _remove_staged(executable)
                raise
            current = legacy
            adopted = True
        unit_created = False
        try:
            if operation == "install":
                with args.unit.open("x", encoding="utf-8") as stream:
                    unit_created = True
                    stream.write(content)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o644)
                    os.fsync(stream.fileno())
                _sync_directory(args.unit.parent)
            elif not adopted and installed_unit != content:
                raise ValueError("installed service configuration differs")
        except BaseException:
            if unit_created:
                args.unit.unlink()
            _remove_staged(executable)
            raise
        try:
            _switch_pointers(args.destination, current=args.version, previous=current)
        except ReleaseRestorationError:
            # A pointer may still reference the newly staged release. Preserve
            # both it and the unit for explicit administrator recovery.
            raise
        except BaseException:
            if unit_created:
                args.unit.unlink()
            _remove_staged(executable)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--version")
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--unit", type=Path)
    parser.add_argument("--video-device", action="append", default=[])
    parser.add_argument("--operation", choices=("install", "update", "rollback"),
                        default="install")
    args = parser.parse_args()
    try:
        if args.operation != "rollback" and any(value is None for value in (
                args.artifact, args.sha256, args.version, args.config, args.unit)):
            raise ValueError("release inputs required")
        install(args)
    except (OSError, ValueError, ConfigurationError, StorageRefused,
            KeyError, subprocess.SubprocessError):
        parser.exit(1, "media-capture-agent installation validation failed\n")
    print("media-capture-agent release prepared; inspect and restart/enable explicitly")


if __name__ == "__main__":
    main()
