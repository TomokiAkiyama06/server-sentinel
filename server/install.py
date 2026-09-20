#!/usr/bin/env python3
"""Install, update or roll back a verified Main Server release."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import tarfile

from app.deployment import Deployment
from app.settings import ConfigurationError


MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?")


def read_artifact(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARTIFACT_BYTES:
            raise ValueError("artifact must be a bounded regular file")
        content = stream.read(MAX_ARTIFACT_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(content) != before.st_size or (
            before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("artifact changed during verification")
    return content


def _extract(content: bytes, destination: Path, expected_version: str) -> None:
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or names.count("manifest.json") != 1:
            raise ValueError("invalid artifact members")
        for member in members:
            path = PurePosixPath(member.name)
            if (not member.isfile() or path.is_absolute() or ".." in path.parts
                    or not path.parts or member.size > MAX_ARTIFACT_BYTES):
                raise ValueError("unsafe artifact member")
        manifest_stream = archive.extractfile("manifest.json")
        if manifest_stream is None:
            raise ValueError("artifact manifest missing")
        try:
            manifest = json.loads(manifest_stream.read(64 * 1024 + 1))
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError("artifact manifest invalid") from None
        expected = {"format", "name", "version", "files"}
        if (not isinstance(manifest, dict) or set(manifest) != expected
                or manifest["format"] != 1 or manifest["name"] != "server-sentinel-main"
                or manifest["version"] != expected_version
                or not isinstance(manifest["files"], dict)
                or set(names) != {"manifest.json", *manifest["files"]}):
            raise ValueError("artifact manifest mismatch")
        for name, digest in manifest["files"].items():
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("artifact digest invalid")
            stream = archive.extractfile(name)
            if stream is None:
                raise ValueError("artifact member missing")
            data = stream.read(MAX_ARTIFACT_BYTES + 1)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("artifact member digest mismatch")
            output = destination.joinpath(*PurePosixPath(name).parts)
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with output.open("xb") as writer:
                writer.write(data)
            output.chmod(0o555 if output.suffix == ".py" else 0o444)


def _quote(value: Path | str) -> str:
    value = str(value)
    if any(ord(character) < 32 for character in value) or "$" in value:
        raise ValueError("invalid systemd argument")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def render_unit(root: Path, config: Path, deployment: Deployment,
                account: pwd.struct_passwd) -> str:
    current = root / "current"
    python = current / "venv/bin/python"
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", account.pw_name):
        raise ValueError("invalid dedicated account")
    return f"""[Unit]
Description=ServerSentinel Main Server
After=local-fs.target network.target
RequiresMountsFor={_quote(deployment.runtime_root)}

[Service]
Type=simple
User={account.pw_name}
Group={account.pw_gid}
WorkingDirectory={_quote(current)}
ExecStartPre={_quote(python)} -m app.deployment --config {_quote(config)} --check
ExecStart={_quote(python)} -m app.deployment --config {_quote(config)}
Restart=on-failure
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={_quote(deployment.runtime_root)}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
"""


def _link_target(root: Path, name: str) -> str | None:
    path = root / name
    if not path.exists() and not path.is_symlink():
        return None
    if not path.is_symlink():
        raise ValueError("release pointer must be a symbolic link")
    target = os.readlink(path)
    if not re.fullmatch(r"releases/" + VERSION.pattern, target):
        raise ValueError("release pointer is invalid")
    return target


def _set_link(root: Path, name: str, target: str | None) -> None:
    path = root / name
    temporary = root / ("." + name + ".new")
    temporary.unlink(missing_ok=True)
    if target is None:
        path.unlink(missing_ok=True)
        return
    temporary.symlink_to(target)
    os.replace(temporary, path)


def _restart(runner) -> None:
    runner(["systemctl", "restart", "server-sentinel.service"], check=True, timeout=90)
    runner(["systemctl", "is-active", "--quiet", "server-sentinel.service"],
           check=True, timeout=30)


def _protected_parent(path: Path) -> None:
    for parent in (path, *path.parents):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("installation ancestors must be root-controlled")


def _switch(root: Path, target: str, runner) -> None:
    old_current = _link_target(root, "current")
    old_previous = _link_target(root, "previous")
    _set_link(root, "previous", old_current)
    _set_link(root, "current", target)
    try:
        _restart(runner)
    except Exception:
        _set_link(root, "current", old_current)
        _set_link(root, "previous", old_previous)
        if old_current is not None:
            try:
                _restart(runner)
            except Exception:
                pass
        raise


def _stage(args, deployment: Deployment, account: pwd.struct_passwd, runner) -> str:
    if not VERSION.fullmatch(args.version):
        raise ValueError("invalid release version")
    content = read_artifact(args.artifact)
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        raise ValueError("verified artifact digest required")
    if hashlib.sha256(content).hexdigest() != args.sha256:
        raise ValueError("artifact digest mismatch")
    releases = args.destination / "releases"
    releases.mkdir(mode=0o755, exist_ok=True)
    final = releases / args.version
    staging = releases / ("." + args.version + ".staging")
    if final.exists() or staging.exists():
        raise ValueError("release version already exists")
    staging.mkdir(mode=0o755)
    try:
        _extract(content, staging, args.version)
        runner([str(args.python), "-m", "venv", str(staging / "venv")],
               check=True, timeout=120)
        runner([
            str(staging / "venv/bin/python"), "-m", "pip", "install", "--no-index",
            "--require-hashes", "--only-binary=:all:", "--no-deps", "--no-cache-dir",
            "--find-links", str(staging / "wheels"), "-r", str(staging / "requirements.lock"),
        ], check=True, timeout=300)
        runner([
            str(staging / "venv/bin/python"), "-m", "app.deployment", "--config",
            str(args.config), "--check",
        ], check=True, timeout=30, user=account.pw_uid, group=account.pw_gid,
           extra_groups=[], cwd=str(staging), env={"PYTHONDONTWRITEBYTECODE": "1"},
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        staging.rename(final)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return "releases/" + args.version


def execute(args, *, runner=subprocess.run) -> None:
    if os.geteuid() != 0:
        raise ValueError("installation requires explicit administrator execution")
    if not args.destination.is_absolute() or not args.unit.is_absolute():
        raise ValueError("absolute installation paths required")
    if args.unit.name != "server-sentinel.service":
        raise ValueError("service must retain its functional name")
    _protected_parent(args.destination.parent)
    _protected_parent(args.unit.parent)
    args.destination.mkdir(mode=0o755, exist_ok=True)
    _protected_parent(args.destination)
    args.config = Path(os.path.abspath(args.config))
    deployment = Deployment.load(args.config, code_root=Path(__file__).resolve().parent,
                                 install_root=args.destination)
    account = pwd.getpwuid(deployment.service_uid)
    if account.pw_uid == 0:
        raise ValueError("dedicated non-root account required")
    unit_content = render_unit(args.destination, args.config, deployment, account)
    if args.command in {"install", "update"}:
        if args.command == "install":
            if _link_target(args.destination, "current") is not None or args.unit.exists():
                raise ValueError("deployment already installed")
        elif (_link_target(args.destination, "current") is None or args.unit.is_symlink()
              or not args.unit.is_file()
              or args.unit.read_text(encoding="utf-8") != unit_content):
            raise ValueError("installed service configuration differs")
        target = _stage(args, deployment, account, runner)
        if args.command == "install":
            try:
                with args.unit.open("x", encoding="utf-8") as stream:
                    stream.write(unit_content)
                args.unit.chmod(0o644)
                runner(["systemctl", "daemon-reload"], check=True, timeout=30)
                _switch(args.destination, target, runner)
            except Exception:
                args.unit.unlink(missing_ok=True)
                shutil.rmtree(args.destination / target, ignore_errors=True)
                try:
                    runner(["systemctl", "daemon-reload"], check=True, timeout=30)
                except Exception:
                    pass
                raise
        else:
            _switch(args.destination, target, runner)
    else:
        if (args.unit.is_symlink() or not args.unit.is_file()
                or args.unit.read_text(encoding="utf-8") != unit_content):
            raise ValueError("installed service configuration differs")
        target = "releases/" + args.version if args.version else _link_target(
            args.destination, "previous"
        )
        if target is None or not (args.destination / target).is_dir():
            raise ValueError("rollback target is unavailable")
        _switch(args.destination, target, runner)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--unit", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "update"):
        command = subparsers.add_parser(name)
        command.add_argument("--artifact", type=Path, required=True)
        command.add_argument("--sha256", required=True)
        command.add_argument("--version", required=True)
        command.add_argument("--python", type=Path, default=Path("/usr/bin/python3"))
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--version")
    args = parser.parse_args()
    try:
        execute(args)
    except (OSError, ValueError, ConfigurationError, KeyError, subprocess.SubprocessError,
            tarfile.TarError):
        parser.exit(1, "ServerSentinel release operation failed\n")


if __name__ == "__main__":
    main()
