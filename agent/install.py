#!/usr/bin/env python3
"""Explicit local installer; never create accounts, change mounts, or start units."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import stat

from media_capture_agent.config import ConfigurationError, Settings
from media_capture_agent.storage import StorageRefused, open_directory


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


def install(args):
    if os.geteuid() != 0:
        raise ValueError("installation requires explicit administrator execution")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?", args.version):
        raise ValueError("invalid release version")
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        raise ValueError("verified artifact digest required")
    artifact = args.artifact.read_bytes()
    if hashlib.sha256(artifact).hexdigest() != args.sha256:
        raise ValueError("artifact digest mismatch")
    fd = os.open(args.config, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError("protected configuration required")
        settings = Settings.parse(json.load(stream), code_root=args.destination)
    code_root = Path(__file__).resolve().parents[1]
    if any(root.is_relative_to(code_root) for root in (settings.runtime_root, settings.media_root)):
        raise ValueError("runtime data must be outside the checkout")
    if info.st_uid != settings.service_uid:
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
    version_root = args.destination / args.version
    version_root.mkdir(mode=0o755)
    executable = version_root / "media-capture-agent"
    unit_created = False
    try:
        with executable.open("xb") as stream:
            stream.write(artifact)
        executable.chmod(0o555)
        # Verify ownership/writability/mount/reserve under the actual service UID,
        # not administrator capabilities. No network, capture or media writes.
        subprocess.run([str(executable), "--config", str(args.config), "--check"],
                       check=True, timeout=30, user=account.pw_uid, group=account.pw_gid,
                       extra_groups=[], env={"PATH": "/usr/bin:/bin",
                                             "PYTHONDONTWRITEBYTECODE": "1"},
                       cwd="/", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        content = render_unit(executable, args.config, settings, account.pw_name,
                              account.pw_gid, args.video_device)
        with args.unit.open("x", encoding="utf-8") as stream:
            unit_created = True
            stream.write(content)
        args.unit.chmod(0o644)
    except Exception:
        if unit_created:
            args.unit.unlink()
        executable.unlink(missing_ok=True)
        version_root.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--unit", type=Path, required=True)
    parser.add_argument("--video-device", action="append", default=[])
    args = parser.parse_args()
    try:
        install(args)
    except (OSError, ValueError, ConfigurationError, StorageRefused,
            KeyError, subprocess.SubprocessError):
        parser.exit(1, "media-capture-agent installation validation failed\n")
    print("media-capture-agent installed; inspect and enable the unit explicitly")


if __name__ == "__main__":
    main()
