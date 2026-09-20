"""Validated stable-deployment configuration and launcher."""

from dataclasses import dataclass
import argparse
import json
import os
from pathlib import Path
import stat

from app.settings import ConfigurationError, Settings


MAX_CONFIGURATION_BYTES = 16 * 1024


def _read_configuration(path: Path) -> tuple[dict, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
                raise ConfigurationError("deployment configuration must be a private regular file")
            content = stream.read(MAX_CONFIGURATION_BYTES + 1)
            after = os.fstat(stream.fileno())
            if len(content) > MAX_CONFIGURATION_BYTES or (
                    before.st_size, before.st_mtime_ns, before.st_ctime_ns
            ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ConfigurationError("deployment configuration changed during validation")
        value = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ConfigurationError("deployment configuration is unavailable") from None
    if not isinstance(value, dict):
        raise ConfigurationError("deployment configuration must be an object")
    return value, before


def _private_directory(path: Path, uid: int, forbidden_roots: tuple[Path, ...]) -> Path:
    if not path.is_absolute():
        raise ConfigurationError("runtime_root must be absolute")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        forbidden = tuple(root.resolve(strict=True) for root in forbidden_roots)
    except (OSError, RuntimeError, ValueError):
        raise ConfigurationError("runtime directory is unavailable") from None
    if (not resolved.is_dir() or info.st_uid != uid or info.st_mode & 0o077
            or any(resolved.is_relative_to(root) for root in forbidden)):
        raise ConfigurationError("runtime directory failed ownership or location checks")
    return resolved


@dataclass(frozen=True)
class Deployment:
    runtime_root: Path
    service_uid: int
    settings: Settings
    recordings_directory: Path
    audit_directory: Path

    @property
    def state_directory(self) -> Path:
        return self.settings.data_directory

    @classmethod
    def load(cls, path: Path, *, code_root: Path | None = None,
             install_root: Path | None = None) -> "Deployment":
        value, info = _read_configuration(path)
        code_root = code_root or Path(__file__).resolve().parents[1]
        allowed = {
            "runtime_root", "runtime_mount_point", "runtime_device", "service_uid",
            "human_host", "human_port", "log_level",
        }
        if set(value) != allowed or type(value.get("service_uid")) is not int:
            raise ConfigurationError("invalid deployment configuration")
        uid = value["service_uid"]
        if uid <= 0 or info.st_uid != uid:
            raise ConfigurationError("deployment configuration must belong to the service account")
        roots = tuple(root for root in (code_root, install_root) if root is not None)
        try:
            configuration_path = path.resolve(strict=True)
            if any(configuration_path.is_relative_to(root.resolve(strict=True)) for root in roots):
                raise ConfigurationError("deployment configuration must be outside code")
            runtime_path = Path(value["runtime_root"])
        except (OSError, RuntimeError, TypeError, ValueError):
            raise ConfigurationError("invalid deployment configuration") from None
        runtime_root = _private_directory(runtime_path, uid, roots)
        device = value["runtime_device"]
        if (not isinstance(device, list) or len(device) != 2
                or any(type(part) is not int or part < 0 for part in device)):
            raise ConfigurationError("invalid runtime filesystem identity")
        try:
            mount_point = Path(value["runtime_mount_point"]).resolve(strict=True)
            mount_info = mount_point.stat()
            root_info = runtime_root.stat()
        except (OSError, RuntimeError, TypeError, ValueError):
            raise ConfigurationError("runtime mount is unavailable") from None
        if (not mount_point.is_absolute() or not mount_point.is_dir()
                or not os.path.ismount(mount_point)
                or not runtime_root.is_relative_to(mount_point)
                or root_info.st_dev != mount_info.st_dev
                or [os.major(root_info.st_dev), os.minor(root_info.st_dev)] != device
                or any(mount_point.is_relative_to(root) for root in roots)):
            raise ConfigurationError("runtime filesystem identity mismatch")
        directories = tuple(
            _private_directory(runtime_root / name, uid, roots)
            for name in ("state", "recordings", "audit")
        )
        for directory in directories:
            directory_device = directory.stat().st_dev
            if (not directory.is_relative_to(runtime_root)
                    or directory_device != root_info.st_dev
                    or [os.major(directory_device), os.minor(directory_device)] != device):
                raise ConfigurationError("runtime subdirectory escapes the approved filesystem")
        settings = Settings(
            directories[0], human_host=value["human_host"],
            human_port=value["human_port"], log_level=value["log_level"],
            source_root=code_root,
        )
        return cls(runtime_root, uid, settings, directories[1], directories[2])


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(arguments)
    try:
        deployment = Deployment.load(args.config)
        if os.geteuid() != deployment.service_uid:
            raise ConfigurationError("launcher must run as the dedicated account")
    except ConfigurationError:
        parser.exit(1, "ServerSentinel deployment validation failed\n")
    if args.check:
        print("ServerSentinel deployment validation passed")
        return 0
    from app.__main__ import run
    return run(deployment.settings)


if __name__ == "__main__":
    raise SystemExit(main())
