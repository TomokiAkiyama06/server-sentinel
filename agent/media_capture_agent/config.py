"""Explicit deployment settings; no private paths or resource thresholds defaulted."""

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
from uuid import UUID

from .addresses import is_tailscale_host, valid_endpoint_host


class ConfigurationError(ValueError):
    """A deployment setting failed validation (never includes setting values)."""


def positive_number(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def absolute_path(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ConfigurationError("invalid deployment path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigurationError("deployment paths must be absolute and normalized")
    return path


@dataclass(frozen=True)
class ExpectedMount:
    mount_point: Path
    filesystem: str
    source: str
    major: int
    minor: int
    filesystem_root: Path
    filesystem_uuid: str | None = None

    @classmethod
    def parse(cls, value):
        if not isinstance(value, dict) or set(value) != {
            "mount_point", "filesystem", "source", "major", "minor", "filesystem_root",
            "filesystem_uuid"
        }:
            raise ConfigurationError("expected mount identity is required")
        for key in ("filesystem", "source"):
            if not isinstance(value[key], str) or not value[key] or any(
                char in value[key] for char in "\0\r\n"
            ):
                raise ConfigurationError("invalid mount identity")
        filesystem_uuid = value["filesystem_uuid"]
        if (not isinstance(filesystem_uuid, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,127}", filesystem_uuid)):
            raise ConfigurationError("invalid stable filesystem identity")
        for key in ("major", "minor"):
            if type(value[key]) is not int or value[key] < 0:
                raise ConfigurationError("invalid device identity")
        return cls(absolute_path(value["mount_point"]), value["filesystem"],
                   value["source"], value["major"], value["minor"],
                   absolute_path(value["filesystem_root"]), filesystem_uuid)


@dataclass(frozen=True)
class MainIngestEndpoint:
    """Where the Agent opens its capture ingest session (Issue #14).

    The Main's dedicated ingest listener (its deployment section
    ``capture_ingest``), not the enrollment endpoint of the trust bundle. The
    TLS server name and trust anchor come from the installed credential, never
    from here. A Tailscale IP literal is refused (Issue #150); a DNS name is
    checked by its connected peer address in ``main_link.connect_to_main``.
    """

    host: str
    port: int

    @classmethod
    def parse(cls, value):
        if not isinstance(value, dict) or set(value) != {"host", "port"}:
            raise ConfigurationError("main ingest endpoint requires host and port")
        host, port = value["host"], value["port"]
        if not valid_endpoint_host(host) or type(port) is not int or not 1 <= port <= 65535:
            raise ConfigurationError("invalid main ingest endpoint")
        if is_tailscale_host(host):
            raise ConfigurationError("main ingest endpoint must not be a Tailscale address")
        return cls(host, port)


# The longest heartbeat interval (Issue #14). The Main's capture ingest idle
# timeout (30 s by default, `server/app/cameras/remote_agent/ingest_config.py`)
# is at least three of these plus 15 s for a slow tick (storage check, clock
# exchange); `server/tests/test_capture_ingest_contract.py` checks the pair.
MAXIMUM_HEARTBEAT_SECONDS = 5.0


@dataclass(frozen=True)
class Settings:
    node_id: UUID
    runtime_root: Path
    media_root: Path
    expected_mount: ExpectedMount
    service_uid: int
    safety_reserve_bytes: int
    max_segment_bytes: int
    heartbeat_seconds: float
    clock_offset_limit_seconds: float
    clock_uncertainty_limit_seconds: float
    clock_step_limit_seconds: float
    # Optional (Issue #14): without it the Agent opens no ingest session.
    main_ingest: MainIngestEndpoint | None = None

    @classmethod
    def parse(cls, value, *, code_root):
        required = set(cls.__dataclass_fields__) - set(_OPTIONAL_SETTINGS)
        if not isinstance(value, dict) or not required <= set(value) <= required | set(
                _OPTIONAL_SETTINGS):
            raise ConfigurationError("settings contain missing or unsupported keys")
        try:
            node_id = UUID(value["node_id"])
            runtime = absolute_path(value["runtime_root"])
            media = absolute_path(value["media_root"])
            expected = ExpectedMount.parse(value["expected_mount"])
        except (ValueError, TypeError, AttributeError) as exc:
            raise ConfigurationError("invalid deployment identity or paths") from exc
        for root in (runtime, media):
            if root.is_relative_to(Path(code_root).resolve()) or root == Path("/"):
                raise ConfigurationError("runtime data must be outside application code")
        if runtime.is_relative_to(media) or media.is_relative_to(runtime):
            raise ConfigurationError("runtime and media roots must not overlap")
        if not media.is_relative_to(expected.mount_point):
            raise ConfigurationError("media root is outside the approved mount")
        for key in ("service_uid", "safety_reserve_bytes", "max_segment_bytes"):
            if type(value[key]) is not int or value[key] <= 0:
                raise ConfigurationError("positive non-root UID and byte limits required")
        for key in ("heartbeat_seconds", "clock_offset_limit_seconds",
                    "clock_uncertainty_limit_seconds", "clock_step_limit_seconds"):
            if not positive_number(value[key]):
                raise ConfigurationError("positive finite timing limits required")
        # The Main closes an ingest session after its idle timeout without a
        # frame (Issue #14), which allows several of these intervals.
        if value["heartbeat_seconds"] > MAXIMUM_HEARTBEAT_SECONDS:
            raise ConfigurationError("heartbeat interval exceeds the Main ingest contract")
        # Absent or ``null``: no ingest session (``dataclasses.asdict`` of
        # unconfigured settings round-trips).
        main_ingest = (MainIngestEndpoint.parse(value["main_ingest"])
                       if value.get("main_ingest") is not None else None)
        return cls(node_id, runtime, media, expected, value["service_uid"],
                   value["safety_reserve_bytes"], value["max_segment_bytes"],
                   value["heartbeat_seconds"], value["clock_offset_limit_seconds"],
                   value["clock_uncertainty_limit_seconds"], value["clock_step_limit_seconds"],
                   main_ingest)

    @classmethod
    def load(cls, path, *, code_root):
        value, _owner = read_protected_configuration(
            path, owner_uid=os.geteuid(), forbidden_roots=(code_root,)
        )
        return cls.parse(value, code_root=code_root)


_OPTIONAL_SETTINGS = ("main_ingest",)
MAX_CONFIGURATION_BYTES = 65536


def read_protected_configuration(path, *, owner_uid=None, forbidden_roots=()):
    """Bound every read even if the service-owned file changes after fstat."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            # Inspect the opened object, so an ancestor alias/replacement cannot
            # turn an apparently external path into configuration inside code.
            actual_path = Path(f"/proc/self/fd/{stream.fileno()}").resolve(strict=True)
            if any(actual_path.is_relative_to(Path(root).resolve()) for root in forbidden_roots):
                raise ConfigurationError("configuration must be outside application code")
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
                raise ConfigurationError("protected regular configuration required")
            if owner_uid is not None and before.st_uid != owner_uid:
                raise ConfigurationError("configuration owner rejected")
            if not 0 < before.st_size <= MAX_CONFIGURATION_BYTES:
                raise ConfigurationError("configuration size rejected")
            data = stream.read(MAX_CONFIGURATION_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (len(data) > MAX_CONFIGURATION_BYTES or len(data) != before.st_size
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ConfigurationError("configuration changed while reading")
            return json.loads(data.decode("utf-8")), before.st_uid
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ConfigurationError("cannot load protected deployment configuration") from exc
