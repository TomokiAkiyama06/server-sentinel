"""Explicit deployment configuration for the Main Server monitoring runtime.

Every numeric storage/recording limit comes from the deployment; this module
adds no product default except the specified 23:00 daily-summary time. Values
never appear in validation messages or repr.
"""

from dataclasses import dataclass, field, fields
import os
from pathlib import Path
import re
from typing import Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.media.recording.model import Limits
from app.notifications.slack import SlackEndpoint
from app.settings import ConfigurationError
from app.storage.policy import StorageLimits


STORAGE_LIMIT_FIELDS = tuple(item.name for item in fields(StorageLimits))
RECORDING_LIMIT_FIELDS = (
    "pre_roll_bytes", "max_segment_bytes", "max_segment_ms",
    "max_active_recordings", "max_spool_segments", "max_segments_per_recording",
)
MONITORING_KEYS = frozenset({
    "time_zone", "daily_summary_time", "slack_webhook_url",
    "storage_limits", "recording_limits", "recording_filesystem",
})
STORAGE_SECTIONS = ("storage_limits", "recording_limits", "recording_filesystem")
SUMMARY_TIME = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])")


@dataclass(frozen=True)
class RecordingFilesystem:
    """Owner-declared expected recording filesystem, re-verified at runtime.

    `resolve_device(uuid)` maps the approved filesystem UUID to the device now
    carrying it (udev `/dev/disk/by-uuid` in production) and raises when it is
    unavailable. `is_mount(path)` reports whether the mount point is mounted.
    Both are re-evaluated on every storage sample, so a detached, reformatted
    or substituted filesystem refuses writes instead of falling back.
    """

    root: Path = field(repr=False)
    filesystem_uuid: str = field(repr=False)
    device: tuple[int, int] = field(repr=False)
    mount_point: Path = field(repr=False)
    resolve_device: Callable[[str], int] = field(repr=False, compare=False)
    is_mount: Callable[[Path], bool] = field(default=os.path.ismount, repr=False,
                                             compare=False)


@dataclass(frozen=True)
class MonitoringConfiguration:
    time_zone: ZoneInfo
    summary_hour: int = 23
    summary_minute: int = 0
    slack: SlackEndpoint | None = field(default=None, repr=False)
    storage_limits: StorageLimits | None = field(default=None, repr=False)
    recording_limits: Limits | None = field(default=None, repr=False)
    recording_filesystem: RecordingFilesystem | None = field(default=None, repr=False)

    def __post_init__(self):
        storage = (self.storage_limits, self.recording_limits, self.recording_filesystem)
        if (not isinstance(self.time_zone, ZoneInfo)
                or type(self.summary_hour) is not int or not 0 <= self.summary_hour <= 23
                or type(self.summary_minute) is not int or not 0 <= self.summary_minute <= 59
                or self.slack is not None and not isinstance(self.slack, SlackEndpoint)
                or self.storage_limits is not None
                and not isinstance(self.storage_limits, StorageLimits)
                or self.recording_limits is not None
                and not isinstance(self.recording_limits, Limits)
                or self.recording_filesystem is not None
                and not isinstance(self.recording_filesystem, RecordingFilesystem)):
            raise ConfigurationError("invalid monitoring configuration")
        if any(item is None for item in storage) and any(item is not None for item in storage):
            raise ConfigurationError("incomplete monitoring storage configuration")

    @property
    def storage_configured(self) -> bool:
        """False: storage admission stays unbound and writes are refused."""
        return self.storage_limits is not None


def _integers(value: object, names: tuple[str, ...]) -> dict[str, int]:
    if (not isinstance(value, dict) or set(value) != set(names)
            or any(type(item) is not int for item in value.values())):
        raise ConfigurationError("invalid monitoring limits")
    return dict(value)


def _time_zone(value: object) -> ZoneInfo:
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or not re.fullmatch(
            r"[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*", value):
        raise ConfigurationError("invalid monitoring time zone")
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ConfigurationError("invalid monitoring time zone") from None


def _recording_filesystem(value: object, recordings_directory: Path, *,
                          resolve_device: Callable[[str], int],
                          root_device: Callable[[], int],
                          is_mount: Callable[[Path], bool]) -> RecordingFilesystem:
    if not isinstance(value, dict) or set(value) != {"filesystem_uuid", "device", "mount_point"}:
        raise ConfigurationError("invalid recording filesystem identity")
    device = value["device"]
    uuid = value["filesystem_uuid"]
    if (not isinstance(device, list) or len(device) != 2
            or any(type(part) is not int or part < 0 for part in device)
            or not isinstance(uuid, str) or not isinstance(value["mount_point"], str)):
        raise ConfigurationError("invalid recording filesystem identity")
    mount = Path(value["mount_point"])
    if not mount.is_absolute() or ".." in mount.parts:
        raise ConfigurationError("recording mount point must be absolute")
    approved = resolve_device(uuid)
    try:
        resolved_mount = mount.resolve(strict=True)
        directory = recordings_directory.resolve(strict=True)
        directory_info = directory.stat()
        mount_info = resolved_mount.stat()
        operating_system_root = root_device()
    except (OSError, RuntimeError, ValueError):
        raise ConfigurationError("recording filesystem is unavailable") from None
    if (resolved_mount == Path(resolved_mount.anchor)
            or not is_mount(resolved_mount)
            or not directory.is_relative_to(resolved_mount)
            or directory_info.st_dev != mount_info.st_dev
            or directory_info.st_dev != approved
            or [os.major(directory_info.st_dev), os.minor(directory_info.st_dev)] != device
            or directory_info.st_dev == operating_system_root):
        raise ConfigurationError("recording filesystem identity mismatch")
    return RecordingFilesystem(directory, uuid, (device[0], device[1]), resolved_mount,
                               resolve_device, is_mount)


def parse_monitoring(value: object, *, recordings_directory: Path,
                     resolve_device: Callable[[str], int],
                     root_device: Callable[[], int],
                     is_mount: Callable[[Path], bool] = os.path.ismount,
                     ) -> MonitoringConfiguration:
    """Validate the optional deployment `monitoring` object, failing closed.

    Omitting all of `storage_limits`, `recording_limits` and
    `recording_filesystem` yields an explicit storage-unconfigured runtime;
    supplying only some of them, or any invalid value, is refused.
    """
    if not isinstance(value, dict) or not set(value) <= MONITORING_KEYS or "time_zone" not in value:
        raise ConfigurationError("invalid monitoring configuration")
    zone = _time_zone(value["time_zone"])
    hour, minute = 23, 0
    if "daily_summary_time" in value:
        match = (SUMMARY_TIME.fullmatch(value["daily_summary_time"])
                 if isinstance(value["daily_summary_time"], str) else None)
        if match is None:
            raise ConfigurationError("invalid daily summary time")
        hour, minute = int(match.group(1)), int(match.group(2))
    slack = None
    if "slack_webhook_url" in value:
        try:
            slack = SlackEndpoint(value["slack_webhook_url"])
        except ValueError:
            raise ConfigurationError("invalid Slack endpoint") from None
    present = [name for name in STORAGE_SECTIONS if name in value]
    if not present:
        return MonitoringConfiguration(zone, hour, minute, slack)
    if len(present) != len(STORAGE_SECTIONS):
        raise ConfigurationError("incomplete monitoring storage configuration")
    try:
        storage = StorageLimits(**_integers(value["storage_limits"], STORAGE_LIMIT_FIELDS))
        recording = Limits(**_integers(value["recording_limits"], RECORDING_LIMIT_FIELDS))
    except (TypeError, ValueError) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError("invalid monitoring limits") from None
    if recording.max_segment_bytes > storage.max_request_bytes:
        raise ConfigurationError("invalid monitoring limits")
    filesystem = _recording_filesystem(value["recording_filesystem"], recordings_directory,
                                       resolve_device=resolve_device,
                                       root_device=root_device, is_mount=is_mount)
    return MonitoringConfiguration(zone, hour, minute, slack, storage, recording, filesystem)
