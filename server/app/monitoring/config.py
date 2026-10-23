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
    "camera_offline_notification",
})
CAMERA_OFFLINE_KEYS = frozenset({"after_seconds", "hourly_limit"})
# Issue #301 item 2 (Owner decision 2026-10-22): five minutes, at most four
# notifications per rolling hour. Kept here (standard library only) because
# the installer validates the deployment with this module.
CAMERA_OFFLINE_SECONDS = 300.0
CAMERA_OFFLINE_SECONDS_BOUNDS = (60.0, 86400.0)
CAMERA_OFFLINE_HOURLY_LIMIT = 4
CAMERA_OFFLINE_HOURLY_LIMIT_BOUNDS = (1, 60)
STORAGE_SECTIONS = ("storage_limits", "recording_limits", "recording_filesystem")
SUMMARY_TIME = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])")
# Kernel block-device attributes by `<major>:<minor>` (Issue #321): a loop
# device has a `loop/` directory (with `backing_file` while attached), a
# device-mapper device a `dm/` directory.
SYS_DEV_BLOCK = Path("/sys/dev/block")
# Bound on the dm/md stacking walked through `slaves/` (each level is one
# mapping on top of another); deeper stacks are refused, not trusted.
MAX_BLOCK_STACK_DEPTH = 8


def _hardware_backed(node: Path, depth: int = 0) -> bool:
    """Whether the sysfs block device ``node`` rests only on hardware disks.

    An allowlist (Issue #321 review): a partition (`partition` attribute) is
    judged by its parent disk, the directory that contains it once the
    `/sys/dev/block` link is resolved; a stacked device (device-mapper, md)
    by every device under `slaves/`, recursively; and every leaf disk must
    have a `device` link to its bus device (SCSI, NVMe, virtio). Loop, nbd,
    ublk, zram and ram disks have none, so an image on the root filesystem,
    or a dm/LVM mapping on one, is never accepted, whatever its major (a
    `losetup -P` partition shares major 259 with NVMe). False also when the
    stack is deeper than `MAX_BLOCK_STACK_DEPTH` or anything cannot be read
    (fail closed).
    """
    if depth > MAX_BLOCK_STACK_DEPTH:
        return False
    try:
        path = node.resolve(strict=True)
        if (path / "partition").exists():
            path = path.parent
            if not path.is_dir():
                return False
        # Defence in depth only: a loop disk also lacks the `device` link.
        if (path / "loop").exists():
            return False
        slaves = path / "slaves"
        below = sorted(slaves.iterdir()) if slaves.exists() else []
        if not below:
            return (path / "device").exists()
        return all(_hardware_backed(slave, depth + 1) for slave in below)
    except (OSError, RuntimeError, ValueError):
        return False


def renumbered_device_acceptable(recorded: tuple[int, int], device: int) -> bool:
    """Whether a recorded major/minor pair may differ from ``device`` (Issue #321).

    Called only for a device the approved UUID, the mount point and the
    runtime root already agree on. An equal pair is always acceptable. A
    differing pair is acceptable only as a reboot renumbering of the same
    kind of device: the major (the driver) is unchanged and only the minor
    differs, and the device rests only on hardware disks (`_hardware_backed`):
    a loop device's backing file may be on the operating-system root
    filesystem (a disk image mounted with `-o loop` gets a
    `/dev/disk/by-uuid` link and a non-root device number), and loop
    partitions (major 259) or dm/LVM on a loop device keep a familiar major. A device-mapper device is accepted only when the
    recorded device was one too, which the unchanged major already implies
    (device-mapper has its own major). Missing or unreadable sysfs entries
    refuse (fail closed).
    """
    major, minor = os.major(device), os.minor(device)
    if tuple(recorded) == (major, minor):
        return True
    if recorded[0] != major:
        return False
    node = SYS_DEV_BLOCK / f"{major}:{minor}"
    try:
        if not node.exists():
            return False
    except (OSError, ValueError):
        return False
    return _hardware_backed(node)


@dataclass(frozen=True)
class RecordingFilesystem:
    """Owner-declared expected recording filesystem, re-verified at runtime.

    `resolve_device(uuid)` maps the approved filesystem UUID to the device now
    carrying it (udev `/dev/disk/by-uuid` in production) and raises when it is
    unavailable. `is_mount(path)` reports whether the mount point is mounted.
    Both are re-evaluated on every storage sample, so a detached, reformatted
    or substituted filesystem refuses writes instead of falling back.

    `device` (and the deployment's `runtime_device`, attached by
    `Deployment.load`) are the recorded Linux major/minor numbers. They only
    corroborate the UUID: the kernel may number the same disk differently
    after a reboot (Issue #321), so a changed minor of the same kind of
    device while the UUID resolves to the mounted device is a stale recorded
    value reported to the Owner; a changed major, a loop device or a new
    device-mapper device is refused (`renumbered_device_acceptable`).
    """

    root: Path = field(repr=False)
    filesystem_uuid: str = field(repr=False)
    device: tuple[int, int] = field(repr=False)
    mount_point: Path = field(repr=False)
    resolve_device: Callable[[str], int] = field(repr=False, compare=False)
    is_mount: Callable[[Path], bool] = field(default=os.path.ismount, repr=False,
                                             compare=False)
    runtime_device: tuple[int, int] | None = field(default=None, repr=False)

    def recorded_device_numbers_match(self, device: int) -> bool:
        """Whether every recorded major/minor pair names ``device``.

        Called only for a device the UUID, the mount point and the root
        already agree on. False is reported to the Owner; whether storage may
        be used at all is `recorded_device_numbers_acceptable`.
        """
        actual = (os.major(device), os.minor(device))
        return self.device == actual and self.runtime_device in (None, actual)

    def recorded_device_numbers_acceptable(self, device: int) -> bool:
        """Whether every recorded pair names ``device`` or is a stale value of
        the same kind of device (`renumbered_device_acceptable`)."""
        return all(renumbered_device_acceptable(recorded, device)
                   for recorded in (self.device, self.runtime_device) if recorded is not None)


@dataclass(frozen=True)
class CameraOfflineNotification:
    """When a camera source that stays offline notifies the Owner (Issue #301).

    ``after_seconds``: how long a source must stay not online (default 300 s,
    60 s to one day; the monitoring tick, 60 s by default, drains it).
    ``hourly_limit``: notifications per rolling hour for all sources together
    (default 4, 1 to 60).
    """

    after_seconds: float = CAMERA_OFFLINE_SECONDS
    hourly_limit: int = CAMERA_OFFLINE_HOURLY_LIMIT

    def __post_init__(self):
        low, high = CAMERA_OFFLINE_SECONDS_BOUNDS
        first, last = CAMERA_OFFLINE_HOURLY_LIMIT_BOUNDS
        if (type(self.after_seconds) not in (int, float)
                or not low <= self.after_seconds <= high
                or type(self.hourly_limit) is not int
                or not first <= self.hourly_limit <= last):
            raise ConfigurationError("invalid camera offline notification")
        object.__setattr__(self, "after_seconds", float(self.after_seconds))


@dataclass(frozen=True)
class MonitoringConfiguration:
    time_zone: ZoneInfo
    summary_hour: int = 23
    summary_minute: int = 0
    slack: SlackEndpoint | None = field(default=None, repr=False)
    storage_limits: StorageLimits | None = field(default=None, repr=False)
    recording_limits: Limits | None = field(default=None, repr=False)
    recording_filesystem: RecordingFilesystem | None = field(default=None, repr=False)
    camera_offline: CameraOfflineNotification = field(default_factory=CameraOfflineNotification)

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
                and not isinstance(self.recording_filesystem, RecordingFilesystem)
                or not isinstance(self.camera_offline, CameraOfflineNotification)):
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


def _camera_offline(value: object) -> CameraOfflineNotification:
    """The optional ``camera_offline_notification`` object; both keys optional.

    ``after_seconds`` is an integer number of seconds; booleans, floats and
    unknown keys are refused, like every other monitoring value.
    """
    if (not isinstance(value, dict) or not set(value) <= CAMERA_OFFLINE_KEYS
            or any(type(item) is not int for item in value.values())):
        raise ConfigurationError("invalid camera offline notification")
    return CameraOfflineNotification(**value)


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
    # The UUID is the identity: it must resolve to the device the recordings
    # directory and the mounted mount point are on, and that device must not
    # be the operating-system root's. The recorded major/minor numbers may
    # change across a reboot (Issue #321): a stale minor of the same kind of
    # device is reported, not refused; a different major, a loop device or a
    # new device-mapper device is refused (`renumbered_device_acceptable`).
    if (resolved_mount == Path(resolved_mount.anchor)
            or not is_mount(resolved_mount)
            or not directory.is_relative_to(resolved_mount)
            or directory_info.st_dev != mount_info.st_dev
            or directory_info.st_dev != approved
            or directory_info.st_dev == operating_system_root
            or not renumbered_device_acceptable((device[0], device[1]), directory_info.st_dev)):
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
    camera_offline = _camera_offline(value.get("camera_offline_notification", {}))
    present = [name for name in STORAGE_SECTIONS if name in value]
    if not present:
        return MonitoringConfiguration(zone, hour, minute, slack, camera_offline=camera_offline)
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
    return MonitoringConfiguration(zone, hour, minute, slack, storage, recording, filesystem,
                                   camera_offline=camera_offline)
