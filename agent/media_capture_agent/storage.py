"""Descriptor-pinned Linux media storage admission; never create fallback roots."""

from dataclasses import dataclass, replace
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import threading
from uuid import UUID

from .config import ExpectedMount


class StorageRefused(RuntimeError):
    """Fixed reason codes are safe to surface; underlying paths are never logged.

    ``str(exc)`` is the stable runtime reason (heartbeat/ring contract).
    ``diagnostic`` is an optional finer fixed code used only by the local
    ``--check`` report; it never contains paths, identities, sizes or users.
    """

    def __init__(self, reason, *, diagnostic=None):
        super().__init__(reason)
        self.diagnostic = diagnostic or reason


@dataclass(frozen=True)
class Mount:
    identity: ExpectedMount
    mount_id: int
    readonly: bool


def decode_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def _inventory_unreadable():
    """/proc mount inventory I/O failure.

    The runtime reason stays ``storage_unavailable`` (heartbeat/ring contract);
    ``--check`` reports the finer ``mount_inventory_unavailable`` diagnostic.
    """
    return StorageRefused("storage_unavailable", diagnostic="mount_inventory_unavailable")


def read_mounts():
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as stream:
            text = stream.read()
    except OSError as exc:
        raise _inventory_unreadable() from exc
    return parse_mounts(text)


def descriptor_mount_id(descriptor):
    try:
        with open(f"/proc/self/fdinfo/{descriptor}", encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("mnt_id:"):
                    return int(line.split(":", 1)[1])
    except OSError as exc:
        raise _inventory_unreadable() from exc
    raise StorageRefused("mount_inventory_unavailable")


def stable_device_matches(expected):
    """Match the Owner-approved filesystem UUID to the block device ``expected`` names.

    ``MediaStore`` passes the approved identity with the major/minor the mount
    inventory currently reports (Issue #324), so this proves the UUID resolves
    to the mounted device; the recorded numbers are judged separately.
    """
    try:
        if expected.filesystem_uuid is None:
            return False
        info = os.stat(Path("/dev/disk/by-uuid") / expected.filesystem_uuid)
        return (stat.S_ISBLK(info.st_mode) and os.major(info.st_rdev) == expected.major
                and os.minor(info.st_rdev) == expected.minor)
    except OSError:
        return False


# Fixed, value-free code for an accepted renumbering (Issue #324): heartbeat
# storage reason, node reason `storage_device_numbers_stale` and `--check`
# warning. It never carries the recorded or current numbers.
DEVICE_NUMBERS_STALE = "device_numbers_stale"

# Kernel block-device attributes by `<major>:<minor>` (Issue #324, the Agent
# counterpart of Main's Issue #321 rule in `server/app/monitoring/config.py`;
# the Agent is a separate artifact and shares no code with Main).
SYS_DEV_BLOCK = Path("/sys/dev/block")
# Bound on the dm/md stacking walked through `slaves/`; deeper stacks are
# refused, not trusted.
MAX_BLOCK_STACK_DEPTH = 8


def _hardware_backed(node, depth=0):
    """Whether the sysfs block device ``node`` rests only on hardware disks.

    An allowlist: a partition (`partition` attribute) is judged by its parent
    disk, the directory containing it once the `/sys/dev/block` link is
    resolved; a stacked device (device-mapper, md) by every device under
    `slaves/`, recursively; every leaf disk must have a `device` link to its
    bus device (SCSI, NVMe, virtio, USB storage). Loop, nbd, ublk, zram and ram
    disks have none, so an image on the root filesystem, or a dm/LVM mapping on
    one, is never accepted whatever its major (a `losetup -P` partition shares
    major 259 with NVMe). False also beyond ``MAX_BLOCK_STACK_DEPTH`` or when
    anything cannot be read (fail closed).
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


def renumbered_device_acceptable(recorded, device):
    """Whether recorded ``(major, minor)`` may differ from ``device`` (Issue #324).

    Called only for the device the approved UUID, the mount inventory and the
    pinned media directory already agree on. Equal numbers are acceptable. A
    difference is acceptable only as a reboot renumbering of the same kind of
    device: the major (the driver) is unchanged, only the minor differs, and
    the device rests only on hardware disks (`_hardware_backed`). A different
    major (for example a loop image `7:N` replacing a disk) or a missing or
    unreadable sysfs entry refuses (fail closed). Device-mapper has its own
    major, so a dm device is accepted only when the recorded one was dm too.
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


def os_root_device():
    """Device of the operating-system root filesystem (never a renumbering target)."""
    return os.stat("/").st_dev


def parse_mounts(text):
    mounts = []
    try:
        for line in text.splitlines():
            before, after = line.split(" - ", 1)
            fields, filesystem = before.split(), after.split()
            major, minor = map(int, fields[2].split(":"))
            mounts.append(Mount(ExpectedMount(
                Path(decode_mount(fields[4])), filesystem[0],
                decode_mount(filesystem[1]), major, minor, Path(decode_mount(fields[3])),
                None,
            ), int(fields[0]), "ro" in fields[5].split(",")
                or "ro" in filesystem[2].split(",")))
    except (ValueError, IndexError) as exc:
        raise StorageRefused("mount_inventory_unavailable") from exc
    return mounts


def open_directory(path):
    """Walk every component without following symlinks, including ancestors."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise StorageRefused("invalid_storage_path")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise StorageRefused("storage_path_unavailable") from exc


class MediaStore:
    """Single bounded segment writes with inter-process admission serialization.

    No parent directory is created. All file actions are relative to a verified
    directory fd, so a mount/path replacement can never redirect into a fallback.
    A dedicated filesystem and external-writer monitoring remain deployment duties.
    """

    def __init__(self, settings, *, mounts=read_mounts, space=os.fstatvfs,
                 mount_id=descriptor_mount_id, stable_device=stable_device_matches,
                 root_device=os_root_device, renumbered=renumbered_device_acceptable):
        self.settings = settings
        self.mounts = mounts
        self.space = space
        self.mount_id = mount_id
        self.stable_device = stable_device
        self.root_device = root_device
        self.renumbered = renumbered
        self._lock = threading.Lock()
        self._mount_id = None
        # (device, stale) of the last accepted device-number judgement.
        self._device_judgement = None
        # True while the approved filesystem is mounted under device numbers
        # other than the recorded ones (Issue #324): accepted, but degraded.
        self.device_numbers_stale = False
        try:
            self._fd = open_directory(settings.media_root)
        except StorageRefused as exc:
            exc.diagnostic = self._unavailable_root_diagnostic()
            raise
        try:
            self.check(require_reserve=False)
        except Exception:
            self.close()
            raise

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def check(self, additional_bytes=0, *, require_reserve=True):
        if type(additional_bytes) is not int or additional_bytes < 0:
            raise StorageRefused("invalid_allocation")
        if self._fd is None:
            raise StorageRefused("storage_closed")
        try:
            info = os.fstat(self._fd)
            current = open_directory(self.settings.media_root)
            try:
                current_info = os.fstat(current)
                if self.mount_id(current) != self.mount_id(self._fd):
                    raise StorageRefused("mount_replaced")
                if (info.st_dev, info.st_ino) != (current_info.st_dev, current_info.st_ino):
                    raise StorageRefused("media_root_replaced")
            finally:
                os.close(current)
            if info.st_uid != self.settings.service_uid:
                raise StorageRefused("media_root_ownership",
                                     diagnostic="media_root_owner_mismatch")
            if info.st_mode & 0o022:
                raise StorageRefused("media_root_ownership",
                                     diagnostic="media_root_permissions_too_open")
            if not info.st_mode & stat.S_IWUSR or not info.st_mode & stat.S_IXUSR:
                raise StorageRefused("media_root_not_writable")
            actual_mount_id = self.mount_id(self._fd)
            mounts = self.mounts()
            applicable = [mount for mount in mounts
                          if mount.mount_id == actual_mount_id
                          and self.settings.media_root.is_relative_to(mount.identity.mount_point)]
            if not applicable:
                raise StorageRefused("mount_missing")
            mount = max(applicable, key=lambda entry: len(entry.identity.mount_point.parts))
            approved = self._approved_mount(mount.identity, mounts)
            if not approved or mount.readonly:
                raise StorageRefused("mount_identity_mismatch", diagnostic=(
                    "mount_readonly" if approved
                    else self._mismatch_diagnostic(mount.identity, mounts)))
            # The approved UUID must resolve to the device actually mounted.
            if not self.stable_device(replace(self.settings.expected_mount,
                                              major=mount.identity.major,
                                              minor=mount.identity.minor)):
                raise StorageRefused("stable_device_mismatch")
            if (os.major(info.st_dev), os.minor(info.st_dev)) != (
                mount.identity.major, mount.identity.minor
            ):
                # The pinned directory is not on the device mountinfo reports:
                # a stacked/replaced mount, not an Owner configuration error.
                raise StorageRefused("mount_device_mismatch", diagnostic="mount_replaced")
            self.device_numbers_stale = self._judge_device_numbers(info.st_dev)
            if self._mount_id is not None and self._mount_id != mount.mount_id:
                raise StorageRefused("mount_replaced")
            self._mount_id = mount.mount_id
            space = self.space(self._fd)
            if space.f_flag & os.ST_RDONLY:
                raise StorageRefused("media_root_readonly", diagnostic="mount_readonly")
            available = space.f_bavail * space.f_frsize
            rounded = ((additional_bytes + space.f_frsize - 1) // space.f_frsize) * space.f_frsize
            if require_reserve and available < self.settings.safety_reserve_bytes + rounded:
                raise StorageRefused("STORAGE_HARD_STOP", diagnostic="insufficient_free_space")
            return available
        except OSError as exc:
            raise StorageRefused("storage_unavailable") from exc

    def _judge_device_numbers(self, device):
        """Compare the recorded major/minor with the verified mounted ``device``.

        UUID, mount and pinned directory already agree on ``device``. Equal
        numbers: not stale. Otherwise only a same-major, hardware-backed
        renumbering of a non-root filesystem is accepted, as stale (Issue
        #324); anything else refuses with ``mount_device_mismatch``. The
        accepted judgement is cached per device: the pinned mount cannot change
        device without a mount ID change, which already refuses.
        """
        expected = self.settings.expected_mount
        recorded = (expected.major, expected.minor)
        if recorded == (os.major(device), os.minor(device)):
            return False
        if self._device_judgement == (device, True):
            return True
        if (expected.mount_point == Path("/") or device == self.root_device()
                or not self.renumbered(recorded, device)):
            raise StorageRefused("mount_identity_mismatch", diagnostic="mount_device_mismatch")
        self._device_judgement = (device, True)
        return True

    def _unavailable_root_diagnostic(self):
        """Fixed code when the media root cannot be opened at startup."""
        try:
            mounts = self.mounts()
        except (OSError, StorageRefused):
            # The inventory itself could not be read or parsed.
            return "mount_inventory_unavailable"
        mount_point = self.settings.expected_mount.mount_point
        if not any(entry.identity.mount_point == mount_point for entry in mounts):
            return "mount_missing"
        return "media_root_unavailable"

    def _mismatch_diagnostic(self, actual, mounts):
        """Name the first differing approved-mount property as one fixed code.

        Diagnostic only: admission already refused. Precedence is fixed so each
        refusal yields exactly one code, and no compared value is returned.
        """
        expected = self.settings.expected_mount
        root = Path("/")
        if actual.mount_point == root and expected.mount_point != root:
            return "media_root_on_root_filesystem"
        if expected.mount_point == root and actual.mount_point != root:
            return "mount_point_is_root"
        reference_root = expected.filesystem_root
        if actual.mount_point != expected.mount_point:
            if actual.mount_point != self.settings.media_root:
                return "mount_identity_mismatch"
            # Narrow service bind at media_root: compare with the approved parent.
            reference_root = expected.filesystem_root / self.settings.media_root.relative_to(
                expected.mount_point)
        if actual.source != expected.source:
            return "mount_source_mismatch"
        # Device numbers are not part of approval (Issue #324); they are judged
        # after the UUID check by `_judge_device_numbers`.
        if actual.filesystem != expected.filesystem or actual.filesystem_root != reference_root:
            return "mount_identity_mismatch"
        # Every field matches a bind, but the approved parent mount is not visible.
        return "mount_missing"

    def _approved_mount(self, actual, mounts):
        """Allow only the exact approved filesystem or its narrow service bind.

        systemd ReadWritePaths creates a namespace bind at media_root. Its root
        in the backing filesystem must equal the approved parent root plus the
        configured relative path; a same-device bind of another directory fails.
        The approved parent mount must remain visible in the namespace inventory.
        Device numbers are taken from ``actual`` (Issue #324): they can change
        across a reboot, so the UUID check and `_judge_device_numbers` decide
        them, and the parent must be on the same device as the bind.
        """
        expected = self.settings.expected_mount
        mountinfo_expected = replace(expected, filesystem_uuid=None,
                                     major=actual.major, minor=actual.minor)
        if actual == mountinfo_expected:
            return True
        if actual.mount_point != self.settings.media_root:
            return False
        if not any(mount.identity == mountinfo_expected for mount in mounts):
            return False
        relative = self.settings.media_root.relative_to(expected.mount_point)
        return (
            actual.filesystem == expected.filesystem and actual.source == expected.source
            and actual.filesystem_root == expected.filesystem_root / relative
        )

    def write_segment(self, segment_id, data):
        """Write a bounded opaque video segment; caller owns video provenance."""
        if not isinstance(segment_id, UUID) or not isinstance(data, bytes):
            raise StorageRefused("invalid_segment")
        if not data or len(data) > self.settings.max_segment_bytes:
            raise StorageRefused("segment_size_limit")
        name = str(segment_id) + ".segment"
        descriptor = None
        created = False
        with self._lock:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
                self.check(len(data))
                descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._fd)
                created = True
                # Reserve actual filesystem blocks before writing media; no sparse fallback.
                os.posix_fallocate(descriptor, 0, len(data))
                self.check()
                remaining = memoryview(data)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise StorageRefused("segment_write_failed")
                    remaining = remaining[written:]
                os.fsync(descriptor)
                self.check()
                os.fsync(self._fd)
            except (OSError, StorageRefused) as exc:
                if created:
                    try:
                        os.unlink(name, dir_fd=self._fd)
                    except OSError as cleanup_error:
                        raise StorageRefused("partial_cleanup_failed") from cleanup_error
                if isinstance(exc, StorageRefused):
                    raise
                raise StorageRefused("segment_write_failed") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        return name

    def list_segments(self):
        """List immutable owned segments for ledger reconciliation; ignore other names."""
        with self._lock:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_SH)
                self.check(require_reserve=False)
                result = {}
                for name in os.listdir(self._fd):
                    if not name.endswith(".segment"):
                        continue
                    try:
                        identity = UUID(name[:-8])
                    except ValueError as exc:
                        raise StorageRefused("segment_identity_invalid") from exc
                    if name != str(identity) + ".segment":
                        raise StorageRefused("segment_identity_invalid")
                    info = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
                    self._validate_segment(info)
                    result[identity] = info.st_size
                return result
            except OSError as exc:
                raise StorageRefused("segment_inventory_failed") from exc
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _validate_segment(self, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.settings.service_uid
                or info.st_mode & 0o077 or info.st_nlink != 1
                or info.st_size > self.settings.max_segment_bytes):
            raise StorageRefused("segment_metadata_invalid")

    def delete_segment(self, segment_id):
        """Caller must authorize retention deletion; mount checks apply at hard stop."""
        if not isinstance(segment_id, UUID):
            raise StorageRefused("invalid_segment")
        name = str(segment_id) + ".segment"
        with self._lock:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
                self.check(require_reserve=False)
                try:
                    info = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                self._validate_segment(info)
                os.unlink(name, dir_fd=self._fd)
                os.fsync(self._fd)
                return True
            except OSError as exc:
                raise StorageRefused("segment_delete_failed") from exc
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)

    @property
    def filesystem_device(self):
        """Verified device of the pinned media directory, independent of path races."""
        self.check(require_reserve=False)
        return os.fstat(self._fd).st_dev

    @property
    def allocation_unit(self):
        self.check(require_reserve=False)
        return self.space(self._fd).f_frsize

    def segment_allocations(self):
        """Allocated bytes, not sparse logical sizes, for conservative reclaim budgets."""
        with self._lock:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_SH)
                self.check(require_reserve=False)
                result = {}
                for name in os.listdir(self._fd):
                    if not name.endswith(".segment"):
                        continue
                    try:
                        identity = UUID(name[:-8])
                    except ValueError as exc:
                        raise StorageRefused("segment_identity_invalid") from exc
                    if name != str(identity) + ".segment":
                        raise StorageRefused("segment_identity_invalid")
                    info = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
                    self._validate_segment(info)
                    result[identity] = info.st_blocks * 512
                return result
            except OSError as exc:
                raise StorageRefused("segment_inventory_failed") from exc
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)

    def verify_segment(self, segment_id, expected_size, sha256_hex):
        """Bounded content verification for crash recovery; no media content is logged."""
        if (not isinstance(segment_id, UUID) or type(expected_size) is not int
                or not 0 < expected_size <= self.settings.max_segment_bytes
                or not isinstance(sha256_hex, str)
                or not re.fullmatch(r"[0-9a-f]{64}", sha256_hex)):
            raise StorageRefused("invalid_segment")
        descriptor = None
        with self._lock:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_SH)
                self.check(require_reserve=False)
                try:
                    descriptor = os.open(str(segment_id) + ".segment", os.O_RDONLY
                                         | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                         dir_fd=self._fd)
                except FileNotFoundError:
                    return False
                info = os.fstat(descriptor)
                self._validate_segment(info)
                if info.st_size != expected_size:
                    return False
                digest = hashlib.sha256()
                remaining = expected_size
                while remaining:
                    data = os.read(descriptor, min(remaining, 65536))
                    if not data:
                        return False
                    digest.update(data)
                    remaining -= len(data)
                after = os.fstat(descriptor)
                self.check(require_reserve=False)
                if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns
                ):
                    return False
                return hmac.compare_digest(digest.hexdigest(), sha256_hex)
            except OSError as exc:
                raise StorageRefused("segment_verification_failed") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                fcntl.flock(self._fd, fcntl.LOCK_UN)
