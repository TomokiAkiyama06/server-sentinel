"""Descriptor-pinned Linux media storage admission; never create fallback roots."""

from dataclasses import dataclass
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
    """Fixed reason codes are safe to surface; underlying paths are never logged."""


@dataclass(frozen=True)
class Mount:
    identity: ExpectedMount
    mount_id: int
    readonly: bool


def decode_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def read_mounts():
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        return parse_mounts(stream.read())


def descriptor_mount_id(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", encoding="utf-8") as stream:
        for line in stream:
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1])
    raise StorageRefused("mount_inventory_unavailable")


def parse_mounts(text):
    mounts = []
    try:
        for line in text.splitlines():
            before, after = line.split(" - ", 1)
            fields, filesystem = before.split(), after.split()
            major, minor = map(int, fields[2].split(":"))
            mounts.append(Mount(ExpectedMount(
                Path(decode_mount(fields[4])), filesystem[0],
                decode_mount(filesystem[1]), major, minor,
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
                 mount_id=descriptor_mount_id):
        self.settings = settings
        self.mounts = mounts
        self.space = space
        self.mount_id = mount_id
        self._lock = threading.Lock()
        self._mount_id = None
        self._fd = open_directory(settings.media_root)
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
            if info.st_uid != self.settings.service_uid or info.st_mode & 0o022:
                raise StorageRefused("media_root_ownership")
            if not info.st_mode & stat.S_IWUSR or not info.st_mode & stat.S_IXUSR:
                raise StorageRefused("media_root_not_writable")
            actual_mount_id = self.mount_id(self._fd)
            applicable = [mount for mount in self.mounts()
                          if mount.mount_id == actual_mount_id
                          and self.settings.media_root.is_relative_to(mount.identity.mount_point)]
            if not applicable:
                raise StorageRefused("mount_missing")
            mount = max(applicable, key=lambda entry: len(entry.identity.mount_point.parts))
            if mount.identity != self.settings.expected_mount or mount.readonly:
                raise StorageRefused("mount_identity_mismatch")
            if (os.major(info.st_dev), os.minor(info.st_dev)) != (
                mount.identity.major, mount.identity.minor
            ):
                raise StorageRefused("mount_device_mismatch")
            if self._mount_id is not None and self._mount_id != mount.mount_id:
                raise StorageRefused("mount_replaced")
            self._mount_id = mount.mount_id
            space = self.space(self._fd)
            if space.f_flag & os.ST_RDONLY:
                raise StorageRefused("media_root_readonly")
            available = space.f_bavail * space.f_frsize
            rounded = ((additional_bytes + space.f_frsize - 1) // space.f_frsize) * space.f_frsize
            if require_reserve and available < self.settings.safety_reserve_bytes + rounded:
                raise StorageRefused("STORAGE_HARD_STOP")
            return available
        except OSError as exc:
            raise StorageRefused("storage_unavailable") from exc

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
