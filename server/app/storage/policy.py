"""Main-host admission: configured thresholds, real filesystem checks, no agent media.

Calls run on the RecordingStore owning worker. External filesystem consumption
is sampled every time; this cannot prevent an unrelated process writing after a
sample. The reserve is never deliberately allocated by this policy.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Protocol
import os
import stat
import threading

from app.media.recording.model import RecordingError
from app.media.recording.store import RootIdentity


class StorageState(StrEnum):
    NORMAL = "NORMAL"
    PRESSURE = "STORAGE_PRESSURE"
    HARD_STOP = "STORAGE_HARD_STOP"


@dataclass(frozen=True)
class StorageLimits:
    recording_limit_bytes: int
    critical_allowance_bytes: int
    hard_reserve_bytes: int
    pressure_free_bytes: int
    recovery_free_bytes: int
    recovery_allocation_bytes: int
    write_overhead_bytes: int
    max_request_bytes: int
    cleanup_batch_size: int

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in vars(self).values()):
            raise ValueError("invalid storage limits")
        if (not self.hard_reserve_bytes < self.pressure_free_bytes < self.recovery_free_bytes
                or self.recovery_allocation_bytes >= self.recording_limit_bytes
                or self.cleanup_batch_size > 1000):
            raise ValueError("invalid storage hysteresis")


@dataclass(frozen=True)
class FilesystemSpace:
    available_bytes: int
    total_bytes: int


class ExpectedFilesystem:
    """Pin an existing private directory; never create a fallback or follow links."""

    def __init__(self, root: Path, expected: RootIdentity):
        self.root = root
        self.expected = expected

    def snapshot(self) -> FilesystemSpace:
        descriptor = -1
        try:
            if not self.root.is_absolute() or ".." in self.root.parts:
                raise OSError()
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open("/", flags)
            for part in self.root.parts[1:]:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            info = os.fstat(descriptor)
            if (RootIdentity(info.st_dev, info.st_ino) != self.expected
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or not stat.S_ISDIR(info.st_mode)):
                raise OSError()
            space = os.fstatvfs(descriptor)
            if space.f_flag & os.ST_RDONLY:
                raise OSError()
            return FilesystemSpace(space.f_bavail * space.f_frsize,
                                   space.f_blocks * space.f_frsize)
        except OSError:
            raise RecordingError("STORAGE_HARD_STOP") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)


class Inventory(Protocol):
    def usage_bytes(self, *, starred_only: bool = False,
                    critical_only: bool = False) -> int: ...


class Reclaimer(Protocol):
    def expired(self, now_ms: int, limit: int) -> int:
        """Delete up to limit completed expired unstarred recordings."""

    def oldest(self, limit: int) -> int:
        """Delete up to limit completed eligible unstarred recordings."""


@dataclass(frozen=True)
class StorageTransition:
    previous: StorageState
    current: StorageState
    at_ms: int


@dataclass(frozen=True)
class StorageStatus:
    state: StorageState
    recording_bytes: int
    starred_bytes: int
    available_bytes: int
    reserved_bytes: int
    hard_reserve_bytes: int
    recording_limit_bytes: int
    critical_allowance_bytes: int
    audit_delivery_failed: bool
    cleanup_failed: bool


class MainStoragePolicy:
    """Implements #18's admit/release port without exposing an HTTP surface.

    Bind once after constructing the store, before admitting work. The same
    owning worker serializes writes, stars and cleanup. A reservation includes
    configured metadata/journal/temp overhead and remains live through fsync.
    Under pressure the total resident critical evidence plus pending critical
    reservation cannot exceed the allowance, including after worker restart.
    """

    def __init__(self, limits: StorageLimits, space: Callable[[], FilesystemSpace],
                 clock_ms: Callable[[], int], audit: Callable[[StorageTransition], None]):
        self.limits = limits
        self._space = space
        self._clock = clock_ms
        self._audit = audit
        self._owner = threading.get_ident()
        self._inventory: Inventory | None = None
        self._reclaimer: Reclaimer | None = None
        self.state = StorageState.NORMAL
        self._reserved_media = 0
        self._reserved_total = 0
        self._reservation = False
        self.audit_delivery_failed = False
        self.cleanup_failed = False

    def bind(self, inventory: Inventory, reclaimer: Reclaimer) -> None:
        if self._inventory is not None or threading.get_ident() != self._owner:
            raise RecordingError("STORAGE_BINDING_UNAVAILABLE")
        self._inventory, self._reclaimer = inventory, reclaimer

    def admit_control(self) -> None:
        """Reserve metadata/recovery space even before inventory binding.

        This physical-only admission never runs retention or queries SQLite;
        it therefore also protects the RecordingStore constructor's recovery.
        """
        if threading.get_ident() != self._owner or self._reservation:
            raise RecordingError("STORAGE_INVALID_RESERVATION")
        try:
            space = self._space()
            if (type(space.available_bytes) is not int or type(space.total_bytes) is not int
                    or not 0 <= space.available_bytes <= space.total_bytes
                    or space.available_bytes - self.limits.write_overhead_bytes
                    < self.limits.hard_reserve_bytes):
                raise ValueError()
        except Exception:
            self._transition(StorageState.HARD_STOP)
            raise RecordingError("STORAGE_HARD_STOP") from None
        self._reservation = True
        self._reserved_total = self.limits.write_overhead_bytes
        self._reserved_media = 0

    @contextmanager
    def control(self):
        """Share this serialized operation's reserved metadata budget if held."""
        if threading.get_ident() != self._owner:
            raise RecordingError("STORAGE_POLICY_UNAVAILABLE")
        owned = not self._reservation
        if owned:
            self.admit_control()
        try:
            yield
        finally:
            if owned:
                self.release()

    def _check(self) -> None:
        if threading.get_ident() != self._owner or self._inventory is None:
            raise RecordingError("STORAGE_POLICY_UNAVAILABLE")

    def _transition(self, state: StorageState) -> None:
        if self.state == state:
            return
        previous, self.state = self.state, state
        try:
            self._audit(StorageTransition(previous, state, self._clock()))
        except Exception:
            # The state remains visible even when a full disk prevents audit
            # delivery. Do not log the callback's potentially sensitive error.
            self.audit_delivery_failed = True

    def _read(self):
        try:
            space = self._space()
            used = self._inventory.usage_bytes()
            critical = self._inventory.usage_bytes(critical_only=True)
            starred = self._inventory.usage_bytes(starred_only=True)
            if (any(type(value) is not int or value < 0
                    for value in (space.available_bytes, space.total_bytes, used, critical, starred))
                    or space.available_bytes > space.total_bytes):
                raise ValueError()
            return space, used, critical, starred
        except Exception:
            self._transition(StorageState.HARD_STOP)
            raise RecordingError("STORAGE_HARD_STOP") from None

    def _state_for(self, space, used, request_total=0, request_media=0):
        free_after = space.available_bytes - self._reserved_total - request_total
        use_after = used + self._reserved_media + request_media
        if free_after < self.limits.hard_reserve_bytes:
            self._transition(StorageState.HARD_STOP)
        elif (free_after < self.limits.pressure_free_bytes
              or used + self._reserved_media >= self.limits.recording_limit_bytes
              or use_after > self.limits.recording_limit_bytes or self.cleanup_failed):
            self._transition(StorageState.PRESSURE)
        elif self.state != StorageState.NORMAL:
            if (free_after >= self.limits.recovery_free_bytes
                    and use_after <= self.limits.recovery_allocation_bytes):
                self._transition(StorageState.NORMAL)

    def status(self) -> StorageStatus:
        self._check()
        space, used, _, starred = self._read()
        self._state_for(space, used)
        return StorageStatus(self.state, used, starred, space.available_bytes,
                             self._reserved_total, self.limits.hard_reserve_bytes,
                             self.limits.recording_limit_bytes,
                             self.limits.critical_allowance_bytes,
                             self.audit_delivery_failed, self.cleanup_failed)

    def guard_metadata(self) -> None:
        """Preflight a serialized metadata operation, including cleanup/star.

        The configured overhead must bound the complete operation's journal and
        temporary allocations. No media write is authorized by this guard.
        """
        self._check()
        space, _, _, _ = self._read()
        if (space.available_bytes - self._reserved_total - self.limits.write_overhead_bytes
                < self.limits.hard_reserve_bytes):
            self._transition(StorageState.HARD_STOP)
            raise RecordingError("STORAGE_HARD_STOP")

    def admit(self, media_bytes: int, *, critical: bool) -> None:
        self._check()
        if (type(media_bytes) is not int or not 0 <= media_bytes <= self.limits.max_request_bytes
                or type(critical) is not bool or self._reservation):
            raise RecordingError("STORAGE_INVALID_RESERVATION")
        total = media_bytes + self.limits.write_overhead_bytes
        # Check identity before cleanup, including on a substituted/missing mount.
        self.guard_metadata()
        self.cleanup_failed = False
        try:
            self._reclaimer.expired(self._clock(), self.limits.cleanup_batch_size)
            for _ in range(self.limits.cleanup_batch_size):
                space, used, _, _ = self._read()
                if (space.available_bytes - total >= self.limits.pressure_free_bytes
                        and used + media_bytes <= self.limits.recording_limit_bytes):
                    break
                if self._reclaimer.oldest(1) == 0:
                    break
        except Exception:
            self.cleanup_failed = True
        space, used, critical_bytes, _ = self._read()
        self._state_for(space, used, total, media_bytes)
        if self.state == StorageState.HARD_STOP:
            raise RecordingError("STORAGE_HARD_STOP")
        if self.state == StorageState.PRESSURE:
            if (not critical or self.cleanup_failed
                    or critical_bytes + total > self.limits.critical_allowance_bytes
                    or used + media_bytes > self.limits.recording_limit_bytes
                    + self.limits.critical_allowance_bytes):
                raise RecordingError("STORAGE_PRESSURE")
        self._reservation = True
        self._reserved_media = media_bytes
        self._reserved_total = total

    def release(self) -> None:
        if threading.get_ident() != self._owner or not self._reservation:
            raise RecordingError("STORAGE_INVALID_RESERVATION")
        self._reservation = False
        self._reserved_media = self._reserved_total = 0
