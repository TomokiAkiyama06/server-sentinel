"""Expected recording filesystem re-verification; never creates a fallback."""

import os
from pathlib import Path
import stat

from app.media.recording.model import RecordingError
from app.media.recording.store import RootIdentity
from app.storage.policy import ExpectedFilesystem, FilesystemSpace

from .config import RecordingFilesystem


class IdentifiedRecordingFilesystem:
    """Pin the recording root and re-check its declared filesystem identity.

    Each sample re-resolves the approved filesystem UUID, checks that it
    still names the device the root was pinned on and that the declared mount
    point is still mounted on that device, then delegates to
    `ExpectedFilesystem`, which pins the root's device/inode and the private
    metadata file without following links. Any mismatch is
    `STORAGE_HARD_STOP`: the caller refuses the write rather than writing into
    whatever is now at that path.

    The recorded major/minor numbers only corroborate the UUID (Issue #321):
    `device_numbers_current` is False when they no longer name the pinned
    device, which the runtime reports to the Owner. Only a changed minor of
    the same kind of device is accepted; a changed major, a loop device or a
    new device-mapper device is `STORAGE_HARD_STOP` when the root is pinned.

    While the numbers are stale that judgement is repeated on every sample
    (Issue #340): a live dm table reload or md member replacement can move the
    pinned device onto loop/virtual backing without changing its own number,
    the mount or `st_dev`, so the sysfs topology is walked again each time and
    a refusal is `STORAGE_HARD_STOP` for that sample only (not latched: the
    next sample on hardware-only backing admits again). Current numbers never
    read sysfs.
    """

    def __init__(self, identity: RecordingFilesystem, metadata: Path):
        self.identity = identity
        try:
            info = os.stat(identity.root, follow_symlinks=False)
        except OSError:
            raise RecordingError("STORAGE_HARD_STOP") from None
        if not stat.S_ISDIR(info.st_mode):
            raise RecordingError("STORAGE_HARD_STOP")
        self.expected = RootIdentity(info.st_dev, info.st_ino)
        # Fixed for this instance: the pinned device number cannot change
        # without every later sample refusing. What lies beneath it can, so
        # `_verify_identity` re-judges the topology while this is False.
        self.device_numbers_current = identity.recorded_device_numbers_match(info.st_dev)
        self._verify_identity()
        self._checker = ExpectedFilesystem(identity.root, self.expected, metadata)

    def _verify_identity(self) -> None:
        identity = self.identity
        try:
            approved = identity.resolve_device(identity.filesystem_uuid)
            mount = os.stat(identity.mount_point, follow_symlinks=False)
            mounted = identity.is_mount(identity.mount_point)
        except Exception:
            raise RecordingError("STORAGE_HARD_STOP") from None
        device = self.expected.device
        if (type(approved) is not int or approved != device
                or not mounted or mount.st_dev != device):
            raise RecordingError("STORAGE_HARD_STOP")
        # Issue #321/#340: a stale minor of the same kind of device on
        # hardware-only backing is reported; a different major, a loop device,
        # a new device-mapper device or backing that moved onto loop/virtual
        # disks is refused, judged again at every sample (a handful of sysfs
        # lookups, never cached), as at deployment validation.
        if self.device_numbers_current:
            return
        try:
            acceptable = identity.recorded_device_numbers_acceptable(device)
        except Exception:
            acceptable = False
        if acceptable is not True:
            raise RecordingError("STORAGE_HARD_STOP")

    def check(self) -> None:
        """Raise `STORAGE_HARD_STOP` unless the expected filesystem is intact."""
        self.snapshot()

    def snapshot(self) -> FilesystemSpace:
        self._verify_identity()
        return self._checker.snapshot()
