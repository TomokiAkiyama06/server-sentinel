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

    Each sample re-resolves the approved filesystem UUID, checks the Linux
    device numbers and that the declared mount point is still mounted on that
    device, then delegates to `ExpectedFilesystem`, which pins the root's
    device/inode and the private metadata file without following links. Any
    mismatch is `STORAGE_HARD_STOP`: the caller refuses the write rather than
    writing into whatever is now at that path.
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
                or (os.major(device), os.minor(device)) != identity.device
                or not mounted or mount.st_dev != device):
            raise RecordingError("STORAGE_HARD_STOP")

    def check(self) -> None:
        """Raise `STORAGE_HARD_STOP` unless the expected filesystem is intact."""
        self.snapshot()

    def snapshot(self) -> FilesystemSpace:
        self._verify_identity()
        return self._checker.snapshot()
