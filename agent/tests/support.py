"""Ephemeral private directories and synthetic capture/transport implementations."""

import os
from pathlib import Path
import tempfile
from uuid import UUID

from media_capture_agent.config import Settings
from media_capture_agent.health import ClockExchange, SourceHealth
from media_capture_agent.storage import descriptor_mount_id, open_directory, read_mounts


NODE = UUID("00000000-0000-4000-8000-000000000001")
SOURCE = UUID("00000000-0000-4000-8000-000000000002")


def configuration(root):
    root = Path(root)
    media, runtime = root / "media", root / "state"
    media.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    fd = open_directory(media)
    try:
        mount_id = descriptor_mount_id(fd)
        mount = next(item.identity for item in read_mounts() if item.mount_id == mount_id)
    finally:
        os.close(fd)
    return {
        "node_id": str(NODE), "media_root": str(media), "runtime_root": str(runtime),
        "expected_mount": {"mount_point": str(mount.mount_point), "filesystem": mount.filesystem,
                           "source": mount.source, "major": mount.major, "minor": mount.minor,
                           "filesystem_root": str(mount.filesystem_root),
                           "filesystem_uuid": "synthetic-filesystem-identity"},
        "service_uid": os.geteuid(), "safety_reserve_bytes": 4096, "max_segment_bytes": 16384,
        "heartbeat_seconds": 0.01, "clock_offset_limit_seconds": 2,
        "clock_uncertainty_limit_seconds": 0.5, "clock_step_limit_seconds": 0.1,
    }


MEMORY_FILESYSTEM = Path("/dev/shm")
MEMORY_FILESYSTEM_MINIMUM_FREE = 256 * 1024 * 1024


def ring_temporary_directory(*, memory_filesystem=MEMORY_FILESYSTEM):
    """A private directory for ring simulations, on tmpfs when one is usable.

    Every ring append commits the SQLite ledger with ``synchronous = FULL`` and
    fsyncs segments and directories. The simulations append hundreds to
    thousands of segments, and on a disk-backed CI runner those flushes, not
    the accounting under test, took most of the agent suite's time limit
    (Issue #179). The same code paths, fsync included, still run on tmpfs,
    where a flush is cheap; no test here simulates power loss, so no
    assertion depends on the flush reaching a disk. Without a usable tmpfs
    with room to spare, the default temporary directory is used.
    """
    try:
        usable = (memory_filesystem.is_dir() and os.access(memory_filesystem, os.W_OK | os.X_OK)
                  and _free_bytes(memory_filesystem) >= MEMORY_FILESYSTEM_MINIMUM_FREE)
    except OSError:
        usable = False
    return tempfile.TemporaryDirectory(prefix="agent-ring-",
                                       dir=str(memory_filesystem) if usable else None)


def _free_bytes(path):
    stat = os.statvfs(path)
    return stat.f_bavail * stat.f_frsize


def settings(root):
    return Settings.parse(configuration(root), code_root=Path(root) / "code")


class SyntheticCapture:
    """No hardware, microphone, media input, or network access."""

    def __init__(self):
        self.online = True
        self.closed = False

    def poll(self):
        return (SourceHealth(SOURCE, "online" if self.online else "offline",
                             "video_ready" if self.online else "camera_missing"),)

    def close(self):
        self.closed = True


class MockSession:
    authenticated = True

    def __init__(self):
        self.heartbeats = []
        self.fail = False
        self.offset = 0
        self.closed = False

    def exchange_clock(self):
        if self.fail:
            raise ConnectionError("synthetic outage")
        return ClockExchange(100, 50, 100.1 + self.offset, 100.1 + self.offset, 100.2, 50.2)

    def send_heartbeat(self, heartbeat):
        if self.fail:
            raise ConnectionError("synthetic outage")
        self.heartbeats.append(heartbeat)

    def close(self):
        self.closed = True
