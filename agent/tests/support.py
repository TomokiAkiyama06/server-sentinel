"""Ephemeral private directories and synthetic capture/transport implementations."""

import os
from pathlib import Path
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
                           "filesystem_root": str(mount.filesystem_root)},
        "service_uid": os.geteuid(), "safety_reserve_bytes": 4096, "max_segment_bytes": 16384,
        "heartbeat_seconds": 0.01, "clock_offset_limit_seconds": 2,
        "clock_uncertainty_limit_seconds": 0.5, "clock_step_limit_seconds": 0.1,
    }


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
