"""Deterministic adapters for mock E2E tests.

The harness owns clocks and faults only. Product state transitions remain in
the production cores exercised by the scenario tests.
"""

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import os
from pathlib import Path
from uuid import UUID

from app.cameras.registry import SourceHealthState, SourceType
from app.integrity.model import Component, Inventory, Kind as IntegrityKind
from app.media.health.service import PipelineStatus
from media_capture_agent.config import Settings
from media_capture_agent.storage import descriptor_mount_id, open_directory, read_mounts


@dataclass
class SyntheticClock:
    """Independently controlled wall and monotonic clocks."""

    wall: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    steady: float = 0.0

    def __post_init__(self):
        if self.wall.tzinfo is None or self.wall.utcoffset() is None:
            raise ValueError("aware synthetic wall clock required")
        if not math.isfinite(self.steady) or self.steady < 0:
            raise ValueError("valid synthetic monotonic clock required")
        self.wall = self.wall.astimezone(timezone.utc)

    def utcnow(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.steady

    def now_us(self) -> int:
        return int(self.wall.timestamp() * 1_000_000)

    def advance(self, seconds: float, *, wall: bool = True, monotonic: bool = True) -> None:
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("non-negative finite advance required")
        if wall:
            self.wall += timedelta(seconds=seconds)
        if monotonic:
            self.steady += seconds

    def shift_wall(self, seconds: float) -> None:
        """Move only UTC, including backwards, to model skew or correction."""
        if not math.isfinite(seconds):
            raise ValueError("finite wall-clock shift required")
        self.wall += timedelta(seconds=seconds)


@dataclass(frozen=True)
class SyntheticSource:
    source_id: UUID
    source_type: SourceType
    node_id: UUID | None


class MixedSourceTopology:
    """A bounded source inventory whose node and camera health never alias."""

    def __init__(self, count: int):
        if type(count) is not int or not 1 <= count <= 4:
            raise ValueError("mock E2E source count must be between one and four")
        self.sources = tuple(
            SyntheticSource(
                UUID(int=100 + index),
                SourceType.LOCAL_UVC if index % 2 == 0 else SourceType.REMOTE_AGENT,
                None if index % 2 == 0 else UUID(int=200 + index),
            )
            for index in range(count)
        )
        self.source_health = {
            item.source_id: SourceHealthState.ONLINE for item in self.sources
        }
        self.node_health = {
            item.node_id: "online" for item in self.sources if item.node_id is not None
        }

    def set_source_health(self, source_id: UUID, state: SourceHealthState) -> None:
        if source_id not in self.source_health or not isinstance(state, SourceHealthState):
            raise ValueError("unknown source or invalid source health")
        self.source_health[source_id] = state

    def set_node_health(self, node_id: UUID, state: str) -> None:
        if node_id not in self.node_health or state not in {"online", "degraded", "offline", "revoked"}:
            raise ValueError("unknown node or invalid node health")
        self.node_health[node_id] = state


class FaultPlan:
    """Finite, named failures consumed at explicit adapter boundaries."""

    ALLOWED = frozenset({
        "integrity.collect", "recording.cleanup", "recording.pipeline",
        "recording.storage", "recording.write", "recording.decode",
        "recording.device_health",
    })

    def __init__(self):
        self._remaining: dict[str, int] = {}

    def arm(self, name: str, *, times: int = 1) -> None:
        if name not in self.ALLOWED or type(times) is not int or not 1 <= times <= 100:
            raise ValueError("invalid synthetic fault")
        self._remaining[name] = times

    def trip(self, name: str) -> bool:
        if name not in self.ALLOWED:
            raise ValueError("invalid synthetic fault")
        remaining = self._remaining.get(name, 0)
        if remaining == 0:
            return False
        if remaining == 1:
            self._remaining.pop(name)
        else:
            self._remaining[name] = remaining - 1
        return True


class SyntheticIntegrityProbe:
    def __init__(self, faults: FaultPlan):
        self.faults = faults
        self.inventory = Inventory((Component(
            IntegrityKind.STORAGE, "synthetic-slot", (("capacity_bytes", "1048576"),),
            (("serial", "synthetic-storage-a"),),
        ),))

    def collect(self) -> Inventory:
        if self.faults.trip("integrity.collect"):
            raise OSError("synthetic integrity probe unavailable")
        return self.inventory


class SyntheticRecorder:
    """No media bytes: it exposes stage boundaries to RecordingHealthService."""

    def __init__(self, topology: MixedSourceTopology, faults: FaultPlan):
        self.topology, self.faults = topology, faults
        self.leftover = False

    def _fail(self, stage: str) -> None:
        if self.faults.trip(f"recording.{stage}"):
            raise OSError("synthetic recorder fault")

    def cleanup(self) -> None:
        self._fail("cleanup")
        self.leftover = False

    def pipeline_status(self) -> PipelineStatus:
        self._fail("pipeline")
        fresh = tuple(
            self.topology.source_health[item.source_id] == SourceHealthState.ONLINE
            for item in self.topology.sources
        )
        return PipelineStatus(fresh, True, True)

    def check_storage(self) -> None:
        self._fail("storage")

    def write_test_segment(self) -> None:
        self._fail("write")
        self.leftover = True

    def reopen_and_decode(self) -> None:
        self._fail("decode")

    def storage_health(self) -> tuple[str, ...]:
        if self.faults.trip("recording.device_health"):
            return ("CRITICAL",)
        return ("OK",)


class AllowRingControls:
    def require_owner(self, _operation: str) -> None:
        pass

    def require_preserve(self) -> None:
        pass


class SyntheticAccess:
    owner_id = UUID(int=999)

    def require_owner(self, context) -> UUID:
        if context != "owner":
            raise PermissionError("not found")
        return self.owner_id

    def require_recordings(self, context) -> None:
        if context not in {"owner", "recordings"}:
            raise PermissionError("not found")


def storage_reservation():
    return nullcontext()


def agent_settings(root: Path, node_id: UUID) -> Settings:
    """Build protected-path settings from an ephemeral local filesystem."""
    media, runtime = root / "media", root / "state"
    root.mkdir(mode=0o700)
    media.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    descriptor = open_directory(media)
    try:
        mount_id = descriptor_mount_id(descriptor)
        mount = next(item.identity for item in read_mounts() if item.mount_id == mount_id)
    finally:
        os.close(descriptor)
    return Settings.parse({
        "node_id": str(node_id), "media_root": str(media), "runtime_root": str(runtime),
        "expected_mount": {
            "mount_point": str(mount.mount_point), "filesystem": mount.filesystem,
            "source": mount.source, "major": mount.major, "minor": mount.minor,
            "filesystem_root": str(mount.filesystem_root),
            "filesystem_uuid": "synthetic-filesystem-identity",
        },
        "service_uid": os.geteuid(), "safety_reserve_bytes": 4096,
        "max_segment_bytes": 16384, "heartbeat_seconds": 1,
        "clock_offset_limit_seconds": 2, "clock_uncertainty_limit_seconds": 0.5,
        "clock_step_limit_seconds": 0.1,
    }, code_root=root / "code")
