"""Bounded, scheduler-driven compressed-packet fanout with demand lifetimes.

This module owns no threads or network routes. Its methods run on one owning
scheduler thread. Codec adapters must perform bounded, nonblocking work; a real
codec process and its supervision are a separate integration requirement.
"""

from collections import deque
from dataclasses import dataclass, replace
from typing import Callable, Protocol
from uuid import UUID

from .model import (
    CompressedPacket, InferenceProfile, QueueLimits, SourceProfiles, ViewerProfile,
)
from .planner import EncodePlan, plan_encoding
from .sampling import InferenceSampler


class AdapterUnavailable(Exception):
    """No audited codec/container adapter can satisfy the requested plan."""


class PacketAdapter(Protocol):
    """An adapter receives every admitted packet in decode order.

    write must complete without blocking, or raise before accepting a packet.
    reset discards codec dependency state and starts a new discontinuous segment;
    close releases processes, buffers and handles, including after write failure.
    An adapter must validate its supported plan rather than treating construction
    as evidence that transcode/stream-copy is available.
    """

    def write(self, packet: CompressedPacket) -> None:
        ...

    def reset(self) -> None:
        ...

    def close(self) -> None:
        ...


AdapterFactory = Callable[[EncodePlan], PacketAdapter]


@dataclass(frozen=True)
class PathStatus:
    active: bool
    available: bool
    failed: bool
    queued_packets: int
    queued_bytes: int
    dropped_packets: int
    skipped_until_keyframe: int
    discontinuities: int
    awaiting_keyframe: bool
    reason: str

    @property
    def healthy(self) -> bool:
        return (self.active and self.available and not self.failed
                and not self.dropped_packets and not self.discontinuities
                and not self.awaiting_keyframe)


class _PacketPath:
    def __init__(self, plan: EncodePlan, factory: AdapterFactory | None,
                 limits: QueueLimits, previous_status: PathStatus | None = None):
        self.plan = plan
        self.limits = limits
        self._queue: deque[CompressedPacket] = deque()
        self._bytes = 0
        # Adapters may be replaced within one stream generation. Resource
        # recovery must not erase that generation's observed media loss.
        self._dropped = previous_status.dropped_packets if previous_status else 0
        self._skipped = previous_status.skipped_until_keyframe if previous_status else 0
        self._discontinuities = previous_status.discontinuities if previous_status else 0
        self._awaiting_keyframe = True
        self._closed = False
        self._failed = False
        self._reason = ("prior_viewer_loss" if self._dropped or self._discontinuities
                        else "awaiting_keyframe")
        self._adapter: PacketAdapter | None = None
        if factory is None:
            self._reason = "adapter_unavailable"
        else:
            try:
                self._adapter = factory(plan)
                if self._adapter is None:
                    raise AdapterUnavailable()
            except AdapterUnavailable:
                self._reason = "adapter_unavailable"
            except Exception:
                # Never expose backend exception text, paths or media content.
                self._reason = "adapter_start_failed"
                self._failed = True

    def offer(self, packet: CompressedPacket) -> bool:
        if self._closed or self._adapter is None or self._failed:
            self._dropped += 1
            return False
        if len(packet.data) > self.limits.maximum_bytes:
            self.discontinuity("packet_exceeds_byte_limit")
            self._dropped += 1
            return False
        if (len(self._queue) >= self.limits.maximum_packets
                or self._bytes + len(packet.data) > self.limits.maximum_bytes):
            self.discontinuity("backpressure")
        if self._failed:
            self._dropped += 1
            return False
        if self._awaiting_keyframe and not packet.keyframe:
            if self._discontinuities:
                self._dropped += 1
            else:
                # Joining between keyframes is normal; no viewer output was
                # promised before its first decodable frame.
                self._skipped += 1
            return False
        self._awaiting_keyframe = False
        self._queue.append(packet)
        self._bytes += len(packet.data)
        if self._reason == "awaiting_keyframe":
            self._reason = "ready"
        return True

    def pump(self, maximum_packets: int) -> int:
        count = 0
        while self._queue and count < maximum_packets and not self._failed:
            packet = self._queue.popleft()
            self._bytes -= len(packet.data)
            try:
                self._adapter.write(packet)
            except Exception:
                self._dropped += 1
                self._fail("adapter_write_failed")
                break
            count += 1
        return count

    def discontinuity(self, reason: str) -> None:
        self._dropped += len(self._queue)
        self._queue.clear()
        self._bytes = 0
        self._discontinuities += 1
        self._awaiting_keyframe = True
        self._reason = reason
        if self._adapter is not None and not self._failed:
            try:
                self._adapter.reset()
            except Exception:
                self._fail("adapter_reset_failed")

    def _fail(self, reason: str) -> None:
        self._failed = True
        self._reason = reason
        self._dropped += len(self._queue)
        self._queue.clear()
        self._bytes = 0
        self._release_adapter()

    def _release_adapter(self) -> None:
        adapter = self._adapter
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                self._failed = True
                self._reason = "adapter_close_failed"
            else:
                self._adapter = None

    def close(self) -> None:
        if self._closed:
            self._release_adapter()
            return
        self._closed = True
        self._dropped += len(self._queue)
        self._queue.clear()
        self._bytes = 0
        self._release_adapter()
        if not self._failed:
            self._reason = "closed"

    @property
    def status(self) -> PathStatus:
        return PathStatus(not self._closed, self._adapter is not None,
                          self._failed, len(self._queue), self._bytes,
                          self._dropped, self._skipped, self._discontinuities,
                          self._awaiting_keyframe, self._reason)


@dataclass(frozen=True)
class OfferResult:
    recording_queued: bool
    viewer_queued: bool
    reason: str


class SourcePipeline:
    """One logical source and one negotiated stream generation.

    Callers supply explicitly bounded queues and codec adapters. Missing adapters
    fail closed as unavailable. Capture/recording renegotiation requires closing
    this generation and constructing another; viewer and inference changes never
    alter durable-recording settings. Subscription methods are internal and do
    not provide human authorization or imply that a live route is exposed.
    """

    def __init__(self, source_id: UUID, stream_id: UUID, profiles: SourceProfiles,
                 recording_limits: QueueLimits, viewer_limits: QueueLimits,
                 recording_factory: AdapterFactory | None = None,
                 viewer_factory: AdapterFactory | None = None):
        if not isinstance(source_id, UUID) or not isinstance(stream_id, UUID):
            raise ValueError("source and stream identities must be UUIDs")
        if not profiles.capture.format.verified or not profiles.capture.format.video_only:
            raise ValueError("capture must be verified as video-only before ingest")
        if not profiles.recording.format.video_only or not profiles.viewer.format.video_only:
            raise ValueError("recording and viewer output must be video-only")
        self.source_id = source_id
        self.stream_id = stream_id
        self._profiles = profiles
        self._viewer_limits = viewer_limits
        self._viewer_factory = viewer_factory
        self._viewers: set[UUID] = set()
        self._viewer: _PacketPath | None = None
        self._last_viewer_status: PathStatus | None = None
        self._recording = _PacketPath(self.recording_plan, recording_factory,
                                      recording_limits)
        self.inference = InferenceSampler(profiles.inference, stream_id)
        self._sequence: int | None = None
        self._dts: int | None = None
        self._renegotiation_required = False
        self._closed = False

    @property
    def profiles(self) -> SourceProfiles:
        return self._profiles

    @property
    def recording_plan(self) -> EncodePlan:
        return plan_encoding(self._profiles.capture.format, self._profiles.recording.format)

    @property
    def viewer_plan(self) -> EncodePlan:
        return plan_encoding(self._profiles.capture.format, self._profiles.viewer.format)

    @property
    def recording_status(self) -> PathStatus:
        return self._recording.status

    @property
    def viewer_status(self) -> PathStatus | None:
        return self._viewer.status if self._viewer else self._last_viewer_status

    @property
    def subscriber_count(self) -> int:
        return len(self._viewers)

    def add_viewer(self, subscriber_id: UUID) -> None:
        self._ensure_open()
        if not isinstance(subscriber_id, UUID):
            raise ValueError("subscriber_id must be a UUID")
        if not self._viewers:
            self._start_viewer()
        self._viewers.add(subscriber_id)

    def remove_viewer(self, subscriber_id: UUID) -> None:
        self._viewers.discard(subscriber_id)
        if not self._viewers:
            self._close_viewer()

    def replace_viewer_profile(self, profile: ViewerProfile) -> None:
        self._ensure_open()
        if not profile.format.video_only:
            raise ValueError("viewer output must be video-only")
        if self._profiles.viewer == profile:
            return
        self._close_viewer()
        self._profiles = replace(self._profiles, viewer=profile)
        if self._viewers:
            self._start_viewer()

    def replace_inference_profile(self, profile: InferenceProfile) -> None:
        self._ensure_open()
        self.inference.replace_profile(profile)
        self._profiles = replace(self._profiles, inference=profile)

    def offer(self, packet: CompressedPacket) -> OfferResult:
        self._ensure_open()
        if packet.source_id != self.source_id or packet.stream_id != self.stream_id:
            return OfferResult(False, False, "foreign_source_or_stream")
        if self._sequence is not None and packet.sequence <= self._sequence:
            return OfferResult(False, False, "stale_or_duplicate_packet")
        if self._renegotiation_required:
            return OfferResult(False, False, "renegotiation_required")
        if packet.time_base != self._profiles.capture.format.time_base:
            self._renegotiation_required = True
            self._discontinuity("time_base_changed")
            return OfferResult(False, False, "renegotiation_required")
        reason = "accepted"
        if self._sequence is not None and packet.sequence != self._sequence + 1:
            reason = "sequence_gap"
        elif self._dts is not None and packet.dts < self._dts:
            reason = "decode_timestamp_reset"
        elif (self._dts is not None
              and (packet.dts - self._dts) * packet.time_base
              > self._profiles.capture.maximum_timestamp_gap):
            reason = "decode_timestamp_gap"
        if reason != "accepted":
            self._discontinuity(reason)
        self._sequence = packet.sequence
        self._dts = packet.dts
        return OfferResult(self._recording.offer(packet),
                           self._viewer.offer(packet) if self._viewer else False,
                           reason)

    def pump(self, maximum_packets_per_path: int) -> tuple[int, int]:
        self._ensure_open()
        if type(maximum_packets_per_path) is not int or maximum_packets_per_path <= 0:
            raise ValueError("pump budget must be a positive integer")
        recording = self._recording.pump(maximum_packets_per_path)
        viewer = self._viewer.pump(maximum_packets_per_path) if self._viewer else 0
        return recording, viewer

    def _discontinuity(self, reason: str) -> None:
        self._recording.discontinuity(reason)
        if self._viewer:
            self._viewer.discontinuity(reason)

    def _close_viewer(self) -> None:
        if self._viewer:
            self._viewer.close()
            self._last_viewer_status = self._viewer.status
            if not self._last_viewer_status.available:
                self._viewer = None

    def _start_viewer(self) -> None:
        # Failed cleanup may leave a codec process alive. Keep the failed path
        # visible and never open another until its resources are released.
        if self._viewer is None:
            self._viewer = _PacketPath(self.viewer_plan, self._viewer_factory,
                                       self._viewer_limits, self._last_viewer_status)

    def close(self) -> None:
        if self._closed:
            self._recording.close()
            self._close_viewer()
            return
        self._closed = True
        self._recording.close()
        self._close_viewer()
        self._viewers.clear()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("pipeline is closed")
