"""Synthetic resource harness for the transport-neutral profile pipeline.

Runs 1-4 generated compressed-packet streams through ``SourcePipeline`` with
in-process synthetic adapters and reports process CPU time, resident memory
and per-path queue depth. It never opens a camera, codec, device, network
socket or file, and it prints no hostname, user, path, environment value,
source identity or media content. Results describe only this synthetic
scheduler workload: they are not deployment defaults and do not measure real
codec, camera, GPU or LAN cost (see ``MANUAL_TEST.md`` C / R).

Run from ``server/``::

    python -m app.media.profiles.measure --sources 2 --packets 3000 \\
        --packet-bytes 4096 --keyframe-interval 30 --viewers 1 \\
        --queue-packets 64 --queue-bytes 1048576 --pump-every 1 \\
        --pump-budget 4 --acceleration prefer_hardware
"""

import argparse
from dataclasses import dataclass, replace
from fractions import Fraction
import hashlib
import json
import os
import platform
import sys
import time
from uuid import UUID

from .adapters import AccelerationPolicy, AdapterCandidate, AdapterKind, AdapterSelector
from .model import (
    CaptureProfile, CompressedPacket, InferenceProfile, QueueLimits,
    RecordingProfile, SourceProfiles, VideoFormat, ViewerProfile,
)
from .pipeline import SourcePipeline

_MAX_PACKETS = 200_000
_MAX_PACKET_BYTES = 1 << 20
_MAX_QUEUE_PACKETS = 10_000
_MAX_QUEUE_BYTES = 256 << 20
_MAX_VIEWERS = 16
_MAX_PUMP = 10_000
# Exact fraction arithmetic in the sampler; the synthetic clock stays fixed.
_TIME_BASE = Fraction(1, 30)


def _bounded(value: int, low: int, high: int, name: str) -> None:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer from {low} to {high}")


@dataclass(frozen=True)
class MeasureConfig:
    sources: int
    packets: int
    packet_bytes: int
    keyframe_interval: int
    viewers: int
    queue_packets: int
    queue_bytes: int
    pump_every: int
    pump_budget: int
    acceleration: AccelerationPolicy

    def __post_init__(self) -> None:
        _bounded(self.sources, 1, 4, "sources")
        _bounded(self.packets, 1, _MAX_PACKETS, "packets")
        _bounded(self.packet_bytes, 1, _MAX_PACKET_BYTES, "packet_bytes")
        _bounded(self.keyframe_interval, 1, _MAX_PACKETS, "keyframe_interval")
        _bounded(self.viewers, 0, _MAX_VIEWERS, "viewers")
        _bounded(self.queue_packets, 1, _MAX_QUEUE_PACKETS, "queue_packets")
        _bounded(self.queue_bytes, 1, _MAX_QUEUE_BYTES, "queue_bytes")
        _bounded(self.pump_every, 1, _MAX_PACKETS, "pump_every")
        _bounded(self.pump_budget, 1, _MAX_PUMP, "pump_budget")
        if not isinstance(self.acceleration, AccelerationPolicy):
            raise ValueError("acceleration must be an explicit policy")


class _DiscardAdapter:
    """Accepts packets and keeps only counters; no media is retained."""

    def __init__(self) -> None:
        self.written = 0
        self.closed = False

    def write(self, packet: CompressedPacket) -> None:
        if self.closed:
            raise RuntimeError()
        self.written += 1

    def reset(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def _software_candidate() -> AdapterCandidate:
    # Only a synthetic software adapter exists here. No hardware candidate is
    # registered, so the harness never probes a real accelerator.
    return AdapterCandidate("synthetic_software", AdapterKind.SOFTWARE,
                            lambda plan: True, lambda plan: _DiscardAdapter())


def _profiles() -> SourceProfiles:
    # Generated descriptor; numbers are synthetic stimulus, not defaults.
    format_ = VideoFormat(
        width=1920, height=1080, fps=Fraction(30), time_base=_TIME_BASE,
        maximum_bitrate=8_000_000, codec="synthetic", codec_profile="fixture",
        container="synthetic-packets", pixel_format="fixture", color_space="fixture",
        configuration_sha256=hashlib.sha256(b"synthetic harness config").hexdigest(),
        verified=True, video_only=True,
    )
    viewer = replace(format_, width=1280, height=720)
    return SourceProfiles(CaptureProfile(format_, Fraction(2)), RecordingProfile(format_),
                          InferenceProfile(640, 360, Fraction(5), Fraction(2)),
                          ViewerProfile(viewer))


def _rss_bytes() -> int | None:
    """Current resident set size, or None when not observable (never 0)."""
    try:
        with open("/proc/self/statm", "rb") as handle:
            fields = handle.read(128).split()
        return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


class _Depth:
    def __init__(self) -> None:
        self.maximum_packets = 0
        self.maximum_bytes = 0

    def observe(self, status) -> None:
        if status is None:
            return
        self.maximum_packets = max(self.maximum_packets, status.queued_packets)
        self.maximum_bytes = max(self.maximum_bytes, status.queued_bytes)


def _path_summary(status, depth: _Depth, delivered: int) -> dict | None:
    if status is None:
        return None
    return {
        "available": status.available,
        "failed": status.failed,
        "reason": status.reason,
        "adapter_state": status.adapter_state,
        "delivered_packets": delivered,
        "dropped_packets": status.dropped_packets,
        "skipped_until_keyframe": status.skipped_until_keyframe,
        "discontinuities": status.discontinuities,
        "maximum_queued_packets": depth.maximum_packets,
        "maximum_queued_bytes": depth.maximum_bytes,
        "final_queued_packets": status.queued_packets,
    }


def run_measurement(config: MeasureConfig) -> dict:
    if not isinstance(config, MeasureConfig):
        raise ValueError("invalid measurement config")
    limits = QueueLimits(config.queue_packets, config.queue_bytes)
    payload = bytes(config.packet_bytes)  # one shared zero buffer; no media
    profiles = _profiles()
    recording_selector = AdapterSelector(config.acceleration, (_software_candidate(),))
    viewer_selector = AdapterSelector(config.acceleration, (_software_candidate(),))
    pipelines = []
    for index in range(config.sources):
        # Synthetic identities never leave this function.
        source = SourcePipeline(UUID(int=2 * index + 1), UUID(int=2 * index + 2),
                                profiles, limits, limits,
                                recording_selector, viewer_selector)
        for viewer in range(config.viewers):
            source.add_viewer(UUID(int=1_000 + viewer))
        pipelines.append(source)
    recording_depth = [_Depth() for _ in pipelines]
    viewer_depth = [_Depth() for _ in pipelines]
    delivered = [[0, 0] for _ in pipelines]
    samples = [0 for _ in pipelines]
    rss_before = _rss_bytes()
    rss_peak = rss_before
    rss_interval = max(1, config.packets // 64)
    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    try:
        for sequence in range(config.packets):
            keyframe = sequence % config.keyframe_interval == 0
            for index, source in enumerate(pipelines):
                source.offer(CompressedPacket(
                    source.source_id, source.stream_id, sequence, sequence, sequence,
                    _TIME_BASE, keyframe, payload))
                if source.inference.select(source.stream_id, sequence, _TIME_BASE).emit:
                    samples[index] += 1
                recording_depth[index].observe(source.recording_status)
                viewer_depth[index].observe(source.viewer_status)
                if (sequence + 1) % config.pump_every == 0:
                    written = source.pump(config.pump_budget)
                    delivered[index][0] += written[0]
                    delivered[index][1] += written[1]
            if sequence % rss_interval == 0:
                current = _rss_bytes()
                if current is None or rss_peak is None:
                    rss_peak = None
                else:
                    rss_peak = max(rss_peak, current)
        cpu_seconds = time.process_time() - cpu_start
        wall_seconds = time.perf_counter() - wall_start
        rss_after = _rss_bytes()
        if rss_after is None or rss_peak is None:
            rss_peak = None
        else:
            rss_peak = max(rss_peak, rss_after)
        statuses = [source.status for source in pipelines]
        # One selector serves every source here; report the selections of the
        # adapters that were active at the end, never one shared last result.
        active = (recording_selector.active_selections
                  + viewer_selector.active_selections)
    finally:
        for source in pipelines:
            source.close()
    sources = []
    for index, status in enumerate(statuses):
        sources.append({
            "index": index,
            "state": status.state,
            "reasons": list(status.reasons),
            "recording": _path_summary(status.recording, recording_depth[index],
                                       delivered[index][0]),
            "viewer": _path_summary(status.viewer, viewer_depth[index],
                                    delivered[index][1]),
            "inference_samples": samples[index],
        })
    return {
        "workload": "generated zero-byte compressed packets; synthetic adapters only",
        "deployment_acceptance": False,
        "python": ".".join(platform.python_version_tuple()[:2]),
        "config": {
            "sources": config.sources,
            "packets_per_source": config.packets,
            "packet_bytes": config.packet_bytes,
            "keyframe_interval": config.keyframe_interval,
            "viewers": config.viewers,
            "queue_packets": config.queue_packets,
            "queue_bytes": config.queue_bytes,
            "pump_every": config.pump_every,
            "pump_budget": config.pump_budget,
            "acceleration": config.acceleration.value,
        },
        "adapter_selection": {
            "active_paths": len(active),
            "fallback_paths": sum(1 for value in active if value.fallback),
            "states": sorted({value.state for value in active}),
            "kinds": sorted({value.kind.value for value in active}),
            "reasons": sorted({reason for value in active for reason in value.reasons}),
        },
        "resources": {
            "cpu_seconds": round(cpu_seconds, 6),
            "wall_seconds": round(wall_seconds, 6),
            "rss_before_bytes": rss_before,
            "rss_peak_sampled_bytes": rss_peak,
            "rss_observable": rss_before is not None and rss_peak is not None,
        },
        "sources": sources,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.media.profiles.measure",
        description="Synthetic profile-pipeline CPU/RSS/queue-depth harness.")
    for name in ("sources", "packets", "packet-bytes", "keyframe-interval", "viewers",
                 "queue-packets", "queue-bytes", "pump-every", "pump-budget"):
        parser.add_argument(f"--{name}", type=int, required=True)
    parser.add_argument("--acceleration", required=True,
                        choices=[value.value for value in AccelerationPolicy])
    return parser


def main(argv: list[str] | None = None) -> int:
    """Exit 0 when every source stayed available, 3 when any was unavailable."""
    parser = _parser()
    arguments = vars(parser.parse_args(argv))
    arguments["acceleration"] = AccelerationPolicy(arguments["acceleration"])
    try:
        config = MeasureConfig(**arguments)
    except ValueError as error:
        parser.error(str(error))
    result = run_measurement(config)
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    unavailable = any(source["state"] == "unavailable" for source in result["sources"])
    return 3 if unavailable else 0


if __name__ == "__main__":
    raise SystemExit(main())
