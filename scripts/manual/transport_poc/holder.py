"""Capture-host camera holder: one process owns the real cameras (manual only).

The holder runs the product Agent ``UvcCapture`` (Owner-approved identity,
sandboxed ``GStreamerLauncher``, video capture node only, never ``/dev/snd``)
in a throwaway runtime root and hands each compressed frame, in memory, to
one local sender over a unix socket inside a private (0700) directory. No
frame is written to disk; the socket file is the only filesystem entry.

Frames on the socket: ``uint8 source_index, uint64 capture_ns, uint32 length``
then ``length`` JPEG bytes. ``capture_ns`` is this host's CLOCK_MONOTONIC when
the frame left the capture queue, the same clock the sender and the local
impairment proxy use. A slow sender only causes counted drop-oldest drops in
the product ``FrameQueue``; the holder never buffers beyond it.

Stand-in Owner approval: ``--approve`` binds sources 0..N-1 to the currently
discovered cameras in a stable order (by hashed identity) through
``UvcCapture.approve``, exactly like ``scripts/manual/uvc_watch.py``. Output is
numeric JSONL only (counts, fps, drops, CPU, RSS): no serial, path or port.
"""
import hashlib
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

from . import materials, records

FRAME_HEADER = struct.Struct(">BQI")
MAX_FRAME_BYTES = 8 * 1024 * 1024


def read_frames(connection, deliver, stop):
    """Sender side: parse holder frames from a unix socket until EOF/stop."""
    buffer = bytearray()
    connection.settimeout(0.5)
    while not stop.is_set():
        try:
            data = connection.recv(1 << 20)
        except socket.timeout:
            continue
        if not data:
            return
        buffer += data
        while len(buffer) >= FRAME_HEADER.size:
            index, capture_ns, length = FRAME_HEADER.unpack_from(buffer)
            if length > MAX_FRAME_BYTES:
                raise ValueError("holder frame exceeds bound")
            if len(buffer) < FRAME_HEADER.size + length:
                break
            payload = bytes(buffer[FRAME_HEADER.size:FRAME_HEADER.size + length])
            del buffer[:FRAME_HEADER.size + length]
            deliver(index, capture_ns, payload)


def encode_frame(index, capture_ns, payload):
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("frame exceeds bound")
    return FRAME_HEADER.pack(index, capture_ns, len(payload)) + payload


def checkout_helper_trust(path):
    """Development-checkout sandbox helper: accept it only if this user owns it
    and nobody else can write it or its parents (MANUAL_TEST §B precedent).

    Used only with the explicit ``--dev-checkout-helper`` flag; the GStreamer
    executable and plugins still require root control.
    """
    from media_capture_agent.uvc_pipeline import PipelineError
    path = Path(path).resolve(strict=True)
    for candidate in (path, *path.parents):
        info = os.stat(candidate)
        if candidate == path and info.st_uid != os.geteuid():
            raise PipelineError("sandbox helper is not owned by this user")
        if info.st_mode & 0o022:
            raise PipelineError("sandbox helper is writable by others")
        if info.st_uid not in (0, os.geteuid()):
            raise PipelineError("sandbox helper parent has a foreign owner")
    return path


def _dev_trust(path):
    """Root-controlled check for everything except the checkout sandbox helper."""
    from media_capture_agent.uvc_pipeline import SANDBOX_HELPER, require_trusted_file
    if Path(path).resolve() == Path(SANDBOX_HELPER).resolve():
        return checkout_helper_trust(path)
    return require_trusted_file(path)


def build_capture(state_dir, n_sources, profile, *, gst, dev_checkout_helper, **inject):
    from media_capture_agent.uvc_capture import UvcCapture, UvcSourceConfig
    from media_capture_agent.uvc_pipeline import (GStreamerLauncher, require_trusted_file)
    if "launcher" not in inject:
        inject["launcher"] = GStreamerLauncher(
            gst, trust_file=_dev_trust if dev_checkout_helper else require_trusted_file)
    settings = SimpleNamespace(runtime_root=Path(state_dir), service_uid=os.geteuid())
    sources = [UvcSourceConfig(uuid4(), profile) for _ in range(n_sources)]
    return UvcCapture(settings, sources, **inject), [source.source_id for source in sources]


def _identity_key(device):
    return hashlib.sha256("\0".join((device.vendor, device.product, device.serial or "",
                                      device.interface)).encode()).hexdigest()


def approve_all(capture, source_ids):
    """Bind each source to a distinct current candidate (stable hashed order).

    Refuses (nothing approved) when any candidate lacks a serial or two share
    an identity: an ambiguous identical camera is never bound automatically,
    not even by this stand-in Owner approval.
    """
    candidates = list(capture.candidates(source_ids[0]))
    keys = [_identity_key(device) for device in candidates]
    if any(not device.serial for device in candidates) or len(set(keys)) != len(keys):
        raise SystemExit("ambiguous camera identity: approve manually, not with --approve")
    candidates = [device for _, device in sorted(zip(keys, candidates), key=lambda x: x[0])]
    if len(candidates) < len(source_ids):
        raise SystemExit("fewer cameras than requested sources")
    for source, candidate in zip(source_ids, candidates):
        capture.approve(source, candidate)


class Holder:
    def __init__(self, capture, source_ids, socket_dir, writer, *, fps=None):
        self.capture = capture
        self.source_ids = source_ids
        self.fps = fps  # camera profile rate, recorded for the summarizer
        self.writer = writer
        self.stop = threading.Event()
        directory = materials.private_directory(socket_dir, exist_ok=True)
        self.path = directory / "frames.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            self.listener.bind(str(self.path))
        finally:
            os.umask(old)
        self.listener.listen(1)
        self.client = None
        self.frames = [0] * len(source_ids)
        self.forward_drops = 0

    def run(self, seconds):
        deadline = time.monotonic() + seconds
        self.listener.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(self.listener, selectors.EVENT_READ)
        next_poll = next_sample = 0.0
        cpu0 = records.process_cpu_seconds()
        self.writer.write("start", sources=len(self.source_ids), fps=self.fps)
        try:
            while not self.stop.is_set() and time.monotonic() < deadline:
                now = time.monotonic()
                if now >= next_poll:
                    self.capture.poll()
                    next_poll = now + 0.5
                for _key, _ in selector.select(timeout=0):
                    connection, _ = self.listener.accept()
                    if self.client is not None:
                        connection.close()  # exactly one local sender
                    else:
                        connection.setblocking(True)
                        connection.settimeout(1.0)
                        self.client = connection
                for index, source in enumerate(self.source_ids):
                    frame = self.capture.frames(source).get(0.005)
                    if frame is None:
                        continue
                    self.frames[index] += 1
                    if self.client is not None:
                        try:
                            self.client.sendall(encode_frame(index, int(
                                frame.received_monotonic * 1e9), frame.data))
                        except OSError:
                            self.client.close()
                            self.client = None
                            self.forward_drops += 1
                if now >= next_sample:
                    next_sample = now + 1.0
                    rss, hwm = records.process_memory()
                    drops = sum(self.capture.frames(source).drop_stats()[0]
                                for source in self.source_ids)
                    self.writer.write("sample", frames=sum(self.frames), queue_drops=drops,
                                      forward_drops=self.forward_drops,
                                      cpu_seconds=records.process_cpu_seconds() - cpu0,
                                      child_cpu_seconds=records.descendant_cpu_seconds(),
                                      rss_bytes=rss, hwm_bytes=hwm,
                                      client=self.client is not None)
        finally:
            self.close()

    def close(self):
        if self.client is not None:
            self.client.close()
        self.listener.close()
        try:
            self.path.unlink()
        except OSError:
            pass
        self.capture.close()
        self.writer.write("end", frames=sum(self.frames))


def run(args, writer):
    from media_capture_agent.uvc_pipeline import MjpegProfile
    width, height, fps = args.profile
    state = materials.private_directory(args.state_dir, exist_ok=True)
    capture, source_ids = build_capture(state, args.sources, MjpegProfile(width, height, fps),
                                        gst=args.gst, dev_checkout_helper=args.dev_checkout_helper)
    if args.approve:
        approve_all(capture, source_ids)
    holder = Holder(capture, source_ids, args.socket_dir, writer, fps=fps)
    signal.signal(signal.SIGTERM, lambda *_: holder.stop.set())
    holder.run(args.seconds)
    return 0
