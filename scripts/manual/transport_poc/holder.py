"""Capture-host camera holder: one process owns the real cameras (manual only).

The holder runs the product Agent ``UvcCapture`` (Owner-approved identity,
sandboxed ``GStreamerLauncher``, video capture node only, never ``/dev/snd``)
in a throwaway runtime root and hands each compressed frame, in memory, to
one local sender over a unix socket inside a private (0700) directory. No
frame is written to disk; the socket file is the only filesystem entry.

Session identity: a connecting sender first writes its 8-byte start nonce
(``HELLO``). The holder records ``session_open`` / ``session_close`` with that
nonce and, at the close, one ``forwarded`` record per source (frames whose
``sendall`` completed on that session). The summarizer accepts a real-input
sender epoch only when this holder's session with the sender's own nonce
forwarded at least, and at most ``HOLDER_INFLIGHT_SLACK`` more than, the
units the sender generated: a concurrently running holder of another sender
cannot vouch for it.

One session at a time: a sender sends nothing after its ``HELLO``, so the
holder watches the session socket and closes the session as soon as it reads
EOF (or anything else), without waiting for a frame whose ``sendall`` fails.
A connection that arrives while a session is open is served only if that
session's sender has already gone; otherwise it is closed and recorded as
``refused`` (``connection_limit``). Before this, a sender restarted while the
camera delivered no frame was refused by its predecessor's stale session
(#307).

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
import select
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
HELLO = struct.Struct(">Q")
MAX_FRAME_BYTES = 8 * 1024 * 1024
DEFAULT_GST = "/usr/bin/gst-launch-1.0"


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


def send_hello(connection, nonce):
    """Sender side: identify this sender execution to the holder."""
    if not 0 < nonce < 1 << 63:
        raise ValueError("holder nonce out of range")
    connection.sendall(HELLO.pack(nonce))


def read_hello(connection):
    """Holder side: the sender's start nonce, or None (closed / malformed)."""
    data = b""
    while len(data) < HELLO.size:
        try:
            chunk = connection.recv(HELLO.size - len(data))
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
    nonce = HELLO.unpack(data)[0]
    return nonce if 0 < nonce < 1 << 63 else None


def peer_gone(connection):
    """Holder side: True if the sender closed (EOF / error) or sent anything
    after its ``HELLO`` (it never does): its socket is readable. Never blocks."""
    return bool(select.select([connection], [], [], 0)[0])


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


def trusted_launcher(gst, *, dev_checkout_helper):
    """The holder's sandboxed ``GStreamerLauncher``.

    Its constructor only runs the launch trust checks (GStreamer executable
    and plugins, this interpreter, the sandbox helper, Landlock ABI) and
    raises ``PipelineError`` on any failure; it opens no camera and starts no
    process, so ``schedule`` also calls it as a preflight.
    """
    from media_capture_agent.uvc_pipeline import GStreamerLauncher, require_trusted_file
    return GStreamerLauncher(
        gst, trust_file=_dev_trust if dev_checkout_helper else require_trusted_file)


def launch_trust_problem(gst, *, dev_checkout_helper):
    """None if ``trusted_launcher`` would accept this host, else the reason."""
    try:
        from media_capture_agent.uvc_pipeline import PipelineError
    except ImportError as error:
        return f"media_capture_agent is not importable ({error.__class__.__name__})"
    try:
        trusted_launcher(gst, dev_checkout_helper=dev_checkout_helper)
    except (PipelineError, OSError) as error:
        return f"{error.__class__.__name__}: {error}"
    return None


def build_capture(state_dir, n_sources, profile, *, gst, dev_checkout_helper, **inject):
    from media_capture_agent.uvc_capture import UvcCapture, UvcSourceConfig
    if "launcher" not in inject:
        inject["launcher"] = trusted_launcher(gst, dev_checkout_helper=dev_checkout_helper)
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
        self.client_nonce = None
        self.client_frames = [0] * len(source_ids)
        self.frames = [0] * len(source_ids)
        self.forward_drops = 0
        self.selector = selectors.DefaultSelector()

    def run(self, seconds):
        deadline = time.monotonic() + seconds
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ)
        next_poll = next_sample = 0.0
        cpu0 = records.process_cpu_seconds()
        self.writer.write("start", sources=len(self.source_ids), fps=self.fps)
        try:
            while not self.stop.is_set() and time.monotonic() < deadline:
                now = time.monotonic()
                if now >= next_poll:
                    self.capture.poll()
                    next_poll = now + 0.5
                for key, _ in self.selector.select(timeout=0):
                    if key.fileobj is self.listener:
                        self._accept()
                    elif key.fileobj is self.client:
                        self._close_client()  # the sender closed (or broke protocol)
                for index, source in enumerate(self.source_ids):
                    frame = self.capture.frames(source).get(0.005)
                    if frame is None:
                        continue
                    self.frames[index] += 1
                    if self.client is not None:
                        try:
                            self.client.sendall(encode_frame(index, int(
                                frame.received_monotonic * 1e9), frame.data))
                            self.client_frames[index] += 1
                        except OSError:
                            self._close_client()
                            self.forward_drops += 1
                if now >= next_sample:
                    next_sample = now + 1.0
                    rss, hwm = records.process_memory()
                    drops = sum(self.capture.frames(source).drop_stats()[0]
                                for source in self.source_ids)
                    # Value-free product counters (Issue #305), judged per
                    # source: restarts are launches beyond each source's first
                    # (a restart of one camera cannot hide behind another
                    # that never started), plus sources never launched,
                    # framing teardowns and tolerated oversized padding.
                    counters = [self.capture.counters(source) for source in self.source_ids]
                    self.writer.write("sample", frames=sum(self.frames), queue_drops=drops,
                                      capture_launches=sum(c.launches for c in counters),
                                      capture_restarts=sum(max(0, c.launches - 1)
                                                           for c in counters),
                                      sources_never_launched=sum(1 for c in counters
                                                                 if c.launches == 0),
                                      stream_invalid=sum(c.stream_invalid for c in counters),
                                      padding_tolerated=sum(c.padding_tolerated
                                                            for c in counters),
                                      forward_drops=self.forward_drops,
                                      cpu_seconds=records.process_cpu_seconds() - cpu0,
                                      child_cpu_seconds=records.descendant_cpu_seconds(),
                                      rss_bytes=rss, hwm_bytes=hwm,
                                      client=self.client is not None)
        finally:
            self.close()

    def _accept(self):
        connection, _ = self.listener.accept()
        if self.client is not None and peer_gone(self.client):
            self._close_client()  # the previous sender has gone; its EOF is not yet handled
        if self.client is not None:
            connection.close()  # exactly one local sender
            self.writer.write("refused", reason="connection_limit")
            return
        connection.setblocking(True)
        connection.settimeout(1.0)
        nonce = read_hello(connection)
        if nonce is None:
            connection.close()  # no session identity: not served
            return
        self.client, self.client_nonce = connection, nonce
        self.client_frames = [0] * len(self.source_ids)
        self.selector.register(connection, selectors.EVENT_READ)
        self.writer.write("session_open", nonce=nonce)

    def _close_client(self):
        """End the current sender session: its per-source forwarded counts."""
        if self.client is None:
            return
        self.selector.unregister(self.client)
        self.client.close()
        for index, frames in enumerate(self.client_frames):
            self.writer.write("forwarded", nonce=self.client_nonce, source=index,
                              frames=frames)
        self.writer.write("session_close", nonce=self.client_nonce)
        self.client = self.client_nonce = None

    def close(self):
        self._close_client()
        self.selector.close()
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
