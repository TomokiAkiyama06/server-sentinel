"""Capture-side PoC sender (stands in for the future Agent transport).

It opens the outbound connection with the product Agent TLS client
(``node_tls.build_capture_client_context`` / ``connect_to_main``: TLS 1.3,
pinned deployment CA, verified Main server name, node client certificate,
Tailscale endpoints refused) and delivers each source in order with the
ADR-0007 envelope. Per source it keeps a bounded drop-oldest pending queue
(``pending_seconds`` of frames, standing in for "units not yet delivered
from the ring buffer"; the Agent ring buffer itself is not exercised). Only
one unit per source is in flight (stop-and-wait) on the streaming candidates;
``b_segment`` sends one PUT per second containing every pending unit.

A transient refusal (backpressure, rate limit, not processed) is retried
with backoff; a duplicate acknowledgement releases the unit. No inbound byte
for ``loss_timeout`` means link loss: the connection is dropped, the loss
time is recorded (the Agent's ``T`` for its T-600 s/T+600 s protection), and
reconnects follow with bounded backoff and no manual action.

Media sources: ``builtin`` (generated pseudo-JPEG byte strings, no image
content), ``gst`` (``videotestsrc`` + ``jpegenc`` synthetic MJPEG), and
``holder`` (real camera frames from ``holder.py`` over a local unix socket,
memory only). Measurements are numeric JSONL only.
"""
from collections import deque
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import ssl
import subprocess
import threading
import time
from uuid import UUID

from . import records, wire
from .records import token


class Unit:
    __slots__ = ("sequence", "capture_ns", "payload", "sent_ns")

    def __init__(self, sequence, capture_ns, payload):
        self.sequence, self.capture_ns, self.payload = sequence, capture_ns, payload
        self.sent_ns = None


class SourceState:
    def __init__(self, index, source_id, pending_limit):
        self.index, self.source_id = index, source_id
        self.pending = deque()
        self.pending_limit = pending_limit
        self.inflight = None
        self.retry_at = 0.0
        self.backoff = 0.02
        self.next_sequence = 0
        self.drops = 0
        self.max_pending = 0
        self.last_committed_capture_ns = None
        self.counts = {name: 0 for name in wire.OUTCOMES}
        self.sent = 0


class SenderConfig:
    def __init__(self, *, candidate, host, port, n_sources, source_kind="builtin", fps=30,
                 frame_bytes=125000, width=1280, height=720, pending_seconds=2.0,
                 loss_timeout_s=None, sndbuf=262144, fast=False, gst="gst-launch-1.0",
                 holder_socket=None, real_inputs=False, segment_seconds=1.0,
                 route_probe=False):
        self.candidate, self.host, self.port = candidate, host, port
        self.n_sources = n_sources
        self.source_kind = source_kind
        self.fps, self.frame_bytes = fps, frame_bytes
        self.width, self.height = width, height
        self.pending_limit = max(1, int(round(pending_seconds * fps)))
        self.loss_timeout_s = loss_timeout_s if loss_timeout_s is not None else (
            1.5 if fast else 5.0)
        self.backoff_initial, self.backoff_max = (0.2, 1.0) if fast else (0.5, 5.0)
        self.sndbuf = sndbuf
        self.gst = gst
        self.holder_socket = holder_socket
        self.real_inputs = real_inputs
        self.segment_seconds = segment_seconds
        self.route_probe = route_probe


class Sender:
    def __init__(self, config, node_dir, epoch, writer):
        from media_capture_agent.node_tls import build_capture_client_context
        self.config = config
        self.writer = writer
        node_dir = Path(node_dir)
        node = json.loads((node_dir / "node.json").read_text(encoding="ascii"))
        self.node_id = UUID(node["node_id"])
        self.server_name = node["server_name"]
        self.context = build_capture_client_context(
            (node_dir / "ca.pem").read_bytes(), certificate_path=node_dir / "cert.pem",
            key_path=node_dir / "key.pem")
        self.epoch = epoch
        ids = wire.source_ids(self.node_id)
        if not 1 <= config.n_sources <= len(ids):
            raise ValueError("between one and five sources")
        self.sources = [SourceState(i, ids[i], config.pending_limit)
                        for i in range(config.n_sources)]
        self.by_id = {state.source_id: state for state in self.sources}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.wake_r, self.wake_w = socket.socketpair()
        self.wake_r.setblocking(False)
        self.wake_w.setblocking(False)
        self.connections = 0
        self.connected = False
        self.payload_bytes = self.wire_bytes = 0
        self.max_outq = 0
        self.latency_rtt = records.Reservoir()
        self.latency_capture = records.Reservoir()
        self.children = []
        self.stale_acks = 0
        self._first_accept_pending = False

    # -- media sources --------------------------------------------------------
    def _offer(self, index, capture_ns, payload):
        if index >= len(self.sources):
            return
        state = self.sources[index]
        with self.lock:
            if len(state.pending) >= state.pending_limit:
                state.pending.popleft()  # live edge wins; the skipped unit is exact loss
                state.drops += 1
            state.pending.append(Unit(state.next_sequence, capture_ns, payload))
            state.next_sequence += 1
            state.max_pending = max(state.max_pending, len(state.pending))
        try:
            self.wake_w.send(b"x")
        except (BlockingIOError, OSError):
            pass

    def _builtin(self, index):
        period = 1.0 / self.config.fps
        body = bytearray(os.urandom(max(64, self.config.frame_bytes - 4)))
        next_at = time.monotonic()
        counter = 0
        while not self.stop.is_set():
            counter += 1
            body[0:8] = counter.to_bytes(8, "big")
            self._offer(index, time.monotonic_ns(), b"\xff\xd8" + bytes(body) + b"\xff\xd9")
            next_at += period
            delay = next_at - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            elif delay < -1.0:
                next_at = time.monotonic()  # do not burst after a stall

    def _gst(self, index):
        from media_capture_agent.uvc_pipeline import MjpegFrameParser
        command = [self.config.gst, "-q", "videotestsrc", "is-live=true", f"pattern={index % 20}",
                   "!", f"video/x-raw,width={self.config.width},height={self.config.height},"
                   f"framerate={self.config.fps}/1", "!", "jpegenc", "!", "fdsink", "fd=1"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
        self.children.append(process)
        parser = MjpegFrameParser(8 * 1024 * 1024)
        try:
            while not self.stop.is_set():
                data = process.stdout.read1(65536)
                if not data:
                    return
                for frame in parser.feed(data):
                    self._offer(index, time.monotonic_ns(), frame)
        finally:
            process.terminate()

    def _holder(self):
        from .holder import read_frames
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(str(self.config.holder_socket))
        try:
            read_frames(connection, self._offer, self.stop)
        finally:
            connection.close()

    def start_sources(self):
        kind = self.config.source_kind
        if kind == "holder":
            targets = [(self._holder, ())]
        elif kind == "gst":
            targets = [(self._gst, (state.index,)) for state in self.sources]
        else:
            targets = [(self._builtin, (state.index,)) for state in self.sources]
        for target, arguments in targets:
            threading.Thread(target=target, args=arguments, daemon=True).start()

    # -- acknowledgements -----------------------------------------------------
    def _ack(self, source_id, epoch, sequence, outcome, reason):
        now = time.monotonic_ns()
        with self.lock:
            state = self.by_id.get(source_id)
            unit = None if state is None else state.inflight
            if unit is None or unit.sequence != sequence or epoch != self.epoch:
                self.stale_acks += 1
                return
            state.counts[outcome] += 1
            if outcome in ("accepted", "duplicate", "rejected"):
                state.inflight = None
                state.backoff = 0.02
                if outcome != "rejected":
                    self.latency_rtt.add(now - unit.sent_ns)
                    self.latency_capture.add(now - unit.capture_ns)
                    previous = state.last_committed_capture_ns
                    if previous is not None and unit.capture_ns - previous > 500_000_000:
                        self.writer.write("committed_gap", source=state.index,
                                          from_capture_ns=previous, to_capture_ns=unit.capture_ns)
                    state.last_committed_capture_ns = unit.capture_ns
                    if self._first_accept_pending:
                        self._first_accept_pending = False
                        self.writer.write("first_accept", connection=self.connections,
                                          source=state.index)
            else:
                # Transient refusal: put the unit back in front, retry later.
                state.pending.appendleft(unit)
                state.inflight = None
                state.retry_at = time.monotonic() + state.backoff
                state.backoff = min(0.5, state.backoff * 2)

    def _requeue_inflight(self):
        with self.lock:
            for state in self.sources:
                if state.inflight is not None:
                    state.pending.appendleft(state.inflight)
                    state.inflight = None
                    while len(state.pending) > state.pending_limit:
                        state.pending.popleft()
                        state.drops += 1

    def _next_units(self, *, stop_and_wait=True, limit=None):
        now = time.monotonic()
        units = []
        with self.lock:
            for state in self.sources:
                if stop_and_wait:
                    if state.inflight is None and state.pending and now >= state.retry_at:
                        unit = state.pending.popleft()
                        state.inflight = unit
                        units.append((state, unit))
                else:
                    take = []
                    while state.pending and (limit is None or len(take) < limit):
                        take.append(state.pending.popleft())
                    for unit in take:
                        units.append((state, unit))
        return units

    # -- connection management ------------------------------------------------
    def _connect(self):
        from media_capture_agent.node_tls import connect_to_main
        from media_capture_agent.pairing import PairingRefused
        self.writer.write("connect", connection=self.connections + 1)
        try:
            connection = connect_to_main(self.context, server_name=self.server_name,
                                         host=self.config.host, port=self.config.port,
                                         timeout_seconds=self.config.loss_timeout_s * 2)
        except PairingRefused as error:
            self.writer.write("connect_failed", reason=token(getattr(error, "reason", None)
                                                             or str(error)))
            return None
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.sndbuf)
        self.connections += 1
        self.connected = True
        self._first_accept_pending = True
        return connection

    def run(self, seconds):
        self.writer.write(
            "start", candidate=self.config.candidate, n_sources=self.config.n_sources,
            source_kind=token(self.config.source_kind),
            inputs="real" if self.config.real_inputs else "synthetic",
            fps=self.config.fps, frame_bytes=self.config.frame_bytes, epoch=self.epoch,
            pending_limit=self.config.pending_limit, sndbuf=self.config.sndbuf,
            loss_timeout_ns=int(self.config.loss_timeout_s * 1e9))
        for state in self.sources:
            self.writer.write("epoch_start", source=state.index, epoch=self.epoch)
        self.start_sources()
        sampler = threading.Thread(target=self._sample, daemon=True)
        sampler.start()
        deadline = time.monotonic() + seconds
        backoff = self.config.backoff_initial
        while not self.stop.is_set() and time.monotonic() < deadline:
            connection = self._connect()
            if connection is None:
                self.stop.wait(backoff)
                backoff = min(self.config.backoff_max, backoff * 2)
                continue
            reason = "peer_closed"
            try:
                if self.config.route_probe:
                    reason = self._route_probe(connection)
                    self.stop.set()
                elif self.config.candidate == "b_segment":
                    reason = self._session_segment(connection, deadline)
                else:
                    reason = self._session_stream(connection, deadline)
            except wire.ProtocolError:
                reason = "protocol_error"
            except (ssl.SSLError, OSError):
                reason = "tls_session_failed"
            finally:
                self.connected = False
                _close(connection)
                self._requeue_inflight()
            self.writer.write("closed", connection=self.connections, reason=token(reason))
            if reason not in ("loss_timeout", "shutdown") and not self.stop.is_set():
                # Any unexpected disconnect is a Main-communication loss for the
                # Agent's T-600 s/T+600 s protection, not only a silent timeout.
                self._loss(0)
            if reason == "loss_timeout":
                backoff = self.config.backoff_initial
            if not self.stop.is_set() and time.monotonic() < deadline:
                self.stop.wait(backoff)
                backoff = min(self.config.backoff_max, backoff * 2)
        self.stop.set()
        sampler.join(timeout=3)
        self._finish()

    def _loss(self, idle_ns):
        for state in self.sources:
            self.writer.write("loss_detected", source=state.index, idle_ns=idle_ns,
                              last_committed_capture_ns=state.last_committed_capture_ns)

    def _session_stream(self, connection, deadline):
        connection.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(connection, selectors.EVENT_READ)
        selector.register(self.wake_r, selectors.EVENT_READ)
        chunked = self.config.candidate == "b_chunked"
        out = bytearray()
        if chunked:
            out += wire.request_head("POST", wire.STREAM_PATH)
        maximum = 4096
        reader = wire.FrameReader(maximum)
        decoder = wire.ChunkDecoder(maximum) if chunked else None
        head = bytearray() if chunked else None
        last_inbound = time.monotonic()
        next_heartbeat = 0.0
        writing = False
        try:
            while not self.stop.is_set() and time.monotonic() < deadline:
                now = time.monotonic()
                if len(out) < 262144:
                    pieces = []
                    for state, unit in self._next_units():
                        unit.sent_ns = time.monotonic_ns()
                        state.sent += 1
                        self.payload_bytes += len(unit.payload)
                        pieces.append(wire.media_frame(state.source_id, self.epoch, unit.sequence,
                                                       unit.capture_ns, unit.payload))
                    if now >= next_heartbeat:
                        pieces.append(wire.heartbeat_frame(time.monotonic_ns()))
                        next_heartbeat = now + 1.0
                    for piece in pieces:
                        out += wire.chunk(piece) if chunked else piece
                want_write = bool(out)
                if want_write != writing:
                    selector.modify(connection, selectors.EVENT_READ | (
                        selectors.EVENT_WRITE if want_write else 0))
                    writing = want_write
                selector.select(timeout=0.05)
                try:
                    while self.wake_r.recv(4096):
                        pass
                except (BlockingIOError, OSError):
                    pass
                # read everything available, including TLS-buffered records
                while True:
                    try:
                        data = connection.recv(65536)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                        break
                    if not data:
                        return "peer_closed"
                    last_inbound = time.monotonic()
                    if chunked and head is not None:
                        head += data
                        if b"\r\n\r\n" not in head:
                            if len(head) > wire.MAX_HEAD_BYTES:
                                raise wire.ProtocolError("response head too large")
                            continue
                        raw, _, data = bytes(head).partition(b"\r\n\r\n")
                        start, _headers = wire.parse_head(raw)
                        if start[1] != "200":
                            return "not_found" if start[1] == "404" else "protocol_error"
                        head = None
                    pieces = decoder.feed(data) if chunked else [data]
                    for piece in pieces:
                        for body in reader.feed(piece):
                            self._inbound(body)
                if out:
                    try:
                        sent = connection.send(out[:65536])
                        del out[:sent]
                        self.wire_bytes += sent
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                        pass
                self._sample_socket(connection)
                idle = time.monotonic() - last_inbound
                if idle > self.config.loss_timeout_s:
                    self._loss(int(idle * 1e9))
                    return "loss_timeout"
        finally:
            selector.close()
        return "shutdown"

    def _inbound(self, body):
        parsed = wire.parse_body(body)
        if parsed[0] == wire.ACK:
            self._ack(*parsed[1:])
        elif parsed[0] != wire.HEARTBEAT_ACK:
            raise wire.ProtocolError("unexpected frame from main")

    def _session_segment(self, connection, deadline):
        connection.settimeout(self.config.loss_timeout_s)
        limit = max(1, int(self.config.fps * self.config.segment_seconds * 2))
        response = bytearray()
        while not self.stop.is_set() and time.monotonic() < deadline:
            started = time.monotonic()
            units = self._next_units(stop_and_wait=False, limit=limit)
            with self.lock:
                for state, unit in units:
                    state.inflight = None
            body = bytearray(wire.heartbeat_frame(time.monotonic_ns()))
            for state, unit in units:
                unit.sent_ns = time.monotonic_ns()
                state.sent += 1
                body += wire.media_frame(state.source_id, self.epoch, unit.sequence,
                                         unit.capture_ns, unit.payload)
            request = wire.request_head("PUT", wire.SEGMENT_PATH, content_length=len(body))
            try:
                connection.sendall(request + body)
                self.wire_bytes += len(request) + len(body)
                self.payload_bytes += sum(len(unit.payload) for _, unit in units)
                self._sample_socket(connection)
                acks, response = self._read_segment_response(connection, response)
            except (socket.timeout, TimeoutError):
                self._restore(units)
                self._loss(int((time.monotonic() - started) * 1e9))
                return "loss_timeout"
            except BaseException:
                self._restore(units)
                raise
            self._apply_segment_acks(units, acks)
            delay = self.config.segment_seconds - (time.monotonic() - started)
            if delay > 0:
                self.stop.wait(delay)
        return "shutdown"

    def _read_segment_response(self, connection, pending):
        while b"\r\n\r\n" not in pending:
            if len(pending) > wire.MAX_HEAD_BYTES:
                raise wire.ProtocolError("response head too large")
            data = connection.recv(65536)
            if not data:
                raise ConnectionError("peer closed")
            pending += data
        raw, _, rest = bytes(pending).partition(b"\r\n\r\n")
        start, headers = wire.parse_head(raw)
        if start[1] != "200":
            raise wire.ProtocolError("segment refused")
        length = int(headers.get("content-length", "-1"))
        if not 0 <= length <= 1 << 22:
            raise wire.ProtocolError("bad response length")
        body = bytearray(rest)
        while len(body) < length:
            data = connection.recv(65536)
            if not data:
                raise ConnectionError("peer closed")
            body += data
        reader = wire.FrameReader(4096)
        acks = [wire.parse_body(item) for item in reader.feed(bytes(body[:length]))]
        return acks, bytearray(body[length:])

    def _restore(self, units):
        """Put unacknowledged units back in order (oldest first), bounded."""
        with self.lock:
            for state in self.sources:
                mine = [unit for owner, unit in units if owner is state]
                state.pending.extendleft(reversed(mine))
                while len(state.pending) > state.pending_limit:
                    state.pending.popleft()
                    state.drops += 1

    def _apply_segment_acks(self, units, acks):
        results = {}
        for parsed in acks:
            if parsed[0] == wire.ACK:
                results[(parsed[1], parsed[3])] = parsed[4]
        retry = []
        now = time.monotonic_ns()
        for state, unit in units:
            outcome = results.get((state.source_id, unit.sequence), "not_processed")
            state.counts[outcome] += 1
            if outcome in ("accepted", "duplicate"):
                self.latency_rtt.add(now - unit.sent_ns)
                self.latency_capture.add(now - unit.capture_ns)
                previous = state.last_committed_capture_ns
                if previous is not None and unit.capture_ns - previous > 500_000_000:
                    self.writer.write("committed_gap", source=state.index,
                                      from_capture_ns=previous, to_capture_ns=unit.capture_ns)
                state.last_committed_capture_ns = unit.capture_ns
                if self._first_accept_pending:
                    self._first_accept_pending = False
                    self.writer.write("first_accept", connection=self.connections,
                                      source=state.index)
            elif outcome != "rejected":
                retry.append((state, unit))
        self._restore(retry)

    def _route_probe(self, connection):
        """Ask the ingest listener for a human/dashboard route; expect 404 + close."""
        connection.settimeout(5)
        connection.sendall(b"GET /api/v1/sources HTTP/1.1\r\nHost: ingest\r\n\r\n")
        try:
            reply = connection.recv(64)
        except (OSError, ssl.SSLError):
            reply = b""
        if reply.startswith(b"HTTP/1.1 404"):
            result = "not_found"
        elif not reply:
            result = "peer_closed"
        else:
            result = "other"
        self.writer.write("route_probe", reason=result)
        return result

    # -- sampling ---------------------------------------------------------------
    def _sample_socket(self, connection):
        outq, _ = records.socket_queues(connection)
        if outq is not None:
            self.max_outq = max(self.max_outq, outq)

    def _sample(self):
        cpu0 = records.process_cpu_seconds()
        while not self.stop.wait(1.0):
            rss, hwm = records.process_memory()
            child_cpu = sum(records.process_cpu_seconds(child.pid) or 0.0
                            for child in self.children)
            with self.lock:
                totals = {name: sum(state.counts[name] for state in self.sources)
                          for name in wire.OUTCOMES}
                pending = max(len(state.pending) for state in self.sources)
                max_pending = max(state.max_pending for state in self.sources)
                drops = sum(state.drops for state in self.sources)
                sent = sum(state.sent for state in self.sources)
            ss = records.ss_skmem(self.config.port, local=False) or {}
            self.writer.write(
                "sample", candidate=self.config.candidate, connected=self.connected,
                connections=self.connections, pending=pending, max_pending=max_pending,
                pending_limit=self.config.pending_limit, drops=drops, sent=sent,
                payload_bytes=self.payload_bytes, wire_bytes=self.wire_bytes,
                max_outq=self.max_outq, sndbuf=self.config.sndbuf, rss_bytes=rss,
                hwm_bytes=hwm, cpu_seconds=records.process_cpu_seconds() - cpu0,
                child_cpu_seconds=child_cpu, stale_acks=self.stale_acks, **totals, **ss)

    def _finish(self):
        for child in self.children:
            child.terminate()
        self.writer.write("metric", payload_bytes=self.payload_bytes, wire_bytes=self.wire_bytes,
                          connections=self.connections, stale_acks=self.stale_acks)
        for state in self.sources:
            self.writer.write("end", source=state.index, epoch=self.epoch,
                              generated=state.next_sequence, drops=state.drops,
                              max_pending=state.max_pending, sent=state.sent, **state.counts)
        for name, reservoir in (("rtt", self.latency_rtt), ("capture", self.latency_capture)):
            points = records.percentiles(reservoir.values)
            self.writer.write("latency", metric=name, samples=reservoir.seen, p50_ns=points[50],
                              p95_ns=points[95], p99_ns=points[99], max_ns=reservoir.maximum)


def _close(connection):
    try:
        connection.close()
    except OSError:
        pass


def next_epoch(path):
    """Persist a strictly increasing capture epoch (ADR-0007) in a private file."""
    path = Path(path)
    try:
        current = int(path.read_text(encoding="ascii").strip())
    except FileNotFoundError:
        current = 0
    value = current + 1
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(str(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return value


def run(config, node_dir, epoch_file, out_path, run_id, seconds):
    writer = records.JsonlWriter(out_path, run_id=run_id, role="sender")
    sender = Sender(config, node_dir, next_epoch(epoch_file), writer)
    signal.signal(signal.SIGTERM, lambda *_: sender.stop.set())
    signal.signal(signal.SIGINT, lambda *_: sender.stop.set())
    sender.run(seconds)
    writer.close()
    return 0
