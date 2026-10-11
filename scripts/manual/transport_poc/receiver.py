"""Main-side PoC receiver: real mTLS admission, continuity and bounded ingest.

The listener is the product ``open_ingest_listener`` + ``CaptureIngestAcceptor``
(TLS 1.3, client certificate required, current pairing-ledger activation).
Every media unit goes through the product ``ContinuityTracker`` in front of the
product ``AgentIngestQueue``. A consumer thread stands in for durable
recording: it drains the queue, hashes each payload (SHA-256) and discards it,
then records only per-source numeric watermarks in a private SQLite file so a
restarted receiver resumes from the "durably recorded" position (ADR-0007
item 1). No media byte is ever written to disk.
"""
import hashlib
from pathlib import Path
import signal
import socket
import sqlite3
import ssl
import threading
import time
from uuid import UUID

from . import materials, records, wire
from .records import token

source_ids = wire.source_ids


class ReceiverConfig:
    def __init__(self, *, candidate, bind_host, port, human_port=8000, fast=False,
                 drain_rate=0.0, max_connections=8, sndbuf=262144, rcvbuf=262144,
                 maximum_message_bytes=2 * 1024 * 1024, maximum_queued_messages=240,
                 maximum_queued_bytes=64 * 1024 * 1024, rate_per_second=900,
                 stale_after_s=None, idle_timeout_s=None, admission_check_s=1.0,
                 maximum_segment_bytes=48 * 1024 * 1024, ss_sampling=True):
        if candidate not in ("a_framed", "b_chunked", "b_segment"):
            raise ValueError("unknown receiver candidate")
        self.candidate = candidate
        self.bind_host, self.port, self.human_port = bind_host, port, human_port
        self.fast = fast
        self.drain_rate = float(drain_rate)
        self.max_connections = max_connections
        self.sndbuf, self.rcvbuf = sndbuf, rcvbuf
        self.maximum_message_bytes = maximum_message_bytes
        self.maximum_queued_messages = maximum_queued_messages
        self.maximum_queued_bytes = maximum_queued_bytes
        self.rate_per_second = rate_per_second
        self.stale_after_s = stale_after_s if stale_after_s is not None else (2.0 if fast else 5.0)
        self.idle_timeout_s = idle_timeout_s if idle_timeout_s is not None else (
            10.0 if fast else 30.0)
        self.admission_check_s = admission_check_s
        self.maximum_segment_bytes = maximum_segment_bytes
        self.ss_sampling = ss_sampling


class Authorizer:
    """Admitted nodes (mTLS + ledger) and their derived source identities."""

    def __init__(self):
        self._admitted = set()
        self._sources = {}
        self._lock = threading.Lock()

    def admit(self, node_id):
        with self._lock:
            self._admitted.add(node_id)
            self._sources[node_id] = frozenset(source_ids(node_id))

    def remove(self, node_id):
        with self._lock:
            self._admitted.discard(node_id)

    def require_node(self, node_id):
        with self._lock:
            if node_id not in self._admitted:
                raise PermissionError("node not admitted")

    def require_source(self, node_id, source_id):
        with self._lock:
            if node_id not in self._admitted or source_id not in self._sources.get(node_id, ()):
                raise PermissionError("source not authorized")


class DurableStandIn:
    """Numeric watermarks of 'persisted' units (hash-then-discard) in SQLite."""

    def __init__(self, path):
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS durable (source TEXT, epoch INTEGER, node TEXT, "
            "min_seq INTEGER, max_seq INTEGER, units INTEGER, duplicates INTEGER, "
            "last_capture_ns INTEGER, PRIMARY KEY (source, epoch))")
        self._connection.commit()
        self._rows = {}
        for row in self._connection.execute("SELECT * FROM durable"):
            self._rows[(UUID(row[0]), row[1])] = [UUID(row[2]), *row[3:]]
        self._dirty = set()
        self._lock = threading.Lock()

    def persist(self, message):
        """Record a drained unit; returns (persisted, durable gap or None).

        A durable gap is ``(missing_units or None, from_capture_ns,
        to_capture_ns)``: the uncommitted interval in the Agent capture clock
        between the previous persisted unit of the source and this one.
        """
        key = (message.source_id, message.capture_epoch)
        with self._lock:
            epochs = [epoch for source, epoch in self._rows if source == message.source_id]
            latest = max(epochs, default=None)
            row = self._rows.get(key)
            if (latest is not None and message.capture_epoch < latest) or (
                    row is not None and message.sequence <= row[2]):
                if row is None:
                    row = self._rows[key] = [message.node_id, message.sequence,
                                             message.sequence, 0, 0, message.capture_time_ns]
                row[4] += 1
                self._dirty.add(key)
                return False, None
            gap = None
            if row is None:
                if latest is not None:
                    previous = self._rows[(message.source_id, latest)]
                    gap = (None, previous[5], message.capture_time_ns)
                self._rows[key] = [message.node_id, message.sequence, message.sequence, 1, 0,
                                   message.capture_time_ns]
            else:
                if message.sequence > row[2] + 1:
                    gap = (message.sequence - row[2] - 1, row[5], message.capture_time_ns)
                row[2] = message.sequence
                row[3] += 1
                row[5] = message.capture_time_ns
            self._dirty.add(key)
            return True, gap

    def flush(self):
        with self._lock:
            rows = [(str(source), epoch, str(row[0]), *row[1:])
                    for (source, epoch), row in self._rows.items()
                    if (source, epoch) in self._dirty]
            self._dirty.clear()
        if rows:
            self._connection.executemany(
                "INSERT OR REPLACE INTO durable VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
            self._connection.commit()

    def watermark(self, source_id):
        from app.cameras.remote_agent.continuity import CommittedWatermark
        with self._lock:
            candidates = [(epoch, row) for (source, epoch), row in self._rows.items()
                          if source == source_id and row[3] > 0]
        if not candidates:
            return None
        epoch, row = max(candidates, key=lambda item: item[0])
        return CommittedWatermark(row[0], epoch, row[2], row[5])

    def summary(self):
        with self._lock:
            return [(source, epoch, list(row)) for (source, epoch), row in self._rows.items()]

    def close(self):
        self.flush()
        self._connection.close()


class Receiver:
    def __init__(self, config, materials_root, state_dir, writer):
        from app.cameras.remote_agent.continuity import ContinuityLimits, ContinuityTracker
        from app.cameras.remote_agent.ingest import AgentIngestQueue, IngestLimits
        from app.cameras.remote_agent.ingest_tls import (
            CaptureIngestAcceptor, CaptureNodeAdmission, IngestListenerConfig,
            build_ingest_server_context, open_ingest_listener)
        self.config = config
        self.writer = writer
        root = Path(materials_root).resolve()
        deployment = materials.load_deployment(root)
        certificate, key = materials.listener_paths(root)
        context = build_ingest_server_context((root / "ca.pem").read_bytes(), certificate, key)
        self.ledger = materials.open_ledger(root)
        self.admission = CaptureNodeAdmission(self.ledger, deployment["deployment_id"])
        self.acceptor = CaptureIngestAcceptor(context, self.admission,
                                              handshake_timeout_seconds=10)
        listener_config = IngestListenerConfig(bind_host=config.bind_host, port=config.port,
                                               human_host=config.bind_host,
                                               human_port=config.human_port)
        self.listener = _open_listener(listener_config, open_ingest_listener)
        self.port = self.listener.getsockname()[1]
        self.node_index = {node: label for label, node in deployment["nodes"].items()}
        self.source_index = {}
        for node in deployment["nodes"].values():
            for index, source in enumerate(source_ids(node)):
                self.source_index[source] = index
        self.authorizer = Authorizer()
        self.queue = AgentIngestQueue(
            IngestLimits(maximum_message_bytes=config.maximum_message_bytes,
                         maximum_queued_messages=config.maximum_queued_messages,
                         maximum_queued_bytes=config.maximum_queued_bytes,
                         maximum_messages_per_window=config.rate_per_second,
                         rate_window_ns=1_000_000_000),
            self.authorizer, clock_ns=time.monotonic_ns)
        self.durable = DurableStandIn(Path(state_dir) / "durable.sqlite3")
        self.tracker = ContinuityTracker(
            ContinuityLimits(maximum_sources=4, maximum_pending_gaps_per_source=64,
                             stale_after_ns=int(config.stale_after_s * 1e9)),
            self.authorizer, self.queue, clock_ns=time.monotonic_ns,
            committed_watermark=self.durable.watermark)
        self.stop = threading.Event()
        self.abrupt = False
        self._lock = threading.Lock()
        self._connections = {}
        self._connection_counter = 0
        self._active = 0
        self.counts = {name: 0 for name in wire.OUTCOMES}
        self.bytes_in = 0
        self.max_queue_messages = self.max_queue_bytes = 0
        self.max_outq = self.max_inq = 0
        self.last_rx_ns = {}
        self.flows = {}
        self.persisted = self.durable_duplicates = 0
        self.discarded_at_stop = 0

    # -- helpers ------------------------------------------------------------
    def _event(self, kind, **fields):
        self.writer.write(kind, candidate=self.config.candidate, **fields)

    def _source_fields(self, source_id):
        return {"source": self.source_index.get(source_id, -1)}

    def _media(self, grant, source, epoch, sequence, capture_ns, payload):
        from app.cameras.remote_agent.continuity import MediaUnitHeader
        try:
            header = MediaUnitHeader(source, epoch, sequence, capture_ns)
        except ValueError:
            raise wire.ProtocolError("invalid envelope") from None
        delivery = self.tracker.receive(grant, header, payload)
        outcome, reason = delivery.outcome.value, delivery.reason or "none"
        with self._lock:
            self.counts[outcome] = self.counts.get(outcome, 0) + 1
            self.last_rx_ns[source] = time.monotonic_ns()
        return outcome, reason

    # -- connection handling ------------------------------------------------
    def serve(self):
        """Accept mTLS connections until stopped (candidates A and B)."""
        self.listener.settimeout(0.5)
        self.serve_with(self._accept_loop)

    def serve_with(self, loop):
        """Run ``loop`` with the consumer and sampler workers, then finish."""
        self._event("ready", port=self.port)
        print("ready", flush=True)
        threads = [threading.Thread(target=self._consume, daemon=True),
                   threading.Thread(target=self._sample, daemon=True)]
        for thread in threads:
            thread.start()
        try:
            loop()
        finally:
            self.stop.set()
            if self.listener is not None:
                try:
                    self.listener.close()
                except OSError:
                    pass
            with self._lock:
                connections = list(self._connections.values())
            for connection in connections:
                _abort(connection)
            for thread in threads:
                thread.join(timeout=5)
            self._finish()

    def _accept_loop(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                # Handshakes in progress count too, so unauthenticated peers
                # cannot grow the thread count beyond the bound.
                too_many = self._active >= self.config.max_connections
                if not too_many:
                    self._active += 1
            if too_many:
                _abort(connection)
                self._event("auth_refused", reason="connection_limit")
                continue
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.sndbuf)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.rcvbuf)
            threading.Thread(target=self._counted_connection, args=(connection,),
                             daemon=True).start()

    def _counted_connection(self, raw):
        try:
            self._connection(raw)
        finally:
            with self._lock:
                self._active -= 1

    def _connection(self, raw):
        from app.cameras.remote_agent.ingest_tls import IngestTlsError
        try:
            session = self.acceptor.accept(raw)
        except IngestTlsError as error:
            self._event("auth_refused", reason=token(error.reason))
            return
        node = session.identity.node_id
        self.authorizer.admit(node)
        try:
            grant = self.tracker.open_session(node)
        except PermissionError:
            session.close()
            self._event("auth_refused", reason="unauthorized")
            return
        with self._lock:
            self._connection_counter += 1
            number = self._connection_counter
            self._connections[number] = session.connection
        label = self.node_index.get(node)
        self._event("session_open", connection=number, generation=grant.generation,
                    node=token(label) if label else "other")
        reason = "peer_closed"
        try:
            reason = self._run_session(session, grant, node)
        except wire.ProtocolError:
            reason = "protocol_error"
        except (ssl.SSLError, OSError):
            reason = "tls_session_failed"
        finally:
            self.tracker.close_session(grant)
            session.close()
            with self._lock:
                self._connections.pop(number, None)
            self._event("session_close", connection=number, reason=token(reason))

    def _recv(self, session, state):
        """One bounded read with periodic admission/idle checks; None on timeout."""
        try:
            data = session.connection.recv(65536)
        except socket.timeout:
            data = None
        except ssl.SSLWantReadError:
            data = None
        now = time.monotonic()
        if data:
            state["last_rx"] = now
            with self._lock:
                self.bytes_in += len(data)
        if now - state["checked"] >= self.config.admission_check_s:
            state["checked"] = now
            if not self._still_admitted(session):
                raise _Close("admission_lost")
        if data is None and now - state["last_rx"] > self.config.idle_timeout_s:
            raise _Close("timeout")
        if data == b"":
            raise _Close("peer_closed")
        return data

    def _still_admitted(self, session):
        node = session.identity.node_id
        if session.still_admitted():
            return True
        # Applied inside the product fence so no grant, charge or enqueue can
        # rest on an authorization read before this point.
        with self.tracker.authorization_change(revoked_node=node):
            self.authorizer.remove(node)
        self._event("revoked", node=token(self.node_index.get(node, "other")))
        return False

    def _run_session(self, session, grant, node):
        connection = session.connection
        connection.settimeout(0.5)
        state = {"last_rx": time.monotonic(), "checked": time.monotonic()}
        try:
            if self.config.candidate == "a_framed":
                self._session_a(session, grant, state)
            elif self.config.candidate == "b_chunked":
                self._session_b_chunked(session, grant, state)
            else:
                self._session_b_segment(session, grant, state)
        except _Close as close:
            return close.reason
        return "peer_closed"

    def _sample_socket(self, connection):
        outq, inq = records.socket_queues(connection)
        with self._lock:
            if outq is not None:
                self.max_outq = max(self.max_outq, outq)
            if inq is not None:
                self.max_inq = max(self.max_inq, inq)

    def _handle_bodies(self, bodies, grant, *, segment_blocked=None):
        replies = []
        for body in bodies:
            parsed = wire.parse_body(body)
            if parsed[0] == wire.MEDIA:
                _, source, epoch, sequence, capture_ns, payload = parsed
                if segment_blocked is not None and source in segment_blocked:
                    outcome, reason = "not_processed", "none"
                else:
                    outcome, reason = self._media(grant, source, epoch, sequence, capture_ns,
                                                  payload)
                    if (segment_blocked is not None
                            and outcome in ("backpressured", "rate_limited", "rejected")):
                        segment_blocked.add(source)
                replies.append(wire.ack_frame(source, epoch, sequence, outcome, reason))
            elif parsed[0] == wire.HEARTBEAT:
                if not self.tracker.heartbeat(grant):
                    raise _Close("superseded")
                replies.append(wire.heartbeat_ack_frame(parsed[1]))
            else:
                raise wire.ProtocolError("unexpected frame from agent")
        return b"".join(replies)

    def _session_a(self, session, grant, state):
        reader = wire.FrameReader(self.config.maximum_message_bytes + wire.MEDIA_HEADER_BYTES)
        while not self.stop.is_set():
            data = self._recv(session, state)
            if not data:
                continue
            reply = self._handle_bodies(reader.feed(data), grant)
            if reply:
                self._send(session, reply)

    def _send(self, session, data):
        try:
            session.connection.sendall(data)
        except socket.timeout:
            raise _Close("send_failed") from None
        self._sample_socket(session.connection)

    def _read_head(self, session, state, pending):
        while b"\r\n\r\n" not in pending:
            if len(pending) > wire.MAX_HEAD_BYTES:
                raise wire.ProtocolError("head too large")
            data = self._recv(session, state)
            if data:
                pending += data
        head, _, rest = bytes(pending).partition(b"\r\n\r\n")
        start, headers = wire.parse_head(head)
        return start, headers, bytearray(rest)

    def _route(self, session, start, method, path):
        if start[0] != method or start[1] != path or start[2:] != ["HTTP/1.1"]:
            self._send(session, wire.response_head(404, close=True))
            self._event("route_probe", reason="not_found")
            raise _Close("not_found")

    def _session_b_chunked(self, session, grant, state):
        start, headers, rest = self._read_head(session, state, bytearray())
        self._route(session, start, "POST", wire.STREAM_PATH)
        if headers.get("transfer-encoding") != "chunked" or "content-length" in headers:
            raise wire.ProtocolError("stream must be chunked")
        self._send(session, wire.response_head(200, chunked=True))
        maximum = self.config.maximum_message_bytes + wire.MEDIA_HEADER_BYTES + 4
        decoder = wire.ChunkDecoder(maximum)
        reader = wire.FrameReader(maximum)
        data = bytes(rest)
        while not self.stop.is_set():
            if data:
                bodies = []
                for piece in decoder.feed(data):
                    bodies.extend(reader.feed(piece))
                reply = self._handle_bodies(bodies, grant)
                if reply:
                    self._send(session, wire.chunk(reply))
                if decoder.finished:
                    self._send(session, wire.LAST_CHUNK)
                    raise _Close("peer_closed")
            data = self._recv(session, state)

    def _session_b_segment(self, session, grant, state):
        pending = bytearray()
        maximum = self.config.maximum_message_bytes + wire.MEDIA_HEADER_BYTES
        while not self.stop.is_set():
            start, headers, pending = self._read_head(session, state, pending)
            self._route(session, start, "PUT", wire.SEGMENT_PATH)
            if "transfer-encoding" in headers:
                raise wire.ProtocolError("segment must have a length")
            try:
                length = int(headers.get("content-length", ""))
            except ValueError:
                raise wire.ProtocolError("bad content length") from None
            if not 0 <= length <= self.config.maximum_segment_bytes:
                self._send(session, wire.response_head(413, close=True))
                raise _Close("protocol_error")
            reader = wire.FrameReader(maximum)
            blocked = set()
            replies = []
            remaining = length
            data = bytes(pending[:remaining])
            pending = bytearray(pending[remaining:])
            while True:
                remaining -= len(data)
                if data:
                    replies.append(self._handle_bodies(reader.feed(data), grant,
                                                       segment_blocked=blocked))
                if remaining <= 0:
                    break
                data = self._recv(session, state) or b""
                if len(data) > remaining:
                    pending += data[remaining:]
                    data = data[:remaining]
            if len(reader):
                raise wire.ProtocolError("segment ended inside a frame")
            reply = b"".join(replies)
            self._send(session, wire.response_head(200, content_length=len(reply)) + reply)

    # -- consumer (durable-recording stand-in) ------------------------------
    def _consume(self):
        budget, last = 0.0, time.monotonic()
        while not self.stop.is_set():
            snapshot = self.queue.snapshot()
            with self._lock:
                self.max_queue_messages = max(self.max_queue_messages, snapshot.queued_messages)
                self.max_queue_bytes = max(self.max_queue_bytes, snapshot.queued_bytes)
            limit = 64
            if self.config.drain_rate > 0:
                now = time.monotonic()
                budget = min(self.config.drain_rate, budget + (now - last) * self.config.drain_rate)
                last = now
                limit = int(budget)
            count = self._persist_batch(limit) if limit > 0 else 0
            if self.config.drain_rate > 0:
                budget -= count
            self._drain_gaps()
            if not count:
                time.sleep(0.005)

    def _persist_batch(self, limit):
        """Drain up to ``limit`` units: hash, discard, record watermark; returns count."""
        from app.cameras.remote_agent.continuity import CommittedWatermark
        batch = self.queue.drain(limit)
        latest = {}
        for message in batch:
            hashlib.sha256(message.payload).digest()  # integrity work, then discard
            persisted, gap = self.durable.persist(message)
            if persisted:
                self.persisted += 1
                latest[message.source_id] = message
            else:
                self.durable_duplicates += 1
                self._event("durable_duplicate", **self._source_fields(message.source_id),
                            epoch=message.capture_epoch, sequence=message.sequence)
            if gap is not None:
                self._event("durable_gap", **self._source_fields(message.source_id),
                            epoch=message.capture_epoch, missing_units=gap[0],
                            from_capture_ns=gap[1], to_capture_ns=gap[2])
        if batch:
            self.durable.flush()
            for source, message in latest.items():
                self.tracker.acknowledge_persisted(source, CommittedWatermark(
                    message.node_id, message.capture_epoch, message.sequence,
                    message.capture_time_ns))
        return len(batch)

    def _drain_gaps(self):
        while True:
            gaps = self.tracker.drain_gaps(256)
            for gap in gaps:
                self._event("gap", **self._source_fields(gap.source_id),
                            reason=token(gap.reason.value), epoch=gap.capture_epoch,
                            after_sequence=gap.after_sequence,
                            before_sequence=gap.before_sequence,
                            missing_units=gap.missing_units)
            if len(gaps) < 256:
                return

    # -- sampling -------------------------------------------------------------
    def _sample(self):
        cpu0, wall0 = records.process_cpu_seconds(), time.monotonic()
        while not self.stop.wait(1.0):
            now_ns = time.monotonic_ns()
            flows = {"receiving": 0, "degraded": 0, "interrupted": 0}
            for state in self.tracker.snapshot():
                flows[state.flow.value] += 1
                previous = self.flows.get(state.source_id)
                if state.flow.value == "interrupted" and previous != "interrupted":
                    last = self.last_rx_ns.get(state.source_id)
                    self._event("interrupted", **self._source_fields(state.source_id),
                                since_last_rx_ns=None if last is None else now_ns - last)
                self.flows[state.source_id] = state.flow.value
            snapshot = self.queue.snapshot()
            rss, hwm = records.process_memory()
            with self._lock:
                counts = dict(self.counts)
                connections = list(self._connections.values())
            for connection in connections:
                try:
                    self._sample_socket(connection)
                except (OSError, ValueError):
                    pass
            fields = {}
            if self.config.ss_sampling:
                fields = records.ss_skmem(self.port, local=True) or {}
            with self._lock:
                self.writer.write(
                    "sample", candidate=self.config.candidate,
                    queued_messages=snapshot.queued_messages, queued_bytes=snapshot.queued_bytes,
                    max_queued_messages=self.max_queue_messages,
                    max_queued_bytes=self.max_queue_bytes,
                    limit_queued_messages=self.config.maximum_queued_messages,
                    limit_queued_bytes=self.config.maximum_queued_bytes,
                    rss_bytes=rss, hwm_bytes=hwm,
                    cpu_seconds=records.process_cpu_seconds() - cpu0,
                    wall_seconds=time.monotonic() - wall0,
                    bytes_in=self.bytes_in, persisted=self.persisted,
                    durable_duplicates=self.durable_duplicates,
                    max_outq=self.max_outq, max_inq=self.max_inq,
                    sndbuf=self.config.sndbuf, connections=len(connections),
                    flows_receiving=flows["receiving"], flows_degraded=flows["degraded"],
                    flows_interrupted=flows["interrupted"], **counts, **fields)

    def _finish(self):
        time.sleep(0.2)
        if self.abrupt:
            # SIGUSR1: a crashing Main loses what it had not yet persisted.
            self.discarded_at_stop = len(self.queue.drain(1 << 20))
        else:
            # SIGTERM: a graceful stop persists everything it accepted.
            while self._persist_batch(256):
                pass
        self._drain_gaps()
        for source, epoch, row in self.durable.summary():
            self._event("durable", **self._source_fields(source), epoch=epoch,
                        min_sequence=row[1], max_sequence=row[2], units=row[3],
                        duplicates=row[4])
        quota, period = records.cgroup_cpu_quota()
        rss, hwm = records.process_memory()
        self._event("end", discarded_at_stop=self.discarded_at_stop, persisted=self.persisted,
                    durable_duplicates=self.durable_duplicates, rss_bytes=rss, hwm_bytes=hwm,
                    cpu_seconds=records.process_cpu_seconds(), cpu_quota_us=quota,
                    cpu_period_us=period, **self.counts)
        self.durable.close()


def _open_listener(config, product_open):
    """Product-validated bind, plus SO_REUSEADDR so a restart can rebind in TIME_WAIT.

    ``IngestListenerConfig`` (explicit IP, no wildcard, no Tailscale range,
    distinct from the human listener) is the product validation. The product
    ``open_ingest_listener`` sets no SO_REUSEADDR, so a Main restart while
    earlier connections sit in TIME_WAIT cannot rebind; the harness records
    that as a finding and binds the same validated address itself.
    """
    import ipaddress
    family = (socket.AF_INET6 if ipaddress.ip_address(config.bind_host).version == 6
              else socket.AF_INET)
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((config.bind_host, config.port))
        listener.listen(config.backlog)
    except OSError:
        listener.close()
        return product_open(config)  # fails with the product's fixed reason
    return listener


class _Close(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _abort(connection):
    try:
        connection.close()
    except OSError:
        pass


def run(config, materials_root, state_dir, out_path, run_id):
    writer = records.JsonlWriter(out_path, run_id=run_id, role="receiver")
    state_dir = materials.private_directory(state_dir, exist_ok=True)
    receiver = Receiver(config, materials_root, state_dir, writer)
    def abrupt(*_):
        receiver.abrupt = True
        receiver.stop.set()
    signal.signal(signal.SIGTERM, lambda *_: receiver.stop.set())
    signal.signal(signal.SIGINT, lambda *_: receiver.stop.set())
    signal.signal(signal.SIGUSR1, abrupt)
    try:
        receiver.serve()
    finally:
        if receiver.listener is not None:
            receiver.listener.close()
    writer.close()
    return 0
