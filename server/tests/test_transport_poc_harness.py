"""Synthetic tests for the Issue #15 transport PoC harness (scripts/manual/transport_poc).

The harness is a manual-test tool outside the product; these tests prove its
wire formats, impairment proxy, numeric-only records and gate summarizer, and
run a short loopback matrix (both ends on 127.0.0.1, generated payload bytes,
disposable CA/ledger in a temporary directory). They do not verify any real
LAN, capture host, camera or transport choice.
"""
import argparse
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import uuid4

HARNESS = Path(__file__).resolve().parents[2] / "scripts" / "manual"
AGENT = Path(__file__).resolve().parents[2] / "agent"
_PATHS = (str(HARNESS), str(AGENT))


def _add_paths():
    """Put the harness and the agent first on ``sys.path``; return what was added."""
    added = []
    for path in _PATHS:
        if path not in sys.path:
            sys.path.insert(0, path)
            added.append(path)
    return added


def _remove_paths(added):
    for path in added:
        while path in sys.path:
            sys.path.remove(path)


# Issue #284: discovery imports every test module before any test runs, so a
# path left on ``sys.path`` here reaches every later test in the process. The
# agent tree has its own ``tests`` package; with it first on the path, a
# process spawned by another module (the isolated detector worker receives
# the parent's ``sys.path``) resolves ``tests`` to the agent's package and
# cannot import its ``tests.*`` factory. The paths are present only while this
# module imports the harness and while its own tests run (``setUpModule``).
_IMPORT_PATHS = _add_paths()
try:
    from transport_poc import (holder, materials, matrix, proxy, receiver,  # noqa: E402
                               records, sender, summarize, wire)
finally:
    _remove_paths(_IMPORT_PATHS)


def setUpModule():
    # The harness imports media_capture_agent lazily while the tests run.
    unittest.addModuleCleanup(_remove_paths, _add_paths())

RUN = "r20261011t000000ab"


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class RecordTests(unittest.TestCase):
    def test_only_numbers_and_known_tokens_are_recorded(self):
        records.validate_record({"run_id": RUN, "kind": "gap", "missing_units": None,
                                 "ratio": 0.5, "flag": True, "reason": "sequence_skip"})
        for value in ("192.168.10.5", "/tmp/x", str(uuid4()), "camera serial", "fd7a::1"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    records.validate_record({"kind": "event", "reason": value})
        with self.assertRaises(ValueError):
            records.validate_record({"Bad-Key": 1})
        with self.assertRaises(ValueError):
            records.validate_record({"value": float("nan")})
        self.assertEqual("other", records.token("main_unreachable: 10.0.0.1"))
        self.assertEqual("main_unreachable", records.token("main_unreachable"))

    def test_writer_is_private_append_only_and_validates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x.jsonl"
            writer = records.JsonlWriter(path, run_id=RUN, role="sender")
            writer.write("sample", queued=3)
            with self.assertRaises(ValueError):
                writer.write("sample", note="free text")
            writer.close()
            self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))
            rows = records.read_jsonl(path)
            self.assertEqual([3], [row["queued"] for row in rows])

    def test_percentiles_and_reservoir_are_bounded(self):
        self.assertEqual({50: 5, 95: 10, 99: 10}, records.percentiles(range(1, 11)))
        self.assertEqual({50: None, 95: None, 99: None}, records.percentiles([]))
        reservoir = records.Reservoir(capacity=10)
        for value in range(1000):
            reservoir.add(value)
        self.assertEqual(10, len(reservoir.values))
        self.assertEqual(999, reservoir.maximum)


class WireTests(unittest.TestCase):
    def test_media_and_ack_round_trip(self):
        source = uuid4()
        reader = wire.FrameReader(4096)
        data = (wire.media_frame(source, 2, 7, 99, b"\xff\xd8abc\xff\xd9")
                + wire.ack_frame(source, 2, 7, "duplicate", "already_committed")
                + wire.heartbeat_frame(5))
        bodies = []
        for index in range(len(data)):  # byte-at-a-time
            bodies.extend(reader.feed(data[index:index + 1]))
        parsed = [wire.parse_body(body) for body in bodies]
        self.assertEqual((wire.MEDIA, source, 2, 7, 99, b"\xff\xd8abc\xff\xd9"), parsed[0])
        self.assertEqual((wire.ACK, source, 2, 7, "duplicate", "already_committed"), parsed[1])
        self.assertEqual((wire.HEARTBEAT, 5), parsed[2])

    def test_hello_carries_the_session_nonce(self):
        reader = wire.FrameReader(4096)
        nonce = wire.new_session_nonce()
        self.assertTrue(0 < nonce < 1 << 63)
        bodies = reader.feed(wire.hello_frame(nonce) + wire.heartbeat_frame(5))
        self.assertEqual([(wire.HELLO, nonce), (wire.HEARTBEAT, 5)],
                         [wire.parse_body(body) for body in bodies])
        for bad in (0, 1 << 63):
            with self.assertRaises(ValueError):
                wire.hello_frame(bad)
        with self.assertRaises(wire.ProtocolError):
            wire.parse_body(bytes([wire.HELLO]) + bytes(8))  # zero is not a nonce
        self.assertEqual(42, wire.parse_session("42"))
        for bad in (None, "", "0", "-1", "x", str(1 << 63)):
            with self.assertRaises(wire.ProtocolError):
                wire.parse_session(bad)
        # an HTTP request after the HELLO: the complete frame before it is kept
        reader = wire.FrameReader(4096)
        with self.assertRaises(wire.ProtocolError) as raised:
            reader.feed(wire.hello_frame(nonce) + b"GET /api/v1/sources HTTP/1.1\r\n")
        self.assertEqual([(wire.HELLO, nonce)],
                         [wire.parse_body(body) for body in raised.exception.bodies])
        self.assertEqual(b"GET /", reader.peek(5))

    def test_pre_read_bounds(self):
        with self.assertRaises(wire.ProtocolError):
            wire.FrameReader(16).feed(b"GET / HTTP/1.1\r\n")
        with self.assertRaises(wire.ProtocolError):
            wire.FrameReader(16).feed(b"\x00\x00\x00\x00")
        with self.assertRaises(wire.ProtocolError):
            wire.parse_body(b"\x09")
        with self.assertRaises(wire.ProtocolError):
            wire.parse_head(b"x" * (wire.MAX_HEAD_BYTES + 1))
        with self.assertRaises(wire.ProtocolError):
            wire.parse_head(b"POST / HTTP/1.1\r\nA: 1\r\na: 2")

    def test_chunk_decoder(self):
        decoder = wire.ChunkDecoder(8)
        stream = wire.chunk(b"abc") + wire.chunk(b"defgh") + wire.LAST_CHUNK
        pieces = []
        for index in range(0, len(stream), 3):
            pieces.extend(decoder.feed(stream[index:index + 3]))
        self.assertEqual([b"abc", b"defgh"], pieces)
        self.assertTrue(decoder.finished)
        for bad in (wire.chunk(b"123456789"), b"zz\r\n", b"3\r\nabcXY", b"0\r\nX-T: 1\r\n\r\n",
                    b"3;ext=1\r\nabc\r\n"):
            with self.subTest(bad=bad):
                with self.assertRaises(wire.ProtocolError):
                    wire.ChunkDecoder(8).feed(bad)

    def test_source_ids_are_deterministic_per_node(self):
        node = uuid4()
        self.assertEqual(wire.source_ids(node), wire.source_ids(node))
        self.assertEqual(5, len(set(wire.source_ids(node))))
        self.assertNotEqual(wire.source_ids(node), wire.source_ids(uuid4()))


class _Upstream:
    """Loopback sink that records what reached the 'Main' side."""

    def __init__(self):
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.received = bytearray()
        self.connections = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            self.connections.append(connection)
            threading.Thread(target=self._read, args=(connection,), daemon=True).start()

    def _read(self, connection):
        while True:
            try:
                data = connection.recv(65536)
            except OSError:
                return
            if not data:
                return
            self.received += data

    def close(self):
        self.server.close()
        for connection in self.connections:
            connection.close()


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.writer = records.JsonlWriter(Path(self.directory.name) / "p.jsonl", run_id=RUN,
                                          role="proxy")
        self.addCleanup(self.writer.close)
        self.upstream = _Upstream()
        self.addCleanup(self.upstream.close)
        self.proxy = proxy.Proxy(("127.0.0.1", 0), ("127.0.0.1", self.upstream.port),
                                 self.writer, buffer_bytes=4096)
        threading.Thread(target=self.proxy.serve, daemon=True).start()
        self.addCleanup(self.proxy.close)

    def client(self):
        connection = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=5)
        self.addCleanup(connection.close)
        return connection

    def test_endpoint_and_schedule_validation(self):
        for text in ("0.0.0.0:1", "100.100.1.1:1", "[fd7a:115c:a1e0::1]:1", "127.0.0.1:0"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    proxy.parse_endpoint(text)
        with self.assertRaises(ValueError):
            proxy.parse_endpoint("192.0.2.1:47210", loopback_only=True)
        self.assertEqual(("127.0.0.1", 47210), proxy.parse_endpoint("127.0.0.1:47210",
                                                                    loopback_only=True))
        self.assertEqual([(1.0, "blackhole", 2.0, 0)],
                         proxy.parse_schedule('[[1, "blackhole", 2]]'))
        for bad in ('[[1, "drop"]]', '[[1, "rate_cap", 2]]', '[[-1, "reset"]]'):
            with self.assertRaises(ValueError):
                proxy.parse_schedule(bad)
        with self.assertRaises(ValueError):
            proxy.Proxy(("127.0.0.1", 0), ("127.0.0.1", 1), self.writer, buffer_bytes=1 << 20)

    def test_forwards_and_blackhole_holds_at_most_one_buffer(self):
        connection = self.client()
        connection.sendall(b"hello")
        self.assertTrue(wait_for(lambda: bytes(self.upstream.received) == b"hello"))
        self.proxy.blackhole(True)
        connection.sendall(b"x" * 100000)
        time.sleep(0.6)
        self.assertEqual(b"hello", bytes(self.upstream.received))  # silent: nothing passes
        self.assertLessEqual(self.proxy.max_held, 4096)
        self.proxy.blackhole(False)
        self.assertTrue(wait_for(lambda: len(self.upstream.received) == 100005))

    def test_connection_opened_during_blackhole_is_not_forwarded(self):
        self.proxy.blackhole(True)
        connection = self.client()
        connection.sendall(b"early")
        time.sleep(0.5)
        self.assertEqual([], self.upstream.connections)
        self.proxy.blackhole(False)
        self.assertTrue(wait_for(lambda: bytes(self.upstream.received) == b"early"))

    def test_reset_sends_rst_to_the_client(self):
        connection = self.client()
        connection.sendall(b"a")
        self.assertTrue(wait_for(lambda: self.upstream.received == b"a"))
        self.proxy.reset_all()
        with self.assertRaises((ConnectionResetError, BrokenPipeError)):
            for _ in range(50):
                connection.sendall(b"b" * 1000)
                data = connection.recv(10)
                if data == b"":
                    raise AssertionError("graceful close instead of reset")
                time.sleep(0.05)

    def test_rate_cap_limits_throughput(self):
        self.proxy.rate_cap(40000)
        connection = self.client()
        started = time.monotonic()
        connection.sendall(b"z" * 60000)
        self.assertTrue(wait_for(lambda: len(self.upstream.received) == 60000, timeout=10))
        self.assertGreater(time.monotonic() - started, 1.0)

    def test_schedule_logs_start_and_end(self):
        proxy.run_schedule(self.proxy, [(0.1, "blackhole", 0.2, 0), (0.4, "reset", 0, 0)], 0.8)
        kinds = [(row["kind"], row.get("impairment"))
                 for row in records.read_jsonl(Path(self.directory.name) / "p.jsonl")
                 if row["kind"].startswith("impairment")]
        self.assertEqual([("impairment_start", "blackhole"), ("impairment_end", "blackhole"),
                          ("impairment_start", "reset"), ("impairment_end", "reset")], kinds)


def _write(directory, name, rows, run_id=RUN):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.jsonl"
    with open(path, "w", encoding="ascii") as stream:
        for row in rows:
            stream.write(json.dumps({"run_id": run_id, **row}) + "\n")


_LATE = 10**15  # after every synthetic event


def _holder(samples, *, start=0, end=_LATE + 10):
    """One complete holder execution: ``start``, samples, ``end`` (capture clock)."""
    return ([{"kind": "start", "t_ns": start, "sources": 1, "fps": 30}, *samples,
             {"kind": "end", "t_ns": end, "frames": 100}])


def _complete(orchestrator, processes, *, side="both", codes=None):
    """The orchestrator records of one finished execution: a spawn and a zero
    exit per child (``codes`` overrides), then ``end`` for the side."""
    rows = list(orchestrator)
    for process in processes:
        rows.append({"kind": "spawn", "t_ns": 1, "process": process, "side": side})
    for process in processes:
        rows.append({"kind": "exit", "t_ns": _LATE, "process": process, "side": side,
                     "code": (codes or {}).get(process, 0)})
    rows.append({"kind": "end", "t_ns": _LATE + 1, "scenario": orchestrator[0]["scenario"],
                 "candidate": orchestrator[0]["candidate"], "side": side, "wall_ns": 1})
    return rows


def _durable_runs_for(row, gaps):
    """The persisted runs a consistent durable stand-in would hold for ``row``:
    ``[min, max]`` minus the exact reported gap ranges of the same epoch."""
    holes = sorted((g["after_sequence"] + 1 if isinstance(g.get("after_sequence"), int) else 0,
                    g["before_sequence"]) for g in gaps
                   if (g["source"], g["epoch"]) == (row["source"], row["epoch"])
                   and g.get("reason") in ("sequence_skip", "ingest_refused")
                   and isinstance(g.get("missing_units"), int))
    runs, cursor = [], row["min_sequence"]
    for first, end in holes:
        if end <= cursor or first > row["max_sequence"]:
            continue
        if first > cursor:
            runs.append((cursor, first - 1))
        cursor = max(cursor, end)
    if cursor <= row["max_sequence"]:
        runs.append((cursor, row["max_sequence"]))
    return runs if row["units"] > 0 else []


def _with_durable_runs(rows):
    """Add ``durable_run`` records (and ``runs``) to durable rows without them,
    as the receiver writes them, derived from the rows' own reported gaps."""
    if any(row["kind"] == "durable_run" for row in rows):
        return rows
    gaps = [row for row in rows if row["kind"] == "gap"]
    out = []
    for row in rows:
        if row["kind"] == "durable" and "runs" not in row:
            runs = _durable_runs_for(row, gaps)
            out += [{"kind": "durable_run", "t_ns": row["t_ns"], "source": row["source"],
                     "epoch": row["epoch"], "first_sequence": first, "last_sequence": last}
                    for first, last in runs]
            row = {**row, "runs": len(runs)}
        out.append(row)
    return out


def _finished_receiver(rows):
    """Receiver rows with one ``ready`` and one ``end`` (one process instance)."""
    rows = _with_durable_runs(list(rows))
    if not any(row["kind"] == "ready" for row in rows):
        rows.insert(0, {"kind": "ready", "t_ns": 0, "port": 1})
    # Like a real receiver, one that persisted units opened a session and
    # counts them as accepted (integrity: the Agent's acks came from it).
    units = sum(row["units"] for row in rows if row["kind"] == "durable")
    if units and not any(row["kind"] == "session_open" for row in rows):
        rows.insert(1, {"kind": "session_open", "t_ns": 0})
    if not any(row["kind"] == "end" for row in rows):
        rows.append({"kind": "end", "t_ns": _LATE, "accepted": units})
    return rows


# A real-input sender start: holder frames, with its holder session nonce.
_REAL_START = {"kind": "start", "t_ns": 0, "n_sources": 1, "inputs": "real",
               "source_kind": "holder", "holder_nonce": 77, "epoch": 1}

_ACCOUNTED = {"drops": 0, "drops_sent": 0, "residual": 0, "residual_sent": 0,
              "unit_ranges": 0}


def _produced(generated, fps=30):
    """Production fields of a source that generated ``generated`` units
    continuously at ``fps`` (sender ``end``)."""
    return {"fps": fps, "produce_ns": generated * 10**9 // fps, "first_offer_delay_ns": 0,
            "last_offer_age_ns": 0, "max_offer_gap_ns": 10**9 // fps}


def _sender_end(source, epoch, generated, accepted, *, ranges=(), **fields):
    """A sender ``end`` with complete unit accounting (G2 drop reconciliation).

    ``ranges``: ``(range_kind, first, last)`` sequence runs; ``_finished_sender``
    writes them as ``unit_range`` records before the ``end``.
    """
    end = {"kind": "end", "t_ns": _LATE, "source": source, "epoch": epoch,
           "generated": generated, "accepted": accepted, **_ACCOUNTED,
           **_produced(generated), "unit_ranges": len(ranges), **fields}
    if ranges:
        end["ranges"] = list(ranges)
    return end


def _expand_ranges(rows):
    out = []
    for row in rows:
        if row.get("kind") == "end" and "ranges" in row:
            row = dict(row)
            for kind, first, last in row.pop("ranges"):
                out.append({"kind": "unit_range", "t_ns": row["t_ns"] - 1,
                            "source": row["source"], "epoch": row["epoch"],
                            "range_kind": kind, "first_sequence": first,
                            "last_sequence": last})
        out.append(row)
    return out


def _finished_sender(rows, sources=1, receiver=()):
    """Sender rows with one ``start`` / ``metric`` and at least one ``end``.

    Without explicit ``end`` rows, one per durable row of ``receiver`` is added
    that accounts for every unit up to its last durable sequence (no drops).
    """
    # Like the real sender, every start declares its fps (tests that probe a
    # missing or mismatched fps set the key explicitly, None to omit it).
    rows = [{"fps": 30, **row} if row["kind"] == "start" else row for row in rows]
    rows = [{k: v for k, v in row.items() if not (k == "fps" and v is None)} for row in rows]
    if not any(row["kind"] == "start" for row in rows):
        rows.insert(0, {"kind": "start", "t_ns": 0, "n_sources": sources, "fps": 30})
    if not any(row["kind"] == "end" for row in rows):
        durable = [row for row in receiver if row["kind"] == "durable" and row["source"] >= 0]
        rows += [_sender_end(row["source"], row["epoch"], row["max_sequence"] + 1, row["units"])
                 for row in durable] or [_sender_end(0, 1, 0, 0)]
    if not any(row["kind"] == "metric" for row in rows):
        rows.append({"kind": "metric", "t_ns": _LATE, "payload_bytes": 0})
    return _expand_ranges(rows)


def _restarted(sender_rows, receiver, starts=None, leading_drops=None):
    """Sender rows of a restarted sender: per epoch (ascending) its process
    ``start`` and then the ``end`` of every durable row of that epoch, in
    file order like successive sender processes appending to one file.
    ``leading_drops``: epoch -> n, the epoch's first n sequences dropped."""
    leading_drops = leading_drops or {}
    durable = [row for row in receiver if row["kind"] == "durable"]
    epochs = sorted({row["epoch"] for row in durable})
    starts = starts or [{"kind": "start", "t_ns": 0, "n_sources": 1, "epoch": epoch}
                        for epoch in epochs]
    rows = []
    for start in starts:
        rows.append(start)
        for row in durable:
            if row["epoch"] != start["epoch"]:
                continue
            dropped = leading_drops.get(row["epoch"], 0)
            extra = ({"ranges": [("drop", 0, dropped - 1)], "drops": dropped}
                     if dropped else {})
            rows.append(_sender_end(row["source"], row["epoch"], row["max_sequence"] + 1,
                                    row["units"], **extra))
        rows.append({"kind": "metric", "t_ns": _LATE, "payload_bytes": 0})
    return rows + list(sender_rows)


def _finished_proxy(rows):
    rows = list(rows)
    if not any(row["kind"] == "ready" for row in rows):
        rows.insert(0, {"kind": "ready", "t_ns": 0, "port": 1})
    if not any(row["kind"] == "end" for row in rows):
        rows.append({"kind": "end", "t_ns": _LATE, "bytes_up": 0, "bytes_down": 0})
    return rows


def _session(nonce, opened_s, closed_s=None, connection=1):
    """Receiver records of one Agent connection: its HELLO session nonce at
    ``opened_s`` and (unless None) its close at ``closed_s`` (Main clock, s)."""
    rows = [{"kind": "session_hello", "t_ns": opened_s * 10**9, "connection": connection,
             "session": nonce}]
    if closed_s is not None:
        rows.append({"kind": "session_close", "t_ns": closed_s * 10**9,
                     "connection": connection, "session": nonce, "reason": "peer_closed"})
    return rows


def _base(scenario, candidate="a_framed", sources=1):
    # duration_ns 0: no production coverage required unless a test sets one
    orchestrator = [{"kind": "start", "t_ns": 0, "scenario": scenario, "candidate": candidate,
                     "n_sources": sources, "inputs": "synthetic", "fast": True,
                     "side": "both", "duration_ns": 0}]
    sample = {"kind": "sample", "max_queued_messages": 3, "max_queued_bytes": 100,
              "limit_queued_messages": 10, "limit_queued_bytes": 1000, "max_outq": 10,
              "sndbuf": 1000, "hwm_bytes": 10, "rss_bytes": 10, "accepted": 5}
    receiver = [{"kind": "ready", "t_ns": 0, "port": 1, "stale_after_ns": 2 * 10**9}]
    receiver += [{**sample, "t_ns": index} for index in range(5)]
    sender_sample = {"kind": "sample", "max_pending": 2, "pending_limit": 4, "max_outq": 1,
                     "sndbuf": 1000, "hwm_bytes": 10, "rss_bytes": 10, "payload_bytes": 100,
                     "cpu_seconds": 0.1, "child_cpu_seconds": 0.0}
    sender_rows = [{**sender_sample, "t_ns": index * 10**9} for index in range(5)]
    return orchestrator, receiver, sender_rows


class SummarizerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_dir(self, name, *, orchestrator, receiver, sender_rows, proxy_rows=(),
                two_host=False):
        """One complete execution (spawn/exit/end and process completion
        records are added when a test does not supply them). ``two_host``:
        Main-side (receiver, actions) and capture-side (proxy, sender)
        orchestrator files, as ``--role main`` / ``--role agent`` write them."""
        directory = self.root / name
        sources = orchestrator[0]["n_sources"]
        if two_host:
            _write(directory, "orchestrator-main", _complete(
                [{**orchestrator[0], "side": "main"}, *orchestrator[1:]], ("receiver",),
                side="main"))
            _write(directory, "orchestrator-agent", _complete(
                [{**orchestrator[0], "side": "agent"}], ("proxy", "sender"), side="agent"))
        else:
            _write(directory, "orchestrator-both", _complete(orchestrator, (
                "receiver", "proxy", "sender")))
        _write(directory, "receiver", _finished_receiver(receiver))
        _write(directory, "sender", _finished_sender(sender_rows, sources, receiver))
        _write(directory, "proxy", _finished_proxy(proxy_rows))

    def restarted_run(self, name, *, orchestrator, receiver, durable, sender_rows, starts=None,
                      leading_drops=None):
        """A run whose sender was restarted once per later epoch of
        ``durable``: one sender spawn / exit / start / metric per epoch."""
        rows = _restarted(sender_rows, durable, starts, leading_drops)
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver, sender_rows=rows)
        complete = _complete(orchestrator, ("receiver", "proxy", "sender"))
        extra = sum(1 for row in rows if row["kind"] == "start") - 1
        complete[1:1] = [{"kind": kind, "t_ns": 1, "process": "sender", "side": "both",
                          **({"code": 0} if kind == "exit" else {})}
                         for _ in range(extra) for kind in ("spawn", "exit")]
        _write(self.root / name, "orchestrator-both", complete)

    def rewrite(self, name, role, rows):
        """Replace one file of a run, keeping its completion records."""
        if role == "sender":
            receiver = records.read_jsonl(self.root / name / "receiver.jsonl")
            _write(self.root / name, role, _finished_sender(rows, receiver=receiver))
            return
        finish = {"receiver": _finished_receiver, "proxy": _finished_proxy}[role]
        _write(self.root / name, role, finish(rows))

    def report(self):
        return {row["scenario"]: row for row in summarize.summarize([self.root])["runs"]}

    def test_gap_accuracy_and_duplicates(self):
        orchestrator, receiver, sender_rows = _base("outage_8s")
        durable = {"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1, "min_sequence": 0,
                   "max_sequence": 99, "units": 90, "duplicates": 0}
        gap = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 1, "reason": "sequence_skip",
               "after_sequence": 10, "before_sequence": 21, "missing_units": 10}
        self.run_dir("outage_8s-a_framed", orchestrator=orchestrator,
                     receiver=receiver + [gap, durable], sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["outage_8s"]["g2"])
        self.rewrite("outage_8s-a_framed", "receiver",
                     receiver + [{**gap, "missing_units": 9}, durable])
        self.assertEqual("fail", self.report()["outage_8s"]["g2"])
        self.rewrite("outage_8s-a_framed", "receiver",
                     receiver + [gap, {**durable, "duplicates": 1}])
        self.assertEqual("fail", self.report()["outage_8s"]["g2"])

    def test_capture_restart_requires_unknown_extent(self):
        orchestrator, receiver, sender_rows = _base("capture_restart")
        rows = [{"kind": "durable", "t_ns": 9, "source": 0, "epoch": epoch, "min_sequence": 0,
                 "max_sequence": 9, "units": 10, "duplicates": 0} for epoch in (1, 2)]
        restart = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 2, "reason": "capture_restart",
                   "after_sequence": None, "before_sequence": 0, "missing_units": None}
        self.restarted_run("capture_restart-a_framed", orchestrator=orchestrator,
                           receiver=receiver + rows + [restart], durable=rows,
                           sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["capture_restart"]["g2"])
        self.rewrite("capture_restart-a_framed", "receiver",
                     receiver + rows + [{**restart, "missing_units": 3}])
        self.assertEqual("fail", self.report()["capture_restart"]["g2"])

    def test_negative_authentication_accepts_nothing(self):
        orchestrator, receiver, sender_rows = _base("auth_unpaired")
        end = {"kind": "end", "t_ns": 9, "accepted": 0}
        refused = {"kind": "auth_refused", "t_ns": 2, "reason": "capture_node_not_admitted"}
        attempt = [{"kind": "start", "t_ns": 0}, {"kind": "connect", "t_ns": 1, "connection": 1}]
        self.run_dir("auth_unpaired-a_framed", orchestrator=orchestrator,
                     receiver=receiver + [refused, end], sender_rows=sender_rows + attempt)
        self.assertEqual("pass", self.report()["auth_unpaired"]["g1"])
        self.rewrite("auth_unpaired-a_framed", "receiver",
                     receiver + [refused, {**end, "accepted": 1}])
        self.assertEqual("fail", self.report()["auth_unpaired"]["g1"])

    def test_negative_authentication_requires_attempt_and_refusal(self):
        orchestrator, receiver, sender_rows = _base("auth_other_ca")
        end = {"kind": "end", "t_ns": 9, "accepted": 0}
        refused = {"kind": "auth_refused", "t_ns": 2, "reason": "tls_handshake_failed"}
        start = {"kind": "start", "t_ns": 0}
        attempt = {"kind": "connect", "t_ns": 1, "connection": 1}
        directory = self.root / "auth_other_ca-a_framed"
        # zero accepted, but the sender never attempted a connection
        self.run_dir("auth_other_ca-a_framed", orchestrator=orchestrator,
                     receiver=receiver + [refused, end], sender_rows=sender_rows + [start])
        self.assertEqual("fail", self.report()["auth_other_ca"]["g1"])
        # an attempt, but no Main-side authentication refusal
        self.rewrite("auth_other_ca-a_framed", "receiver", receiver + [end])
        self.rewrite("auth_other_ca-a_framed", "sender", sender_rows + [start, attempt])
        self.assertEqual("fail", self.report()["auth_other_ca"]["g1"])
        # a resource-bound refusal is not an authentication result
        self.rewrite("auth_other_ca-a_framed", "receiver",
                     receiver + [{**refused, "reason": "connection_limit"}, end])
        self.assertEqual("fail", self.report()["auth_other_ca"]["g1"])
        # the Agent-side run is missing entirely: incomplete, never pass
        (directory / "sender.jsonl").unlink()
        self.rewrite("auth_other_ca-a_framed", "receiver", receiver + [refused, end])
        self.assertEqual("unmeasured", self.report()["auth_other_ca"]["g1"])
        self.rewrite("auth_other_ca-a_framed", "sender", sender_rows + [start, attempt])
        row = self.report()["auth_other_ca"]
        self.assertEqual(("pass", 1, 1), (row["g1"], row["connect_attempts"],
                                          row["auth_refusal_evidence"]))

    def test_bounds(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["normal"]["g3"])
        receiver[3]["max_queued_messages"] = 11
        self.rewrite("normal-a_framed", "receiver", receiver)
        self.assertEqual("fail", self.report()["normal"]["g3"])

    def test_reconnect_and_detection_and_protection(self):
        orchestrator, receiver, sender_rows = _base("outage_8s")
        second = 10**9
        proxy_rows = [{"kind": "impairment_start", "t_ns": 10 * second, "impairment": "blackhole",
                       "duration_ns": 5 * second, "rate_bytes": 0},
                      {"kind": "impairment_end", "t_ns": 15 * second, "impairment": "blackhole",
                       "duration_ns": 5 * second, "rate_bytes": 0}]
        events = [{"kind": "start", "t_ns": 0, "loss_timeout_ns": 2 * second},
                  {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                   "t_ns": 12 * second, "source": 0, "idle_ns": 1,
                   "last_committed_capture_ns": 10 * second},
                  {"kind": "closed", "t_ns": 12 * second, "reason": "loss_timeout"},
                  {"kind": "first_accept", "t_ns": 16 * second, "connection": 2, "source": 0}]
        gap = {"kind": "durable_gap", "t_ns": 1, "source": 0, "epoch": 1, "missing_units": 4,
               "from_capture_ns": 10 * second, "to_capture_ns": 15 * second}
        receiver = receiver + [
            {"kind": "durable", "t_ns": 30 * second, "source": 0, "epoch": 1,
             "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0},
            {"kind": "interrupted", "t_ns": 13 * second, "source": 0,
             "since_last_rx_ns": 3 * second}]
        self.run_dir("outage_8s-a_framed", orchestrator=orchestrator, receiver=receiver + [gap],
                     sender_rows=sender_rows + events, proxy_rows=proxy_rows)
        row = self.report()["outage_8s"]
        self.assertEqual(("pass", "pass"), (row["g4"], row["g5"]))
        self.assertEqual(second, row["reconnect_p95_ns"])
        late = [*events[:3], {**events[3], "t_ns": 26 * second}]
        self.rewrite("outage_8s-a_framed", "sender", sender_rows + late)
        self.assertEqual("fail", self.report()["outage_8s"]["g4"])
        self.rewrite("outage_8s-a_framed", "sender", sender_rows + events)
        self.rewrite("outage_8s-a_framed", "receiver",
                     receiver + [{**gap, "to_capture_ns": 700 * second}])
        self.assertEqual("fail", self.report()["outage_8s"]["g5"])

    def test_main_side_outage_requires_agent_detection(self):
        second = 10**9
        for scenario, actions in (
                ("slow_stop_10s", [("sigstop", 10), ("sigcont", 20)]),
                ("main_restart", [("restart_receiver", 10), ("ready", 12)])):
            with self.subTest(scenario=scenario):
                orchestrator, receiver, sender_rows = _base(scenario)
                orchestrator = orchestrator + [
                    {"kind": "action", "t_ns": at * second, "action": action,
                     "duration_ns": 0} for action, at in actions]
                start = {"kind": "start", "t_ns": 0, "loss_timeout_ns": 5 * second}
                name = f"{scenario}-a_framed"
                # the Agent connection (session nonce 11) live across the outage
                receiver = receiver + _session(11, 1, 25)
                # neither side detects anything and there is no durable gap
                self.run_dir(name, orchestrator=orchestrator, receiver=receiver,
                             sender_rows=sender_rows + [start])
                self.assertEqual("fail", self.report()[scenario]["g5"])
                loss = {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                        "t_ns": 15 * second, "source": 0,
                        "idle_ns": 5 * second, "connection": 1, "session": 11,
                        "last_committed_capture_ns": 9 * second}
                self.rewrite(name, "sender", sender_rows + [start, loss])
                row = self.report()[scenario]
                self.assertEqual("pass", row["g5"])
                self.assertEqual((1, 1), (row["main_outages"], row["agent_loss_episodes"]))
                # detection later than the 15 s threshold on the Agent clock
                self.rewrite(name, "sender",
                             sender_rows + [start, {**loss, "idle_ns": 16 * second}])
                self.assertEqual("fail", self.report()[scenario]["g5"])
                # a loss outside the outage window does not count for it
                self.rewrite(name, "sender",
                             sender_rows + [start, {**loss, "t_ns": 2 * second}])
                self.assertEqual("fail", self.report()[scenario]["g5"])
                # two hosts: no clock comparison, one Agent episode per outage
                self.rewrite(name, "sender", sender_rows + [start, {**loss, "t_ns": 1}])
                runs = summarize.summarize([self.root], single_host=False)["runs"]
                self.assertEqual("pass", runs[0]["g5"])
                # the Main-side orchestrator record is missing: incomplete
                _write(self.root / name, "orchestrator-both",
                       _complete(orchestrator[:1], ("receiver", "proxy", "sender")))
                self.assertEqual("unmeasured", self.report()[scenario]["g5"])
                for path in (self.root / name).iterdir():
                    path.unlink()

    def test_capacity_requires_cpu_cap_on_both_sides(self):
        orchestrator, receiver, sender_rows = _base("capacity_4", sources=4)
        durable = [{"kind": "durable", "t_ns": 9, "source": index, "epoch": 1,
                    "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
                   for index in range(4)]
        ends = [{"kind": "end", "t_ns": 9, "source": index, "epoch": 1, "accepted": 10,
                 "rejected": 0, "drops": 0, "generated": 10, **_produced(10)}
                for index in range(4)]
        receiver_end = {"kind": "end", "t_ns": 9, "accepted": 40, "backpressured": 0,
                        "rate_limited": 0, "cpu_quota_us": 200000, "cpu_period_us": 100000}
        metric = {"kind": "metric", "t_ns": 9, "payload_bytes": 100,
                  "cpu_quota_us": 100000, "cpu_period_us": 100000}
        name = "capacity_4-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + durable + [receiver_end],
                     sender_rows=sender_rows + ends + [metric])
        self.assertEqual("pass", self.report()["capacity_4"]["g6"])
        self.rewrite(name, "sender",
                     sender_rows + ends + [{**metric, "cpu_quota_us": None}])
        row = self.report()["capacity_4"]
        self.assertEqual(("fail", True, False), (row["g6"], row["cpu_capped"],
                                                 row["agent_cpu_capped"]))
        self.rewrite(name, "sender", sender_rows + ends + [metric])
        self.rewrite(name, "receiver",
                     receiver + durable + [{**receiver_end, "cpu_quota_us": None}])
        self.assertEqual("fail", self.report()["capacity_4"]["g6"])

    def test_agent_cpu_uses_counter_deltas(self):
        orchestrator, receiver, sender_rows = _base("normal", sources=2)
        # 10 s process / 4 s child CPU consumed before the first sample; then
        # 1 s process + 1 s child over 4 s wall -> 0.5 core / 2 sources.
        for index, row in enumerate(sender_rows):
            row.update(cpu_seconds=10.0 + 0.25 * index, child_cpu_seconds=4.0 + 0.25 * index)
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows)
        self.assertEqual(0.25, self.report()["normal"]["agent_cpu_per_source"])

    def test_cgroup_quota_uses_tightest_ancestor(self):
        root = self.root / "cg"
        leaf = root / "user.slice" / "ss-poc15-main.scope"
        leaf.mkdir(parents=True)
        (root / "cpu.max").write_text("max 100000\n")
        (root / "user.slice" / "cpu.max").write_text("150000 100000\n")
        (leaf / "cpu.max").write_text("max 100000\n")
        cgroup = self.root / "cgroup"
        cgroup.write_text("0::/user.slice/ss-poc15-main.scope\n")
        self.assertEqual((150000, 100000), records.cgroup_cpu_quota(root, cgroup))
        (leaf / "cpu.max").write_text("200000 50000\n")  # 4 cores: looser than parent
        self.assertEqual((150000, 100000), records.cgroup_cpu_quota(root, cgroup))
        (root / "user.slice" / "cpu.max").write_text("max 100000\n")
        (leaf / "cpu.max").write_text("max 100000\n")
        self.assertEqual((None, None), records.cgroup_cpu_quota(root, cgroup))

    def test_fifth_source_refused(self):
        orchestrator, receiver, sender_rows = _base("fifth_refused", sources=5)
        durable = [{"kind": "durable", "t_ns": 9, "source": index, "epoch": 1,
                    "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
                   for index in range(4)]
        ends = [{"kind": "end", "t_ns": 9, "source": index, "epoch": 1,
                 "accepted": 0 if index == 4 else 10, "rejected": 10 if index == 4 else 0,
                 "drops": 0, "rejected_source_capacity": 10 if index == 4 else 0,
                 "generated": 10, **_produced(10)} for index in range(5)]
        receiver_end = {"kind": "end", "t_ns": 9, "accepted": 40, "backpressured": 0,
                        "rate_limited": 0, "cpu_quota_us": 200000}
        self.run_dir("fifth_refused-a_framed", orchestrator=orchestrator,
                     receiver=receiver + durable + [receiver_end], sender_rows=sender_rows + ends)
        self.assertEqual("pass", self.report()["fifth_refused"]["g6"])
        self.rewrite("fifth_refused-a_framed", "receiver", receiver + durable + [
            {**durable[0], "source": 4}, receiver_end])
        self.assertEqual("fail", self.report()["fifth_refused"]["g6"])
        # refused for another reason than the active-source limit
        self.rewrite("fifth_refused-a_framed", "receiver",
                     receiver + durable + [receiver_end])
        self.rewrite("fifth_refused-a_framed", "sender", sender_rows + ends[:4] + [
            {**ends[4], "rejected_source_capacity": 0}])
        self.assertEqual("fail", self.report()["fifth_refused"]["g6"])
        # the reason was not recorded at all
        fifth = {k: v for k, v in ends[4].items() if k != "rejected_source_capacity"}
        self.rewrite("fifth_refused-a_framed", "sender", sender_rows + ends[:4] + [fifth])
        self.assertEqual("unmeasured", self.report()["fifth_refused"]["g6"])

    # -- regressions for the PR #222 review ------------------------------------
    def test_reconnect_episodes_are_matched_once_per_window(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("rst")
        proxy_rows = []
        for at in (10, 12):
            proxy_rows += [{"kind": "impairment_start", "t_ns": at * second,
                            "impairment": "reset", "duration_ns": 0, "rate_bytes": 0},
                           {"kind": "impairment_end", "t_ns": at * second,
                            "impairment": "reset", "duration_ns": 0, "rate_bytes": 0}]
        start = {"kind": "start", "t_ns": 0, "loss_timeout_ns": 2 * second}
        close_1 = {"kind": "closed", "t_ns": int(10.5 * second), "reason": "peer_closed"}
        accept_1 = {"kind": "first_accept", "t_ns": 11 * second, "connection": 2, "source": 0}
        close_2 = {"kind": "closed", "t_ns": int(12.5 * second), "reason": "peer_closed"}
        accept_2 = {"kind": "first_accept", "t_ns": 13 * second, "connection": 3, "source": 0}
        self.run_dir("rst-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows + [start, close_1, accept_1],
                     proxy_rows=proxy_rows)
        # one close/accept episode cannot serve both scheduled resets
        row = self.report()["rst"]
        self.assertEqual(("fail", 1, 2), (row["g4"], row["reconnects"],
                                          row["reconnects_required"]))
        self.rewrite("rst-a_framed", "sender",
                     sender_rows + [start, close_1, accept_1, close_2, accept_2])
        row = self.report()["rst"]
        self.assertEqual(("pass", 2), (row["g4"], row["reconnects"]))
        # two disconnects but a single accepted unit: the second never reconnected
        self.rewrite("rst-a_framed", "sender",
                     sender_rows + [start, close_1, close_2, accept_2])
        self.assertEqual("fail", self.report()["rst"]["g4"])
        # both close/accept pairs after the second reset: the first reset's
        # window ends where the second starts, so it has no episode of its own
        late_close = {**close_1, "t_ns": int(12.2 * second)}
        late_accept = {**accept_1, "t_ns": int(12.4 * second)}
        self.rewrite("rst-a_framed", "sender",
                     sender_rows + [start, late_close, late_accept, close_2, accept_2])
        row = self.report()["rst"]
        self.assertEqual(("fail", 1), (row["g4"], row["reconnects"]))
        # the first reset's close is in its window, but its first accepted
        # unit only came after the second reset started: not its own reconnect
        self.rewrite("rst-a_framed", "sender", sender_rows + [
            start, close_1, {**accept_1, "t_ns": int(12.2 * second)}, close_2, accept_2])
        self.assertEqual("fail", self.report()["rst"]["g4"])

    def test_loss_before_the_first_durable_unit_is_counted(self):
        orchestrator, receiver, sender_rows = _base("normal")
        durable = {"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1, "min_sequence": 5,
                   "max_sequence": 99, "units": 95, "duplicates": 0}
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver + [durable],
                     sender_rows=sender_rows)
        row = self.report()["normal"]
        self.assertEqual(("fail", 5, 0), (row["g2"], row["actual_missing"],
                                          row["reported_missing"]))
        leading = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 1, "reason": "sequence_skip",
                   "after_sequence": None, "before_sequence": 5, "missing_units": 5}
        self.rewrite("normal-a_framed", "receiver", receiver + [leading, durable])
        row = self.report()["normal"]
        self.assertEqual(("pass", 5, 5), (row["g2"], row["actual_missing"],
                                          row["reported_missing"]))
        # Agent evidence: an epoch with accepted units but no durable row at all
        end = {"kind": "end", "t_ns": 9, "source": 0, "epoch": 2, "accepted": 3}
        self.rewrite("normal-a_framed", "sender", sender_rows + [end])
        self.assertEqual("fail", self.report()["normal"]["g2"])

    def _revoked_live(self, *, action=True, revoked_accepted=40, after=(40, 40), retry=True,
                      sender_extra=()):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("auth_revoked_live")
        if action:
            orchestrator = orchestrator + [{"kind": "action", "t_ns": 3 * second,
                                            "action": "revoke", "duration_ns": 0}]
        rows = [receiver[0], {**receiver[1], "t_ns": 2 * second, "accepted": 30}]
        revoked = {"kind": "revoked", "t_ns": 4 * second, "node": "revoked_live"}
        if revoked_accepted is not None:
            revoked["accepted"] = revoked_accepted
        rows.append(revoked)
        rows += [{**receiver[1], "t_ns": (5 + index) * second, "accepted": value}
                 for index, value in enumerate(after)]
        rows += [{"kind": "session_open", "t_ns": second, "connection": 1, "generation": 1},
                 {"kind": "end", "t_ns": 9 * second, "accepted": 40}]
        if retry is True:
            retry = {"kind": "auth_refused", "t_ns": 6 * second,
                     "reason": "capture_node_not_admitted"}
        if retry:
            rows.append(retry)
        self.run_dir("auth_revoked_live-a_framed", orchestrator=orchestrator, receiver=rows,
                     sender_rows=sender_rows + list(sender_extra))
        return self.report()["auth_revoked_live"]["g1"]

    def test_revoked_live_requires_complete_evidence(self):
        second = 10**9
        self.assertEqual("pass", self._revoked_live())
        # samples after detection agree with each other but not with the count
        # at the decision: media was accepted after the revocation
        self.assertEqual("fail", self._revoked_live(after=(41, 41)))
        # older record without the count: the last pre-detection sample is used
        self.assertEqual("fail", self._revoked_live(revoked_accepted=None, after=(40, 40)))
        self.assertEqual("pass", self._revoked_live(revoked_accepted=None, after=(30, 30)))
        # the revoke action is not on record: incomplete, never pass
        self.assertEqual("unmeasured", self._revoked_live(action=False))
        # nothing observed after the decision: "frozen" would be vacuous
        self.assertEqual("unmeasured", self._revoked_live(after=()))
        # no refused re-admission after the revocation
        self.assertEqual("fail", self._revoked_live(retry=False))
        # a sender connect is written before the TLS attempt: on one host it
        # is no evidence that Main refused the revoked node
        connect = {"kind": "connect", "t_ns": 6 * second, "connection": 2}
        self.assertEqual("fail", self._revoked_live(retry=False, sender_extra=[connect]))
        # a refusal before the revocation decision, or for a resource bound
        # (not an authentication result), does not count either
        self.assertEqual("fail", self._revoked_live(retry={
            "kind": "auth_refused", "t_ns": 3 * second, "reason": "capture_node_not_admitted"}))
        self.assertEqual("fail", self._revoked_live(retry={
            "kind": "auth_refused", "t_ns": 6 * second, "reason": "connection_limit"}))

    def test_send_queue_gate_uses_queued_bytes_not_buffer_limit(self):
        orchestrator, receiver, sender_rows = _base("normal")
        # skmem tb (limit, kernel-expanded before SO_SNDBUF) is not a queue
        for row in sender_rows:
            row.update(ss_sockets=1, ss_tb=2_626_560, ss_w=900)
        name = "normal-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver, sender_rows=sender_rows)
        row = self.report()["normal"]
        self.assertEqual(("pass", 2_626_560, True), (row["g3"], row["sender_ss_tb"],
                                                     row["sender_ss_measured"]))
        sender_rows[2]["ss_w"] = 2 * 1000 + 64 * 1024 + 1
        self.rewrite(name, "sender", sender_rows)
        self.assertEqual("fail", self.report()["normal"]["g3"])
        # without ss: synthetic loopback relies on TIOCOUTQ; a real run is incomplete
        for row in sender_rows:
            for key in ("ss_sockets", "ss_tb", "ss_w"):
                row.pop(key)
        self.rewrite(name, "sender", sender_rows)
        self.assertEqual("pass", self.report()["normal"]["g3"])
        _write(self.root / name, "orchestrator-both",
               _complete([{**orchestrator[0], "inputs": "real"}], ("receiver", "proxy", "sender")))
        self.rewrite(name, "sender", [_REAL_START] + sender_rows)
        self.assertEqual("unmeasured", self.report()["normal"]["g3"])
        _write(self.root / name, "orchestrator-both",
               _complete(orchestrator, ("receiver", "proxy", "sender")))
        # too few samples for the warmup comparison, or one side missing
        self.rewrite(name, "sender", sender_rows[:3])
        self.assertEqual("unmeasured", self.report()["normal"]["g3"])
        (self.root / name / "sender.jsonl").unlink()
        self.assertEqual("unmeasured", self.report()["normal"]["g3"])

    def test_silent_outage_needs_proxy_and_main_detection(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("outage_8s")
        proxy_rows = [{"kind": "impairment_start", "t_ns": 10 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0},
                      {"kind": "impairment_end", "t_ns": 13 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0}]
        events = [{"kind": "start", "t_ns": 0, "loss_timeout_ns": int(1.5 * second)},
                  {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                   "t_ns": 12 * second, "source": 0, "idle_ns": 1,
                   "last_committed_capture_ns": 10 * second},
                  {"kind": "closed", "t_ns": 12 * second, "reason": "loss_timeout"},
                  {"kind": "first_accept", "t_ns": 14 * second, "connection": 2, "source": 0}]
        durable = {"kind": "durable", "t_ns": 30 * second, "source": 0, "epoch": 1,
                   "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
        flagged = {"kind": "interrupted", "t_ns": 12 * second, "source": 0,
                   "since_last_rx_ns": 2 * second}
        name = "outage_8s-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + [durable, flagged],
                     sender_rows=sender_rows + events, proxy_rows=proxy_rows)
        self.assertEqual("pass", self.report()["outage_8s"]["g5"])
        # Main never flagged the silent outage itself
        self.rewrite(name, "receiver", receiver + [durable])
        self.assertEqual("fail", self.report()["outage_8s"]["g5"])
        # Main flagged it, but later than 15 s after the last received unit
        self.rewrite(name, "receiver",
                     receiver + [durable, {**flagged, "since_last_rx_ns": 16 * second}])
        self.assertEqual("fail", self.report()["outage_8s"]["g5"])
        # two hosts: one Main detection per window and source, no clock comparison
        self.rewrite(name, "receiver", receiver + [durable, {**flagged, "t_ns": 1}])
        runs = summarize.summarize([self.root], single_host=False)["runs"]
        self.assertEqual("pass", runs[0]["g5"])
        self.rewrite(name, "receiver", receiver + [durable, flagged])
        # the Agent-side proxy record is missing: incomplete, never pass
        (self.root / name / "proxy.jsonl").unlink()
        self.assertEqual("unmeasured", self.report()["outage_8s"]["g5"])
        # fewer blackholes recorded than scheduled
        self.rewrite(name, "proxy", [{"kind": "sample", "t_ns": 1, "max_held": 0,
                                      "buffer_bytes": 65536}])
        self.assertEqual("fail", self.report()["outage_8s"]["g5"])

    def test_agent_detection_is_required_only_past_the_loss_timeout_margin(self):
        # #308: a blackhole equal to the loss timeout is detected only when
        # inbound had already paused before it, so G5 requires an Agent loss
        # episode only for the G4 rule (timeout + LOSS_MARGIN_NS).
        second = 10**9
        orchestrator, receiver, sender_rows = _base("outage_8s")
        proxy_rows = [{"kind": "impairment_start", "t_ns": 10 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0},
                      {"kind": "impairment_end", "t_ns": 13 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0}]
        durable = {"kind": "durable", "t_ns": 30 * second, "source": 0, "epoch": 1,
                   "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
        flagged = {"kind": "interrupted", "t_ns": 12 * second, "source": 0,
                   "since_last_rx_ns": 2 * second}
        name = "outage_8s-a_framed"
        for timeout_s, verdict in ((3, "pass"), (2.5, "pass"), (2, "fail")):
            with self.subTest(loss_timeout_s=timeout_s):
                start = {"kind": "start", "t_ns": 0, "loss_timeout_ns": int(timeout_s * second)}
                self.run_dir(name, orchestrator=orchestrator, receiver=receiver + [durable, flagged],
                             sender_rows=sender_rows + [start], proxy_rows=proxy_rows)
                self.assertEqual(verdict, self.report()["outage_8s"]["g5"])
                for path in (self.root / name).iterdir():
                    path.unlink()

    def test_capacity_needs_every_sender_total(self):
        orchestrator, receiver, sender_rows = _base("capacity_4", sources=4)
        durable = [{"kind": "durable", "t_ns": 9, "source": index, "epoch": 1,
                    "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
                   for index in range(4)]
        ends = [{"kind": "end", "t_ns": 9, "source": index, "epoch": 1, "accepted": 10,
                 "rejected": 0, "drops": 0, "generated": 10, **_produced(10)}
                for index in range(4)]
        receiver_end = {"kind": "end", "t_ns": 9, "accepted": 40, "backpressured": 0,
                        "rate_limited": 0, "cpu_quota_us": 200000, "cpu_period_us": 100000}
        metric = {"kind": "metric", "t_ns": 9, "payload_bytes": 100,
                  "cpu_quota_us": 100000, "cpu_period_us": 100000}
        name = "capacity_4-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + durable + [receiver_end],
                     sender_rows=sender_rows + ends[:3] + [metric])
        self.assertEqual("fail", self.report()["capacity_4"]["g6"])
        _write(self.root / name, "sender",
               [{"kind": "start", "t_ns": 0, "n_sources": 4}, *sender_rows, metric])
        self.assertEqual("unmeasured", self.report()["capacity_4"]["g6"])

    def test_candidate_verdict_requires_every_gate_scenario(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows)
        report = summarize.summarize([self.root])
        self.assertEqual("pass", report["runs"][0]["g3"])
        candidate = report["candidates"][0]
        self.assertEqual("unmeasured", candidate["g3"])
        self.assertEqual(len(summarize.REQUIRED_SCENARIOS["g3"]) - 1,
                         candidate["g3_missing_scenarios"])
        self.assertIn("required scenarios missing", summarize.render(report))
        # a failure is still reported as a failure
        receiver[3]["max_queued_messages"] = 11
        self.rewrite("normal-a_framed", "receiver", receiver)
        self.assertEqual("fail", summarize.summarize([self.root])["candidates"][0]["g3"])

    def test_two_host_records_are_never_compared_across_clocks(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("slow_stop_10s")
        main = [orchestrator[0],
                {"kind": "action", "t_ns": 10 * second, "action": "sigstop", "duration_ns": 0},
                {"kind": "action", "t_ns": 20 * second, "action": "sigcont", "duration_ns": 0}]
        start = {"kind": "start", "t_ns": 0, "loss_timeout_ns": 5 * second}
        # Agent-clock loss far outside the Main-clock window: fine on two hosts
        # (the lost connection was live at the stop on the Main clock)
        loss = {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0, "t_ns": 900 * second, "source": 0,
                "idle_ns": 5 * second, "connection": 1, "session": 11,
                "last_committed_capture_ns": 1}
        self.run_dir("slow_stop_10s-a_framed", orchestrator=main,
                     receiver=receiver + _session(11, 1, 21),
                     sender_rows=sender_rows + [start, loss], two_host=True)
        self.assertEqual("pass", self.report()["slow_stop_10s"]["g5"])
        # only the Main-side directory was passed: the capture side is missing
        (self.root / "slow_stop_10s-a_framed" / "orchestrator-agent.jsonl").unlink()
        row = self.report()["slow_stop_10s"]
        self.assertEqual(("unmeasured", "unmeasured"), (row["integrity"], row["g5"]))

    def test_holder_forwarding_is_checked(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=[{**orchestrator[0], "inputs": "real"}],
                     receiver=receiver, sender_rows=sender_rows)
        sample = {"kind": "sample", "t_ns": 1, "frames": 100, "queue_drops": 0,
                  "forward_drops": 1, "cpu_seconds": 0.1, "child_cpu_seconds": 0.0}
        path = self.root / "holder.jsonl"  # a file at the top level is not a run
        _write(self.root, "holder", _holder([sample, {**sample, "t_ns": 2}]))
        holder = summarize.summarize([self.root], holder_files=[path])["holder"]
        self.assertEqual(("pass", 1, 1), (holder["holder_verdict"],
                                          holder["holder_forward_drops_allowed"],
                                          holder["holder_runs_matched"]))
        _write(self.root, "holder", _holder([{**sample, "forward_drops": 2}]))
        holder = summarize.summarize([self.root], holder_files=[path])["holder"]
        self.assertEqual("fail", holder["holder_verdict"])
        _write(self.root, "holder", _holder([{**sample, "queue_drops": 1}]))
        report = summarize.summarize([self.root], holder_files=[path])
        self.assertEqual("fail", report["holder"]["holder_verdict"])
        self.assertIn("holder: fail", summarize.render(report))

    def test_holder_capture_counters_are_checked(self):
        # Issue #305: a restarted GStreamer child or a framing loss fails the
        # holder; tolerated padding alone does not. Files without the
        # counters (written before them) are judged as before.
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=[{**orchestrator[0], "inputs": "real"}],
                     receiver=receiver, sender_rows=sender_rows)
        sample = {"kind": "sample", "t_ns": 1, "frames": 100, "queue_drops": 0,
                  "forward_drops": 0, "cpu_seconds": 0.1, "child_cpu_seconds": 0.0,
                  "capture_launches": 1, "capture_restarts": 0, "sources_never_launched": 0,
                  "stream_invalid": 0, "padding_tolerated": 50}
        path = self.root / "holder.jsonl"

        def holder(row):
            _write(self.root, "holder", _holder([row]))
            return summarize.summarize([self.root], holder_files=[path])["holder"]

        result = holder(sample)
        self.assertEqual(("pass", 0, 0, 50), (result["holder_verdict"],
                                              result["holder_capture_restarts"],
                                              result["holder_stream_invalid"],
                                              result["holder_padding_tolerated"]))
        # Exactly one restart already fails (no off-by-one slack).
        result = holder({**sample, "capture_launches": 2, "capture_restarts": 1})
        self.assertEqual(("fail", 1), (result["holder_verdict"],
                                       result["holder_capture_restarts"]))
        # Per-source judgement: two sources, A restarted once and B never
        # started; the launch total (2) equals the sources, still a fail.
        result = holder({**sample, "capture_launches": 2, "capture_restarts": 1,
                         "sources_never_launched": 1})
        self.assertEqual(("fail", 1, 1), (result["holder_verdict"],
                                          result["holder_capture_restarts"],
                                          result["holder_sources_never_launched"]))
        result = holder({**sample, "sources_never_launched": 1})
        self.assertEqual(("fail", 1), (result["holder_verdict"],
                                       result["holder_sources_never_launched"]))
        result = holder({**sample, "stream_invalid": 1})
        self.assertEqual(("fail", 1), (result["holder_verdict"],
                                       result["holder_stream_invalid"]))
        for key in ("capture_restarts", "sources_never_launched", "stream_invalid"):
            with self.subTest(key):
                self.assertEqual("fail", holder({**sample, key: None})["holder_verdict"])
                missing = {k: v for k, v in sample.items() if k != key}
                self.assertEqual("fail", holder(missing)["holder_verdict"])
        legacy = {key: value for key, value in sample.items()
                  if key not in summarize.CAPTURE_COUNTER_KEYS}
        self.assertEqual("pass", holder(legacy)["holder_verdict"])
        # Any single counter key makes it a counter sample: the rest must be there.
        for key in summarize.CAPTURE_COUNTER_KEYS:
            with self.subTest(only=key):
                self.assertEqual("fail", holder({**legacy, key: 0})["holder_verdict"])
        _write(self.root, "holder", _holder([{**sample, "stream_invalid": 1}]))
        report = summarize.summarize([self.root], holder_files=[path])
        self.assertIn("stream_invalid 1", summarize.render(report))

    def test_holder_file_must_be_one_complete_execution_of_the_run(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=[{**orchestrator[0], "inputs": "real"}],
                     receiver=receiver, sender_rows=sender_rows)
        sample = {"kind": "sample", "t_ns": 1, "frames": 100, "queue_drops": 0,
                  "forward_drops": 0, "cpu_seconds": 0.1, "child_cpu_seconds": 0.0}
        path = self.root / "holder.jsonl"
        other = self.root / "other.jsonl"

        def verdict(paths=(path,)):
            return summarize.summarize([self.root], holder_files=list(paths))[
                "holder"]["holder_verdict"]

        _write(self.root, "holder", _holder([sample]))
        self.assertEqual("pass", verdict())
        # a holder that crashed / was killed (no end) or never logged its start
        _write(self.root, "holder", _holder([sample])[:-1])
        self.assertEqual("fail", verdict())
        _write(self.root, "holder", _holder([sample])[1:])
        self.assertEqual("fail", verdict())
        # stale: the file of another run (run_id matches no real-input run)
        _write(self.root, "holder", _holder([sample]), run_id="r20261010t000000ab")
        self.assertEqual("unmeasured", verdict())
        # two executions appended to one file (same path reused across runs)
        _write(self.root, "holder", _holder([sample]) + _holder([sample]))
        self.assertEqual("fail", verdict())
        _write(self.root, "holder", _holder([sample]))
        with open(path, "a", encoding="ascii") as stream:
            for row in _holder([sample]):
                stream.write(json.dumps({"run_id": "r20261010t000000ab", **row}) + "\n")
        self.assertEqual("fail", verdict())
        # two files claiming the same run
        _write(self.root, "holder", _holder([sample]))
        _write(self.root, "other", _holder([sample]))
        self.assertEqual("fail", verdict((path, other)))
        # the holder stopped before the run's last sender record
        _write(self.root, "holder", _holder([sample], end=2))
        self.assertEqual("fail", verdict())
        # no samples: forwarding health unknown
        _write(self.root, "holder", _holder([]))
        self.assertEqual("unmeasured", verdict())
        # a second real-input run without a holder record of its own
        _write(self.root / "outage_8s-a_framed", "orchestrator-both", _complete(
            [{**orchestrator[0], "inputs": "real", "scenario": "outage_8s"}],
            ("receiver", "proxy", "sender")), run_id="r20261010t000000ab")
        _write(self.root, "holder", _holder([sample]))
        self.assertEqual("unmeasured", verdict())

    def test_report_is_numeric_and_renders(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows)
        report = summarize.summarize([self.root])
        self.assertEqual("unmeasured", report["candidates"][0]["secondary_packet_loss"])
        self.assertIn("a_framed", summarize.render(report))

    # -- regressions for the PR #222 review (head 946d654) ---------------------
    def _real_run(self, name="normal-a_framed", units=10):
        """A real-input run whose sender fed source 0 from the holder (nonce 77)."""
        orchestrator, receiver, sender_rows = _base(name.rsplit("-", 1)[0])
        orchestrator[0]["inputs"] = "real"
        durable = [{"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1, "min_sequence": 0,
                    "max_sequence": units - 1, "units": units, "duplicates": 0}]
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + durable,
                     sender_rows=[_REAL_START] + sender_rows)
        return orchestrator, receiver, sender_rows

    def _holder_file(self, sessions, *, name="holder", run_id=RUN, samples=None):
        """A complete holder execution; ``sessions``: (nonce, {source: frames})."""
        rows = []
        for nonce, forwarded in sessions:
            rows.append({"kind": "session_open", "t_ns": 1, "nonce": nonce})
            rows += [{"kind": "forwarded", "t_ns": 2, "nonce": nonce, "source": source,
                      "frames": frames} for source, frames in forwarded.items()]
            rows.append({"kind": "session_close", "t_ns": 3, "nonce": nonce})
        sample = {"kind": "sample", "t_ns": 1, "frames": 100, "queue_drops": 0,
                  "forward_drops": 0, "cpu_seconds": 0.1, "child_cpu_seconds": 0.0}
        if samples is None:
            samples = [sample]
        _write(self.root, name, _holder(samples + rows), run_id=run_id)
        return self.root / f"{name}.jsonl"

    def _real_report(self, holder_files):
        report = summarize.summarize([self.root], holder_files=holder_files)
        return {row["scenario"]: row for row in report["runs"]}, report

    def test_real_inputs_from_a_generated_source_fail(self):
        """``--real-inputs`` with ``builtin``/``gst`` is never scored real-and-passing,
        even when a holder file of the same run id shows a session."""
        _orchestrator, _receiver, sender_rows = self._real_run()
        path = self._holder_file([(77, {0: 10})])
        rows, _ = self._real_report([path])
        self.assertEqual(("pass", "pass", "pass"),
                         (rows["normal"]["integrity"], rows["normal"]["g2"],
                          rows["normal"]["holder_linkage"]))
        for kind in ("builtin", "gst", None):
            with self.subTest(source_kind=kind):
                start = {**_REAL_START, "source_kind": kind}
                if kind is None:
                    del start["source_kind"]
                self.rewrite("normal-a_framed", "sender", [start] + sender_rows)
                rows, _ = self._real_report([path])
                self.assertEqual("fail", rows["normal"]["integrity"])
                self.assertEqual(["fail"] * 3, [rows["normal"][g] for g in ("g1", "g2", "g3")])
        # a holder start without its session nonce cannot be linked either
        start = {**_REAL_START}
        del start["holder_nonce"]
        self.rewrite("normal-a_framed", "sender", [start] + sender_rows)
        rows, _ = self._real_report([path])
        self.assertEqual(("fail", "fail"), (rows["normal"]["integrity"], rows["normal"]["g2"]))

    def test_real_run_requires_the_holder_session_of_its_own_sender(self):
        self._real_run()
        # no holder record: never a pass
        rows, _ = self._real_report([])
        self.assertEqual(("unmeasured", "unmeasured"),
                         (rows["normal"]["holder_linkage"], rows["normal"]["g2"]))
        cases = {
            # a concurrent holder serving another sender (another nonce)
            "other sender's session": ([(78, {0: 10})], "fail"),
            # forwarded fewer frames than the sender generated from it
            "fewer forwarded than generated": ([(77, {0: 9})], "fail"),
            # far more forwarded than this sender ever generated
            "forwarded beyond in-flight slack": (
                [(77, {0: 10 + summarize.HOLDER_INFLIGHT_SLACK + 1})], "fail"),
            # the session was opened twice under one nonce
            "nonce reused": ([(77, {0: 10}), (77, {0: 10})], "fail"),
            # no per-source count for the declared source
            "source not forwarded": ([(77, {1: 10})], "fail"),
            "matching session": ([(77, {0: 10})], "pass"),
            "matching session with in-flight frames": (
                [(78, {0: 500}), (77, {0: 10 + summarize.HOLDER_INFLIGHT_SLACK})], "pass"),
        }
        for label, (sessions, expected) in cases.items():
            with self.subTest(case=label):
                path = self._holder_file(sessions)
                rows, _ = self._real_report([path])
                self.assertEqual((expected, expected),
                                 (rows["normal"]["holder_linkage"], rows["normal"]["g2"]))

    def test_restarted_real_sender_needs_a_session_per_epoch(self):
        orchestrator, receiver, sender_rows = _base("capture_restart")
        orchestrator[0]["inputs"] = "real"
        durable = [{"kind": "durable", "t_ns": 9, "source": 0, "epoch": epoch,
                    "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
                   for epoch in (1, 2)]
        restart = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 2,
                   "reason": "capture_restart", "after_sequence": None, "before_sequence": 0,
                   "missing_units": None}
        starts = [_REAL_START, {**_REAL_START, "holder_nonce": 88, "epoch": 2}]
        # two sender executions: two spawns / exits / starts / metrics
        self.restarted_run("capture_restart-a_framed", orchestrator=orchestrator,
                           receiver=receiver + durable + [restart], durable=durable,
                           sender_rows=sender_rows, starts=starts)
        rows, _ = self._real_report([self._holder_file([(77, {0: 10}), (88, {0: 10})])])
        self.assertEqual("pass", rows["capture_restart"]["g2"])
        rows, _ = self._real_report([self._holder_file([(77, {0: 10})])])
        self.assertEqual("fail", rows["capture_restart"]["g2"])
        # two sender starts claiming one nonce are not two sessions
        self.rewrite("capture_restart-a_framed", "sender", _restarted(
            sender_rows, durable, [_REAL_START, {**_REAL_START, "epoch": 2}]))
        rows, _ = self._real_report([self._holder_file([(77, {0: 10})])])
        self.assertEqual("fail", rows["capture_restart"]["integrity"])

    def test_agent_cpu_unmeasured_unless_every_real_run_has_its_holder_cpu(self):
        self._real_run("normal-a_framed")
        self._real_run("capacity_4-a_framed")
        other = "r20261011t000000cd"
        for path in (self.root / "capacity_4-a_framed").glob("*.jsonl"):
            rows = [{k: v for k, v in row.items() if k != "run_id"}
                    for row in records.read_jsonl(path)]
            _write(path.parent, path.stem, rows, run_id=other)
        samples = [{"kind": "sample", "t_ns": index * 10**9, "frames": 100, "queue_drops": 0,
                    "forward_drops": 0, "cpu_seconds": 0.01 * index,
                    "child_cpu_seconds": 0.0} for index in range(2)]
        first = self._holder_file([(77, {0: 10})], samples=samples)
        _rows, report = self._real_report([first])
        candidate = report["candidates"][0]
        # one real run has its holder CPU, the other has none: not a pass
        self.assertEqual("unmeasured", candidate["secondary_agent_cpu"])
        second = self._holder_file([(77, {0: 10})], name="holder-2", run_id=other,
                                   samples=samples)
        _rows, report = self._real_report([first, second])
        self.assertEqual("pass", report["candidates"][0]["secondary_agent_cpu"])

    def test_gap_ranges_must_equal_the_durable_missing_set(self):
        """Matching gap counts are not enough: the reported ranges must be the
        durable stand-in's missing sequences exactly, each reported once."""
        orchestrator, receiver, sender_rows = _base("outage_8s")
        name = "outage_8s-a_framed"
        durable = {"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1, "min_sequence": 0,
                   "max_sequence": 19, "units": 15, "duplicates": 0, "runs": 2}
        runs = [{"kind": "durable_run", "t_ns": 9, "source": 0, "epoch": 1,
                 "first_sequence": first, "last_sequence": last}
                for first, last in ((0, 4), (10, 19))]

        def gap(after, before):
            return {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 1,
                    "reason": "sequence_skip", "after_sequence": after,
                    "before_sequence": before, "missing_units": before - after - 1}

        self.run_dir(name, orchestrator=orchestrator,
                     receiver=receiver + [gap(4, 10)] + runs + [durable],
                     sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["outage_8s"]["g2"])
        cases = {
            # the same 5 units, but two overlapping reports (2 + 3 = 5)
            "double-reported": [gap(4, 7), gap(5, 9)],
            # 5 units reported where Main holds them, none where it lacks them
            "misplaced": [gap(11, 17)],
            # one range reported twice and the count split elsewhere
            "duplicate range": [gap(4, 10), gap(4, 10)],
            # a count that does not match its own range
            "inconsistent count": [{**gap(4, 10), "missing_units": 4}, gap(11, 13)],
        }
        for label, gaps in cases.items():
            with self.subTest(case=label):
                self.rewrite(name, "receiver", receiver + gaps + runs + [durable])
                row = self.report()["outage_8s"]
                self.assertEqual("fail", row["g2"])
                self.assertGreater(row["gap_set_mismatches"], 0)
        # persisted runs that are not the durable row's sequence set
        for label, bad in {
                "units": [*runs[:1], {**runs[1], "last_sequence": 18}],
                "count": runs[:1],
                "overlap": [runs[0], {**runs[1], "first_sequence": 3}]}.items():
            with self.subTest(runs=label):
                self.rewrite(name, "receiver", receiver + [gap(4, 10)] + bad + [durable])
                self.assertEqual("fail", self.report()["outage_8s"]["g2"])
        # older records without the persisted runs: the set cannot be checked
        self.rewrite(name, "receiver",
                     receiver + [gap(4, 10), {**durable, "runs": None}])
        self.assertEqual("unmeasured", self.report()["outage_8s"]["g2"])

    def test_gap_set_after_capture_restart_excludes_the_unknown_extent(self):
        orchestrator, receiver, sender_rows = _base("capture_restart")
        name = "capture_restart-a_framed"
        rows = [{"kind": "durable_run", "t_ns": 9, "source": 0, "epoch": 1,
                 "first_sequence": 0, "last_sequence": 9},
                {"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1, "min_sequence": 0,
                 "max_sequence": 9, "units": 10, "duplicates": 0, "runs": 1},
                {"kind": "durable_run", "t_ns": 9, "source": 0, "epoch": 2,
                 "first_sequence": 3, "last_sequence": 5},
                {"kind": "durable_run", "t_ns": 9, "source": 0, "epoch": 2,
                 "first_sequence": 8, "last_sequence": 9},
                {"kind": "durable", "t_ns": 9, "source": 0, "epoch": 2, "min_sequence": 3,
                 "max_sequence": 9, "units": 5, "duplicates": 0, "runs": 2}]
        restart = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 2,
                   "reason": "capture_restart", "after_sequence": None, "before_sequence": 3,
                   "missing_units": None}
        skip = {"kind": "gap", "t_ns": 6, "source": 0, "epoch": 2, "reason": "sequence_skip",
                "after_sequence": 5, "before_sequence": 8, "missing_units": 2}
        self.restarted_run(name, orchestrator=orchestrator,
                           receiver=receiver + [restart, skip] + rows, durable=rows,
                           sender_rows=sender_rows, leading_drops={2: 3})
        row = self.report()["capture_restart"]
        self.assertEqual(("pass", 3, False), (row["g2"], row["unknown_extent_units"],
                                              row["lossless"]))
        # the same 2 units claimed inside the unknown-extent restart gap instead
        misplaced = {**skip, "after_sequence": None, "before_sequence": 2}
        self.rewrite(name, "receiver", receiver + [restart, misplaced] + rows)
        self.assertEqual("fail", self.report()["capture_restart"]["g2"])

    def test_capture_restart_gap_must_be_a_sender_proven_later_epoch(self):
        """PR #222 review (head 327fd26): a ``capture_restart`` gap only moves
        an epoch's origin when it is the single restart into a later durable
        epoch that the sender records as a new, advancing process."""
        orchestrator, receiver, sender_rows = _base("capture_restart")
        name = "capture_restart-a_framed"

        def epoch_rows(epoch, first, last):
            return [{"kind": "durable_run", "t_ns": 9, "source": 0, "epoch": epoch,
                     "first_sequence": first, "last_sequence": last},
                    {"kind": "durable", "t_ns": 9, "source": 0, "epoch": epoch,
                     "min_sequence": first, "max_sequence": last,
                     "units": last - first + 1, "duplicates": 0, "runs": 1}]

        def restart(epoch, before):
            return {"kind": "gap", "t_ns": 5, "source": 0, "epoch": epoch,
                    "reason": "capture_restart", "after_sequence": None,
                    "before_sequence": before, "missing_units": None}

        def skip(epoch, after, before):
            return {"kind": "gap", "t_ns": 5, "source": 0, "epoch": epoch,
                    "reason": "sequence_skip", "after_sequence": after,
                    "before_sequence": before,
                    "missing_units": before - (0 if after is None else after + 1)}

        def g2(gaps, durable, starts=None, sender=None, leading_drops=None):
            self.restarted_run(name, orchestrator=orchestrator, receiver=receiver + gaps + durable,
                               durable=durable, sender_rows=sender_rows, starts=starts,
                               leading_drops=leading_drops)
            if sender is not None:
                self.rewrite(name, "sender", sender)
            return self.report()["capture_restart"]["g2"]

        late = epoch_rows(1, 10, 19)  # sequences 0-9 of the first epoch never arrived
        second = epoch_rows(2, 0, 9)
        # compliant: the leading loss of epoch 1 is a sequence_skip, epoch 2 a restart
        self.assertEqual("pass", g2([skip(1, None, 10), restart(2, 0)], late + second))
        # a spurious restart at epoch 1's first durable unit hides 0-9
        self.assertEqual("fail", g2([restart(1, 10), restart(2, 0)], late + second))
        self.assertEqual("fail", g2([restart(1, 10)], late))
        # duplicate restart gaps for one transition, or none at all
        self.assertEqual("fail", g2([skip(1, None, 10), restart(2, 0), restart(2, 0)],
                                    late + second))
        self.assertEqual("fail", g2([skip(1, None, 10)], late + second))
        # a restart claimed for an epoch the sender never ran
        self.assertEqual("fail", g2([skip(1, None, 10), restart(2, 0), restart(3, 0)],
                                    late + second))
        # a restart point after the epoch's first durable unit
        later = epoch_rows(2, 3, 9)
        self.assertEqual("fail", g2([skip(1, None, 10), restart(2, 5)], late + later))
        # restart noted at a refused unit, the rest reported as a skip: exact
        # when the Agent accounts for the unknown-extent leading unit 0
        noted = [skip(1, None, 10), restart(2, 1), skip(2, 0, 3)]
        self.assertEqual("pass", g2(noted, late + later, leading_drops={2: 1}))
        row = self.report()["capture_restart"]
        self.assertEqual((1, 0), (row["unknown_extent_units"],
                                  row["unexplained_unknown_extent_units"]))
        # ... and fails when nothing on the Agent side explains it
        self.assertEqual("fail", g2(noted, late + later))
        self.assertEqual(1, self.report()["capture_restart"]["unexplained_unknown_extent_units"])
        gaps = [skip(1, None, 10), restart(2, 0)]
        # sender epochs must advance: process starts out of order
        starts = [{"kind": "start", "t_ns": 0, "n_sources": 1, "epoch": epoch}
                  for epoch in (2, 1)]
        self.assertEqual("fail", g2(gaps, late + second, starts=starts))
        rows = _restarted(sender_rows, late + second)
        self.assertEqual("pass", g2(gaps, late + second, sender=rows))
        # a start that does not state its epoch
        unstated = [{k: v for k, v in row.items() if not (row["kind"] == "start"
                                                          and row["epoch"] == 2 and k == "epoch")}
                    for row in rows]
        self.assertEqual("fail", g2(gaps, late + second, sender=unstated))
        # epoch 1 had not ended when epoch 2 started
        first_end = next(i for i, row in enumerate(rows) if row["kind"] == "end")
        reordered = rows[:first_end] + rows[first_end + 1:]
        second_end = max(i for i, row in enumerate(reordered) if row["kind"] == "end")
        reordered.insert(second_end + 1, rows[first_end])
        self.assertEqual("fail", g2(gaps, late + second, sender=reordered))
        # per-source epoch_start marks, when recorded, are one per epoch
        marked = []
        for row in rows:
            marked.append(row)
            if row["kind"] == "start":
                marked.append({"kind": "epoch_start", "t_ns": 0, "source": 0,
                               "epoch": row["epoch"]})
        self.assertEqual("pass", g2(gaps, late + second, sender=marked))
        self.assertEqual("fail", g2(gaps, late + second,
                                    sender=[row for row in marked
                                            if not (row["kind"] == "epoch_start"
                                                    and row["epoch"] == 2)]))

    def test_sender_acks_need_this_runs_receiver(self):
        """Media the Agent saw accepted must have reached this run's receiver
        (a session and accepted units); otherwise it hit another receiver."""
        orchestrator, receiver, sender_rows = _base("outage_8s")
        name = "outage_8s-a_framed"
        durable = {"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1, "min_sequence": 0,
                   "max_sequence": 9, "units": 10, "duplicates": 0}
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + [durable],
                     sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["outage_8s"]["integrity"])
        rows = _finished_receiver(receiver + [durable])
        for label, changed in (
                ("nothing accepted", [{**r, "accepted": 0} if r["kind"] == "end" else r
                                      for r in rows]),
                ("no session", [r for r in rows if r["kind"] != "session_open"])):
            with self.subTest(case=label):
                _write(self.root / name, "receiver", changed)
                row = self.report()["outage_8s"]
                self.assertEqual(("fail", "fail", "fail"),
                                 (row["integrity"], row["g4"], row["g5"]))

    # -- regressions for the PR #222 review (head a28c38a) ---------------------
    def _durable(self, sources, units=10):
        return [{"kind": "durable", "t_ns": 9, "source": index, "epoch": 1, "min_sequence": 0,
                 "max_sequence": units - 1, "units": units, "duplicates": 0}
                for index in range(sources)]

    def test_records_of_different_executions_never_pass(self):
        orchestrator, receiver, sender_rows = _base("normal")
        name = "normal-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + self._durable(1),
                     sender_rows=sender_rows)
        row = self.report()["normal"]
        self.assertEqual(("pass", "pass", "pass", 1), (row["integrity"], row["g2"], row["g3"],
                                                       row["run_ids"]))
        # the capture-side file comes from another execution (other run_id)
        _write(self.root / name, "sender", _finished_sender(sender_rows),
               run_id="r20261011t000001cd")
        row = self.report()["normal"]
        self.assertEqual(("fail", 2), (row["integrity"], row["run_ids"]))
        self.assertEqual(["fail"] * 3, [row["g1"], row["g2"], row["g3"]])
        self.assertEqual("not_applicable", row["g6"])
        # one file mixes two run_ids
        _write(self.root / name, "sender", _finished_sender(sender_rows))
        with open(self.root / name / "receiver.jsonl", "a", encoding="ascii") as stream:
            stream.write(json.dumps({"run_id": "r20261011t000001cd", "kind": "sample",
                                     "t_ns": 7, **{k: v for k, v in receiver[1].items()
                                                   if k not in ("kind", "t_ns")}}) + "\n")
        self.assertEqual("fail", self.report()["normal"]["g3"])
        # the same run_id re-run into the same directory: two starts on one side
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + self._durable(1),
                     sender_rows=sender_rows)
        rows = _complete(orchestrator, ("receiver", "proxy", "sender"))
        _write(self.root / name, "orchestrator-both", rows + rows)
        self.assertEqual(("fail", "fail"), (self.report()["normal"]["integrity"],
                                            self.report()["normal"]["g2"]))

    def test_crashed_children_or_orchestrator_never_pass(self):
        orchestrator, receiver, sender_rows = _base("normal")
        name = "normal-a_framed"
        processes = ("receiver", "proxy", "sender")
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + self._durable(1),
                     sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["normal"]["g2"])
        complete = _complete(orchestrator, processes)
        cases = {
            "sender exit 1": _complete(orchestrator, processes, codes={"sender": 1}),
            "receiver killed": _complete(orchestrator, processes, codes={"receiver": -9}),
            "no orchestrator end": complete[:-1],
            "spawn without exit": [row for row in complete
                                   if not (row["kind"] == "exit" and row["process"] == "proxy")],
            "child never spawned": [row for row in complete if row.get("process") != "proxy"],
        }
        for label, rows in cases.items():
            with self.subTest(case=label):
                _write(self.root / name, "orchestrator-both", rows)
                row = self.report()["normal"]
                self.assertEqual("fail", row["integrity"])
                self.assertEqual(["fail"] * 3, [row["g1"], row["g2"], row["g3"]])
        _write(self.root / name, "orchestrator-both", complete)
        # a process instance without its own completion record crashed
        _write(self.root / name, "receiver", [r for r in _finished_receiver(receiver)
                                              if r["kind"] != "end"] + self._durable(1))
        self.assertEqual("fail", self.report()["normal"]["g2"])
        self.rewrite(name, "receiver", receiver + self._durable(1))
        _write(self.root / name, "sender", [r for r in _finished_sender(sender_rows)
                                            if r["kind"] != "metric"])
        self.assertEqual("fail", self.report()["normal"]["g2"])
        # a restarted receiver needs a second spawn, exit, ready and end
        self.rewrite(name, "sender", sender_rows)
        _write(self.root / name, "orchestrator-both", complete + [
            {"kind": "spawn", "t_ns": 5, "process": "receiver", "side": "both"},
            {"kind": "exit", "t_ns": 5, "process": "receiver", "side": "both", "code": 0}])
        self.assertEqual("fail", self.report()["normal"]["integrity"])
        second = [{"kind": "end", "t_ns": 5, "accepted": 0},
                  {"kind": "ready", "t_ns": 6, "port": 1},
                  {"kind": "end", "t_ns": 8, "accepted": 10}]
        self.rewrite(name, "receiver", receiver + second + self._durable(1))
        self.assertEqual(("pass", "pass"), (self.report()["normal"]["integrity"],
                                            self.report()["normal"]["g2"]))

    def _topology(self, counts, *, short=None):
        for count in counts:
            scenario = {1: "normal", 2: "sources_2", 3: "sources_3"}[count]
            orchestrator, receiver, sender_rows = _base(scenario, sources=count)
            observed = short if short is not None and count == 2 else count
            self.run_dir(f"{scenario}-a_framed", orchestrator=orchestrator,
                         receiver=receiver + self._durable(observed), sender_rows=sender_rows)

    def _g6_runs(self):
        orchestrator, receiver, sender_rows = _base("capacity_4", sources=4)
        ends = [{"kind": "end", "t_ns": 9, "source": index, "epoch": 1, "accepted": 10,
                 "rejected": 0, "drops": 0, "generated": 10, **_produced(10)}
                for index in range(4)]
        receiver_end = {"kind": "end", "t_ns": 9, "accepted": 40, "backpressured": 0,
                        "rate_limited": 0, "cpu_quota_us": 200000, "cpu_period_us": 100000}
        metric = {"kind": "metric", "t_ns": 9, "payload_bytes": 100,
                  "cpu_quota_us": 100000, "cpu_period_us": 100000}
        self.run_dir("capacity_4-a_framed", orchestrator=orchestrator,
                     receiver=receiver + self._durable(4) + [receiver_end],
                     sender_rows=[{"kind": "start", "t_ns": 0, "n_sources": 4}]
                     + sender_rows + ends + [metric])
        orchestrator, receiver, sender_rows = _base("fifth_refused", sources=5)
        ends = [{"kind": "end", "t_ns": 9, "source": index, "epoch": 1,
                 "accepted": 0 if index == 4 else 10, "rejected": 10 if index == 4 else 0,
                 "drops": 0, "rejected_source_capacity": 10 if index == 4 else 0,
                 "generated": 10, **_produced(10)} for index in range(5)]
        self.run_dir("fifth_refused-a_framed", orchestrator=orchestrator,
                     receiver=receiver + self._durable(4) + [receiver_end],
                     sender_rows=[{"kind": "start", "t_ns": 0, "n_sources": 5}]
                     + sender_rows + ends)

    def test_every_one_to_four_source_count_is_required(self):
        self._g6_runs()
        self._topology((1, 3))
        report = summarize.summarize([self.root])
        candidate = report["candidates"][0]
        runs = {row["scenario"]: row for row in report["runs"]}
        self.assertEqual((4, None), (runs["capacity_4"]["exercised_sources"],
                                     runs["fifth_refused"]["exercised_sources"]))
        self.assertEqual(("unmeasured", 0, 1), (candidate["g6"], candidate["g6_missing_scenarios"],
                                                candidate["g6_missing_source_counts"]))
        self.assertIn("1-4 source counts not exercised for: g2, g3, g6",
                      summarize.render(report))
        # a 2-source run in which only one source reached the durable stand-in
        self._topology((2,), short=1)
        candidate = summarize.summarize([self.root])["candidates"][0]
        self.assertEqual(("unmeasured", 1), (candidate["g6"],
                                             candidate["g6_missing_source_counts"]))
        self._topology((2,))
        candidate = summarize.summarize([self.root])["candidates"][0]
        self.assertEqual(("pass", 0, 0), (candidate["g6"], candidate["g6_missing_scenarios"],
                                          candidate["g6_missing_source_counts"]))
        self.assertNotIn("g1_missing_source_counts", candidate)

    def test_reconnect_requirement_follows_only_the_loss_timeout_rule(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("outage_8s")
        # fast outage_8s: one 4 s blackhole; a 5 s Agent loss timeout requires
        # no disconnect (4 s < 5 s + 1 s), so no reconnect episode is needed
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": 5 * second}
        self.run_dir("outage_8s-a_framed", orchestrator=orchestrator,
                     receiver=receiver + self._durable(1), sender_rows=[start] + sender_rows)
        row = self.report()["outage_8s"]
        self.assertEqual(("pass", 0, 0), (row["g4"], row["reconnects"],
                                          row["reconnects_required"]))
        # a 1.5 s loss timeout requires one, and it is missing
        self.rewrite("outage_8s-a_framed", "sender",
                     [{**start, "loss_timeout_ns": int(1.5 * second)}] + sender_rows)
        row = self.report()["outage_8s"]
        self.assertEqual(("fail", 1), (row["g4"], row["reconnects_required"]))

    def test_post_run_stale_flag_is_not_outage_detection(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("outage_8s")
        proxy_rows = [{"kind": "impairment_start", "t_ns": 10 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0},
                      {"kind": "impairment_end", "t_ns": 13 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0}]
        events = [{"kind": "start", "t_ns": 0, "n_sources": 1,
                   "loss_timeout_ns": int(1.5 * second)},
                  {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                   "t_ns": 12 * second, "source": 0, "idle_ns": 1,
                   "last_committed_capture_ns": 10 * second},
                  {"kind": "closed", "t_ns": 12 * second, "reason": "loss_timeout"},
                  {"kind": "first_accept", "t_ns": 14 * second, "connection": 2, "source": 0}]
        sessions = [{"kind": "session_open", "t_ns": 1, "connection": 1, "generation": 1},
                    {"kind": "session_close", "t_ns": 11 * second, "connection": 1,
                     "reason": "peer_closed"},
                    {"kind": "session_open", "t_ns": 14 * second, "connection": 2,
                     "generation": 1},
                    {"kind": "session_close", "t_ns": 20 * second, "connection": 2,
                     "reason": "peer_closed"}]
        in_window = {"kind": "interrupted", "t_ns": 12 * second, "source": 0,
                     "since_last_rx_ns": 2 * second}
        post_run = {**in_window, "t_ns": 23 * second}
        name = "outage_8s-a_framed"
        for two_host in (False, True):
            with self.subTest(two_host=two_host):
                self.run_dir(name, orchestrator=orchestrator, two_host=two_host,
                             receiver=receiver + sessions + self._durable(1) + [in_window],
                             sender_rows=sender_rows + events, proxy_rows=proxy_rows)
                self.assertEqual("pass", self.report()["outage_8s"]["g5"])
                # only the flag raised after the sender shut down (main grace)
                self.rewrite(name, "receiver",
                             receiver + sessions + self._durable(1) + [post_run])
                row = self.report()["outage_8s"]
                self.assertEqual(("fail", 0), (row["g5"], row["main_detect_matched"]))
                for path in (self.root / name).iterdir():
                    path.unlink()

    def test_real_inputs_declared_by_either_side(self):
        orchestrator, receiver, sender_rows = _base("normal")
        name = "normal-a_framed"
        real_sender = [_REAL_START]
        # the README Main command carries no --real-inputs; the capture side does
        self.run_dir(name, orchestrator=orchestrator, two_host=True,
                     receiver=receiver + self._durable(1), sender_rows=real_sender + sender_rows)
        _write(self.root / name, "orchestrator-agent", _complete(
            [{**orchestrator[0], "side": "agent", "inputs": "real"}], ("proxy", "sender"),
            side="agent"))
        row = self.report()["normal"]
        self.assertEqual(("real", False, "unmeasured"), (row["inputs"], row["inputs_consistent"],
                                                         row["integrity"]))
        self.assertEqual("unmeasured", row["g3"])  # never a synthetic pass without ss
        # both sides declare real inputs: consistent, still no ss -> unmeasured
        _write(self.root / name, "orchestrator-main", _complete(
            [{**orchestrator[0], "side": "main", "inputs": "real"}], ("receiver",),
            side="main"))
        row = self.report()["normal"]
        self.assertEqual(("real", True, "pass", "unmeasured"),
                         (row["inputs"], row["inputs_consistent"], row["integrity"], row["g3"]))
        # the holder allowance counts this real run regardless of file order
        sample = {"kind": "sample", "t_ns": 1, "frames": 100, "queue_drops": 0,
                  "forward_drops": 1, "cpu_seconds": 0.1, "child_cpu_seconds": 0.0}
        _write(self.root, "holder", _holder([sample]))
        holder = summarize.summarize([self.root], holder_files=[self.root / "holder.jsonl"])
        self.assertEqual(("pass", 1), (holder["holder"]["holder_verdict"],
                                       holder["holder"]["holder_forward_drops_allowed"]))
        # an ss sample that found no socket is not an ss measurement
        for sample_row in sender_rows + receiver[1:]:
            sample_row.update(ss_sockets=0, ss_w=0, ss_tb=0)
        self.rewrite(name, "receiver", receiver + self._durable(1))
        self.rewrite(name, "sender", real_sender + sender_rows)
        row = self.report()["normal"]
        self.assertEqual((False, "unmeasured"), (row["sender_ss_measured"], row["g3"]))

    def test_continuity_needs_agent_side_evidence(self):
        orchestrator, receiver, sender_rows = _base("capture_restart")
        rows = [{"kind": "durable", "t_ns": 9, "source": 0, "epoch": epoch, "min_sequence": 0,
                 "max_sequence": 9, "units": 10, "duplicates": 0} for epoch in (1, 2)]
        restart = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 2, "reason": "capture_restart",
                   "after_sequence": None, "before_sequence": 0, "missing_units": None}
        name = "capture_restart-a_framed"
        self.restarted_run(name, orchestrator=orchestrator, receiver=receiver + rows + [restart],
                           durable=rows, sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["capture_restart"]["g2"])
        (self.root / name / "sender.jsonl").unlink()
        self.assertEqual("unmeasured", self.report()["capture_restart"]["g2"])
        # a (twice started) sender that left no per-source totals
        _write(self.root / name, "sender",
               [row for epoch in (1, 2) for row in (
                   {"kind": "start", "t_ns": 0, "n_sources": 1, "epoch": epoch},
                   {"kind": "metric", "t_ns": 9, "payload_bytes": 0})] + sender_rows)
        self.assertEqual("unmeasured", self.report()["capture_restart"]["g2"])

    def test_two_host_receiver_stop_close_burst_is_one_episode(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("main_restart")
        orchestrator = orchestrator + [
            {"kind": "action", "t_ns": 10 * second, "action": "restart_receiver",
             "duration_ns": 0},
            {"kind": "action", "t_ns": 12 * second, "action": "ready", "duration_ns": 0}]
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": 5 * second}
        # Agent clock: the stopping receiver drops the live connection (11),
        # then accepts one more connection (12) and drops it in _finish, then
        # the new receiver accepts (13)
        lost = {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                "t_ns": 500 * second, "source": 0, "idle_ns": 1,
                "connection": 1, "session": 11, "last_committed_capture_ns": 1}
        burst = [{"kind": "closed", "t_ns": 500 * second, "reason": "peer_closed",
                  "session": 11},
                 {"kind": "closed", "t_ns": 501 * second, "reason": "tls_session_failed",
                  "session": 12},
                 {"kind": "connected", "t_ns": 502 * second + second // 2, "connection": 3,
                  "session": 13},
                 {"kind": "first_accept", "t_ns": 503 * second, "connection": 3, "source": 0,
                  "session": 13}]
        # Main clock: the stopping receiver closes 11 at 11 s (the old process
        # ends before the new one is ready: a session left open past the
        # restart window would not be its detection)
        sessions = _session(11, 1, 11) + _session(12, 11, 11, 2) + _session(13, 13, 30, 1)
        receiver = receiver + self._durable(1) + sessions
        self.run_dir("main_restart-a_framed", orchestrator=orchestrator, two_host=True,
                     receiver=receiver, sender_rows=[start] + sender_rows + [lost] + burst)
        row = self.report()["main_restart"]
        self.assertEqual(("pass", 1, 1), (row["g4"], row["reconnects"],
                                          row["reconnects_required"]))
        # from the new receiver's ready (12 s) to Main greeting 13 (13 s), plus
        # 13's connected -> first accept (0.5 s, Agent clock); 12 was greeted
        # by the stopping receiver before the window end and does not count
        self.assertEqual(3 * second // 2, row["reconnect_p95_ns"])
        # the connection live at the restart has no accepted unit after it
        self.rewrite("main_restart-a_framed", "sender",
                     [start] + sender_rows + [lost] + burst[:2])
        self.assertEqual("fail", self.report()["main_restart"]["g4"])

    def test_every_scheduled_reset_needs_agent_loss_detection(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("rst")
        proxy_rows = []
        for at in (10, 12):
            proxy_rows += [{"kind": "impairment_start", "t_ns": at * second,
                            "impairment": "reset", "duration_ns": 0, "rate_bytes": 0},
                           {"kind": "impairment_end", "t_ns": at * second,
                            "impairment": "reset", "duration_ns": 0, "rate_bytes": 0}]
        losses = [{"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                   "t_ns": at * second + 1, "source": 0, "idle_ns": 1,
                   "connection": index, "last_committed_capture_ns": 1}
                  for index, at in enumerate((10, 12), 1)]
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": 2 * second}
        name = "rst-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + self._durable(1),
                     sender_rows=[start] + sender_rows + losses, proxy_rows=proxy_rows)
        row = self.report()["rst"]
        self.assertEqual(("pass", 2), (row["g5"], row["resets_recorded"]))
        self.rewrite(name, "sender", [start] + sender_rows + losses[:1])
        self.assertEqual("fail", self.report()["rst"]["g5"])
        self.rewrite(name, "sender", [start] + sender_rows + losses)
        (self.root / name / "proxy.jsonl").unlink()
        self.assertEqual("unmeasured", self.report()["rst"]["g5"])

    # -- regressions for the PR #222 review (head 30e17ff) ---------------------
    def test_one_loss_episode_never_covers_two_resets(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("rst", sources=2)
        proxy_rows = []
        for at in (10, 12):
            proxy_rows += [{"kind": "impairment_start", "t_ns": at * second,
                            "impairment": "reset", "duration_ns": 0, "rate_bytes": 0},
                           {"kind": "impairment_end", "t_ns": at * second,
                            "impairment": "reset", "duration_ns": 0, "rate_bytes": 0}]
        start = {"kind": "start", "t_ns": 0, "n_sources": 2, "loss_timeout_ns": 2 * second}

        def loss(at, connection, source):
            return {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                    "t_ns": at, "source": source, "idle_ns": 1,
                    "connection": connection, "last_committed_capture_ns": 1}

        # one connection lost after the second reset, recorded once per source:
        # within 15 s of both resets, but it is one episode
        after_second = [loss(12 * second + 1, 1, 0), loss(12 * second + 2, 1, 1)]
        name = "rst-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + self._durable(2),
                     sender_rows=[start] + sender_rows + after_second, proxy_rows=proxy_rows)
        self.assertEqual("fail", self.report()["rst"]["g5"])
        # one episode per reset (each recorded for both sources) passes
        both = [loss(10 * second + 1, 1, 0), loss(10 * second + 2, 1, 1),
                loss(12 * second + 1, 2, 0), loss(12 * second + 2, 2, 1)]
        self.rewrite(name, "sender", [start] + sender_rows + both)
        self.assertEqual("pass", self.report()["rst"]["g5"])
        # matching consumes episodes in time order, one each
        self.assertEqual([1, None], summarize._match_episodes([10, 12], [11], 15))
        self.assertEqual([1, 9], summarize._match_episodes([12, 10], [11, 21]))
        self.assertEqual([5, 7], summarize._loss_episodes(
            [{"t_ns": 7, "connection": 2}, {"t_ns": 6, "connection": 1},
             {"t_ns": 5, "connection": 1}]))

    def test_sender_drops_are_reconciled_with_main(self):
        orchestrator, receiver, sender_rows = _base("normal")
        name = "normal-a_framed"
        durable = self._durable(1, units=100)  # sequences 0..99, contiguous: no gap at Main
        start = {"kind": "start", "t_ns": 0, "n_sources": 1}

        def run(**fields):
            end = _sender_end(0, 1, fields.pop("generated", 110), 100, **fields)
            self.run_dir(name, orchestrator=orchestrator, receiver=receiver + durable,
                         sender_rows=[start] + sender_rows + [end])
            return self.report()["normal"]

        # ten trailing units dropped by backpressure: no gap reaches Main, but
        # the Agent accounted for them
        row = run(drops=10, ranges=[("drop", 100, 109)])
        self.assertEqual(("pass", "pass", 10, False),
                         (row["g2"], row["drop_accounting"], row["agent_accounted_tail_units"],
                          row["lossless"]))
        # still held at shutdown (not lost) is fine too
        self.assertEqual("pass", run(residual=10, ranges=[("residual", 100, 109)])["g2"])
        # trailing units neither dropped nor held: vanished silently
        row = run()
        self.assertEqual(("fail", 10), (row["g2"], row["unexplained_loss_units"]))
        # drops the Agent recorded that appear neither as Main gaps nor in the
        # tail: the named sequences are Main's durable units
        row = run(generated=100, drops=5, ranges=[("drop", 20, 24)])
        self.assertEqual(("fail", 5), (row["g2"], row["durable_named_units"]))
        # ... unless those units had been sent unacknowledged (Main may hold them)
        self.assertEqual("pass", run(generated=100, drops=5, drops_sent=5,
                                     ranges=[("drop", 20, 24)])["g2"])
        # ranges that do not describe the counts
        self.assertEqual("fail", run(drops=10, ranges=[("drop", 100, 105)])["g2"])
        # Claude review of 1dbbd1d (H3): a range beyond the generated units
        # cannot explain a lost tail (5 units 105..109 vanished)
        self.assertEqual("fail", run(drops=10, ranges=[("drop", 110, 119)])["g2"])
        self.assertEqual("fail", run(drops=10, ranges=[("drop", 100, 104),
                                                       ("drop", 110, 114)])["g2"])
        # (H4) the same 5-unit range written twice while 10 tail units are lost
        self.assertEqual("fail", run(drops=10, ranges=[("drop", 100, 104),
                                                       ("drop", 100, 104)])["g2"])
        # a unit named both dropped and residual is still one unit
        self.assertEqual("fail", run(drops=5, residual=5, ranges=[
            ("drop", 100, 104), ("residual", 104, 108)])["g2"])
        # only a sent-unacknowledged unit may be durable on Main
        self.assertEqual("fail", run(drops=15, drops_sent=2, ranges=[
            ("drop", 30, 34), ("drop", 100, 109)])["g2"])
        # a refused unit is never durable, whatever was sent
        self.assertEqual("fail", run(drops=10, rejected=1, drops_sent=5, ranges=[
            ("rejected", 30, 30), ("drop", 100, 109)])["g2"])
        self.assertEqual("fail", run(drops=10, ranges=[("drop", 100, 109)],
                                     unit_ranges=2)["g2"])
        # an interior drop is Main's reported gap
        gap = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 1, "reason": "sequence_skip",
               "after_sequence": 10, "before_sequence": 16, "missing_units": 5}
        interior = [{**durable[0], "units": 95}]
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + interior + [gap],
                     sender_rows=[start] + sender_rows + [_sender_end(
                         0, 1, 100, 95, drops=5, ranges=[("drop", 11, 15)])])
        self.assertEqual("pass", self.report()["normal"]["g2"])
        # (I1, Claude review of 1dbbd1d) the same counts, but the drop range
        # names durable sequences 30..34 instead of Main's gap 11..15
        self.rewrite(name, "sender", [start] + sender_rows + [_sender_end(
            0, 1, 100, 95, drops=5, ranges=[("drop", 30, 34)])])
        row = self.report()["normal"]
        self.assertEqual(("fail", 5), (row["g2"], row["durable_named_units"]))
        # a sender end without the accounting counts cannot be reconciled
        legacy = {"kind": "end", "t_ns": 9, "source": 0, "epoch": 1, "accepted": 100,
                  "drops": 0}
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + durable,
                     sender_rows=[start] + sender_rows + [legacy])
        row = self.report()["normal"]
        self.assertEqual(("unmeasured", "unmeasured"), (row["g2"], row["drop_accounting"]))
        # durable units of an epoch the Agent gave no totals for
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + durable,
                     sender_rows=[start] + sender_rows + [_sender_end(0, 2, 0, 0)])
        row = self.report()["normal"]
        self.assertEqual(("unmeasured", "unmeasured"), (row["g2"], row["drop_accounting"]))

    def test_declared_fps_is_one_value(self):
        """Claude review of 1dbbd1d: production is scored against the fps the
        sender declared, so every record of it must agree."""
        second = 10**9
        orchestrator, receiver, sender_rows = _base("normal")
        orchestrator = [{**orchestrator[0], "duration_ns": 8 * second, "fps": 30}]
        name = "normal-a_framed"
        durable = self._durable(1, units=240)

        def production(start_fps=30, end_fps=30, generated=240, orchestrator_fps=30,
                       **end_fields):
            end = _sender_end(0, 1, generated, generated, **{
                **_produced(generated, fps=end_fps), "produce_ns": 8 * second,
                **end_fields})
            start = {"kind": "start", "t_ns": 0, "n_sources": 1, "fps": start_fps}
            self.run_dir(name, orchestrator=[{**orchestrator[0], "fps": orchestrator_fps}],
                         receiver=receiver + durable, sender_rows=[start] + sender_rows + [end])
            return self.report()["normal"]["production"]

        self.assertEqual("pass", production())
        # the end row claims another rate than the start
        self.assertEqual("fail", production(end_fps=10, generated=60))
        # the sender declared 1 fps (7 units in 8 s pass at 1 fps) but the
        # orchestrator ran the scenario at 30 fps
        self.assertEqual("fail", production(start_fps=1, end_fps=1, generated=7))
        # a sender start without its fps
        self.assertEqual("unmeasured", production(start_fps=None))
        # continuity fields: missing is unmeasured, None only with no units
        for field in ("last_offer_age_ns", "max_offer_gap_ns", "first_offer_delay_ns"):
            with self.subTest(field=field):
                self.assertEqual("unmeasured", production(**{field: None}))

    def test_mid_epoch_drops_never_explain_a_lost_tail(self):
        """Claude review of 85d91b3: drops / refusals already reported by Main
        as interior gaps must not also explain trailing units that vanished."""
        orchestrator, receiver, sender_rows = _base("normal")
        name = "normal-a_framed"
        start = {"kind": "start", "t_ns": 0, "n_sources": 1}

        def g2(generated, top, interior, reason="sequence_skip", receiver_end=None, **end):
            # Main holds 0..top except ``interior`` units after sequence 9
            durable = [{"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1,
                        "min_sequence": 0, "max_sequence": top,
                        "units": top + 1 - interior, "duplicates": 0}]
            gaps = [{"kind": "gap", "t_ns": 5, "source": 0, "epoch": 1, "reason": reason,
                     "after_sequence": 9, "before_sequence": 10 + interior,
                     "missing_units": interior}] if interior else []
            extra = [receiver_end] if receiver_end else []
            self.run_dir(name, orchestrator=orchestrator,
                         receiver=receiver + durable + gaps + extra,
                         sender_rows=[start] + sender_rows + [_sender_end(
                             0, 1, generated, top + 1 - interior, **end)])
            return self.report()["normal"]

        mid = [("drop", 10, 103)]
        # slow_stop_60s shape: 94 mid drops (Main gap) and 50 trailing units
        # acknowledged by Main and then lost
        row = g2(250, 199, 94, drops=94, ranges=mid)
        self.assertEqual(("fail", "fail", 50), (row["g2"], row["drop_accounting"],
                                                row["unexplained_loss_units"]))
        # the same mid drops with the tail genuinely dropped at the live edge
        row = g2(250, 199, 94, drops=144, ranges=mid + [("drop", 200, 249)])
        self.assertEqual(("pass", 50), (row["g2"], row["agent_accounted_tail_units"]))
        # outage_120s shape: 100 mid drops cannot cover 100 lost trailing units
        self.assertEqual("fail", g2(400, 299, 100, drops=100,
                                    ranges=[("drop", 10, 109)])["g2"])
        # normal: 3 mid ingest refusals (Main gap) and 3 trailing units lost
        refused = g2(103, 99, 3, reason="ingest_refused", rejected=3,
                     ranges=[("rejected", 10, 12)])
        self.assertEqual("fail", refused["g2"])
        # more accounted after Main's last sequence than units exist (slow_drain
        # "drops -2"): the records are inconsistent
        self.assertEqual("fail", g2(100, 97, 0, drops=4, ranges=[("drop", 96, 99)])["g2"])
        # Main's last receiver accepted units and then discarded them at stop
        end = {"kind": "end", "t_ns": _LATE + 5, "accepted": 100, "discarded_at_stop": 7}
        row = g2(100, 99, 0, receiver_end=end)
        self.assertEqual(("fail", 7), (row["g2"], row["final_discarded_at_stop"]))
        self.assertEqual("pass", g2(100, 99, 0, receiver_end={**end, "discarded_at_stop": 0})[
            "g2"])
        # (an abrupt stop earlier in the run is reported by the restarted
        # receiver: main_restart in the loopback matrix tests)

    def test_sender_records_its_unit_accounting(self):
        state = sender.SourceState(0, uuid4(), 2)
        unsent = sender.Unit(1, 1, b"x")
        sent = sender.Unit(2, 2, b"x")
        sent.sent_ns = 5
        state.drop(unsent)
        state.drop(sent)
        state.drop(sender.Unit(7, 7, b"x"))
        state.reject(sender.Unit(3, 3, b"x"))
        self.assertEqual((3, 1), (state.drops, state.drops_sent))
        self.assertEqual(([[1, 2], [7, 7]], [[3, 3]]), (state.drop_ranges, state.reject_ranges))
        self.assertEqual([[1, 3], [5, 5]], sender.sequence_ranges([5, 3, 1, 2]))

    def test_sides_must_declare_the_same_run(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("slow_stop_10s")
        main = [orchestrator[0],
                {"kind": "action", "t_ns": 10 * second, "action": "sigstop", "duration_ns": 0},
                {"kind": "action", "t_ns": 20 * second, "action": "sigcont", "duration_ns": 0}]
        start = {"kind": "start", "t_ns": 0, "loss_timeout_ns": 5 * second}
        loss = {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0, "t_ns": 900 * second, "source": 0,
                "idle_ns": 5 * second, "connection": 1, "session": 11,
                "last_committed_capture_ns": 1}
        name = "slow_stop_10s-a_framed"
        self.run_dir(name, orchestrator=main,
                     receiver=receiver + self._durable(1) + _session(11, 1, 21),
                     sender_rows=sender_rows + [start, loss], two_host=True)
        report = summarize.summarize([self.root])
        row = report["runs"][0]
        self.assertEqual(("pass", "pass", True), (row["integrity"], row["g5"], row["fast"]))
        candidate = report["candidates"][0]
        self.assertEqual((True, 1), (candidate["fast"], candidate["fast_runs"]))
        self.assertIn("fast (CI) timing runs: 1 of 1", summarize.render(report))
        path = self.root / name / "orchestrator-agent.jsonl"
        original = records.read_jsonl(path)
        for field, value in (("fast", False), ("duration_ns", 12 * second),
                             ("scenario", "slow_stop_60s"), ("candidate", "b_chunked")):
            with self.subTest(field=field):
                _write(self.root / name, "orchestrator-agent",
                       [{**item, field: value} if item["kind"] == "start" else item
                        for item in original])
                row = summarize.summarize([self.root])["runs"][0]
                self.assertEqual("unmeasured", row["integrity"])
                self.assertNotIn("pass", [row[g] for g in summarize.GATES])
        # every run on full timing: the candidate is not marked fast
        for item in (path, self.root / name / "orchestrator-main.jsonl"):
            rows = records.read_jsonl(item)
            _write(self.root / name, item.stem,
                   [{**r, "fast": False} if r["kind"] == "start" else r for r in rows])
        report = summarize.summarize([self.root])
        self.assertEqual((False, 0), (report["candidates"][0]["fast"],
                                      report["candidates"][0]["fast_runs"]))
        self.assertNotIn("fast (CI)", summarize.render(report))

    # -- regressions for the PR #222 review (head 85d91b3) ---------------------
    def test_sources_must_produce_continuously_for_the_run(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("sources_2", sources=2)
        orchestrator[0]["duration_ns"] = 10 * second
        durable = self._durable(2, units=300)
        start = {"kind": "start", "t_ns": 0, "n_sources": 2, "fps": 30}
        name = "sources_2-a_framed"

        def run(*ends, extra=()):
            self.run_dir(name, orchestrator=orchestrator, receiver=receiver + durable,
                         sender_rows=[start] + sender_rows + list(extra) + list(ends))
            return self.report()["sources_2"]

        full = [_sender_end(source, 1, 300, 300) for source in range(2)]
        row = run(*full)
        self.assertEqual(("pass", "pass", 2), (row["integrity"], row["production"],
                                               row["exercised_sources"]))
        # source 1 hit EOF after a few frames but some reached Main: the sender
        # recorded producer_failed (and exited non-zero)
        failed = {"kind": "producer_failed", "t_ns": 2 * second, "source": 1, "reason": "eof"}
        row = run(*full, extra=[failed])
        self.assertEqual(("fail", "fail", None), (row["integrity"], row["production"],
                                                  row["exercised_sources"]))
        self.assertNotIn("pass", [row[g] for g in summarize.GATES])
        # no producer_failed record, but source 1 produced for 2 s of 10 s
        row = run(full[0], _sender_end(1, 1, 60, 60))
        self.assertEqual(("fail", 1), (row["production"], row["production_uncovered_sources"]))
        # ran the whole time but generated far fewer units than the declared fps
        slow = _sender_end(1, 1, 50, 50, produce_ns=10 * second)
        row = run(full[0], slow)
        self.assertEqual("fail", row["production"])
        self.assertGreater(row["production_shortfall_units"], 0)
        # a long pause, or a producer that stopped well before the run ended
        for field in ("max_offer_gap_ns", "last_offer_age_ns", "first_offer_delay_ns"):
            with self.subTest(field=field):
                stalled = _sender_end(1, 1, 300, 300, **{field: 5 * second})
                self.assertEqual("fail", run(full[0], stalled)["production"])
        # a source with no end at all
        self.assertEqual("fail", run(full[0])["production"])
        # production fields not on record: cannot be assessed, never a pass
        legacy = [{k: v for k, v in end.items() if k != "produce_ns"} for end in full]
        row = run(*legacy)
        self.assertEqual(("unmeasured", "unmeasured"), (row["integrity"], row["production"]))
        # capture restart: two epochs per source together cover the run
        epochs = [_sender_end(source, epoch, 150, 150) for source in range(2)
                  for epoch in (1, 2)]
        self.assertEqual("pass", run(*epochs)["production"])

    def test_loss_episode_never_matches_across_a_later_impairment(self):
        second = 10**9

        def reset(at, kind="reset", length=0):
            return [{"kind": "impairment_start", "t_ns": at, "impairment": kind,
                     "duration_ns": length, "rate_bytes": 0},
                    {"kind": "impairment_end", "t_ns": at + length, "impairment": kind,
                     "duration_ns": length, "rate_bytes": 0}]

        def loss(at, connection):
            return {"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                    "t_ns": at, "source": 0, "idle_ns": 1,
                    "connection": connection, "last_committed_capture_ns": 1}

        orchestrator, receiver, sender_rows = _base("rst")
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": 2 * second}
        proxy_rows = reset(10 * second) + reset(13 * second)
        name = "rst-a_framed"

        def g5(*losses):
            self.run_dir(name, orchestrator=orchestrator, receiver=receiver + self._durable(1),
                         sender_rows=[start] + sender_rows + list(losses),
                         proxy_rows=proxy_rows)
            return self.report()["rst"]["g5"]

        self.assertEqual("pass", g5(loss(10 * second + 5, 1), loss(13 * second + 5, 2)))
        # two episodes, both after the second reset: within 15 s of the first
        # reset, but the first reset was never detected before the next began
        self.assertEqual("fail", g5(loss(13 * second + 5, 1), loss(14 * second, 2)))
        # the last window still ends 15 s after the last reset
        self.assertEqual("fail", g5(loss(10 * second + 5, 1), loss(29 * second, 2)))
        # unit level: [start_i, min(start_i + within, start_{i+1}))
        match = summarize._match_episodes
        self.assertEqual([None, 1], match([10, 12], [13, 14], 15))
        self.assertEqual([1, 1], match([10, 12], [11, 13], 15))
        self.assertEqual([None], match([10], [12], 15, bounds=[11]))  # other impairment
        self.assertEqual([None], match([10], [26], 15))
        self.assertEqual([15], match([10], [25], 15))
        # blackholes: an episode after the next blackhole began is not the earlier one's
        orchestrator, receiver, sender_rows = _base("outage_8s")
        start = {**start, "loss_timeout_ns": int(1.5 * second)}
        proxy_rows = reset(10 * second, "blackhole", 3 * second) + reset(
            20 * second, "blackhole", 3 * second)
        name = "outage_8s-a_framed"
        # Main flagged both blackholes itself (only the Agent matching is under test)
        flagged = [{"kind": "interrupted", "t_ns": at * second, "source": 0,
                    "since_last_rx_ns": 2 * second} for at in (12, 22)]
        late = [loss(21 * second, 1), loss(22 * second, 2)]
        self.run_dir(name, orchestrator=orchestrator,
                     receiver=receiver + self._durable(1) + flagged,
                     sender_rows=[start] + sender_rows + late, proxy_rows=proxy_rows)
        self.assertEqual("fail", self.report()["outage_8s"]["g5"])
        self.rewrite(name, "sender", [start] + sender_rows + [loss(12 * second, 1),
                                                              loss(22 * second, 2)])
        row = self.report()["outage_8s"]
        self.assertEqual(("pass", 2 * second), (row["g5"], row["agent_detect_max_ns"]))

    # -- regressions for the PR #222 review (head 7749efa) ---------------------
    def test_route_probe_must_reach_this_runs_receiver(self):
        """A 404 / closed connection from a stale or unrelated listener on the
        same address is not this run's refusal: the receiver must record the
        probe's session nonce."""
        orchestrator, receiver, sender_rows = _base("route_probe")
        probe = {"kind": "route_probe", "t_ns": second_ns(1), "reason": "not_found",
                 "session": 21}
        seen = {"kind": "route_probe", "t_ns": second_ns(1), "candidate": "a_framed",
                "reason": "protocol_error", "session": 21}
        name = "route_probe-a_framed"
        for two_host in (False, True):
            with self.subTest(two_host=two_host):
                # the probe went to another listener: this receiver saw nothing
                self.run_dir(name, orchestrator=orchestrator, receiver=receiver,
                             sender_rows=sender_rows + [probe], two_host=two_host)
                row = self.report()["route_probe"]
                self.assertEqual(("fail", 0), (row["g1"], row["route_probes_seen_by_receiver"]))
                # this receiver refused a different connection's probe
                self.rewrite(name, "receiver", receiver + [{**seen, "session": 22}])
                self.assertEqual("fail", self.report()["route_probe"]["g1"])
                # this receiver refused this probe
                self.rewrite(name, "receiver", receiver + [seen])
                self.assertEqual("pass", self.report()["route_probe"]["g1"])
                # a probe record without its nonce cannot be tied to the receiver
                self.rewrite(name, "sender", sender_rows + [
                    {k: v for k, v in probe.items() if k != "session"}])
                self.assertEqual("unmeasured", self.report()["route_probe"]["g1"])
                for path in (self.root / name).iterdir():
                    path.unlink()

    def test_two_host_incidental_disconnect_is_not_main_outage_detection(self):
        """Two hosts: an Agent loss on a connection that had already closed
        before the scheduled Main stop/restart (Main clock) does not detect it;
        only the loss of a connection live at the window's start does."""
        second = 10**9
        for scenario, actions in (
                ("slow_stop_10s", [("sigstop", 10), ("sigcont", 20)]),
                ("main_restart", [("restart_receiver", 10), ("ready", 12)])):
            with self.subTest(scenario=scenario):
                orchestrator, receiver, sender_rows = _base(scenario)
                orchestrator = orchestrator + [
                    {"kind": "action", "t_ns": at * second, "action": action,
                     "duration_ns": 0} for action, at in actions]
                # a short loss timeout: the (fast, 2 s) stop must also disconnect
                start = {"kind": "start", "t_ns": 0, "n_sources": 1,
                         "loss_timeout_ns": second // 2}

                def lost(at, session, connection):
                    return [{"kind": "loss_detected", "last_echo_ns": None, "echo_frames": 0,
                             "t_ns": at * second, "source": 0,
                             "idle_ns": 2 * second, "connection": connection,
                             "session": session, "last_committed_capture_ns": 1},
                            {"kind": "closed", "t_ns": at * second, "reason": "peer_closed",
                             "connection": connection, "session": session}]

                def accept(at, session, connection):
                    # TLS handshake done 0.5 s (Agent clock) before the accept
                    return [{"kind": "connected", "t_ns": at * second - second // 2,
                             "connection": connection, "session": session},
                            {"kind": "first_accept", "t_ns": at * second,
                             "connection": connection, "source": 0, "session": session}]

                # Main clock: connection 10 closed at 5 s (incidental), 11 opened at
                # 6 s and was live when the outage started at 10 s
                sessions = _session(10, 1, 5, 1) + _session(11, 6, 21, 2)
                # Agent clock (unrelated offset): only connection 10's loss and the
                # reconnect after it are on record; connection 11 never lost
                incidental = [start] + sender_rows + accept(101, 10, 1) + lost(
                    104, 10, 1) + accept(106, 11, 2)
                name = f"{scenario}-a_framed"
                self.run_dir(name, orchestrator=orchestrator, two_host=True,
                             receiver=receiver + self._durable(1) + sessions,
                             sender_rows=incidental)
                row = self.report()[scenario]
                self.assertEqual(("fail", "fail"), (row["g4"], row["g5"]))
                # connection 11 lost at the outage and the Agent reconnected (12)
                detected = incidental + lost(111, 11, 2) + accept(113, 12, 3)
                # Main greets connection 12 one second after the window end:
                # reconnect = 1 s (Main) + 0.5 s connected -> accept (Agent)
                end = actions[1][1]
                self.rewrite(name, "receiver", receiver + self._durable(1) + sessions
                             + _session(12, end + 1, 30, 3))
                self.rewrite(name, "sender", detected)
                row = self.report()[scenario]
                self.assertEqual(("pass", "pass", 3 * second // 2),
                                 (row["g4"], row["g5"], row["reconnect_p95_ns"]))
                # the receiver records carry no session nonces: not correlated
                self.rewrite(name, "receiver", receiver + self._durable(1))
                row = self.report()[scenario]
                self.assertEqual(("unmeasured", "unmeasured"), (row["g4"], row["g5"]))
                for path in (self.root / name).iterdir():
                    path.unlink()

    def test_two_host_loss_after_the_main_outage_is_not_its_detection(self):
        """Two hosts: a connection the Agent kept alive through the Main
        stop/restart and that dropped later for an unrelated reason is not the
        outage's detection (G5) nor its reconnect episode (G4). Main clock
        evidence only: the receiver must see that session end by the window
        end + 15 s + grace, and the Agent must not have received a Main
        heartbeat reply sent after the window started."""
        second = 10**9
        for scenario, actions in (
                ("slow_stop_10s", [("sigstop", 10), ("sigcont", 20)]),
                ("main_restart", [("restart_receiver", 10), ("ready", 12)])):
            with self.subTest(scenario=scenario):
                orchestrator, receiver, sender_rows = _base(scenario)
                orchestrator = orchestrator + [
                    {"kind": "action", "t_ns": at * second, "action": action,
                     "duration_ns": 0} for action, at in actions]
                end = actions[1][1]
                start = {"kind": "start", "t_ns": 0, "n_sources": 1,
                         "loss_timeout_ns": second // 2}

                def lost(at, echo, frames=0):
                    # Agent clock (unrelated offset); echo: an Agent clock value;
                    # frames: heartbeat_ack frames the Agent received on 11
                    return [{"kind": "loss_detected", "t_ns": at * second, "source": 0,
                             "idle_ns": 2 * second, "connection": 1, "session": 11,
                             "last_echo_ns": echo, "echo_frames": frames,
                             "last_committed_capture_ns": 1},
                            {"kind": "closed", "t_ns": at * second, "reason": "peer_closed",
                             "connection": 1, "session": 11, "last_echo_ns": echo,
                             "echo_frames": frames},
                            {"kind": "connected", "t_ns": (at + 1) * second,
                             "connection": 2, "session": 12},
                            {"kind": "first_accept", "t_ns": (at + 2) * second,
                             "connection": 2, "source": 0, "session": 12}]

                def ack(at, echo):
                    # Main clock reply on session 11, echoing an Agent clock value
                    return {"kind": "heartbeat_ack", "t_ns": at * second,
                            "connection": 1, "session": 11, "echo_ns": echo}

                name = f"{scenario}-a_framed"
                # replies before the outage echo Agent heartbeats 104..108
                before = [ack(at, (100 + at) * second) for at in range(4, 9)]

                def check(close_s, replies, echo, expected, greeted=None):
                    # Main greets the reconnect (12) at ``greeted`` (default:
                    # after 11 closed); G4 adds 1 s connected -> accept
                    greeted = close_s + 1 if greeted is None else greeted
                    sessions = (_session(11, 1, close_s, 1) + _session(12, greeted, 90, 2))
                    # Main numbers each session's frames in write order; the
                    # Agent received them up to the one carrying its last echo
                    # (5 when that frame is not on record)
                    counts, numbered = {}, []
                    for item in replies:
                        counts[item["session"]] = counts.get(item["session"], 0) + 1
                        numbered.append({**item, "index": counts[item["session"]]})
                    frames = next((item["index"] for item in numbered if item["session"] == 11
                                   and item["echo_ns"] == echo), 5)
                    self.run_dir(name, orchestrator=orchestrator, two_host=True,
                                 receiver=receiver + self._durable(1) + sessions + numbered,
                                 sender_rows=[start] + sender_rows + lost(200, echo, frames))
                    row = self.report()[scenario]
                    for path in (self.root / name).iterdir():
                        path.unlink()
                    return self.assertEqual(expected, (row["g4"], row["g5"]),
                                            (close_s, echo))

                # compliant: the Agent's last echo is from before the outage and
                # Main sees the session end promptly after it (backlog replies
                # after SIGCONT never reached the Agent)
                drained = [ack(end, 109 * second)] if scenario == "slow_stop_10s" else []
                check(end + 1, before + drained, 108 * second, ("pass", "pass"))
                check(end + 15 + 5, before + drained, 108 * second, ("pass", "pass"),
                      greeted=end + 2)
                # the same, but Main greets the reconnect only 21 s after the
                # window end: G4 measures from the window end and fails
                check(end + 15 + 5, before + drained, 108 * second, ("fail", "pass"))
                # the session stayed open well past the window: it survived, and
                # its later loss (an unrelated drop) is not the detection
                check(end + 15 + 6, before, 108 * second, ("fail", "fail"))
                check(end + 300, before, 108 * second, ("fail", "fail"))
                if scenario == "slow_stop_10s":
                    # closed inside the bound, but the Agent received a reply
                    # Main sent after the stop (echo 111 acked at 21 s): it was
                    # alive across SIGSTOP/SIGCONT, so its loss is not detection
                    alive = before + [ack(end, 109 * second), ack(end + 1, 111 * second)]
                    check(end + 3, alive, 111 * second, ("fail", "fail"))
                    # the Agent's echoes have no Main-side record at all
                    check(end + 1, [], 108 * second, ("unmeasured", "unmeasured"))
                # per session: the Agent's last echo on session 11 (108) has no
                # sent-reply record on that session -- only earlier echoes, or
                # the same echo on another session -- so its Main time is unknown
                check(end + 1, before[:-1], 108 * second, ("unmeasured", "unmeasured"))
                other = [dict(item, session=99, connection=9) for item in before]
                check(end + 1, other, 108 * second, ("unmeasured", "unmeasured"))
                # sender records from before the echo evidence: not correlated
                sessions = _session(11, 1, end + 1, 1) + _session(12, end + 2, 90, 2)
                old = [{key: value for key, value in row.items() if key != "last_echo_ns"}
                       for row in lost(200, None)]
                self.run_dir(name, orchestrator=orchestrator, two_host=True,
                             receiver=receiver + self._durable(1) + sessions,
                             sender_rows=[start] + sender_rows + old)
                row = self.report()[scenario]
                self.assertEqual(("unmeasured", "unmeasured"), (row["g4"], row["g5"]))
                for path in (self.root / name).iterdir():
                    path.unlink()

    def test_two_host_reconnect_is_measured_from_the_main_window_end(self):
        """#237: on two hosts the G4 reconnect after a Main SIGSTOP excludes
        Main's own stop time, like one host (window end -> first accepted
        unit), as Main (window end -> HELLO received) + Agent (connected ->
        first accept): never less than the true value, so a slow reconnect
        after SIGCONT still fails."""
        second = 10**9
        name = "slow_stop_60s-a_framed"
        orchestrator, receiver, sender_rows = _base("slow_stop_60s")
        # Main clock: SIGSTOP 10 s -> SIGCONT 70 s
        orchestrator = orchestrator + [
            {"kind": "action", "t_ns": at * second, "action": action, "duration_ns": 0}
            for action, at in (("sigstop", 10), ("sigcont", 70))]
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": 2 * second}

        def run(greeted_ms, connected_ms, accepted_ms, *, connected=True):
            # Agent clock (offset 200 s): the Agent loses connection 11 5 s into
            # the stop, then reconnects as 12 once Main runs again
            agent = [start] + sender_rows + [
                {"kind": "loss_detected", "t_ns": 205 * second, "source": 0,
                 "idle_ns": 5 * second, "connection": 1, "session": 11,
                 "last_echo_ns": None, "echo_frames": 0, "last_committed_capture_ns": 1},
                {"kind": "closed", "t_ns": 205 * second, "reason": "loss_timeout",
                 "connection": 1, "session": 11, "last_echo_ns": None},
                {"kind": "first_accept", "t_ns": accepted_ms * 10**6, "connection": 2,
                 "source": 0, "session": 12}]
            if connected:
                agent.append({"kind": "connected", "t_ns": connected_ms * 10**6,
                              "connection": 2, "session": 12})
            main = (receiver + self._durable(1) + _session(11, 1, 72, 1)
                    + [{"kind": "session_hello", "t_ns": greeted_ms * 10**6,
                        "connection": 2, "session": 12}])
            self.run_dir(name, orchestrator=orchestrator, two_host=True, receiver=main,
                         sender_rows=agent)
            row = self.report()["slow_stop_60s"]
            for path in (self.root / name).iterdir():
                path.unlink()
            return row

        # the Agent-clock close -> accept is 65.5 s (the old false FAIL); from
        # the window end it is 0.4 s (Main) + 0.2 s (Agent)
        row = run(70_400, 270_300, 270_500)
        self.assertEqual("pass", row["g4"])
        self.assertEqual(600 * 10**6, row["reconnect_p95_ns"])
        # Main greets the reconnect 11 s after SIGCONT: fails
        row = run(81_000, 270_300, 270_500)
        self.assertEqual("fail", row["g4"])
        self.assertEqual(11_200 * 10**6, row["reconnect_p95_ns"])
        # the reconnect's first accept comes 10.5 s after its handshake: fails
        row = run(70_400, 270_300, 280_800)
        self.assertEqual("fail", row["g4"])
        # a HELLO Main received before the window end is not the reconnect
        self.assertEqual("fail", run(69_000, 270_300, 270_500)["g4"])
        # records without the Agent ``connected`` evidence: not measured
        self.assertEqual("unmeasured",
                         run(70_400, 270_300, 270_500, connected=False)["g4"])

    def test_two_host_failure_on_record_is_fail_without_session_matching(self):
        """#237: when the two-host session matching is not possible (here the
        Agent's ``echo_frames`` is missing), a failure the records show anyway
        is ``fail``, not ``unmeasured``: G4 when Main greeted no connection
        after a window the Agent had to reconnect after, G5 when there are
        fewer Agent loss episodes than Main windows or an episode detected
        later than 15 s. Otherwise both stay ``unmeasured``."""
        second = 10**9
        for scenario, actions in (
                ("slow_stop_10s", [("sigstop", 10), ("sigcont", 20)]),
                ("main_restart", [("restart_receiver", 10), ("ready", 12)])):
            with self.subTest(scenario=scenario):
                name = f"{scenario}-a_framed"
                orchestrator, receiver, sender_rows = _base(scenario)
                end = actions[1][1]
                start = {"kind": "start", "t_ns": 0, "n_sources": 1,
                         "loss_timeout_ns": second // 2}

                def lost(connection, session, idle_s=2):
                    # Agent clock; no ``echo_frames``: the matching is impossible
                    return [{"kind": "loss_detected", "t_ns": (200 + connection) * second,
                             "source": 0, "idle_ns": idle_s * second,
                             "connection": connection, "session": session,
                             "last_echo_ns": None, "last_committed_capture_ns": 1},
                            {"kind": "closed", "t_ns": (200 + connection) * second,
                             "reason": "peer_closed", "connection": connection,
                             "session": session, "last_echo_ns": None}]

                reconnect = [{"kind": "connected", "t_ns": 210 * second, "connection": 9,
                              "session": 12},
                             {"kind": "first_accept", "t_ns": 211 * second, "connection": 9,
                              "source": 0, "session": 12}]

                def run(sessions, agent, windows=1):
                    rows = list(orchestrator)
                    for repeat in range(windows):
                        rows += [{"kind": "action", "t_ns": (at + 100 * repeat) * second,
                                  "action": action, "duration_ns": 0}
                                 for action, at in actions]
                    self.run_dir(name, orchestrator=rows, two_host=True,
                                 receiver=receiver + self._durable(1) + sessions,
                                 sender_rows=[start] + sender_rows + agent)
                    row = self.report()[scenario]
                    for path in (self.root / name).iterdir():
                        path.unlink()
                    return row["g4"], row["g5"]

                # Main greeted the reconnect after the window end: no failure on
                # record, the matching decides -> unmeasured
                greeted = _session(11, 1, end + 1, 1) + _session(12, end + 1, 90, 2)
                self.assertEqual(("unmeasured", "unmeasured"),
                                 run(greeted, lost(1, 11) + reconnect))
                # no HELLO after the window end: the Agent never reconnected
                alone = _session(11, 1, end + 1, 1)
                self.assertEqual(("fail", "unmeasured"), run(alone, lost(1, 11)))
                # a HELLO before the window end is not a reconnect
                early = alone + _session(12, end - 1, 90, 2)
                self.assertEqual(("fail", "unmeasured"), run(early, lost(1, 11) + reconnect))
                # the Agent detected the loss after 20 s (> 15 s)
                self.assertEqual(("unmeasured", "fail"),
                                 run(greeted, lost(1, 11, idle_s=20) + reconnect))
                # two Main windows, one Agent loss episode: one went undetected
                # (G4: the recorded windows do not pair with the plan's one
                # action, so it is left to the matching)
                self.assertEqual(("unmeasured", "fail"),
                                 run(greeted, lost(1, 11) + reconnect, windows=2))
                # receiver records from before ``session_hello``: unmeasured
                self.assertEqual(("unmeasured", "unmeasured"), run([], lost(1, 11)))

    def test_main_reply_cutoff_needs_proof_that_main_had_stopped(self):
        """#237: a heartbeat reply written after the orchestrator recorded the
        stop/restart but before the receiver actually stopped is no survival
        evidence, only when a record proves when Main stopped replying (the
        orchestrator's confirmed ``stopped``, or the stopped receiver's
        coordinated ``stopping``). Without that proof, or for a reply written
        after it, the session still counts as answered (fail)."""
        second = 10**9
        ms = 10**6
        for scenario, actions in (
                ("slow_stop_10s", [("sigstop", 10), ("sigcont", 20)]),
                ("main_restart", [("restart_receiver", 10), ("ready", 12)])):
            with self.subTest(scenario=scenario):
                name = f"{scenario}-a_framed"
                orchestrator, receiver, sender_rows = _base(scenario)
                orchestrator = orchestrator + [
                    {"kind": "action", "t_ns": at * second, "action": action,
                     "duration_ns": 0} for action, at in actions]
                end = actions[1][1]
                start = {"kind": "start", "t_ns": 0, "n_sources": 1,
                         "loss_timeout_ns": second // 2}
                agent = [start] + sender_rows + [
                    {"kind": "loss_detected", "t_ns": 200 * second, "source": 0,
                     "idle_ns": 2 * second, "connection": 1, "session": 11,
                     "last_echo_ns": 109 * second, "echo_frames": 6,
                     "last_committed_capture_ns": 1},
                    {"kind": "closed", "t_ns": 200 * second, "reason": "peer_closed",
                     "connection": 1, "session": 11, "last_echo_ns": 109 * second,
                     "echo_frames": 6},
                    {"kind": "connected", "t_ns": 201 * second, "connection": 2,
                     "session": 12},
                    {"kind": "first_accept", "t_ns": 202 * second, "connection": 2,
                     "source": 0, "session": 12}]
                before = [{"kind": "heartbeat_ack", "t_ns": at * second, "sent_ns": at * second,
                           "connection": 1, "session": 11, "echo_ns": (100 + at) * second,
                           "index": at - 3} for at in range(4, 9)]

                def check(extra_main, sent_ms, expected, *, extra_orchestrator=(),
                          record_ms=None):
                    # the Agent's last echo (109) was written at ``sent_ms``
                    # (Main clock); its record may be written later
                    last = {"kind": "heartbeat_ack", "t_ns": (record_ms or sent_ms) * ms,
                            "sent_ns": sent_ms * ms, "connection": 1, "session": 11,
                            "echo_ns": 109 * second, "index": 6}
                    main = (receiver + self._durable(1) + _session(11, 1, end + 1, 1)
                            + _session(12, end + 1, 90, 2) + before + [last]
                            + list(extra_main))
                    self.run_dir(name, orchestrator=orchestrator + list(extra_orchestrator),
                                 two_host=True, receiver=main, sender_rows=agent)
                    row = self.report()[scenario]
                    for path in (self.root / name).iterdir():
                        path.unlink()
                    self.assertEqual(expected, (row["g4"], row["g5"]),
                                     (sent_ms, extra_main, extra_orchestrator))

                # written before the window start: never evidence (record late)
                check((), 9_990, ("pass", "pass"), record_ms=10_020)
                # written 5 ms after the recorded start, no proof: answered
                check((), 10_005, ("fail", "fail"))
                if scenario == "slow_stop_10s":
                    stopped = [{"kind": "action", "t_ns": 10_010 * ms, "action": "stopped",
                                "duration_ns": 0}]
                    check((), 10_005, ("pass", "pass"), extra_orchestrator=stopped)
                    # written after the receiver was seen frozen: answered
                    check((), 10_015, ("fail", "fail"), extra_orchestrator=stopped)
                    # a ``stopped`` outside the window proves nothing
                    late = [{**stopped[0], "t_ns": 30 * second}]
                    check((), 10_005, ("fail", "fail"), extra_orchestrator=late)
                else:
                    stopping = {"kind": "stopping", "t_ns": 11 * second,
                                "stop_ns": 10_010 * ms, "abrupt": True, "coordinated": True}
                    check([stopping], 10_005, ("pass", "pass"))
                    # written after the receiver's own stop time: answered
                    check([stopping], 10_015, ("fail", "fail"))
                    # an uncoordinated stop proves nothing about later writes
                    check([{**stopping, "coordinated": False}], 10_005, ("fail", "fail"))
                    # a graceful stop's record (not the restart) proves nothing
                    check([{**stopping, "abrupt": False}], 10_005, ("fail", "fail"))

    def test_repeated_echo_counts_only_if_the_agent_received_that_frame(self):
        """#237 review: after SIGCONT the receiver drains data the Agent sent
        before dropping the connection and its reply repeats the old latest
        echo (same value as the Agent's last echo). With numbered frames the
        Agent's received count, not the value, decides: a repeat beyond that
        count is no survival evidence (pass), one within it is (fail), and a
        count beyond Main's records is unmeasured."""
        second = 10**9
        name = "slow_stop_10s-a_framed"
        orchestrator, receiver, sender_rows = _base("slow_stop_10s")
        orchestrator = orchestrator + [
            {"kind": "action", "t_ns": at * second, "action": action, "duration_ns": 0}
            for action, at in (("sigstop", 10), ("sigcont", 20))]
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": second // 2}

        def ack(at, echo, index):
            row = {"kind": "heartbeat_ack", "t_ns": at * second, "sent_ns": at * second,
                   "connection": 1, "session": 11, "echo_ns": echo}
            return row if index is None else {**row, "index": index}

        def run(frames, *, numbered=True, repeat_index=6, last_echo=108 * second,
                more=None, repeat=True):
            # replies 1..5 before the stop echo Agent heartbeats 104..108; the
            # repeat of 108 is written at SIGCONT (20 s), after the cutoff
            replies = [ack(at, (100 + at) * second, (at - 3) if numbered else None)
                       for at in range(4, 9)]
            if repeat:
                replies.append(ack(20, 108 * second, repeat_index if numbered else None))
            counted = {} if frames is None else {"echo_frames": frames}
            loss = {"kind": "loss_detected", "t_ns": 200 * second, "source": 0,
                    "idle_ns": 2 * second, "connection": 1, "session": 11,
                    "last_echo_ns": last_echo, "last_committed_capture_ns": 1, **counted}
            # ``more``: a second loss record of the same connection (one is
            # written per source) carrying another count
            extra = [] if more is None else [{**loss, "echo_frames": more}]
            agent = [start] + sender_rows + [loss] + extra + [
                {"kind": "closed", "t_ns": 200 * second, "reason": "peer_closed",
                 "connection": 1, "session": 11, "last_echo_ns": last_echo, **counted},
                {"kind": "connected", "t_ns": 201 * second, "connection": 2, "session": 12},
                {"kind": "first_accept", "t_ns": 202 * second, "connection": 2,
                 "source": 0, "session": 12}]
            main = (receiver + self._durable(1) + _session(11, 1, 21, 1)
                    + _session(12, 21, 90, 2) + replies)
            self.run_dir(name, orchestrator=orchestrator, two_host=True, receiver=main,
                         sender_rows=agent)
            row = self.report()["slow_stop_10s"]
            for path in (self.root / name).iterdir():
                path.unlink()
            return row["g4"], row["g5"]

        # the review's repro: the Agent received frames 1..5 only, so the
        # repeat (frame 6, after SIGCONT) never reached it: compliant
        self.assertEqual(("pass", "pass"), run(5))
        # the Agent received the repeat (6 frames): it survived the stop
        self.assertEqual(("fail", "fail"), run(6))
        # the Agent counts a frame Main has no record of: unmeasured
        self.assertEqual(("unmeasured", "unmeasured"), run(7))
        self.assertEqual(("unmeasured", "unmeasured"), run(6, repeat_index=7))
        # #222-era records without the numbering (either side): unmeasured,
        # never judged by echo values
        self.assertEqual(("unmeasured", "unmeasured"), run(None))
        self.assertEqual(("unmeasured", "unmeasured"), run(5, numbered=False))
        # the false-PASS lean the old echo-value rule had: a session kept
        # alive after SIGCONT by media acknowledgements alone shows no echo
        # after the cutoff, so that rule would pass it; unmeasured instead
        self.assertEqual(("unmeasured", "unmeasured"),
                         run(5, numbered=False, repeat=False))
        self.assertEqual(("pass", "pass"), run(5, repeat=False))
        # an ``echo_frames`` that is negative or not an integer: unmeasured
        for bad in (-1, 5.5, True, None):  # (free strings never load at all)
            with self.subTest(echo_frames=bad):
                self.assertEqual(("unmeasured", "unmeasured"), run(bad))
        # the Agent's last echo is not the largest echo of frames 1..k
        self.assertEqual(("unmeasured", "unmeasured"), run(5, last_echo=107 * second))
        self.assertEqual(("unmeasured", "unmeasured"), run(5, last_echo=None))
        self.assertEqual(("unmeasured", "unmeasured"), run(0))  # k=0 but an echo
        # loss records of one connection with different counts: the largest
        # is what the Agent received (a smaller one never hides the repeat)
        self.assertEqual(("fail", "fail"), run(5, more=6))
        self.assertEqual(("fail", "fail"), run(6, more=5))
        self.assertEqual(("pass", "pass"), run(5, more=5))


def second_ns(value):
    return value * 10**9


class SenderProducerTests(unittest.TestCase):
    """A producer that ends while the run is still going is fatal for the sender."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="poc15-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        materials.init(self.root / "m")
        with socket.socket() as probe:  # a closed loopback port: Main unreachable
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]

    def test_echo_frames_count_reset_and_record(self):
        # #237: the Agent counts every heartbeat_ack frame it parses on a
        # connection (even a repeated, older echo), restarts the count on a
        # new connection, and records it with each loss and close. The
        # summarizer relies on this: a missed repeat (an old value) would not
        # change ``last_echo_ns``, so its echo check could not notice it.
        config = sender.SenderConfig(candidate="a_framed", host="127.0.0.1", port=self.port,
                                     n_sources=2, fast=True)
        out = self.root / "echo.jsonl"
        writer = records.JsonlWriter(out, run_id=RUN, role="sender")
        instance = sender.Sender(config, self.root / "m" / "nodes" / "good", 1, writer)
        self.addCleanup(instance.wake_r.close)
        self.addCleanup(instance.wake_w.close)
        self.assertEqual((0, None), (instance.echo_frames, instance.last_echo_ns))
        for echo in (5, 9, 9, 7):  # a repeat (9) and an older value (7) count too
            instance._inbound(wire.FrameReader(64).feed(wire.heartbeat_ack_frame(echo))[0])
        self.assertEqual((4, 9), (instance.echo_frames, instance.last_echo_ns))
        instance._loss(123)
        connection = mock.Mock()
        with mock.patch("media_capture_agent.node_tls.connect_to_main",
                        return_value=connection):
            self.assertIs(connection, instance._connect())
        self.assertEqual((0, None), (instance.echo_frames, instance.last_echo_ns))
        # b_segment parses whole responses and counts their frames the same way
        body = wire.FrameReader(64).feed(wire.heartbeat_ack_frame(11))[0]
        instance._apply_segment_acks([], [wire.parse_body(body)])
        instance._loss(456)
        writer.close()
        losses = [(row["source"], row["echo_frames"], row["last_echo_ns"])
                  for row in records.read_jsonl(out) if row["kind"] == "loss_detected"]
        self.assertEqual([(0, 4, 9), (1, 4, 9), (0, 1, 11), (1, 1, 11)], losses)
        # ``closed`` (written by ``run``) is checked on real records in
        # LoopbackMatrixTests.test_two_host_roles_on_loopback

    def run_sender(self, source_kind, seconds=6.0, **config):
        config = sender.SenderConfig(candidate="a_framed", host="127.0.0.1", port=self.port,
                                     n_sources=2, source_kind=source_kind, fps=30,
                                     frame_bytes=2000, fast=True, **config)
        out = self.root / f"{source_kind}-{seconds}-{time.monotonic_ns()}.jsonl"
        writer = records.JsonlWriter(out, run_id=RUN, role="sender")
        instance = sender.Sender(config, self.root / "m" / "nodes" / "good", 1, writer)
        started = time.monotonic()
        code = instance.run(seconds)
        elapsed = time.monotonic() - started
        writer.close()
        instance.wake_r.close()
        instance.wake_w.close()
        return code, elapsed, records.read_jsonl(out)

    def test_early_eof_of_gst_producer_is_fatal(self):
        # a stand-in "gst-launch" that exits at once: immediate EOF on stdout
        code, elapsed, rows = self.run_sender("gst", gst="/bin/true")
        failed = [row for row in rows if row["kind"] == "producer_failed"]
        self.assertEqual(1, code)
        self.assertLess(elapsed, 5.0)  # stopped early, not at the deadline
        # the first producer to end stops the sender (the other may then end
        # as part of that shutdown, which is not a second failure)
        self.assertTrue(failed)
        self.assertLessEqual({row["source"] for row in failed}, {0, 1})
        self.assertEqual({"eof"}, {row["reason"] for row in failed})
        ends = [row for row in rows if row["kind"] == "end"]
        self.assertEqual(2, len(ends))
        self.assertTrue(all(row["generated"] == 0 and row["first_offer_delay_ns"] is None
                            for row in ends))

    def test_holder_socket_error_records_its_errno(self):
        # #307: the record names the OS error by number only (no message/path)
        code, elapsed, rows = self.run_sender("holder", holder_socket=self.root / "absent.sock")
        failed = [row for row in rows if row["kind"] == "producer_failed"]
        self.assertEqual(1, code)
        self.assertLess(elapsed, 5.0)
        self.assertEqual({("exception", errno.ENOENT)},
                         {(row["reason"], row["errno"]) for row in failed})
        self.assertEqual({0, 1}, {row["source"] for row in failed})

    def test_producer_exception_is_fatal_and_normal_runs_exit_zero(self):
        calls = []

        def few_then_raise(instance, index):
            for number in range(3):
                instance._offer(index, time.monotonic_ns(), b"\xff\xd8%d\xff\xd9" % number)
            calls.append(index)
            if index == 1:
                raise RuntimeError("producer broke")
            original(instance, index)

        original = sender.Sender._builtin
        with mock.patch.object(sender.Sender, "_builtin", few_then_raise):
            code, elapsed, rows = self.run_sender("builtin")
        failed = [row for row in rows if row["kind"] == "producer_failed"]
        self.assertEqual((1, [1], ["exception"], [None]),
                         (code, [r["source"] for r in failed], [r["reason"] for r in failed],
                          [r["errno"] for r in failed]))
        self.assertLess(elapsed, 5.0)
        # a healthy producer stops only with the sender: exit 0, production on record
        code, elapsed, rows = self.run_sender("builtin", seconds=2.0)
        self.assertEqual(0, code)
        self.assertFalse([row for row in rows if row["kind"] == "producer_failed"])
        ends = [row for row in rows if row["kind"] == "end"]
        self.assertEqual(2, len(ends))
        for row in ends:
            self.assertGreaterEqual(row["produce_ns"], 1_900_000_000)
            self.assertGreater(row["generated"], 30)
            self.assertLess(row["max_offer_gap_ns"], 10**9)


class ReceiverHeartbeatAckTests(unittest.TestCase):
    """``heartbeat_ack`` (Main clock evidence for G4/G5) is written only after
    the reply carrying the echo was sent, for every candidate: a record taken
    before the send (e.g. before a SIGSTOP that delays it past SIGCONT, or
    while a segment body is still being read) would predate the moment the
    Agent could receive the echo and let a surviving session pass."""

    class Connection:
        def __init__(self, chunks, log, fail=None):
            self.chunks, self.log, self.fail = list(chunks), log, fail
            self.on_recv = self.on_send = None

        def settimeout(self, _value):
            pass

        def fileno(self):
            raise ValueError("fake socket")

        def recv(self, _size):
            if self.on_recv is not None:
                self.on_recv(len(self.chunks))
            return self.chunks.pop(0) if self.chunks else b""

        def sendall(self, data):
            if self.fail is not None and wire.heartbeat_ack_frame(7) in data:
                raise self.fail
            if self.on_send is not None:
                self.on_send(bytes(data))
            self.log.append(("send", bytes(data)))

    class Writer:
        def __init__(self, log):
            self.log = log

        def write(self, kind, **fields):
            self.log.append(("event", kind, fields))

    def _receiver(self, candidate, log):
        config = receiver.ReceiverConfig(candidate=candidate, bind_host="127.0.0.1", port=0)
        config.admission_check_s = config.idle_timeout_s = 10**6
        instance = object.__new__(receiver.Receiver)
        instance.config, instance.writer = config, self.Writer(log)
        instance._init_stop_state()
        instance._lock = threading.Lock()
        instance.bytes_in = instance.max_outq = instance.max_inq = 0
        instance.tracker = mock.Mock(heartbeat=mock.Mock(return_value=True))
        return instance

    @staticmethod
    def _chunks(candidate):
        first = wire.hello_frame(5) + wire.heartbeat_frame(7)
        second = wire.heartbeat_frame(8)
        if candidate == "a_framed":
            return [first, second]
        if candidate == "b_chunked":
            return [wire.request_head("POST", wire.STREAM_PATH) + wire.chunk(first),
                    wire.chunk(second) + wire.LAST_CHUNK]
        # the second heartbeat arrives in a later read of the same segment body
        head = wire.request_head("PUT", wire.SEGMENT_PATH,
                                 content_length=len(first) + len(second))
        return [head + first, second]

    def _run(self, candidate, fail=None, stop_before_last=False, on_send=None):
        log = []
        instance = self._receiver(candidate, log)
        connection = self.Connection(self._chunks(candidate), log, fail)
        if on_send is not None:
            connection.on_send = lambda data: on_send(instance, data)
        if stop_before_last:
            # The stop arrives while the session thread is inside its read:
            # the last chunk (heartbeat 8) is read after ``stop`` was set.
            def on_recv(left):
                if left == 1:
                    instance.stop.set()
            connection.on_recv = on_recv
        session = mock.Mock(connection=connection)
        state = {"last_rx": time.monotonic(), "checked": time.monotonic(),
                 "connection": 1, "session": None}
        try:
            reason = instance._run_session(session, object(), state)
        except OSError:
            reason = "tls_session_failed"
        self.last_instance = instance
        return log, reason

    def test_ack_recorded_only_after_its_reply_was_sent(self):
        for candidate in ("a_framed", "b_chunked", "b_segment"):
            with self.subTest(candidate=candidate):
                log, _ = self._run(candidate)
                acks = [index for index, item in enumerate(log)
                        if item[0] == "event" and item[1] == "heartbeat_ack"]
                self.assertEqual([7, 8], [log[index][2]["echo_ns"] for index in acks])
                for index in acks:
                    echo = wire.heartbeat_ack_frame(log[index][2]["echo_ns"])
                    sent = [position for position, item in enumerate(log)
                            if item[0] == "send" and echo in item[1]]
                    self.assertTrue(sent and sent[0] < index, (candidate, log))
                    self.assertEqual(5, log[index][2]["session"])

    def test_failed_reply_send_records_no_ack(self):
        for candidate in ("a_framed", "b_chunked", "b_segment"):
            for failure in (socket.timeout("send"), OSError("reset")):
                with self.subTest(candidate=candidate, failure=type(failure).__name__):
                    log, reason = self._run(candidate, fail=failure)
                    self.assertIn(reason, ("send_failed", "tls_session_failed"))
                    echoes = [item[2]["echo_ns"] for item in log
                              if item[0] == "event" and item[1] == "heartbeat_ack"]
                    self.assertNotIn(7, echoes)


    def test_no_reply_or_ack_once_stop_is_set(self):
        # A heartbeat read after SIGUSR1/SIGTERM set ``stop`` is never
        # answered nor recorded: an answer from a stopping Main would reach
        # the Agent inside the outage window (false G4/G5 survivor).
        for candidate in ("a_framed", "b_chunked", "b_segment"):
            with self.subTest(candidate=candidate):
                log, reason = self._run(candidate, stop_before_last=True)
                # a_framed / b_segment refuse the reply to the late chunk;
                # b_chunked leaves its loop before processing it. Either way
                # the session of a stopping receiver closes as ``shutdown``.
                self.assertEqual("shutdown", reason, candidate)
                echoes = [item[2]["echo_ns"] for item in log
                          if item[0] == "event" and item[1] == "heartbeat_ack"]
                self.assertNotIn(8, echoes)
                self.assertFalse([item for item in log if item[0] == "send"
                                  and wire.heartbeat_ack_frame(8) in item[1]], log)

    def test_send_refused_once_stop_is_set(self):
        log = []
        instance = self._receiver("a_framed", log)
        connection = self.Connection([], log)
        instance.stop.set()
        with self.assertRaises(receiver._Close) as raised:
            instance._send(mock.Mock(connection=connection), b"reply")
        self.assertEqual("shutdown", raised.exception.reason)
        self.assertEqual([], log)

    @staticmethod
    def _acks(log):
        return [item[2] for item in log if item[0] == "event" and item[1] == "heartbeat_ack"]

    def test_stop_requested_inside_sendall_waits_for_the_reply_and_its_record(self):
        # #237: SIGUSR1 (``request_stop``) arriving while a reply is being
        # written waits for the write and its record: the echo is recorded
        # with a ``sent_ns`` before ``stop_ns``, and nothing is written after.
        for candidate in ("a_framed", "b_chunked", "b_segment"):
            with self.subTest(candidate=candidate):
                stopper = {}

                def on_send(instance, data):
                    if wire.heartbeat_ack_frame(7) in data and "thread" not in stopper:
                        thread = threading.Thread(target=instance.request_stop,
                                                  kwargs={"abrupt": True})
                        stopper["thread"] = thread
                        thread.start()
                        # the stop request cannot complete inside this write
                        stopper["set_inside_send"] = instance.stop.wait(0.3)

                log = []
                instance = self._receiver(candidate, log)
                connection = self.Connection(self._chunks(candidate), log)
                connection.on_send = lambda data: on_send(instance, data)
                # the read after the reply carrying echo 7 (heartbeat 8; for
                # b_segment the next segment head) happens once the stop landed
                after = 0 if candidate == "b_segment" else 1
                connection.on_recv = lambda left: left == after and instance.stop.wait(5)
                state = {"last_rx": time.monotonic(), "checked": time.monotonic(),
                         "connection": 1, "session": None}
                reason = instance._run_session(mock.Mock(connection=connection), object(),
                                               state)
                stopper["thread"].join(5)
                self.assertFalse(stopper["set_inside_send"])
                self.assertEqual("shutdown", reason)
                self.assertTrue(instance.stop_coordinated)
                self.assertTrue(instance.abrupt)
                acks = self._acks(log)
                # b_segment answers both heartbeats of its one segment at once
                expected = [7, 8] if candidate == "b_segment" else [7]
                self.assertEqual(expected, [ack["echo_ns"] for ack in acks])
                for ack in acks:
                    self.assertLess(ack["sent_ns"], instance.stop_ns)
                if candidate != "b_segment":
                    self.assertFalse([item for item in log if item[0] == "send"
                                      and wire.heartbeat_ack_frame(8) in item[1]], log)

    def test_stop_set_inside_sendall_without_the_lock_still_records_the_reply(self):
        # A stop that bypasses ``request_stop`` while the write is in
        # progress: the Agent may receive the reply, so it is still recorded,
        # with a ``sent_ns`` no earlier than the stop (conservative for G4/G5).
        for candidate in ("a_framed", "b_chunked", "b_segment"):
            with self.subTest(candidate=candidate):
                stopped = {}

                def on_send(instance, data):
                    if wire.heartbeat_ack_frame(7) in data and not stopped:
                        stopped["at"] = time.monotonic_ns()
                        instance.stop.set()

                log, reason = self._run(candidate, on_send=on_send)
                self.assertEqual("shutdown", reason)
                acks = self._acks(log)
                self.assertTrue(acks and acks[0]["echo_ns"] == 7, log)
                for ack in acks:
                    self.assertGreaterEqual(ack["sent_ns"], stopped["at"])
                if candidate != "b_segment":
                    self.assertNotIn(8, [ack["echo_ns"] for ack in acks])

    def test_stop_request_without_the_send_lock_is_recorded_uncoordinated(self):
        instance = self._receiver("a_framed", [])
        instance.request_stop()
        self.assertTrue(instance.stop.is_set())
        self.assertTrue(instance.stop_coordinated)
        self.assertFalse(instance.abrupt)
        first = instance.stop_ns
        instance.request_stop(abrupt=True)
        self.assertEqual(first, instance.stop_ns)  # the first stop decision stays

        # a session thread holds the lock (a write in progress) too long
        held = self._receiver("a_framed", [])
        taken, release = threading.Event(), threading.Event()

        def writer():
            with held._send_lock:
                taken.set()
                release.wait(5)

        thread = threading.Thread(target=writer)
        thread.start()
        self.assertTrue(taken.wait(5))
        try:
            with mock.patch.object(receiver, "STOP_SEND_WAIT_S", 0.05):
                held.request_stop(abrupt=True)
        finally:
            release.set()
            thread.join(5)
        self.assertTrue(held.stop.is_set())
        self.assertFalse(held.stop_coordinated)

        # a signal handler interrupting the main thread's own request_stop
        # (lock held by the same thread) re-enters instead of waiting on itself
        nested = self._receiver("a_framed", [])
        with nested._send_lock:
            with mock.patch.object(receiver, "STOP_SEND_WAIT_S", 5.0):
                began = time.monotonic()
                nested.request_stop(abrupt=True)
        self.assertLess(time.monotonic() - began, 1.0)
        self.assertTrue(nested.stop_coordinated)

    def test_heartbeat_replies_come_first_for_mixed_bodies(self):
        # #237: whatever the body order, the heartbeat replies lead the write
        # (in body order), then the media acknowledgements (in body order).
        log = []
        instance = self._receiver("a_framed", log)
        instance.counts, instance.last_rx_ns = {}, {}
        instance.tracker.receive.return_value = mock.Mock(
            outcome=mock.Mock(value="accepted"), reason=None)
        source = uuid4()
        stream = (wire.hello_frame(5)
                  + wire.media_frame(source, 1, 0, 1000, b"a") + wire.heartbeat_frame(7)
                  + wire.media_frame(source, 1, 1, 2000, b"b") + wire.heartbeat_frame(8))
        bodies = wire.FrameReader(1024).feed(stream)
        state = {"connection": 1, "session": None}
        reply, echoes = instance._handle_bodies(bodies, object(), state)
        expected = (wire.heartbeat_ack_frame(7) + wire.heartbeat_ack_frame(8)
                    + wire.ack_frame(source, 1, 0, "accepted", "none")
                    + wire.ack_frame(source, 1, 1, "accepted", "none"))
        self.assertEqual((expected, [7, 8]), (reply, echoes))
        self.assertEqual(8, state["echo"])

    def test_first_reply_after_a_pause_repeats_the_latest_echo(self):
        # #237: a reply holding only media acknowledgements (the Agent's
        # heartbeat still queued behind its backlog) after a pause carries the
        # session's latest echo, recorded like any other heartbeat reply.
        log = []
        instance = self._receiver("a_framed", log)
        ack = wire.ack_frame(uuid4(), 1, 3, "accepted", "none")
        state = {"connection": 1, "session": 5, "echo": 7,
                 "echo_sent": time.monotonic() - 2 * receiver.ECHO_REPEAT_S}
        reply, echoes = instance._with_echo(state, ack, [])
        # first in the write, so any part of it the Agent reads includes it
        self.assertEqual((wire.heartbeat_ack_frame(7) + ack, [7]), (reply, echoes))
        connection = self.Connection([], log)
        instance._send(mock.Mock(connection=connection), reply, state, echoes)
        # numbered like every heartbeat_ack frame of the session (1-based)
        self.assertEqual([(7, 1)], [(item["echo_ns"], item["index"])
                                    for item in self._acks(log)])
        instance._send(mock.Mock(connection=connection), wire.heartbeat_ack_frame(8),
                       state, [8])
        self.assertEqual([(7, 1), (8, 2)], [(item["echo_ns"], item["index"])
                                            for item in self._acks(log)])
        state["echo_sent"] = time.monotonic()
        # within the repeat interval, with its own echo, without any echo yet,
        # or with nothing to send: unchanged
        self.assertEqual((ack, []), instance._with_echo(state, ack, []))
        stale = {**state, "echo_sent": time.monotonic() - 2 * receiver.ECHO_REPEAT_S}
        own = ack + wire.heartbeat_ack_frame(9)
        self.assertEqual((own, [9]), instance._with_echo(stale, own, [9]))
        self.assertEqual((ack, []), instance._with_echo({"echo_sent": None}, ack, []))
        self.assertEqual((b"", []), instance._with_echo(stale, b"", []))


class MiscTests(unittest.TestCase):
    def test_every_main_stop_outlasts_the_agent_loss_timeout(self):
        # #237: G5 requires an Agent loss detection for every Main stop, so
        # each scheduled SIGSTOP (fast and full) must outlast the default loss
        # timeout of that timing by the b_segment cadence + reply timeout
        # margin; the old 2 s fast stop could end undetected.
        for fast in (True, False):
            loss_timeout = sender.SenderConfig(candidate="b_segment", host="127.0.0.1",
                                               port=1, n_sources=1, fast=fast).loss_timeout_s
            for name, spec in matrix.SCENARIOS.items():
                for item in spec["fast" if fast else "full"].get("actions", []):
                    if item[1] == "sigstop":
                        with self.subTest(scenario=name, fast=fast):
                            self.assertGreaterEqual(item[2], loss_timeout + 2.5)

    def test_no_blackhole_is_borderline_to_the_agent_loss_timeout(self):
        # #308: a 5 s blackhole against the 5 s loss timeout was detected
        # 3/2/0 of 3 times on a real run. Each scheduled blackhole is either
        # shorter than the timeout (no detection expected) or outlasts it like
        # a Main stop; in a disconnect scenario it must also require one (G4).
        for fast in (True, False):
            loss_timeout = sender.SenderConfig(candidate="b_segment", host="127.0.0.1",
                                               port=1, n_sources=1, fast=fast).loss_timeout_s
            for name, spec in matrix.SCENARIOS.items():
                for item in spec["fast" if fast else "full"].get("proxy", []):
                    if item[1] != "blackhole":
                        continue
                    with self.subTest(scenario=name, fast=fast, at=item[0]):
                        if name in summarize.DISCONNECT_SCENARIOS:
                            self.assertGreaterEqual(item[2], loss_timeout + 2.5)
                            self.assertTrue(summarize._must_disconnect(
                                item, int(loss_timeout * 10**9)))
                        else:
                            self.assertLess(item[2], loss_timeout)

    def test_sigstop_is_confirmed_from_the_process_state(self):
        with tempfile.TemporaryDirectory() as directory:
            stat = Path(directory) / "42" / "stat"
            stat.parent.mkdir()
            # a command name with a space and parenthesis does not confuse it
            stat.write_text("42 (py (x) R) T 1 42 42 0 -1\n", encoding="ascii")
            self.assertTrue(matrix._wait_stopped(42, timeout=0.1, stat_root=directory))
            for state in ("R", "S", "t"):
                stat.write_text(f"42 (py) {state} 1 42\n", encoding="ascii")
                self.assertFalse(matrix._wait_stopped(42, timeout=0.05, stat_root=directory))
            self.assertFalse(matrix._wait_stopped(43, timeout=0.05, stat_root=directory))

    def test_epoch_strictly_increases_in_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "epoch"
            self.assertEqual([1, 2, 3], [sender.next_epoch(path) for _ in range(3)])
            self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))

    def test_outputs_must_be_outside_repository(self):
        with self.assertRaises(materials.MaterialsError):
            materials.require_outside_repository(HARNESS / "transport_poc" / "out")

    def test_holder_frame_protocol(self):
        left, right = socket.socketpair()
        payloads = [(0, 10, b"\xff\xd8a\xff\xd9"), (3, 11, b"\xff\xd8bb\xff\xd9")]
        left.sendall(b"".join(holder.encode_frame(*item) for item in payloads))
        left.close()
        received = []
        holder.read_frames(right, lambda *item: received.append(item), threading.Event())
        right.close()
        self.assertEqual(payloads, received)

    def test_holder_launch_trust_problem_uses_the_holder_launcher(self):
        """The schedule preflight runs the holder's own launcher construction
        (mocked here: no GStreamer, no camera) and reports its refusal."""
        from media_capture_agent import uvc_pipeline
        with mock.patch.object(uvc_pipeline, "GStreamerLauncher") as launcher:
            self.assertIsNone(holder.launch_trust_problem("/usr/bin/gst",
                                                          dev_checkout_helper=False))
            self.assertIs(uvc_pipeline.require_trusted_file,
                          launcher.call_args.kwargs["trust_file"])
            self.assertIsNone(holder.launch_trust_problem("/usr/bin/gst",
                                                          dev_checkout_helper=True))
            self.assertIs(holder._dev_trust, launcher.call_args.kwargs["trust_file"])
            self.assertEqual(("/usr/bin/gst",), launcher.call_args.args)
            for error, text in ((uvc_pipeline.PipelineError("sandbox helper is writable by "
                                                            "others"), "writable by others"),
                                (FileNotFoundError("gone"), "FileNotFoundError")):
                launcher.side_effect = error
                with self.subTest(error=text):
                    self.assertIn(text, holder.launch_trust_problem(
                        "/usr/bin/gst", dev_checkout_helper=True))

    def test_holder_never_auto_binds_ambiguous_cameras(self):
        from media_capture_agent.uvc_identity import DeviceEvidence

        def device(number, serial):
            return DeviceEvidence(device_path=f"/dev/video{number}", vendor="1234",
                                  product="5678", serial=serial, device_number=number)
        sources = [uuid4(), uuid4()]
        for candidates in ([device(0, None), device(2, "B")], [device(0, "A"), device(2, "A")]):
            capture = mock.Mock()
            capture.candidates.return_value = candidates
            with self.subTest(candidates=len(candidates)):
                with self.assertRaises(SystemExit):
                    holder.approve_all(capture, sources)
                capture.approve.assert_not_called()
        capture = mock.Mock()
        capture.candidates.return_value = [device(2, "B"), device(0, "A")]
        holder.approve_all(capture, sources)
        self.assertEqual(2, capture.approve.call_count)

    def test_real_inputs_require_the_holder_source(self):
        common = dict(candidate="a_framed", host="127.0.0.1", port=1, n_sources=1)
        for kind in ("builtin", "gst"):
            with self.subTest(source_kind=kind):
                with self.assertRaises(ValueError):
                    sender.SenderConfig(source_kind=kind, real_inputs=True, **common)
        with self.assertRaises(ValueError):
            sender.SenderConfig(source_kind="holder", real_inputs=True, **common)  # no socket
        sender.SenderConfig(source_kind="holder", holder_socket="/x", real_inputs=True,
                            **common)
        from transport_poc import poc15
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                poc15.main(["sender", "--candidate", "a_framed", "--host", "127.0.0.1",
                            "--port", "1", "--node-dir", directory, "--epoch-file",
                            str(Path(directory) / "e"), "--seconds", "1", "--out",
                            str(Path(directory) / "s.jsonl"), "--run-id", RUN,
                            "--source-kind", "gst", "--real-inputs"])
            self.assertFalse((Path(directory) / "s.jsonl").exists())

    def test_host_roles_run_exactly_one_scenario_and_candidate(self):
        """PR #222 review (head 327fd26): a ``--role main`` / ``--role agent``
        invocation with several runs lets the agent reach the previous run's
        receiver, so each host role refuses more than one scenario or candidate."""
        from transport_poc import poc15
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(matrix, "Orchestrator") as orchestrator:
            orchestrator.return_value.run.return_value = Path(directory)
            base = ["matrix", "--materials", directory, "--state", directory,
                    "--out", directory, "--run-id", RUN]
            for role in ("main", "agent"):
                for extra in (["--scenarios", "normal,outage_8s", "--candidates", "a_framed"],
                              ["--scenarios", "normal"],  # default: three candidates
                              ["--scenarios", "default", "--candidates", "a_framed"]):
                    with self.subTest(role=role, extra=extra):
                        with self.assertRaises(SystemExit) as raised:
                            poc15.main(base + ["--role", role] + extra)
                        self.assertIn("exactly one scenario", str(raised.exception.code))
            orchestrator.assert_not_called()
            with contextlib.redirect_stdout(io.StringIO()):
                poc15.main(base + ["--role", "main", "--scenarios", "normal",
                                   "--candidates", "a_framed"])
                poc15.main(base + ["--scenarios", "normal,outage_8s"])  # role both
            self.assertEqual(2, orchestrator.call_count)

    def test_holder_hello_identifies_the_sender(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        holder.send_hello(left, 12345)
        self.assertEqual(12345, holder.read_hello(right))
        left.sendall(b"\0" * 8)  # zero is not a nonce
        self.assertIsNone(holder.read_hello(right))
        left.close()
        self.assertIsNone(holder.read_hello(right))
        for bad in (0, 1 << 63):
            with self.assertRaises(ValueError):
                holder.send_hello(right, bad)

    def test_holder_forwards_frames_from_capture_in_memory(self):
        frame = mock.Mock(data=b"\xff\xd8x\xff\xd9", received_monotonic=1.5)
        queue = mock.Mock()
        queue.get.side_effect = lambda timeout: frame
        queue.drop_stats.return_value = (0, None)
        capture = mock.Mock()
        capture.frames.return_value = queue
        capture.counters.return_value = SimpleNamespace(launches=1, stream_invalid=0,
                                                        padding_tolerated=2)
        with tempfile.TemporaryDirectory() as directory:
            writer = records.JsonlWriter(Path(directory) / "h.jsonl", run_id=RUN, role="holder")
            instance = holder.Holder(capture, [uuid4()], Path(directory) / "sock", writer)
            self.assertEqual(0o700, stat.S_IMODE(os.stat(Path(directory) / "sock").st_mode))
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(instance.path))
            holder.send_hello(client, 4242)
            got = []
            stop = threading.Event()
            reader = threading.Thread(target=lambda: holder.read_frames(
                client, lambda *item: (got.append(item), stop.set()), stop))
            reader.start()
            instance.run(0.5)
            reader.join(5)
            client.close()
            writer.close()
            self.assertEqual((0, 1_500_000_000, b"\xff\xd8x\xff\xd9"), got[0])
            capture.close.assert_called_once()
            self.assertFalse(instance.path.exists())
            # the session is recorded under the sender's nonce, with its counts
            rows = records.read_jsonl(Path(directory) / "h.jsonl")
            opened = [row for row in rows if row["kind"] == "session_open"]
            forwarded = [row for row in rows if row["kind"] == "forwarded"]
            self.assertEqual([4242], [row["nonce"] for row in opened])
            self.assertEqual([(4242, 0)], [(row["nonce"], row["source"]) for row in forwarded])
            self.assertGreaterEqual(forwarded[0]["frames"], 1)
            self.assertEqual(1, sum(1 for row in rows if row["kind"] == "session_close"))
            samples = [row for row in rows if row["kind"] == "sample"]
            self.assertTrue(samples)
            self.assertEqual((1, 0, 0, 0, 2), tuple(samples[-1][key] for key in (
                "capture_launches", "capture_restarts", "sources_never_launched",
                "stream_invalid", "padding_tolerated")))

    def test_holder_samples_judge_restarts_per_source(self):
        # A total of 3 launches equals the 3 sources, yet source 0 restarted
        # once and source 1 never started: the holder counts per source.
        sources = [uuid4(), uuid4(), uuid4()]
        per_source = {sources[0]: SimpleNamespace(launches=2, stream_invalid=1,
                                                  padding_tolerated=2),
                      sources[1]: SimpleNamespace(launches=0, stream_invalid=0,
                                                  padding_tolerated=0),
                      sources[2]: SimpleNamespace(launches=1, stream_invalid=0,
                                                  padding_tolerated=0)}
        queue = mock.Mock()
        queue.get.side_effect = lambda timeout: None
        queue.drop_stats.return_value = (0, None)
        capture = mock.Mock()
        capture.frames.return_value = queue
        capture.counters.side_effect = per_source.__getitem__
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "h.jsonl"
            writer = records.JsonlWriter(out, run_id=RUN, role="holder")
            holder.Holder(capture, sources, Path(directory) / "sock", writer).run(0.2)
            writer.close()
            samples = [row for row in records.read_jsonl(out) if row["kind"] == "sample"]
        self.assertTrue(samples)
        self.assertEqual((3, 1, 1, 1, 2), tuple(samples[-1][key] for key in (
            "capture_launches", "capture_restarts", "sources_never_launched",
            "stream_invalid", "padding_tolerated")))

    def _idle_holder(self, directory):
        """A holder whose camera delivers no frame (as during a capture stall)."""
        queue = mock.Mock()
        queue.get.side_effect = lambda timeout: None
        queue.drop_stats.return_value = (0, None)
        capture = mock.Mock()
        capture.frames.return_value = queue
        capture.counters.return_value = SimpleNamespace(launches=1, stream_invalid=0,
                                                        padding_tolerated=2)
        out = Path(directory) / "h.jsonl"
        writer = records.JsonlWriter(out, run_id=RUN, role="holder")
        return holder.Holder(capture, [uuid4()], Path(directory) / "sock", writer), writer, out

    def _hello(self, instance, nonce):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.connect(str(instance.path))
        holder.send_hello(client, nonce)
        return client

    def test_holder_ends_a_session_at_sender_eof_without_frames(self):
        # #307: with no frame to send, the holder still sees the sender's EOF
        with tempfile.TemporaryDirectory() as directory:
            instance, writer, out = self._idle_holder(directory)
            first = self._hello(instance, 11)
            runner = threading.Thread(target=instance.run, args=(3.0,))
            runner.start()
            deadline = time.monotonic() + 2
            while instance.client is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIsNotNone(instance.client)
            first.close()
            while instance.client is not None and time.monotonic() < deadline:
                time.sleep(0.01)
            ended = instance.client is None
            instance.stop.set()
            runner.join(5)
            writer.close()
            self.assertTrue(ended)
            rows = records.read_jsonl(out)
            self.assertEqual([("session_open", 11), ("forwarded", 11), ("session_close", 11)],
                             [(row["kind"], row["nonce"]) for row in rows if "nonce" in row])
            self.assertEqual(0, instance.forward_drops)

    def test_holder_serves_a_restarted_sender_and_refuses_a_concurrent_one(self):
        with tempfile.TemporaryDirectory() as directory:
            instance, writer, out = self._idle_holder(directory)
            instance.listener.setblocking(False)
            instance.selector.register(instance.listener, selectors.EVENT_READ)
            first = self._hello(instance, 11)
            instance._accept()
            self.assertEqual(11, instance.client_nonce)
            # the restarted sender connects before the holder handled the EOF
            first.close()
            second = self._hello(instance, 22)
            instance._accept()
            self.assertEqual(22, instance.client_nonce)
            # a second sender while the current one is alive is refused
            third = self._hello(instance, 33)
            instance._accept()
            self.assertEqual(22, instance.client_nonce)
            third.settimeout(2)
            try:
                self.assertEqual(b"", third.recv(1))
            except ConnectionResetError:
                pass  # closed with its HELLO unread
            self.assertFalse(holder.peer_gone(instance.client))
            second.close()
            self.assertTrue(holder.peer_gone(instance.client))
            instance.close()
            writer.close()
            rows = records.read_jsonl(out)
            self.assertEqual([("session_open", 11), ("forwarded", 11), ("session_close", 11),
                              ("session_open", 22), ("refused", None), ("forwarded", 22),
                              ("session_close", 22)],
                             [(row["kind"], row.get("nonce")) for row in rows
                              if row["kind"] in ("session_open", "session_close", "forwarded",
                                                 "refused")])
            self.assertEqual("connection_limit",
                             next(row for row in rows if row["kind"] == "refused")["reason"])


def _free_offset():
    for offset in range(11000, 18000, 37):
        try:
            for port in (47200 + offset, 47201 + offset, 47210 + offset, 47211 + offset,
                         47212 + offset):
                with socket.create_server(("127.0.0.1", port)):
                    pass
            return offset
        except OSError:
            continue
    raise unittest.SkipTest("no free loopback ports")


class LoopbackMatrixTests(unittest.TestCase):
    """A short synthetic loopback run of real receiver/sender/proxy processes."""

    def test_short_matrix(self):
        directory = tempfile.TemporaryDirectory(prefix="poc15-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        materials.init(root / "m")
        args = argparse.Namespace(
            role="both", materials=str(root / "m"), node_root=str(root / "m" / "nodes"),
            state=str(root / "st"), out=str(root / "out"), fast=True, sources=1, fps=30,
            frame_bytes=8000, source_kind="builtin", holder_socket=None, real_inputs=False,
            bind="127.0.0.1", upstream_host="127.0.0.1", upstream_port=0,
            proxy_host="127.0.0.1", port_offset=_free_offset(), main_grace=0)
        orchestrator = matrix.Orchestrator(args, RUN)
        out = orchestrator.run(["normal", "outage_8s", "auth_other_ca", "route_probe"],
                               ["a_framed"])
        orchestrator.run(["rst", "route_probe"], ["b_chunked"])
        # #237: the fast Main stop is long enough for b_segment's Agent to
        # detect it (G5), and the orchestrator confirms the SIGSTOP
        orchestrator.run(["normal", "slow_stop_10s"], ["b_segment"])
        actions = [row["action"] for row in records.read_jsonl(
            out / "slow_stop_10s-b_segment" / "orchestrator-both.jsonl")
            if row["kind"] == "action"]
        self.assertEqual(["sigstop", "stopped", "sigcont"], actions)
        report = summarize.summarize([out])
        runs = {(row["scenario"], row["candidate"]): row for row in report["runs"]}
        for key, row in runs.items():
            with self.subTest(run=key):
                # The whole row (numbers and tokens only) explains a failure.
                detail = json.dumps(row, sort_keys=True)
                self.assertEqual("pass", row["g1"], detail)
                self.assertEqual("pass", row["g2"], detail)
                # route_probe moves no media: no resource bound to assess
                self.assertEqual("not_applicable" if key[0] == "route_probe" else "pass",
                                 row["g3"], detail)
                self.assertIn(row["g4"], ("pass", "not_applicable"), detail)
                self.assertIn(row["g5"], ("pass", "not_applicable"), detail)
        self.assertGreater(runs[("outage_8s", "a_framed")]["reported_missing"], 0)
        self.assertEqual(0, runs[("auth_other_ca", "a_framed")]["receiver_accepted"])
        self.assertGreater(runs[("normal", "b_segment")]["receiver_accepted"], 0)
        for candidate in ("a_framed", "b_chunked"):
            # this run's receiver recorded each probe's session nonce
            row = runs[("route_probe", candidate)]
            self.assertEqual((1, 1), (row["route_probes"], row["route_probes_seen_by_receiver"]))
        for path in out.rglob("*.jsonl"):
            records.read_jsonl(path)  # every stored value is numeric or a token
        for row in runs.values():
            self.assertEqual("pass", row["integrity"], json.dumps(row, sort_keys=True))

    def test_two_host_roles_on_loopback(self):
        """``--role main`` and ``--role agent`` as two orchestrators (two output
        trees, one run id): Main restart and the post-run Main grace period."""
        directory = tempfile.TemporaryDirectory(prefix="poc15-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        materials.init(root / "m")
        offset = _free_offset()
        outs = {}

        def side(role):
            args = argparse.Namespace(
                role=role, materials=str(root / "m"), node_root=str(root / "m" / "nodes"),
                state=str(root / f"st-{role}"), out=str(root / f"out-{role}"), fast=True,
                sources=1, fps=30, frame_bytes=8000, source_kind="builtin", holder_socket=None,
                real_inputs=False, bind="127.0.0.1", upstream_host="127.0.0.1",
                upstream_port=0, proxy_host="127.0.0.1", port_offset=offset, main_grace=4)
            outs[role] = matrix.Orchestrator(args, RUN).run(["main_restart"], ["a_framed"])

        with mock.patch("builtins.print"):
            main = threading.Thread(target=side, args=("main",))
            main.start()
            time.sleep(1.0)
            side("agent")
            main.join(60)
        self.assertFalse(main.is_alive())
        report = summarize.summarize([outs["main"], outs["agent"]])
        row = report["runs"][0]
        detail = json.dumps(row, sort_keys=True)
        self.assertEqual(("pass", 1), (row["integrity"], row["run_ids"]), detail)
        self.assertEqual(("pass", "pass", "pass"), (row["g2"], row["g4"], row["g5"]), detail)
        # #237: the restarted receiver's stop was coordinated with its reply
        # writes, and the Agent recorded each connection's handshake
        name = "main_restart-a_framed"
        stops = [(item["abrupt"], item["coordinated"]) for item in records.read_jsonl(
            Path(outs["main"]) / name / "receiver.jsonl") if item["kind"] == "stopping"]
        self.assertIn((True, True), stops)
        agent = records.read_jsonl(Path(outs["agent"]) / name / "sender.jsonl")
        connected = [item for item in agent if item["kind"] == "connected"]
        self.assertGreaterEqual(len(connected), 2)
        # every loss / close carries the received heartbeat_ack frame count,
        # and the Main side numbered its heartbeat replies
        counted = [item for item in agent if item["kind"] in ("loss_detected", "closed")]
        self.assertTrue(counted)
        for item in counted:
            self.assertTrue(isinstance(item.get("echo_frames"), int)
                            and item["echo_frames"] >= 0, item)
        self.assertTrue(any(item["echo_frames"] > 0 for item in counted))
        acks = [item for item in records.read_jsonl(Path(outs["main"]) / name / "receiver.jsonl")
                if item["kind"] == "heartbeat_ack"]
        self.assertTrue(acks and all(isinstance(item.get("index"), int) for item in acks))
        # one Main-side tree alone is incomplete, never a pass
        alone = summarize.summarize([outs["main"]])["runs"][0]
        self.assertEqual("unmeasured", alone["integrity"])
        self.assertNotIn("pass", [alone[g] for g in ("g1", "g2", "g3", "g4", "g5")])


_CASES = (RecordTests, WireTests, ProxyTests, SummarizerTests, SenderProducerTests,
          ReceiverHeartbeatAckTests, MiscTests, LoopbackMatrixTests)

if os.environ.get("POC15_HARNESS_CHILD") != "1":
    # Earlier tests in the same interpreter may install process-wide audit
    # hooks that refuse socket connects (smoke observation); they cannot be
    # removed. Run these cases in a fresh interpreter instead.
    for _case in _CASES:
        del globals()[_case.__name__]
    del _case, _CASES

    class TransportPocHarnessTests(unittest.TestCase):
        def test_harness_cases_in_a_fresh_interpreter(self):
            import subprocess
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "-v", "tests.test_transport_poc_harness"],
                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
                timeout=540, env={**os.environ, "POC15_HARNESS_CHILD": "1"})
            self.assertEqual(0, result.returncode, result.stderr[-6000:])
            self.assertIn("OK", result.stderr.splitlines()[-1])


if __name__ == "__main__":
    unittest.main()
