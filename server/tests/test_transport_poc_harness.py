"""Synthetic tests for the Issue #15 transport PoC harness (scripts/manual/transport_poc).

The harness is a manual-test tool outside the product; these tests prove its
wire formats, impairment proxy, numeric-only records and gate summarizer, and
run a short loopback matrix (both ends on 127.0.0.1, generated payload bytes,
disposable CA/ledger in a temporary directory). They do not verify any real
LAN, capture host, camera or transport choice.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from uuid import uuid4

HARNESS = Path(__file__).resolve().parents[2] / "scripts" / "manual"
AGENT = Path(__file__).resolve().parents[2] / "agent"
for path in (str(HARNESS), str(AGENT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from transport_poc import (holder, materials, matrix, proxy, records,  # noqa: E402
                           sender, summarize, wire)

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


def _finished_receiver(rows):
    """Receiver rows with one ``ready`` and one ``end`` (one process instance)."""
    rows = list(rows)
    if not any(row["kind"] == "ready" for row in rows):
        rows.insert(0, {"kind": "ready", "t_ns": 0, "port": 1})
    if not any(row["kind"] == "end" for row in rows):
        rows.append({"kind": "end", "t_ns": _LATE, "accepted": 0})
    return rows


_ACCOUNTED = {"drops": 0, "drops_sent": 0, "residual": 0, "residual_sent": 0}


def _sender_end(source, epoch, generated, accepted, **fields):
    """A sender ``end`` with complete unit accounting (G2 drop reconciliation)."""
    return {"kind": "end", "t_ns": _LATE, "source": source, "epoch": epoch,
            "generated": generated, "accepted": accepted, **_ACCOUNTED, **fields}


def _finished_sender(rows, sources=1, receiver=()):
    """Sender rows with one ``start`` / ``metric`` and at least one ``end``.

    Without explicit ``end`` rows, one per durable row of ``receiver`` is added
    that accounts for every unit up to its last durable sequence (no drops).
    """
    rows = list(rows)
    if not any(row["kind"] == "start" for row in rows):
        rows.insert(0, {"kind": "start", "t_ns": 0, "n_sources": sources})
    if not any(row["kind"] == "end" for row in rows):
        durable = [row for row in receiver if row["kind"] == "durable" and row["source"] >= 0]
        rows += [_sender_end(row["source"], row["epoch"], row["max_sequence"] + 1, row["units"])
                 for row in durable] or [_sender_end(0, 1, 0, 0)]
    if not any(row["kind"] == "metric" for row in rows):
        rows.append({"kind": "metric", "t_ns": _LATE, "payload_bytes": 0})
    return rows


def _finished_proxy(rows):
    rows = list(rows)
    if not any(row["kind"] == "ready" for row in rows):
        rows.insert(0, {"kind": "ready", "t_ns": 0, "port": 1})
    if not any(row["kind"] == "end" for row in rows):
        rows.append({"kind": "end", "t_ns": _LATE, "bytes_up": 0, "bytes_down": 0})
    return rows


def _base(scenario, candidate="a_framed", sources=1):
    orchestrator = [{"kind": "start", "t_ns": 0, "scenario": scenario, "candidate": candidate,
                     "n_sources": sources, "inputs": "synthetic", "fast": True,
                     "side": "both"}]
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
        orchestrator, receiver, sender_rows = _base("outage_5s")
        durable = {"kind": "durable", "t_ns": 9, "source": 0, "epoch": 1, "min_sequence": 0,
                   "max_sequence": 99, "units": 90, "duplicates": 0}
        gap = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 1, "reason": "sequence_skip",
               "after_sequence": 10, "before_sequence": 21, "missing_units": 10}
        self.run_dir("outage_5s-a_framed", orchestrator=orchestrator,
                     receiver=receiver + [gap, durable], sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["outage_5s"]["g2"])
        self.rewrite("outage_5s-a_framed", "receiver",
                     receiver + [{**gap, "missing_units": 9}, durable])
        self.assertEqual("fail", self.report()["outage_5s"]["g2"])
        self.rewrite("outage_5s-a_framed", "receiver",
                     receiver + [gap, {**durable, "duplicates": 1}])
        self.assertEqual("fail", self.report()["outage_5s"]["g2"])

    def test_capture_restart_requires_unknown_extent(self):
        orchestrator, receiver, sender_rows = _base("capture_restart")
        rows = [{"kind": "durable", "t_ns": 9, "source": 0, "epoch": epoch, "min_sequence": 0,
                 "max_sequence": 9, "units": 10, "duplicates": 0} for epoch in (1, 2)]
        restart = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 2, "reason": "capture_restart",
                   "after_sequence": None, "before_sequence": 0, "missing_units": None}
        self.run_dir("capture_restart-a_framed", orchestrator=orchestrator,
                     receiver=receiver + rows + [restart], sender_rows=sender_rows)
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
        orchestrator, receiver, sender_rows = _base("outage_5s")
        second = 10**9
        proxy_rows = [{"kind": "impairment_start", "t_ns": 10 * second, "impairment": "blackhole",
                       "duration_ns": 5 * second, "rate_bytes": 0},
                      {"kind": "impairment_end", "t_ns": 15 * second, "impairment": "blackhole",
                       "duration_ns": 5 * second, "rate_bytes": 0}]
        events = [{"kind": "start", "t_ns": 0, "loss_timeout_ns": 2 * second},
                  {"kind": "loss_detected", "t_ns": 12 * second, "source": 0, "idle_ns": 1,
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
        self.run_dir("outage_5s-a_framed", orchestrator=orchestrator, receiver=receiver + [gap],
                     sender_rows=sender_rows + events, proxy_rows=proxy_rows)
        row = self.report()["outage_5s"]
        self.assertEqual(("pass", "pass"), (row["g4"], row["g5"]))
        self.assertEqual(second, row["reconnect_p95_ns"])
        late = [*events[:3], {**events[3], "t_ns": 26 * second}]
        self.rewrite("outage_5s-a_framed", "sender", sender_rows + late)
        self.assertEqual("fail", self.report()["outage_5s"]["g4"])
        self.rewrite("outage_5s-a_framed", "sender", sender_rows + events)
        self.rewrite("outage_5s-a_framed", "receiver",
                     receiver + [{**gap, "to_capture_ns": 700 * second}])
        self.assertEqual("fail", self.report()["outage_5s"]["g5"])

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
                # neither side detects anything and there is no durable gap
                self.run_dir(name, orchestrator=orchestrator, receiver=receiver,
                             sender_rows=sender_rows + [start])
                self.assertEqual("fail", self.report()[scenario]["g5"])
                loss = {"kind": "loss_detected", "t_ns": 15 * second, "source": 0,
                        "idle_ns": 5 * second, "connection": 1,
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
        ends = [{"kind": "end", "t_ns": 9, "source": index, "accepted": 10, "rejected": 0,
                 "drops": 0} for index in range(4)]
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
        ends = [{"kind": "end", "t_ns": 9, "source": index, "accepted": 0 if index == 4 else 10,
                 "rejected": 10 if index == 4 else 0, "drops": 0,
                 "rejected_source_capacity": 10 if index == 4 else 0} for index in range(5)]
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
        close_1 = {"kind": "closed", "t_ns": int(12.5 * second), "reason": "peer_closed"}
        accept_1 = {"kind": "first_accept", "t_ns": 13 * second, "connection": 2, "source": 0}
        close_2 = {"kind": "closed", "t_ns": int(13.5 * second), "reason": "peer_closed"}
        accept_2 = {"kind": "first_accept", "t_ns": 14 * second, "connection": 3, "source": 0}
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

    def _revoked_live(self, *, action=True, revoked_accepted=40, after=(40, 40), retry=True):
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
        if retry:
            rows.append({"kind": "auth_refused", "t_ns": 6 * second,
                         "reason": "capture_node_not_admitted"})
        self.run_dir("auth_revoked_live-a_framed", orchestrator=orchestrator, receiver=rows,
                     sender_rows=sender_rows)
        return self.report()["auth_revoked_live"]["g1"]

    def test_revoked_live_requires_complete_evidence(self):
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
        orchestrator, receiver, sender_rows = _base("outage_5s")
        proxy_rows = [{"kind": "impairment_start", "t_ns": 10 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0},
                      {"kind": "impairment_end", "t_ns": 13 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0}]
        events = [{"kind": "start", "t_ns": 0, "loss_timeout_ns": int(1.5 * second)},
                  {"kind": "loss_detected", "t_ns": 12 * second, "source": 0, "idle_ns": 1,
                   "last_committed_capture_ns": 10 * second},
                  {"kind": "closed", "t_ns": 12 * second, "reason": "loss_timeout"},
                  {"kind": "first_accept", "t_ns": 14 * second, "connection": 2, "source": 0}]
        durable = {"kind": "durable", "t_ns": 30 * second, "source": 0, "epoch": 1,
                   "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
        flagged = {"kind": "interrupted", "t_ns": 12 * second, "source": 0,
                   "since_last_rx_ns": 2 * second}
        name = "outage_5s-a_framed"
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + [durable, flagged],
                     sender_rows=sender_rows + events, proxy_rows=proxy_rows)
        self.assertEqual("pass", self.report()["outage_5s"]["g5"])
        # Main never flagged the silent outage itself
        self.rewrite(name, "receiver", receiver + [durable])
        self.assertEqual("fail", self.report()["outage_5s"]["g5"])
        # Main flagged it, but later than 15 s after the last received unit
        self.rewrite(name, "receiver",
                     receiver + [durable, {**flagged, "since_last_rx_ns": 16 * second}])
        self.assertEqual("fail", self.report()["outage_5s"]["g5"])
        # two hosts: one Main detection per window and source, no clock comparison
        self.rewrite(name, "receiver", receiver + [durable, {**flagged, "t_ns": 1}])
        runs = summarize.summarize([self.root], single_host=False)["runs"]
        self.assertEqual("pass", runs[0]["g5"])
        self.rewrite(name, "receiver", receiver + [durable, flagged])
        # the Agent-side proxy record is missing: incomplete, never pass
        (self.root / name / "proxy.jsonl").unlink()
        self.assertEqual("unmeasured", self.report()["outage_5s"]["g5"])
        # fewer blackholes recorded than scheduled
        self.rewrite(name, "proxy", [{"kind": "sample", "t_ns": 1, "max_held": 0,
                                      "buffer_bytes": 65536}])
        self.assertEqual("fail", self.report()["outage_5s"]["g5"])

    def test_capacity_needs_every_sender_total(self):
        orchestrator, receiver, sender_rows = _base("capacity_4", sources=4)
        durable = [{"kind": "durable", "t_ns": 9, "source": index, "epoch": 1,
                    "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
                   for index in range(4)]
        ends = [{"kind": "end", "t_ns": 9, "source": index, "accepted": 10, "rejected": 0,
                 "drops": 0} for index in range(4)]
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
        loss = {"kind": "loss_detected", "t_ns": 900 * second, "source": 0,
                "idle_ns": 5 * second, "connection": 1, "last_committed_capture_ns": 1}
        self.run_dir("slow_stop_10s-a_framed", orchestrator=main, receiver=receiver,
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
        _write(self.root, "holder", [sample, {**sample, "t_ns": 2}])
        holder = summarize.summarize([self.root], holder_files=[path])["holder"]
        self.assertEqual(("pass", 1), (holder["holder_verdict"],
                                       holder["holder_forward_drops_allowed"]))
        _write(self.root, "holder", [{**sample, "forward_drops": 2}])
        holder = summarize.summarize([self.root], holder_files=[path])["holder"]
        self.assertEqual("fail", holder["holder_verdict"])
        _write(self.root, "holder", [{**sample, "queue_drops": 1}])
        report = summarize.summarize([self.root], holder_files=[path])
        self.assertEqual("fail", report["holder"]["holder_verdict"])
        self.assertIn("holder: fail", summarize.render(report))

    def test_report_is_numeric_and_renders(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows)
        report = summarize.summarize([self.root])
        self.assertEqual("unmeasured", report["candidates"][0]["secondary_packet_loss"])
        self.assertIn("a_framed", summarize.render(report))

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
                  {"kind": "end", "t_ns": 8, "accepted": 0}]
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
        ends = [{"kind": "end", "t_ns": 9, "source": index, "accepted": 10, "rejected": 0,
                 "drops": 0} for index in range(4)]
        receiver_end = {"kind": "end", "t_ns": 9, "accepted": 40, "backpressured": 0,
                        "rate_limited": 0, "cpu_quota_us": 200000, "cpu_period_us": 100000}
        metric = {"kind": "metric", "t_ns": 9, "payload_bytes": 100,
                  "cpu_quota_us": 100000, "cpu_period_us": 100000}
        self.run_dir("capacity_4-a_framed", orchestrator=orchestrator,
                     receiver=receiver + self._durable(4) + [receiver_end],
                     sender_rows=[{"kind": "start", "t_ns": 0, "n_sources": 4}]
                     + sender_rows + ends + [metric])
        orchestrator, receiver, sender_rows = _base("fifth_refused", sources=5)
        ends = [{"kind": "end", "t_ns": 9, "source": index, "accepted": 0 if index == 4 else 10,
                 "rejected": 10 if index == 4 else 0, "drops": 0,
                 "rejected_source_capacity": 10 if index == 4 else 0} for index in range(5)]
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
        orchestrator, receiver, sender_rows = _base("outage_5s")
        # fast outage_5s: one 3 s blackhole; a 5 s Agent loss timeout requires
        # no disconnect (3 s < 5 s + 1 s), so no reconnect episode is needed
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": 5 * second}
        self.run_dir("outage_5s-a_framed", orchestrator=orchestrator,
                     receiver=receiver + self._durable(1), sender_rows=[start] + sender_rows)
        row = self.report()["outage_5s"]
        self.assertEqual(("pass", 0, 0), (row["g4"], row["reconnects"],
                                          row["reconnects_required"]))
        # a 1.5 s loss timeout requires one, and it is missing
        self.rewrite("outage_5s-a_framed", "sender",
                     [{**start, "loss_timeout_ns": int(1.5 * second)}] + sender_rows)
        row = self.report()["outage_5s"]
        self.assertEqual(("fail", 1), (row["g4"], row["reconnects_required"]))

    def test_post_run_stale_flag_is_not_outage_detection(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("outage_5s")
        proxy_rows = [{"kind": "impairment_start", "t_ns": 10 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0},
                      {"kind": "impairment_end", "t_ns": 13 * second, "impairment": "blackhole",
                       "duration_ns": 3 * second, "rate_bytes": 0}]
        events = [{"kind": "start", "t_ns": 0, "n_sources": 1,
                   "loss_timeout_ns": int(1.5 * second)},
                  {"kind": "loss_detected", "t_ns": 12 * second, "source": 0, "idle_ns": 1,
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
        name = "outage_5s-a_framed"
        for two_host in (False, True):
            with self.subTest(two_host=two_host):
                self.run_dir(name, orchestrator=orchestrator, two_host=two_host,
                             receiver=receiver + sessions + self._durable(1) + [in_window],
                             sender_rows=sender_rows + events, proxy_rows=proxy_rows)
                self.assertEqual("pass", self.report()["outage_5s"]["g5"])
                # only the flag raised after the sender shut down (main grace)
                self.rewrite(name, "receiver",
                             receiver + sessions + self._durable(1) + [post_run])
                row = self.report()["outage_5s"]
                self.assertEqual(("fail", 0), (row["g5"], row["main_detect_matched"]))
                for path in (self.root / name).iterdir():
                    path.unlink()

    def test_real_inputs_declared_by_either_side(self):
        orchestrator, receiver, sender_rows = _base("normal")
        name = "normal-a_framed"
        real_sender = [{"kind": "start", "t_ns": 0, "n_sources": 1, "inputs": "real"}]
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
        _write(self.root, "holder", [sample])
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
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + rows + [restart],
                     sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["capture_restart"]["g2"])
        (self.root / name / "sender.jsonl").unlink()
        self.assertEqual("unmeasured", self.report()["capture_restart"]["g2"])
        # a sender that started but left no per-source totals
        _write(self.root / name, "sender",
               [{"kind": "start", "t_ns": 0, "n_sources": 1}, *sender_rows,
                {"kind": "metric", "t_ns": 9, "payload_bytes": 0}])
        self.assertEqual("unmeasured", self.report()["capture_restart"]["g2"])

    def test_two_host_receiver_stop_close_burst_is_one_episode(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("main_restart")
        orchestrator = orchestrator + [
            {"kind": "action", "t_ns": 10 * second, "action": "restart_receiver",
             "duration_ns": 0},
            {"kind": "action", "t_ns": 12 * second, "action": "ready", "duration_ns": 0}]
        start = {"kind": "start", "t_ns": 0, "n_sources": 1, "loss_timeout_ns": 5 * second}
        # Agent clock: the stopping receiver drops the live connection, then
        # accepts one more connection and drops it in _finish, then the new
        # receiver accepts
        burst = [{"kind": "closed", "t_ns": 500 * second, "reason": "peer_closed"},
                 {"kind": "closed", "t_ns": 501 * second, "reason": "tls_session_failed"},
                 {"kind": "first_accept", "t_ns": 503 * second, "connection": 3, "source": 0}]
        self.run_dir("main_restart-a_framed", orchestrator=orchestrator, two_host=True,
                     receiver=receiver + self._durable(1),
                     sender_rows=[start] + sender_rows + burst)
        row = self.report()["main_restart"]
        self.assertEqual(("pass", 1, 1), (row["g4"], row["reconnects"],
                                          row["reconnects_required"]))
        # two separate episodes (an accept between them) still need two accepts
        split = burst[:1] + [{**burst[2], "t_ns": 500 * second + 1}] + burst[1:2]
        self.rewrite("main_restart-a_framed", "sender", [start] + sender_rows + split)
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
        losses = [{"kind": "loss_detected", "t_ns": at * second + 1, "source": 0, "idle_ns": 1,
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
            return {"kind": "loss_detected", "t_ns": at, "source": source, "idle_ns": 1,
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
        row = run(drops=10)
        self.assertEqual(("pass", "pass", 10, False),
                         (row["g2"], row["drop_accounting"], row["agent_accounted_tail_units"],
                          row["lossless"]))
        # still held at shutdown (not lost) is fine too
        self.assertEqual("pass", run(residual=10)["g2"])
        # trailing units neither dropped nor held: vanished silently
        row = run()
        self.assertEqual(("fail", 10), (row["g2"], row["unexplained_loss_units"]))
        # drops the Agent recorded that appear neither as Main gaps nor in the tail
        row = run(generated=100, drops=5)
        self.assertEqual(("fail", 5), (row["g2"], row["unexplained_drop_units"]))
        # ... unless those units had been sent unacknowledged (Main may hold them)
        self.assertEqual("pass", run(generated=100, drops=5, drops_sent=5)["g2"])
        # an interior drop is Main's reported gap
        gap = {"kind": "gap", "t_ns": 5, "source": 0, "epoch": 1, "reason": "sequence_skip",
               "after_sequence": 10, "before_sequence": 16, "missing_units": 5}
        interior = [{**durable[0], "units": 95}]
        self.run_dir(name, orchestrator=orchestrator, receiver=receiver + interior + [gap],
                     sender_rows=[start] + sender_rows + [_sender_end(0, 1, 100, 95, drops=5)])
        self.assertEqual("pass", self.report()["normal"]["g2"])
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

    def test_sender_records_its_unit_accounting(self):
        state = sender.SourceState(0, uuid4(), 2)
        unsent = sender.Unit(1, 1, b"x")
        sent = sender.Unit(2, 2, b"x")
        sent.sent_ns = 5
        state.drop(unsent)
        state.drop(sent)
        self.assertEqual((2, 1), (state.drops, state.drops_sent))

    def test_sides_must_declare_the_same_run(self):
        second = 10**9
        orchestrator, receiver, sender_rows = _base("slow_stop_10s")
        orchestrator[0]["duration_ns"] = 9 * second
        main = [orchestrator[0],
                {"kind": "action", "t_ns": 10 * second, "action": "sigstop", "duration_ns": 0},
                {"kind": "action", "t_ns": 20 * second, "action": "sigcont", "duration_ns": 0}]
        start = {"kind": "start", "t_ns": 0, "loss_timeout_ns": 5 * second}
        loss = {"kind": "loss_detected", "t_ns": 900 * second, "source": 0,
                "idle_ns": 5 * second, "connection": 1, "last_committed_capture_ns": 1}
        name = "slow_stop_10s-a_framed"
        self.run_dir(name, orchestrator=main, receiver=receiver + self._durable(1),
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


class MiscTests(unittest.TestCase):
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

    def test_holder_forwards_frames_from_capture_in_memory(self):
        frame = mock.Mock(data=b"\xff\xd8x\xff\xd9", received_monotonic=1.5)
        queue = mock.Mock()
        queue.get.side_effect = lambda timeout: frame
        queue.drop_stats.return_value = (0, None)
        capture = mock.Mock()
        capture.frames.return_value = queue
        with tempfile.TemporaryDirectory() as directory:
            writer = records.JsonlWriter(Path(directory) / "h.jsonl", run_id=RUN, role="holder")
            instance = holder.Holder(capture, [uuid4()], Path(directory) / "sock", writer)
            self.assertEqual(0o700, stat.S_IMODE(os.stat(Path(directory) / "sock").st_mode))
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(instance.path))
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
        out = orchestrator.run(["normal", "outage_5s", "auth_other_ca"], ["a_framed"])
        orchestrator.run(["rst"], ["b_chunked"])
        orchestrator.run(["normal"], ["b_segment"])
        report = summarize.summarize([out])
        runs = {(row["scenario"], row["candidate"]): row for row in report["runs"]}
        for key, row in runs.items():
            with self.subTest(run=key):
                # The whole row (numbers and tokens only) explains a failure.
                detail = json.dumps(row, sort_keys=True)
                self.assertEqual("pass", row["g1"], detail)
                self.assertEqual("pass", row["g2"], detail)
                self.assertEqual("pass", row["g3"], detail)
                self.assertIn(row["g4"], ("pass", "not_applicable"), detail)
                self.assertIn(row["g5"], ("pass", "not_applicable"), detail)
        self.assertGreater(runs[("outage_5s", "a_framed")]["reported_missing"], 0)
        self.assertEqual(0, runs[("auth_other_ca", "a_framed")]["receiver_accepted"])
        self.assertGreater(runs[("normal", "b_segment")]["receiver_accepted"], 0)
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
        # one Main-side tree alone is incomplete, never a pass
        alone = summarize.summarize([outs["main"]])["runs"][0]
        self.assertEqual("unmeasured", alone["integrity"])
        self.assertNotIn("pass", [alone[g] for g in ("g1", "g2", "g3", "g4", "g5")])


_CASES = (RecordTests, WireTests, ProxyTests, SummarizerTests, MiscTests,
          LoopbackMatrixTests)

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
