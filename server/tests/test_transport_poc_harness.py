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
                           sender, srt_adapter, summarize, wire)

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

    def test_jpeg_comment_envelope(self):
        frame = b"\xff\xd8\xff\xdbpayload\xff\xd9"
        embedded = wire.embed_envelope(frame, 3, 4, 5, 6)
        self.assertEqual(((3, 4, 5, 6), frame), wire.extract_envelope(embedded))
        with self.assertRaises(wire.ProtocolError):
            wire.extract_envelope(frame)

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


def _write(directory, name, rows):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.jsonl"
    with open(path, "w", encoding="ascii") as stream:
        for row in rows:
            stream.write(json.dumps({"run_id": RUN, **row}) + "\n")


def _base(scenario, candidate="a_framed", sources=1):
    orchestrator = [{"kind": "start", "t_ns": 0, "scenario": scenario, "candidate": candidate,
                     "n_sources": sources, "inputs": "synthetic"}]
    sample = {"kind": "sample", "max_queued_messages": 3, "max_queued_bytes": 100,
              "limit_queued_messages": 10, "limit_queued_bytes": 1000, "max_outq": 10,
              "sndbuf": 1000, "hwm_bytes": 10, "rss_bytes": 10, "accepted": 5}
    receiver = [{**sample, "t_ns": index} for index in range(5)]
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

    def run_dir(self, name, *, orchestrator, receiver, sender_rows, proxy_rows=()):
        directory = self.root / name
        _write(directory, "orchestrator-both", orchestrator)
        _write(directory, "receiver", receiver)
        _write(directory, "sender", sender_rows)
        if proxy_rows:
            _write(directory, "proxy", proxy_rows)

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
        _write(self.root / "outage_5s-a_framed", "receiver",
               receiver + [{**gap, "missing_units": 9}, durable])
        self.assertEqual("fail", self.report()["outage_5s"]["g2"])
        _write(self.root / "outage_5s-a_framed", "receiver",
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
        _write(self.root / "capture_restart-a_framed", "receiver",
               receiver + rows + [{**restart, "missing_units": 3}])
        self.assertEqual("fail", self.report()["capture_restart"]["g2"])

    def test_negative_authentication_accepts_nothing(self):
        orchestrator, receiver, sender_rows = _base("auth_unpaired")
        end = {"kind": "end", "t_ns": 9, "accepted": 0}
        self.run_dir("auth_unpaired-a_framed", orchestrator=orchestrator,
                     receiver=receiver + [end], sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["auth_unpaired"]["g1"])
        _write(self.root / "auth_unpaired-a_framed", "receiver",
               receiver + [{**end, "accepted": 1}])
        self.assertEqual("fail", self.report()["auth_unpaired"]["g1"])

    def test_bounds(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows)
        self.assertEqual("pass", self.report()["normal"]["g3"])
        receiver[2]["max_queued_messages"] = 11
        _write(self.root / "normal-a_framed", "receiver", receiver)
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
        self.run_dir("outage_5s-a_framed", orchestrator=orchestrator, receiver=receiver + [gap],
                     sender_rows=sender_rows + events, proxy_rows=proxy_rows)
        row = self.report()["outage_5s"]
        self.assertEqual(("pass", "pass"), (row["g4"], row["g5"]))
        self.assertEqual(second, row["reconnect_p95_ns"])
        late = [*events[:3], {**events[3], "t_ns": 26 * second}]
        _write(self.root / "outage_5s-a_framed", "sender", sender_rows + late)
        self.assertEqual("fail", self.report()["outage_5s"]["g4"])
        _write(self.root / "outage_5s-a_framed", "sender", sender_rows + events)
        _write(self.root / "outage_5s-a_framed", "receiver",
               receiver + [{**gap, "to_capture_ns": 700 * second}])
        self.assertEqual("fail", self.report()["outage_5s"]["g5"])

    def test_fifth_source_refused(self):
        orchestrator, receiver, sender_rows = _base("fifth_refused", sources=5)
        durable = [{"kind": "durable", "t_ns": 9, "source": index, "epoch": 1,
                    "min_sequence": 0, "max_sequence": 9, "units": 10, "duplicates": 0}
                   for index in range(4)]
        ends = [{"kind": "end", "t_ns": 9, "source": index, "accepted": 0 if index == 4 else 10,
                 "rejected": 10 if index == 4 else 0, "drops": 0} for index in range(5)]
        receiver_end = {"kind": "end", "t_ns": 9, "accepted": 40, "backpressured": 0,
                        "rate_limited": 0, "cpu_quota_us": 200000}
        self.run_dir("fifth_refused-a_framed", orchestrator=orchestrator,
                     receiver=receiver + durable + [receiver_end], sender_rows=sender_rows + ends)
        self.assertEqual("pass", self.report()["fifth_refused"]["g6"])
        _write(self.root / "fifth_refused-a_framed", "receiver", receiver + durable + [
            {**durable[0], "source": 4}, receiver_end])
        self.assertEqual("fail", self.report()["fifth_refused"]["g6"])

    def test_report_is_numeric_and_renders(self):
        orchestrator, receiver, sender_rows = _base("normal")
        self.run_dir("normal-a_framed", orchestrator=orchestrator, receiver=receiver,
                     sender_rows=sender_rows)
        report = summarize.summarize([self.root])
        self.assertEqual("unmeasured", report["candidates"][0]["secondary_packet_loss"])
        self.assertIn("a_framed", summarize.render(report))


class SrtTests(unittest.TestCase):
    def test_refuses_without_ffmpeg_srt(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertFalse(srt_adapter.srt_available())
            with self.assertRaises(srt_adapter.SrtUnavailable):
                srt_adapter.require_srt()

    def test_detects_srt_in_both_directions(self):
        both = "Supported file protocols:\nInput:\n  file\n  srt\nOutput:\n  file\n  srt\n"
        input_only = "Supported file protocols:\nInput:\n  srt\nOutput:\n  file\n"
        for text, expected in ((both, True), (input_only, False)):
            run = mock.Mock(return_value=mock.Mock(stdout=text))
            with mock.patch("shutil.which", return_value="/usr/bin/ffmpeg"):
                self.assertEqual(expected, srt_adapter.srt_available(run=run))

    def test_passphrase_file_must_be_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pass"
            path.write_text("abcdefghijk")
            os.chmod(path, 0o644)
            with self.assertRaises(srt_adapter.SrtUnavailable):
                srt_adapter.read_passphrase(path)
            os.chmod(path, 0o600)
            self.assertEqual("abcdefghijk", srt_adapter.read_passphrase(path))
        argv = srt_adapter.receiver_argv("ffmpeg", "srt://x")
        self.assertIn("-an", argv)


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
                self.assertEqual("pass", row["g1"])
                self.assertEqual("pass", row["g2"])
                self.assertEqual("pass", row["g3"])
                self.assertIn(row["g4"], ("pass", "not_applicable"))
                self.assertIn(row["g5"], ("pass", "not_applicable"))
        self.assertGreater(runs[("outage_5s", "a_framed")]["reported_missing"], 0)
        self.assertEqual(0, runs[("auth_other_ca", "a_framed")]["receiver_accepted"])
        self.assertGreater(runs[("normal", "b_segment")]["receiver_accepted"], 0)
        for path in out.rglob("*.jsonl"):
            records.read_jsonl(path)  # every stored value is numeric or a token


_CASES = (RecordTests, WireTests, ProxyTests, SummarizerTests, SrtTests, MiscTests,
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
