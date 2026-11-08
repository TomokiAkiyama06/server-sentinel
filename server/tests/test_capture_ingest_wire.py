"""Issue #14: the capture ingest wire protocol, node health and the deployment section.

Synthetic only: no real host, address, credential or media.
"""
from contextlib import suppress
import json
from pathlib import Path
import socket
import struct
import threading
import time
import unittest
from uuid import uuid4

from app.cameras.remote_agent.ingest_config import (
    CaptureIngestLimits, IngestConfigurationError, IngestListenerConfig, parse_capture_ingest,
)
from app.cameras.remote_agent.ingest_wire import (
    FrameType, PeerClosed, WireRefused, encode_frame, parse_heartbeat, read_frame,
)
from app.cameras.remote_agent.node_health import CaptureNodeHealthRegistry
from app.settings import ConfigurationError


def heartbeat(node, **changes):
    value = {
        "schema_version": 1, "node_id": str(node), "sequence": 1,
        "utc_seconds": 1_800_000_000.5, "monotonic_seconds": 12.25,
        "node_state": "online", "node_reasons": [],
        "clock": {"state": "online", "reason": "clock_within_limit",
                  "offset_seconds": 0.01, "uncertainty_seconds": 0.002},
        "storage": {"state": "online", "available_bytes": 10 ** 9,
                    "safety_reserve_bytes": 10 ** 8},
        "sources": [{"source_id": str(uuid4()), "state": "online", "reason": "none"}],
    }
    value.update(changes)
    return value


def body(value):
    return json.dumps(value).encode()


class FrameTests(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        right.settimeout(2)
        return left, right

    def test_round_trip(self):
        left, right = self.pair()
        left.sendall(encode_frame(FrameType.HEARTBEAT, {"a": 1}))
        frame = read_frame(right, 1024)
        self.assertIs(frame.kind, FrameType.HEARTBEAT)
        self.assertEqual(json.loads(frame.body), {"a": 1})

    def test_length_is_refused_before_the_body_is_read(self):
        left, right = self.pair()
        # Only the header: a reader that waited for the body would time out.
        left.sendall(struct.pack(">IB", 1025, FrameType.HEARTBEAT))
        with self.assertRaises(WireRefused) as refused:
            read_frame(right, 1024)
        self.assertEqual(refused.exception.reason, "frame_too_large")

    def test_empty_and_unknown_frames_are_refused(self):
        left, right = self.pair()
        left.sendall(struct.pack(">IB", 0, FrameType.HEARTBEAT))
        with self.assertRaises(WireRefused) as refused:
            read_frame(right, 1024)
        self.assertEqual(refused.exception.reason, "frame_empty")
        left.sendall(struct.pack(">IB", 1, 0x20) + b"x")
        with self.assertRaises(WireRefused) as refused:
            read_frame(right, 1024)
        self.assertEqual(refused.exception.reason, "frame_type_refused")

    def test_a_trickled_frame_ends_at_its_one_deadline(self):
        # PR #401 Codex review: a byte per receive must not keep a frame open.
        left, right = self.pair()
        frame = encode_frame(FrameType.HEARTBEAT, {"a": 1})
        stop = threading.Event()

        def trickle():
            for byte in frame:
                if stop.wait(0.15):
                    return
                with suppress(OSError):
                    left.sendall(bytes([byte]))

        sender = threading.Thread(target=trickle)
        sender.start()
        self.addCleanup(sender.join)
        self.addCleanup(stop.set)
        started = time.monotonic()
        with self.assertRaises(socket.timeout):
            read_frame(right, 1024, deadline=started + 0.6)
        self.assertLess(time.monotonic() - started, 1.2)

    def test_a_stalled_frame_ends_at_its_deadline_not_the_socket_timeout(self):
        # Each receive is capped to what is left of the deadline.
        left, right = self.pair()
        right.settimeout(10)
        left.sendall(b"\x00\x00")
        started = time.monotonic()
        with self.assertRaises(socket.timeout):
            read_frame(right, 1024, deadline=started + 0.5)
        self.assertLess(time.monotonic() - started, 2)

    def test_a_frame_within_its_deadline_is_read(self):
        left, right = self.pair()
        left.sendall(encode_frame(FrameType.HEARTBEAT, {"a": 1}))
        self.assertIs(read_frame(right, 1024, deadline=time.monotonic() + 2).kind,
                      FrameType.HEARTBEAT)

    def test_a_truncated_frame_is_peer_closed(self):
        left, right = self.pair()
        left.sendall(struct.pack(">IB", 10, FrameType.HEARTBEAT) + b"abc")
        left.close()
        with self.assertRaises(PeerClosed):
            read_frame(right, 1024)


class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.node = uuid4()

    def test_a_valid_heartbeat_keeps_only_words_and_counts(self):
        parsed = parse_heartbeat(body(heartbeat(self.node)))
        self.assertEqual(parsed.node_id, self.node)
        self.assertEqual((parsed.node_state, parsed.reasons, parsed.storage_state,
                          parsed.clock_state, parsed.source_count),
                         ("online", (), "online", "online", 1))

    def test_degraded_reasons_outside_the_vocabulary_become_other(self):
        parsed = parse_heartbeat(body(heartbeat(
            self.node, node_state="degraded",
            node_reasons=["storage_device_numbers_stale", "some_future_reason"],
            storage={"state": "degraded", "reason": "device_numbers_stale"})))
        self.assertEqual(parsed.reasons, ("storage_device_numbers_stale", "other"))
        self.assertEqual(parsed.storage_state, "degraded")

    def test_invalid_heartbeats_are_refused(self):
        source = str(uuid4())
        cases = {
            "unknown key": heartbeat(self.node, extra=1),
            "missing key": {k: v for k, v in heartbeat(self.node).items() if k != "clock"},
            "schema": heartbeat(self.node, schema_version=2),
            "schema bool": heartbeat(self.node, schema_version=True),
            "node uuid": heartbeat(self.node, node_id="not-a-uuid"),
            "node uuid spelling": heartbeat(self.node, node_id=str(self.node).upper()),
            "sequence zero": heartbeat(self.node, sequence=0),
            "sequence float": heartbeat(self.node, sequence=1.0),
            "utc string": heartbeat(self.node, utc_seconds="1"),
            "online with reason": heartbeat(self.node, node_reasons=["main_unavailable"]),
            "degraded without reason": heartbeat(self.node, node_state="degraded"),
            "state": heartbeat(self.node, node_state="revoked"),
            "reason text": heartbeat(self.node, node_state="degraded",
                                     node_reasons=["Free Text"]),
            "duplicate reason": heartbeat(self.node, node_state="degraded",
                                          node_reasons=["other", "other"]),
            "too many reasons": heartbeat(self.node, node_state="degraded",
                                          node_reasons=[f"r{index}" for index in range(17)]),
            "storage state": heartbeat(self.node, storage={"state": "full"}),
            "storage bytes": heartbeat(self.node, storage={"state": "online",
                                                           "available_bytes": -1}),
            "storage key": heartbeat(self.node, storage={"state": "online", "path": "/data"}),
            "clock key": heartbeat(self.node, clock={"state": "online", "reason": "x",
                                                     "server": "ntp"}),
            "too many sources": heartbeat(self.node, sources=[
                {"source_id": str(uuid4()), "state": "online", "reason": "none"}
                for _ in range(5)]),
            "duplicate source": heartbeat(self.node, sources=[
                {"source_id": source, "state": "online", "reason": "none"}] * 2),
            "source key": heartbeat(self.node, sources=[
                {"source_id": source, "state": "online", "reason": "none", "device": "x"}]),
        }
        for name, value in cases.items():
            with self.subTest(name), self.assertRaises(WireRefused) as refused:
                parse_heartbeat(body(value))
            self.assertEqual(refused.exception.reason, "heartbeat_invalid")

    def test_non_json_duplicates_and_non_finite_numbers_are_refused(self):
        valid = body(heartbeat(self.node))
        cases = (b"\xff", b"[]", b'{"a":1,"a":2}', valid.replace(b"12.25", b"NaN"),
                 valid.replace(b"12.25", b"Infinity"))
        for value in cases:
            with self.subTest(value=value[:20]), self.assertRaises(WireRefused):
                parse_heartbeat(value)


class NodeHealthTests(unittest.TestCase):
    def setUp(self):
        self.now = [100.0]
        self.registry = CaptureNodeHealthRegistry(maximum_nodes=2, stale_after_seconds=5,
                                                  monotonic=lambda: self.now[0])

    def beat(self, node, generation, **changes):
        return self.registry.heartbeat(generation, parse_heartbeat(body(heartbeat(node, **changes))))

    def test_states_follow_heartbeats_and_staleness(self):
        node = uuid4()
        self.assertTrue(self.registry.connected(node, 1))
        self.assertEqual(self.registry.state(node), "offline")
        self.assertTrue(self.beat(node, 1))
        self.assertEqual(self.registry.state(node), "online")
        self.assertTrue(self.beat(node, 1, node_state="degraded",
                                  node_reasons=["storage_device_numbers_stale"],
                                  storage={"state": "degraded"}))
        snapshot = self.registry.snapshot()
        self.assertEqual((snapshot.degraded_nodes, snapshot.storage_degraded_nodes,
                          snapshot.reasons), (1, 1, ("storage_device_numbers_stale",)))
        self.now[0] += 5.5
        self.assertEqual(self.registry.state(node), "offline")
        self.assertEqual(self.registry.snapshot().reasons, ())
        self.registry.disconnected(node, 1)
        self.assertEqual(self.registry.snapshot().connected_nodes, 0)
        self.registry.forget(node)
        self.assertIsNone(self.registry.state(node))

    def test_a_superseded_session_cannot_report(self):
        node = uuid4()
        self.registry.connected(node, 1)
        self.registry.connected(node, 2)
        self.assertFalse(self.beat(node, 1))
        self.registry.disconnected(node, 1)
        self.assertEqual(self.registry.snapshot().connected_nodes, 1)
        self.assertTrue(self.beat(node, 2))

    def test_an_older_generation_never_replaces_a_newer(self):
        # PR #401 Codex review: a late registration of an older session must
        # not overwrite the newer one, whose heartbeats then keep working.
        node = uuid4()
        self.assertTrue(self.registry.connected(node, 2))
        self.assertFalse(self.registry.connected(node, 1))
        self.assertFalse(self.registry.connected(node, 2))
        self.assertTrue(self.beat(node, 2))
        self.assertFalse(self.beat(node, 1))
        self.assertEqual(self.registry.state(node), "online")

    def test_forgetting_one_generation_keeps_a_newer_one(self):
        node = uuid4()
        self.registry.connected(node, 1)
        self.registry.connected(node, 2)
        self.assertFalse(self.registry.forget(node, 1))
        self.assertTrue(self.beat(node, 2))
        self.assertTrue(self.registry.forget(node, 2))
        self.assertIsNone(self.registry.state(node))

    def test_the_table_is_bounded(self):
        first, second, third = uuid4(), uuid4(), uuid4()
        self.assertTrue(self.registry.connected(first, 1))
        self.assertTrue(self.registry.connected(second, 2))
        self.assertFalse(self.registry.connected(third, 3))
        self.registry.disconnected(first, 1)
        self.assertTrue(self.registry.connected(third, 3))
        self.assertIsNone(self.registry.state(first))
        self.assertEqual(self.registry.snapshot().known_nodes, 2)


class CaptureIngestSectionTests(unittest.TestCase):
    def parse(self, **changes):
        value = {"bind_host": "192.168.0.10", "port": 47200,
                 "listener_directory": "/var/lib/serversentinel-listener"}
        value.update(changes)
        return parse_capture_ingest({k: v for k, v in value.items() if v is not None},
                                    human_host="127.0.0.1", human_port=8000,
                                    forbidden_roots=(Path("/srv/runtime"), Path("/opt/code")))

    def test_a_valid_section(self):
        section = self.parse(maximum_connections=4)
        self.assertEqual(section.listener.port, 47200)
        self.assertEqual(section.limits.maximum_connections, 4)
        self.assertNotIn("192.168", repr(section))

    def test_invalid_sections_are_refused_without_values(self):
        cases = {
            "wildcard": {"bind_host": "0.0.0.0"},
            "tailscale v4": {"bind_host": "100.100.1.2"},
            "tailscale v6": {"bind_host": "fd7a:115c:a1e0::5"},
            "name": {"bind_host": "capture.example"},
            "port": {"port": 0},
            "privileged port": {"port": 443},
            "relative": {"listener_directory": "listener"},
            "dot dot": {"listener_directory": "/var/../srv/runtime/x"},
            "runtime": {"listener_directory": "/srv/runtime/state"},
            "parent of code": {"listener_directory": "/opt"},
            "connections": {"maximum_connections": 0},
            "connections type": {"maximum_connections": "4"},
            "unknown key": {"tailscale": True},
            "missing key": {"port": None},
        }
        for name, changes in cases.items():
            with self.subTest(name), self.assertRaises(ConfigurationError) as refused:
                self.parse(**changes)
            self.assertNotIn("192.168", str(refused.exception))

    def test_the_human_listener_socket_is_refused(self):
        with self.assertRaises(ConfigurationError):
            parse_capture_ingest({"bind_host": "127.0.0.1", "port": 8000,
                                  "listener_directory": "/var/lib/x"},
                                 human_host="127.0.0.1", human_port=8000)
        with self.assertRaises(IngestConfigurationError):
            IngestListenerConfig("192.168.0.10", 8000, "0.0.0.0", 8000)

    def test_limits_are_bounded(self):
        for changes in ({"idle_timeout_seconds": 0.5}, {"idle_timeout_seconds": float("nan")},
                        {"maximum_frame_bytes": 2 * 1024 * 1024}, {"frames_per_second": 0},
                        {"maximum_connections": 257}):
            with self.subTest(changes), self.assertRaises(ValueError):
                CaptureIngestLimits(**changes)


if __name__ == "__main__":
    unittest.main()
