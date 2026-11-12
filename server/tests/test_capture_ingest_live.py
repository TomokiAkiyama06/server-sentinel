"""Issue #14 (Owner decision 2026-11-12, option A): capture ingest live frames.

The wire form of ``LIVE_FRAME``, its rate budget, the registry authorization
of its source, the in-memory remote preview hub and the listener over real
loopback TLS 1.3 mTLS. Synthetic only: generated keys and certificates
(``CaptureTlsHarness``), a temporary database and JPEG-shaped bytes (an SOI
marker, ASCII filler and an EOI marker; no image of anything). No real Agent,
camera, host or address is involved.
"""
from contextlib import closing
import json
import socket
import ssl
import struct
import time
import unittest
from uuid import uuid4

from app.cameras.registry import CameraRegistry, SourceType
from app.cameras.registry.models import NodeHealthState
from app.cameras.remote_agent.ingest_config import CaptureIngestLimits
from app.cameras.remote_agent.ingest_server import CaptureIngestServer
from app.cameras.remote_agent.ingest_tls import CaptureIngestAcceptor
from app.cameras.remote_agent.ingest_wire import (
    HEADER, INGEST_ALPN, MAXIMUM_LIVE_FRAME_BODY_BYTES, MAXIMUM_LIVE_FRAME_BYTES, FrameType,
    PeerClosed, WireRefused, encode_frame, encode_live_frame, parse_live_frame, read_frame,
)
from app.cameras.remote_agent.live_frames import (
    LIVE_FRAMES_PER_NODE_PER_SECOND, LIVE_FRAMES_PER_SOURCE_PER_SECOND,
    MAXIMUM_LIVE_SOURCES_PER_NODE, LiveFrameBudget, RegistryLiveSources,
)
from app.media.live.remote_preview import RemotePreviewHub
from app.media.live.sessions import LiveSessionUnavailable
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.test_capture_ingest_wire import heartbeat
from tests.test_capture_mtls import SERVER_NAME, CaptureTlsHarness, Owner


JPEG = b"\xff\xd8\xff\xe0" + b"synthetic-not-an-image" + b"\xff\xd9"
OTHER_JPEG = b"\xff\xd8\xff\xdb" + b"synthetic-second-frame" + b"\xff\xd9"


class Clock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value


class NanoClock:
    def __init__(self):
        self.value = 10 ** 12

    def __call__(self):
        return self.value


def add_remote(database, node, *, enabled=True, name="Synthetic remote", node_state=None,
               node_row=True, node_row_id=None):
    """A registry node (with the ledger node's UUID) and one remote source of it."""
    registry = CameraRegistry(database, unaudited_writes=True)
    source = uuid4()
    with closing(database.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if node_row:
            registry.create_capture_node_on(connection, node_row_id or node, "Synthetic node")
            if node_state is not None:
                registry.update_capture_node_on(connection, node_row_id or node,
                                                health_state=node_state)
        registry.create_source_on(connection, source, source_type=SourceType.REMOTE_AGENT,
                                  name=name, capture_node_id=node_row_id or node, enabled=enabled)
        connection.execute("COMMIT")
    return source


class LiveFrameWireTests(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        right.settimeout(2)
        return left, right

    def test_the_fixed_contract(self):
        # The Agent sender is built to exactly these values (Issue #14).
        self.assertEqual(int(FrameType.LIVE_FRAME), 0x10)
        self.assertEqual(INGEST_ALPN, "serversentinel-capture-ingest/1")
        self.assertEqual(MAXIMUM_LIVE_FRAME_BYTES, 1_048_576)
        self.assertEqual(MAXIMUM_LIVE_FRAME_BODY_BYTES, 16 + 1_048_576)
        source = uuid4()
        encoded = encode_live_frame(source, JPEG)
        self.assertEqual(encoded, struct.pack(">IB", 16 + len(JPEG), 0x10) + source.bytes + JPEG)

    def test_a_live_frame_round_trips(self):
        source = uuid4()
        parsed = parse_live_frame(source.bytes + JPEG)
        self.assertEqual((parsed.source_id, parsed.jpeg), (source, JPEG))
        self.assertNotIn("synthetic", repr(parsed))
        smallest = parse_live_frame(source.bytes + b"\xff\xd8\xff\xd9")
        self.assertEqual(smallest.jpeg, b"\xff\xd8\xff\xd9")

    def test_anything_but_one_whole_jpeg_is_refused(self):
        source = uuid4().bytes
        for body in (b"", source, source + b"\xff\xd8\xff", source + b"\xff\xd8",
                     source + b"\x00" + JPEG, source + JPEG + b"\x00",
                     source + b"\xff\xd9" + JPEG[2:-2] + b"\xff\xd8",
                     source[:15] + JPEG[:1],
                     source + b"\xff\xd8" + b"x" * MAXIMUM_LIVE_FRAME_BYTES + b"\xff\xd9"):
            with self.subTest(length=len(body)):
                with self.assertRaises(WireRefused) as refused:
                    parse_live_frame(body)
                self.assertEqual(refused.exception.reason, "live_frame_invalid")
        largest = source + b"\xff\xd8" + b"x" * (MAXIMUM_LIVE_FRAME_BYTES - 4) + b"\xff\xd9"
        self.assertEqual(len(parse_live_frame(largest).jpeg), MAXIMUM_LIVE_FRAME_BYTES)

    def test_each_type_has_its_own_limit_before_the_body(self):
        left, right = self.pair()
        limits = {FrameType.LIVE_FRAME: MAXIMUM_LIVE_FRAME_BODY_BYTES}
        # A heartbeat keeps the default limit even with a live frame limit.
        left.sendall(struct.pack(">IB", 16 * 1024 + 1, FrameType.HEARTBEAT))
        with self.assertRaises(WireRefused) as refused:
            read_frame(right, 16 * 1024, type_limits=limits)
        self.assertEqual(refused.exception.reason, "frame_too_large")
        # Only the header: the live frame's length is refused before its body.
        left.sendall(struct.pack(">IB", MAXIMUM_LIVE_FRAME_BODY_BYTES + 1, FrameType.LIVE_FRAME))
        with self.assertRaises(WireRefused) as refused:
            read_frame(right, 16 * 1024, type_limits=limits)
        self.assertEqual(refused.exception.reason, "frame_too_large")
        # Without its own limit a live frame has the default one.
        left.sendall(struct.pack(">IB", 16 * 1024 + 1, FrameType.LIVE_FRAME))
        with self.assertRaises(WireRefused):
            read_frame(right, 16 * 1024)
        # An unknown type keeps the default limit, then is refused by type.
        left.sendall(struct.pack(">IB", 16 * 1024 + 1, 0x20))
        with self.assertRaises(WireRefused) as refused:
            read_frame(right, 16 * 1024, type_limits=limits)
        self.assertEqual(refused.exception.reason, "frame_too_large")

    def test_a_large_live_frame_within_its_limit_is_read(self):
        left, right = self.pair()
        source = uuid4()
        jpeg = b"\xff\xd8" + b"x" * (300 * 1024) + b"\xff\xd9"
        frame = encode_live_frame(source, jpeg)

        import threading
        writer = threading.Thread(target=left.sendall, args=(frame,))
        writer.start()
        read = read_frame(right, 16 * 1024,
                          type_limits={FrameType.LIVE_FRAME: MAXIMUM_LIVE_FRAME_BODY_BYTES})
        writer.join(5)
        self.assertIs(read.kind, FrameType.LIVE_FRAME)
        self.assertEqual(parse_live_frame(read.body).jpeg, jpeg)

    def test_invalid_type_limits_are_refused(self):
        left, right = self.pair()
        for limits in ({FrameType.LIVE_FRAME: 0}, {0x10: 10}, {FrameType.LIVE_FRAME: True}):
            with self.assertRaises(ValueError):
                read_frame(right, 1024, type_limits=limits)


class LiveFrameBudgetTests(unittest.TestCase):
    def setUp(self):
        self.clock = NanoClock()
        self.budget = LiveFrameBudget(maximum_nodes=2, clock_ns=self.clock)
        self.node = uuid4()

    def test_the_defaults_are_the_contract(self):
        self.assertEqual((LIVE_FRAMES_PER_SOURCE_PER_SECOND, LIVE_FRAMES_PER_NODE_PER_SECOND,
                          MAXIMUM_LIVE_SOURCES_PER_NODE), (6, 24, 4))

    def test_six_per_source_per_second(self):
        source = uuid4()
        self.assertTrue(all(self.budget.charge(self.node, source) for _ in range(6)))
        self.assertFalse(self.budget.charge(self.node, source))
        # Another source of the same node has its own window.
        self.assertTrue(self.budget.charge(self.node, uuid4()))
        self.clock.value += 1_000_000_000
        self.assertTrue(self.budget.charge(self.node, source))

    def test_twenty_four_per_node_per_second(self):
        sources = [uuid4() for _ in range(4)]
        for _ in range(6):
            for source in sources:
                self.assertTrue(self.budget.charge(self.node, source))
        self.assertFalse(self.budget.charge(self.node, sources[0]))
        # Another node is not charged.
        self.assertTrue(self.budget.charge(uuid4(), sources[0]))

    def test_the_node_bound_applies_with_fewer_sources_too(self):
        budget = LiveFrameBudget(maximum_nodes=1, per_source=100, per_node=24, clock_ns=self.clock)
        source = uuid4()
        self.assertTrue(all(budget.charge(self.node, source) for _ in range(24)))
        self.assertFalse(budget.charge(self.node, source))

    def test_at_most_four_sources_per_node_and_expired_ones_are_reclaimed(self):
        for _ in range(4):
            self.assertTrue(self.budget.charge(self.node, uuid4()))
        self.assertFalse(self.budget.charge(self.node, uuid4()))
        self.clock.value += 1_000_000_000
        self.assertTrue(self.budget.charge(self.node, uuid4()))

    def test_the_node_table_is_bounded_and_reclaims_expired_nodes(self):
        self.assertTrue(self.budget.charge(uuid4(), uuid4()))
        self.assertTrue(self.budget.charge(uuid4(), uuid4()))
        self.assertFalse(self.budget.charge(uuid4(), uuid4()))
        self.assertEqual(self.budget.tracked_nodes, 2)
        self.clock.value += 1_000_000_000
        self.assertTrue(self.budget.charge(uuid4(), uuid4()))
        self.assertLessEqual(self.budget.tracked_nodes, 2)

    def test_a_clock_regression_refuses(self):
        source = uuid4()
        self.assertTrue(self.budget.charge(self.node, source))
        self.clock.value -= 1
        self.assertFalse(self.budget.charge(self.node, source))

    def test_invalid_input_is_refused(self):
        self.assertFalse(self.budget.charge(str(self.node), uuid4()))
        self.assertFalse(self.budget.charge(self.node, None))
        with self.assertRaises(ValueError):
            LiveFrameBudget(maximum_nodes=0)


class RegistryLiveSourcesTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        directory = tempfile.TemporaryDirectory(prefix="live-sources-")
        self.addCleanup(directory.cleanup)
        self.database = Database(Path(directory.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.authorized = RegistryLiveSources(self.database)
        self.node = uuid4()

    def test_only_an_enabled_remote_source_of_this_node(self):
        source = add_remote(self.database, self.node)
        self.assertTrue(self.authorized(self.node, source))
        # Another node, an unknown source, a disabled source: refused.
        self.assertFalse(self.authorized(uuid4(), source))
        self.assertFalse(self.authorized(self.node, uuid4()))
        registry = CameraRegistry(self.database, unaudited_writes=True)
        registry.update_source(source, enabled=False)
        self.assertFalse(self.authorized(self.node, source))

    def test_a_local_source_is_never_a_live_frame_source(self):
        registry = CameraRegistry(self.database, unaudited_writes=True)
        local = registry.create_source(source_type=SourceType.LOCAL_UVC, name="Synthetic local",
                                       enabled=True).id
        self.assertFalse(self.authorized(self.node, local))

    def test_a_registry_node_under_another_uuid_authorizes_nothing(self):
        # The registry node must carry the ledger's node_id; one created with
        # its own UUID is not this session's node (fail closed).
        source = add_remote(self.database, self.node, node_row_id=uuid4())
        self.assertFalse(self.authorized(self.node, source))

    def test_a_revoked_registry_node_authorizes_nothing(self):
        source = add_remote(self.database, self.node, node_state=NodeHealthState.REVOKED)
        self.assertFalse(self.authorized(self.node, source))

    def test_a_storage_failure_denies(self):
        source = add_remote(self.database, self.node)

        class Broken:
            def connect_read_only(self):
                raise OSError("synthetic")

        self.assertFalse(RegistryLiveSources(Broken())(self.node, source))
        self.assertFalse(self.authorized(str(self.node), source))
        with self.assertRaises(ValueError):
            RegistryLiveSources(object())


class RemotePreviewHubTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.hub = RemotePreviewHub(monotonic=self.clock)
        self.node = uuid4()
        self.source = uuid4()
        self.hub.open_node(self.node, 1)

    def viewed(self, source=None):
        slot = self.hub.source(source or self.source)
        viewer = uuid4()
        slot.add_viewer(viewer)
        return slot, viewer

    def test_nothing_is_retained_without_viewers(self):
        self.assertTrue(self.hub.publish(self.node, 1, self.source, JPEG))
        self.assertEqual(self.hub.status.retained_bytes, 0)
        # Nor in a slot a failed open left without a viewer.
        self.hub.source(self.source)
        self.assertTrue(self.hub.publish(self.node, 1, self.source, JPEG))
        self.assertEqual(self.hub.status.retained_bytes, 0)
        # The receive time alone makes the source live in the list.
        self.assertTrue(self.hub.receiving(self.source, self.node))
        self.assertFalse(self.hub.receiving(self.source, uuid4()))

    def test_only_the_newest_frame_is_kept_while_viewed(self):
        slot, viewer = self.viewed()
        self.hub.publish(self.node, 1, self.source, JPEG)
        self.hub.publish(self.node, 1, self.source, OTHER_JPEG)
        frame = self.hub.latest(self.source)
        self.assertEqual((frame.data, frame.sequence), (OTHER_JPEG, 2))
        self.assertIsNone(self.hub.latest(self.source, 2))
        self.assertEqual(self.hub.status.retained_bytes, len(OTHER_JPEG))
        self.assertTrue(slot.remove_viewer(viewer))
        self.assertEqual(self.hub.status.retained_bytes, 0)
        self.assertEqual(self.hub.status.viewed_sources, 0)

    def test_a_frame_older_than_five_seconds_is_not_live(self):
        self.viewed()
        self.hub.publish(self.node, 1, self.source, JPEG)
        self.clock.value += 5.0
        self.assertIsNotNone(self.hub.latest(self.source))
        self.assertTrue(self.hub.receiving(self.source, self.node))
        self.clock.value += 0.01
        self.assertIsNone(self.hub.latest(self.source))
        self.assertFalse(self.hub.receiving(self.source, self.node))
        # A clock that ran backwards is not live either.
        self.hub.publish(self.node, 1, self.source, JPEG)
        self.clock.value -= 1
        self.assertIsNone(self.hub.latest(self.source))

    def test_an_ended_or_superseded_session_drops_its_frames(self):
        self.viewed()
        self.hub.publish(self.node, 1, self.source, JPEG)
        # A newer session of the node replaces the older one entirely.
        self.hub.open_node(self.node, 2)
        self.assertIsNone(self.hub.latest(self.source))
        # Released at once, not only hidden.
        self.assertEqual((self.hub.status.retained_bytes, self.hub.status.tracked_sources), (0, 0))
        self.assertFalse(self.hub.receiving(self.source, self.node))
        self.assertFalse(self.hub.publish(self.node, 1, self.source, JPEG))
        self.assertTrue(self.hub.publish(self.node, 2, self.source, OTHER_JPEG))
        # The sequence goes on, so a viewer's `after` stays meaningful.
        self.assertEqual(self.hub.latest(self.source, 1).data, OTHER_JPEG)
        # Ending an older generation changes nothing; ending the current drops.
        self.hub.close_node(self.node, 1)
        self.assertIsNotNone(self.hub.latest(self.source))
        self.hub.close_node(self.node, 2)
        self.assertIsNone(self.hub.latest(self.source))
        self.assertFalse(self.hub.publish(self.node, 2, self.source, JPEG))
        self.assertEqual(self.hub.status.nodes, 0)

    def test_an_older_generation_never_replaces_a_newer(self):
        self.hub.open_node(self.node, 3)
        self.hub.open_node(self.node, 2)
        self.assertFalse(self.hub.publish(self.node, 2, self.source, JPEG))
        self.assertTrue(self.hub.publish(self.node, 3, self.source, JPEG))

    def test_a_node_without_a_session_publishes_nothing(self):
        self.assertFalse(self.hub.publish(uuid4(), 1, self.source, JPEG))

    def test_at_most_four_sources_per_node(self):
        for _ in range(4):
            self.assertTrue(self.hub.publish(self.node, 1, uuid4(), JPEG))
        self.assertFalse(self.hub.publish(self.node, 1, uuid4(), JPEG))
        other = uuid4()
        self.hub.open_node(other, 2)
        self.assertTrue(self.hub.publish(other, 2, uuid4(), JPEG))
        self.assertEqual(self.hub.status.tracked_sources, 5)

    def test_an_oversized_frame_is_refused(self):
        hub = RemotePreviewHub(max_frame_bytes=len(JPEG) - 1, monotonic=self.clock)
        hub.open_node(self.node, 1)
        self.assertFalse(hub.publish(self.node, 1, self.source, JPEG))
        self.assertEqual(hub.status.refused_frames, 1)

    def test_viewer_slots_are_bounded_and_unviewed_ones_reclaimed(self):
        hub = RemotePreviewHub(maximum_viewed_sources=2, monotonic=self.clock)
        first = hub.source(uuid4())
        first.add_viewer(uuid4())
        hub.source(uuid4())  # a failed open: no viewer
        hub.source(uuid4()).add_viewer(uuid4())  # reclaims it
        with self.assertRaises(LiveSessionUnavailable):
            hub.source(uuid4())

    def test_clear_drops_everything_and_accepts_nothing_more(self):
        self.viewed()
        self.hub.publish(self.node, 1, self.source, JPEG)
        self.hub.clear()
        self.assertIsNone(self.hub.latest(self.source))
        self.assertFalse(self.hub.publish(self.node, 1, self.source, JPEG))
        self.hub.open_node(self.node, 5)
        self.assertFalse(self.hub.publish(self.node, 5, self.source, JPEG))
        with self.assertRaises(LiveSessionUnavailable):
            self.hub.source(uuid4())

    def test_bounds_are_validated(self):
        for options in ({"fresh_seconds": 0}, {"fresh_seconds": True}, {"maximum_sources_per_node": 0},
                        {"max_frame_bytes": 9 * 1024 * 1024}, {"monotonic": None}):
            with self.assertRaises(ValueError):
                RemotePreviewHub(**options)


class CaptureIngestLiveFrameTests(CaptureTlsHarness):
    def setUp(self):
        super().setUp()
        self.claim, _, self.certificate, self.key = self._paired_node("a")
        self.node = self.claim.node_id
        self.source = add_remote(self.database, self.node)
        self.clock = Clock()
        self.hub = RemotePreviewHub(monotonic=self.clock)

    def serve(self, *, live=True, authorizer=None, **limits):
        listener = socket.create_server(("127.0.0.1", 0))
        self.address = listener.getsockname()
        options = dict(idle_timeout_seconds=5, frames_per_second=10)
        options.update(limits)
        acceptor = CaptureIngestAcceptor(self.context, self.admission,
                                         handshake_timeout_seconds=10, log_refusals=False,
                                         required_alpn=INGEST_ALPN)
        self.lookups = []

        def authorized(node, source):
            self.lookups.append((node, source))
            return (authorizer or RegistryLiveSources(self.database))(node, source)

        # A clock that stands still: every rate window here is one window.
        self.nanos = NanoClock()
        server = CaptureIngestServer(listener, acceptor, limits=CaptureIngestLimits(**options),
                                     monotonic_ns=self.nanos,
                                     **({"live_preview": self.hub, "live_sources": authorized}
                                        if live else {}))
        server.start()
        self.addCleanup(lambda: (server.stop(), server.join(10)))
        return server

    def connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.ca_path))
        context.load_cert_chain(certfile=str(self.certificate), keyfile=str(self.key))
        context.set_alpn_protocols([INGEST_ALPN])
        raw = socket.create_connection(self.address, timeout=5)
        tls = context.wrap_socket(raw, server_hostname=SERVER_NAME)
        self.addCleanup(tls.close)
        return tls

    def reply(self, tls):
        frame = read_frame(tls, 4096)
        return frame.kind, json.loads(frame.body)

    def closed_with(self, tls):
        kind, value = self.reply(tls)
        self.assertIs(kind, FrameType.CLOSE)
        return value["reason"]

    def wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()

    def viewed(self, source=None):
        slot = self.hub.source(source or self.source)
        slot.add_viewer(uuid4())
        return slot

    def heartbeat_acknowledged(self, tls, sequence):
        tls.sendall(encode_frame(FrameType.HEARTBEAT, heartbeat(self.node, sequence=sequence)))
        kind, value = self.reply(tls)
        self.assertIs(kind, FrameType.HEARTBEAT_ACK)
        self.assertEqual(value["sequence"], sequence)

    def assertNothingSent(self, tls, seconds=0.5):
        tls.settimeout(seconds)
        with self.assertRaises(socket.timeout):
            tls.recv(1)
        tls.settimeout(5)

    def test_an_authorized_frame_is_kept_in_memory_and_never_acknowledged(self):
        server = self.serve()
        self.viewed()
        tls = self.connect()
        self.heartbeat_acknowledged(tls, 1)
        tls.sendall(encode_live_frame(self.source, JPEG))
        self.assertTrue(self.wait_for(lambda: self.hub.latest(self.source) is not None))
        self.assertEqual(self.hub.latest(self.source).data, JPEG)
        # No reply of any kind to a live frame (the Main stores nothing).
        self.assertNothingSent(tls)
        # The next reply on the stream is the next heartbeat's ack.
        tls.sendall(encode_live_frame(self.source, OTHER_JPEG))
        self.heartbeat_acknowledged(tls, 2)
        self.assertEqual(self.hub.latest(self.source).data, OTHER_JPEG)
        self.assertTrue(self.hub.receiving(self.source, self.node))
        self.assertEqual(server.status().closed_sessions, 0)

    def test_live_frames_do_not_spend_the_heartbeat_budget(self):
        self.serve(frames_per_second=2)
        tls = self.connect()
        for _ in range(5):
            tls.sendall(encode_live_frame(self.source, JPEG))
        self.heartbeat_acknowledged(tls, 1)
        self.heartbeat_acknowledged(tls, 2)

    def test_an_unauthorized_source_closes_the_session(self):
        server = self.serve()
        tls = self.connect()
        tls.sendall(encode_live_frame(uuid4(), JPEG))
        self.assertEqual(self.closed_with(tls), "source_not_authorized")
        self.assertEqual(self.hub.status.tracked_sources, 0)
        self.assertTrue(self.wait_for(lambda: "source_not_authorized" in server.last_close_reasons()))

    def test_another_nodes_source_is_not_authorized(self):
        other = add_remote(self.database, uuid4())
        self.serve()
        tls = self.connect()
        tls.sendall(encode_live_frame(other, JPEG))
        self.assertEqual(self.closed_with(tls), "source_not_authorized")
        self.assertFalse(self.hub.receiving(other, self.node))

    def test_a_disabled_source_is_refused_at_its_next_frame(self):
        self.serve()
        self.viewed()
        tls = self.connect()
        tls.sendall(encode_live_frame(self.source, JPEG))
        self.heartbeat_acknowledged(tls, 1)
        CameraRegistry(self.database, unaudited_writes=True).update_source(self.source, enabled=False)
        tls.sendall(encode_live_frame(self.source, OTHER_JPEG))
        self.assertEqual(self.closed_with(tls), "source_not_authorized")
        # The session ended, so its frames are gone too.
        self.assertTrue(self.wait_for(lambda: self.hub.latest(self.source) is None))

    def test_without_a_live_preview_every_frame_is_refused(self):
        self.serve(live=False)
        tls = self.connect()
        tls.sendall(encode_live_frame(self.source, JPEG))
        self.assertEqual(self.closed_with(tls), "source_not_authorized")

    def test_an_authorizer_failure_denies(self):
        def broken(node, source):
            raise RuntimeError("synthetic")

        self.serve(authorizer=broken)
        tls = self.connect()
        tls.sendall(encode_live_frame(self.source, JPEG))
        self.assertEqual(self.closed_with(tls), "source_not_authorized")

    def test_an_oversized_live_frame_is_refused_from_its_header(self):
        self.serve()
        tls = self.connect()
        # The body never follows: the length alone is refused.
        tls.sendall(HEADER.pack(MAXIMUM_LIVE_FRAME_BODY_BYTES + 1, FrameType.LIVE_FRAME))
        self.assertEqual(self.closed_with(tls), "frame_too_large")
        self.assertEqual(self.lookups, [])

    def test_a_heartbeat_keeps_its_own_limit(self):
        self.serve()
        tls = self.connect()
        tls.sendall(HEADER.pack(16 * 1024 + 1, FrameType.HEARTBEAT))
        self.assertEqual(self.closed_with(tls), "frame_too_large")

    def test_a_maximum_size_frame_is_accepted(self):
        self.serve(idle_timeout_seconds=30)
        self.viewed()
        tls = self.connect()
        jpeg = b"\xff\xd8" + b"x" * (MAXIMUM_LIVE_FRAME_BYTES - 4) + b"\xff\xd9"
        tls.sendall(encode_live_frame(self.source, jpeg))
        self.heartbeat_acknowledged(tls, 1)
        self.assertEqual(len(self.hub.latest(self.source).data), MAXIMUM_LIVE_FRAME_BYTES)

    def test_a_malformed_live_frame_is_refused(self):
        self.serve()
        tls = self.connect()
        tls.sendall(HEADER.pack(16 + 3, FrameType.LIVE_FRAME) + self.source.bytes + b"abc")
        self.assertEqual(self.closed_with(tls), "live_frame_invalid")
        self.assertEqual(self.lookups, [])

    def test_more_than_six_frames_per_source_per_second_close(self):
        self.serve()
        tls = self.connect()
        for _ in range(LIVE_FRAMES_PER_SOURCE_PER_SECOND + 1):
            tls.sendall(encode_live_frame(self.source, JPEG))
        self.assertEqual(self.closed_with(tls), "rate_limited")
        # The over-budget frame caused no registry read.
        self.assertEqual(len(self.lookups), LIVE_FRAMES_PER_SOURCE_PER_SECOND)

    def test_more_than_twenty_four_frames_per_node_per_second_close(self):
        CameraRegistry(self.database, unaudited_writes=True).set_active_limit(8)
        sources = [self.source] + [add_remote(self.database, self.node, node_row=False)
                                   for _ in range(3)]
        self.serve()
        tls = self.connect()
        for _ in range(LIVE_FRAMES_PER_SOURCE_PER_SECOND):
            for source in sources:
                tls.sendall(encode_live_frame(source, JPEG))
        self.heartbeat_acknowledged(tls, 1)
        tls.sendall(encode_live_frame(sources[0], JPEG))
        self.assertEqual(self.closed_with(tls), "rate_limited")

    def test_a_fifth_source_of_a_node_closes(self):
        CameraRegistry(self.database, unaudited_writes=True).set_active_limit(8)
        sources = [self.source] + [add_remote(self.database, self.node, node_row=False)
                                   for _ in range(4)]
        self.serve()
        tls = self.connect()
        for source in sources[:4]:
            tls.sendall(encode_live_frame(source, JPEG))
        self.heartbeat_acknowledged(tls, 1)
        tls.sendall(encode_live_frame(sources[4], JPEG))
        self.assertEqual(self.closed_with(tls), "rate_limited")

    def test_a_revocation_ends_the_session_and_drops_its_frames(self):
        server = self.serve()
        self.viewed()
        tls = self.connect()
        tls.sendall(encode_live_frame(self.source, JPEG))
        self.heartbeat_acknowledged(tls, 1)
        self.assertIsNotNone(self.hub.latest(self.source))
        self.ledger.revoke(Owner(), "owner", node_id=self.node)
        tls.sendall(encode_live_frame(self.source, OTHER_JPEG))
        with self.assertRaises((PeerClosed, OSError, ssl.SSLError)):
            while True:
                read_frame(tls, 4096)
        self.assertTrue(self.wait_for(lambda: "not_admitted" in server.last_close_reasons()))
        self.assertIsNone(self.hub.latest(self.source))
        self.assertFalse(self.hub.receiving(self.source, self.node))
        self.assertEqual(self.hub.status.nodes, 0)

    def test_a_closed_session_drops_its_frames(self):
        server = self.serve()
        self.viewed()
        tls = self.connect()
        tls.sendall(encode_live_frame(self.source, JPEG))
        self.heartbeat_acknowledged(tls, 1)
        tls.close()
        self.assertTrue(self.wait_for(lambda: self.hub.status.nodes == 0))
        self.assertIsNone(self.hub.latest(self.source))
        self.assertTrue(self.wait_for(lambda: server.status().closed_sessions == 1))

    def test_a_newer_session_replaces_the_older_ones_frames(self):
        self.serve()
        self.viewed()
        first = self.connect()
        first.sendall(encode_live_frame(self.source, JPEG))
        self.heartbeat_acknowledged(first, 1)
        second = self.connect()
        self.heartbeat_acknowledged(second, 2)
        self.assertIsNone(self.hub.latest(self.source))
        # Released at once, not only hidden behind the newer generation.
        self.assertEqual(self.hub.status.retained_bytes, 0)
        second.sendall(encode_live_frame(self.source, OTHER_JPEG))
        self.heartbeat_acknowledged(second, 3)
        self.assertEqual(self.hub.latest(self.source).data, OTHER_JPEG)

    def test_stop_drops_every_frame(self):
        server = self.serve()
        self.viewed()
        tls = self.connect()
        tls.sendall(encode_live_frame(self.source, JPEG))
        self.heartbeat_acknowledged(tls, 1)
        server.stop()
        self.assertIsNone(self.hub.latest(self.source))
        self.assertTrue(server.join(10))

    def test_invalid_live_dependencies_are_refused(self):
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        acceptor = CaptureIngestAcceptor(self.context, self.admission, handshake_timeout_seconds=10)
        for options in ({"live_preview": object()}, {"live_sources": "registry"}):
            with self.assertRaises(ValueError):
                CaptureIngestServer(listener, acceptor, **options)


if __name__ == "__main__":
    unittest.main()
