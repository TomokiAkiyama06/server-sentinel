"""Issue #14: the capture ingest listener over real loopback TLS 1.3 mTLS.

Every key, CA and certificate is generated in a temporary directory
(`CaptureTlsHarness`); the Agent side is an in-process synthetic client. No
real host, address, credential or media is used.
"""
import asyncio
from contextlib import contextmanager
import json
import socket
import ssl
import struct
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.cameras.remote_agent.ingest_config import (
    CaptureIngestDeployment, CaptureIngestLimits, CaptureIngestMaterial,
    CaptureIngestUnavailable, IngestListenerConfig, load_capture_ingest_material,
)
from app.cameras.remote_agent.ingest_server import CaptureIngestServer
from app.cameras.remote_agent.ingest_wire import (
    HEADER, INGEST_ALPN, FrameType, PeerClosed, encode_frame, read_frame,
)
from app.cameras.remote_agent.node_ca import (
    DeploymentAuthority, PrivateDirectory, publish_public_certificate,
)
from app.main import create_app
from app.settings import Settings
from tests.test_capture_ingest_wire import heartbeat
from tests.test_capture_mtls import DAY, SERVER_NAME, CaptureTlsHarness, Owner


class CaptureIngestServerTests(CaptureTlsHarness):
    def setUp(self):
        super().setUp()
        self.claim, _, self.certificate, self.key = self._paired_node("a")
        self.node = self.claim.node_id

    def serve(self, **limits):
        listener = socket.create_server(("127.0.0.1", 0))
        self.address = listener.getsockname()
        options = dict(idle_timeout_seconds=5, frames_per_second=10)
        options.update(limits)
        server = CaptureIngestServer(listener, self.acceptor,
                                     limits=CaptureIngestLimits(**options))
        server.start()
        self.addCleanup(lambda: (server.stop(), server.join(10)))
        return server

    def connect(self, *, alpn=True, certificate=None, key=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.ca_path))
        context.load_cert_chain(certfile=str(certificate or self.certificate),
                                keyfile=str(key or self.key))
        if alpn:
            context.set_alpn_protocols([INGEST_ALPN])
        raw = socket.create_connection(self.address, timeout=5)
        tls = context.wrap_socket(raw, server_hostname=SERVER_NAME)
        self.addCleanup(tls.close)
        return tls

    def send_heartbeat(self, tls, node=None, **changes):
        tls.sendall(encode_frame(FrameType.HEARTBEAT, heartbeat(node or self.node, **changes)))

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

    def assertPeerGone(self, tls):
        with self.assertRaises((PeerClosed, OSError, ssl.SSLError)):
            while True:
                read_frame(tls, 4096)

    # -- accepted heartbeat ----------------------------------------------------

    def test_a_heartbeat_is_acknowledged_with_main_times(self):
        server = self.serve()
        tls = self.connect()
        before = time.time()
        self.send_heartbeat(tls, sequence=7)
        kind, value = self.reply(tls)
        self.assertIs(kind, FrameType.HEARTBEAT_ACK)
        self.assertEqual(value["sequence"], 7)
        self.assertLessEqual(before, value["receive_utc"])
        self.assertLessEqual(value["receive_utc"], value["send_utc"])
        snapshot = server.registry.snapshot()
        self.assertEqual((snapshot.connected_nodes, snapshot.online_nodes), (1, 1))
        self.assertEqual(server.registry.state(self.node), "online")

    def test_a_degraded_node_and_its_storage_reason_are_kept_as_words(self):
        server = self.serve()
        tls = self.connect()
        self.send_heartbeat(tls, node_state="degraded",
                            node_reasons=["storage_device_numbers_stale"],
                            storage={"state": "degraded", "reason": "device_numbers_stale"})
        self.assertIs(self.reply(tls)[0], FrameType.HEARTBEAT_ACK)
        snapshot = server.registry.snapshot()
        self.assertEqual((snapshot.degraded_nodes, snapshot.storage_degraded_nodes,
                          snapshot.reasons), (1, 1, ("storage_device_numbers_stale",)))
        self.assertNotIn(str(self.node), repr(snapshot))

    # -- refusals ------------------------------------------------------------

    def test_a_session_without_the_ingest_alpn_is_refused(self):
        server = self.serve()
        tls = self.connect(alpn=False)
        self.assertEqual(self.closed_with(tls), "alpn_refused")
        self.assertEqual(server.registry.snapshot().known_nodes, 0)

    def test_a_heartbeat_for_another_node_is_refused(self):
        server = self.serve()
        tls = self.connect()
        self.send_heartbeat(tls, node=uuid4())
        self.assertEqual(self.closed_with(tls), "node_identity_mismatch")
        self.assertEqual(server.registry.snapshot().online_nodes, 0)

    def test_an_oversized_frame_is_refused_from_its_header(self):
        self.serve(maximum_frame_bytes=1024)
        tls = self.connect()
        # The body never follows: the length alone is refused.
        tls.sendall(HEADER.pack(1025, FrameType.HEARTBEAT))
        self.assertEqual(self.closed_with(tls), "frame_too_large")

    def test_media_and_other_frame_types_are_refused(self):
        self.serve()
        tls = self.connect()
        tls.sendall(struct.pack(">IB", 4, 0x20) + b"data")
        self.assertEqual(self.closed_with(tls), "frame_type_refused")
        tls = self.connect()
        tls.sendall(encode_frame(FrameType.HEARTBEAT_ACK, {"sequence": 1}))
        self.assertEqual(self.closed_with(tls), "frame_type_refused")

    def test_an_invalid_heartbeat_is_refused(self):
        self.serve()
        tls = self.connect()
        self.send_heartbeat(tls, extra="value")
        self.assertEqual(self.closed_with(tls), "heartbeat_invalid")

    def test_a_revocation_ends_the_session_at_the_next_frame(self):
        server = self.serve()
        tls = self.connect()
        self.send_heartbeat(tls)
        self.assertIs(self.reply(tls)[0], FrameType.HEARTBEAT_ACK)
        self.ledger.revoke(Owner(), "owner", node_id=self.node)
        self.send_heartbeat(tls, sequence=2)
        self.assertPeerGone(tls)
        self.assertTrue(self.wait_for(lambda: server.registry.state(self.node) is None))
        self.assertIn("not_admitted", server.last_close_reasons())
        # A new connection with the revoked credential is refused at admission.
        with self.assertRaises((OSError, ssl.SSLError, PeerClosed)):
            again = self.connect()
            self.send_heartbeat(again)
            read_frame(again, 4096)

    def test_a_newer_session_supersedes_the_older(self):
        server = self.serve()
        first = self.connect()
        self.send_heartbeat(first)
        self.assertIs(self.reply(first)[0], FrameType.HEARTBEAT_ACK)
        second = self.connect()
        self.send_heartbeat(second, sequence=2)
        self.assertIs(self.reply(second)[0], FrameType.HEARTBEAT_ACK)
        # Shut down at once, not left until its idle timeout (5 s here).
        first.settimeout(2)
        with self.assertRaises((PeerClosed, ssl.SSLError, ConnectionError)):
            read_frame(first, 4096)
        self.assertTrue(self.wait_for(lambda: server.registry.snapshot().connected_nodes == 1))
        self.send_heartbeat(second, sequence=3)
        self.assertIs(self.reply(second)[0], FrameType.HEARTBEAT_ACK)

    def test_frames_beyond_the_rate_are_refused(self):
        self.serve(frames_per_second=2)
        tls = self.connect()
        for sequence in (1, 2):
            self.send_heartbeat(tls, sequence=sequence)
            self.assertIs(self.reply(tls)[0], FrameType.HEARTBEAT_ACK)
        self.send_heartbeat(tls, sequence=3)
        self.assertEqual(self.closed_with(tls), "rate_limited")

    def test_an_idle_session_is_closed(self):
        server = self.serve(idle_timeout_seconds=1)
        tls = self.connect()
        self.send_heartbeat(tls)
        self.assertIs(self.reply(tls)[0], FrameType.HEARTBEAT_ACK)
        started = time.monotonic()
        self.assertEqual(self.closed_with(tls), "idle_timeout")
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(self.wait_for(lambda: server.registry.state(self.node) == "offline"))

    def test_unauthenticated_peers_and_plain_http_get_nothing(self):
        server = self.serve()
        # No client certificate: the handshake fails, nothing is registered.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.ca_path))
        context.set_alpn_protocols([INGEST_ALPN])
        with self.assertRaises((OSError, ssl.SSLError, PeerClosed)):
            with socket.create_connection(self.address, timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=SERVER_NAME) as tls:
                    self.send_heartbeat(tls)
                    read_frame(tls, 4096)
        # A dashboard request on the ingest port: no HTTP answer at all.
        with socket.create_connection(self.address, timeout=5) as raw:
            raw.sendall(b"GET / HTTP/1.1\r\nHost: capture\r\n\r\n")
            try:
                reply = raw.recv(64)
            except OSError:
                reply = b""
        self.assertFalse(reply.startswith(b"HTTP/"))
        self.assertTrue(self.wait_for(lambda: server.status().refused_connections >= 2))
        self.assertEqual(server.registry.snapshot().known_nodes, 0)

    def test_handshakes_per_address_and_connections_are_bounded(self):
        server = self.serve(maximum_handshakes_per_address=1, maximum_connections=4)
        holder = socket.create_connection(self.address, timeout=5)
        self.addCleanup(holder.close)
        self.assertTrue(self.wait_for(lambda: server.status().open_connections == 1))
        extra = socket.create_connection(self.address, timeout=5)
        self.addCleanup(extra.close)
        # Closed at accept, before any handshake byte.
        self.assertEqual(extra.recv(1), b"")
        self.assertEqual(server.status().refused_connections, 1)

    # -- stop -----------------------------------------------------------------

    def test_stop_waits_for_nothing_and_every_thread_ends(self):
        server = self.serve(idle_timeout_seconds=30)
        pending = socket.create_connection(self.address, timeout=5)
        self.addCleanup(pending.close)
        live = self.connect()
        self.send_heartbeat(live)
        self.assertIs(self.reply(live)[0], FrameType.HEARTBEAT_ACK)
        self.assertTrue(self.wait_for(lambda: server.status().open_connections == 2))
        started = time.monotonic()
        server.stop()
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertTrue(server.join(5))
        self.assertEqual(server.status().state, "stopped")
        self.assertPeerGone(live)
        self.assertEqual(server.status().open_connections, 0)
        with self.assertRaises(OSError):
            socket.create_connection(self.address, timeout=2).close()

    def test_a_connection_thread_failure_stays_contained(self):
        server = self.serve()
        original = server.registry.connected

        def broken(*args):
            raise RuntimeError("synthetic")

        server.registry.connected = broken
        tls = self.connect()
        self.send_heartbeat(tls)
        self.assertPeerGone(tls)
        server.registry.connected = original
        threads = threading.enumerate()
        tls = self.connect()
        self.send_heartbeat(tls)
        self.assertIs(self.reply(tls)[0], FrameType.HEARTBEAT_ACK)
        self.assertTrue(any(thread.name == "capture-ingest-accept" for thread in threads))


@contextmanager
def synthetic_admission():
    """Stands in for a bound Main Server storage admission reservation."""
    yield


class CaptureIngestApplicationTests(CaptureTlsHarness):
    """The application opens the listener in its lifespan and stops it first."""

    def setUp(self):
        super().setUp()
        self.claim, _, self.certificate, self.key = self._paired_node("a")
        with socket.create_server(("127.0.0.1", 0)) as probe:
            self.port = probe.getsockname()[1]
        self.address = ("127.0.0.1", self.port)
        self.material = CaptureIngestMaterial(
            IngestListenerConfig("127.0.0.1", self.port, "127.0.0.1", 8000),
            CaptureIngestLimits(idle_timeout_seconds=5), self.context, self.deployment)
        (self.root / "app").mkdir(mode=0o700)
        self.settings = Settings(self.root / "app")

    def application(self, **options):
        return create_app(self.settings, database=self.database,
                          storage_reservation=synthetic_admission, **options)

    def heartbeat_round_trip(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.ca_path))
        context.load_cert_chain(certfile=str(self.certificate), keyfile=str(self.key))
        context.set_alpn_protocols([INGEST_ALPN])
        with socket.create_connection(self.address, timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=SERVER_NAME) as tls:
                tls.sendall(encode_frame(FrameType.HEARTBEAT, heartbeat(self.claim.node_id)))
                return read_frame(tls, 4096).kind

    @staticmethod
    async def until(predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        return predicate()

    def test_the_lifespan_opens_the_listener_and_the_stop_closes_it_first(self):
        application = self.application(capture_ingest=self.material)
        self.assertEqual(application.state.capture_ingest_state, "starting")

        async def scenario():
            async with application.router.lifespan_context(application):
                self.assertTrue(await self.until(
                    lambda: application.state.capture_ingest_state == "running"))
                kind = await asyncio.to_thread(self.heartbeat_round_trip)
                self.assertIs(kind, FrameType.HEARTBEAT_ACK)
                server = application.state.capture_ingest
                # The client closed after its acknowledged heartbeat: known
                # and offline (SPECIFICATION §5.8).
                self.assertTrue(await self.until(
                    lambda: server.registry.state(self.claim.node_id) == "offline"))
                self.assertEqual(server.registry.snapshot().known_nodes, 1)
            return server

        server = asyncio.run(scenario())
        self.assertEqual(application.state.capture_ingest_state, "stopped")
        self.assertTrue(server.join(5))
        with self.assertRaises(OSError):
            socket.create_connection(self.address, timeout=2).close()

    def test_a_failed_bind_is_retried(self):
        application = self.application(capture_ingest=self.material)
        blocker = socket.create_server(self.address)

        async def scenario():
            with patch("app.main.CAPTURE_INGEST_BIND_RETRY_SECONDS", 0.05):
                async with application.router.lifespan_context(application):
                    self.assertTrue(await self.until(
                        lambda: application.state.capture_ingest_state == "unavailable"))
                    blocker.close()
                    self.assertTrue(await self.until(
                        lambda: application.state.capture_ingest_state == "running"))
                    self.assertIs(await asyncio.to_thread(self.heartbeat_round_trip),
                                  FrameType.HEARTBEAT_ACK)
            return application.state.capture_ingest

        try:
            server = asyncio.run(scenario())
        finally:
            blocker.close()
        self.assertTrue(server.join(5))

    def test_without_material_no_listener_exists(self):
        for options, state in (({}, "disabled"), ({"capture_ingest_unavailable": True},
                                                  "unavailable")):
            with self.subTest(state=state):
                application = self.application(**options)

                async def scenario():
                    async with application.router.lifespan_context(application):
                        await asyncio.sleep(0.1)
                        return application.state.capture_ingest_state

                self.assertEqual(asyncio.run(scenario()), state)
                self.assertIsNone(application.state.capture_ingest)
                with self.assertRaises(OSError):
                    socket.create_connection(self.address, timeout=2).close()

    def test_material_of_another_type_is_refused(self):
        with self.assertRaises(TypeError):
            self.application(capture_ingest=object())


class CaptureIngestMaterialTests(CaptureTlsHarness):
    """`load_capture_ingest_material` as the service account (synthetic CA)."""

    def section(self, directory):
        return CaptureIngestDeployment(
            IngestListenerConfig("127.0.0.1", 47200, "127.0.0.1", 8000), directory,
            CaptureIngestLimits())

    def test_the_prepared_listener_directory_loads(self):
        material = load_capture_ingest_material(self.section(self.root / "listener"))
        self.assertEqual(material.deployment_id, self.deployment)
        self.assertEqual(material.context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertNotIn(str(self.root), repr(material))

    def test_incomplete_or_foreign_material_is_refused_with_a_word(self):
        missing = self.root / "empty-listener"
        missing.mkdir(mode=0o700)
        with self.assertRaises(CaptureIngestUnavailable) as refused:
            load_capture_ingest_material(self.section(missing))
        self.assertEqual(refused.exception.reason, "listener_credential_incomplete")
        with self.assertRaises(CaptureIngestUnavailable) as refused:
            load_capture_ingest_material(self.section(self.root / "absent"))
        self.assertEqual(refused.exception.reason, "listener_material_unavailable")
        # Another deployment's CA copy next to this listener certificate.
        other = uuid4()
        DeploymentAuthority.create(PrivateDirectory(self.root / "other-authority"), other,
                                   validity=3650 * DAY)
        foreign = DeploymentAuthority.load(PrivateDirectory(self.root / "other-authority"), other)
        listener = self.root / "listener"
        (listener / "deployment-ca-certificate.pem").unlink(missing_ok=True)
        publish_public_certificate(PrivateDirectory(listener), foreign.ca_certificate_pem())
        with self.assertRaises(CaptureIngestUnavailable) as refused:
            load_capture_ingest_material(self.section(listener))
        self.assertIn(refused.exception.reason,
                      {"listener_authority_mismatch", "listener_material_unavailable"})


if __name__ == "__main__":
    unittest.main()
