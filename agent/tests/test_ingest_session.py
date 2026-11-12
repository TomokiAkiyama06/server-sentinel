"""Issue #14: the Agent's capture ingest session over real loopback TLS 1.3 mTLS.

A scripted Main peer (this file) stands in for the Main listener; the real
listener is exercised in ``server/tests/test_capture_ingest_session.py``. All
keys and certificates are synthetic and generated per test.
"""
import json
import select
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from media_capture_agent import ingest_session
from media_capture_agent.config import ConfigurationError, MainIngestEndpoint, Settings
from media_capture_agent.ingest_session import (
    INGEST_ALPN, FrameType, IngestSession, IngestSessionError, encode_frame,
)
from media_capture_agent.pairing import NodeCredentialStore
from media_capture_agent.runtime import Agent, UnconfiguredIngestSession
from tests import support
from tests.test_node_tls import NodeTlsHarness


HEADER = struct.Struct(">IB")


def read_frame(tls):
    header = b""
    while len(header) < HEADER.size:
        chunk = tls.recv(HEADER.size - len(header))
        if not chunk:
            return None
        header += chunk
    length, kind = HEADER.unpack(header)
    body = b""
    while len(body) < length:
        chunk = tls.recv(length - len(body))
        if not chunk:
            return None
        body += chunk
    return kind, json.loads(body)


def ack(tls, frame, **changes):
    value = {"sequence": frame[1]["sequence"], "receive_utc": time.time(),
             "send_utc": time.time()}
    value.update(changes)
    tls.sendall(encode_frame(FrameType.HEARTBEAT_ACK, value))


def acknowledge_all(tls, received):
    while (frame := read_frame(tls)) is not None:
        received.append(frame)
        ack(tls, frame)


class ScriptedMain:
    """A TLS 1.3 server requiring a client certificate; one handler per connection."""

    def __init__(self, certificate: Path, key: Path, client_ca_pem: bytes, handlers, *,
                 alpn=True):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=client_ca_pem.decode("ascii"))
        context.load_cert_chain(str(certificate), str(key))
        if alpn:
            context.set_alpn_protocols([INGEST_ALPN])
        self.context = context
        self.handlers = list(handlers)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self.alpn = []
        self.received = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            handler = self.handlers[min(self.connections, len(self.handlers)) - 1]
            try:
                connection.settimeout(10)
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    self.alpn.append(tls.selected_alpn_protocol())
                    handler(tls, self.received)
            except (ssl.SSLError, OSError):
                pass

    def stop(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(10)


class FreeStore:
    """Media storage stand-in (the mount checks have their own tests)."""

    device_numbers_stale = False

    def check(self):
        return 10 ** 9

    def close(self):
        pass


def heartbeat(sequence=1):
    return {"schema_version": 1, "sequence": sequence, "node_state": "online"}


class IngestSessionTests(NodeTlsHarness):
    def setUp(self):
        super().setUp()
        _, _, self.node, material = self._enrolled()
        self.store = NodeCredentialStore(self.runtime)
        self.store.install(material)
        self.server_certificate, self.server_key = self.authority.server_files(
            self.root / "main")

    def main(self, *handlers, alpn=True):
        peer = ScriptedMain(self.server_certificate, self.server_key,
                            self.bundle.ca_certificate_pem, handlers or (acknowledge_all,),
                            alpn=alpn)
        self.addCleanup(peer.stop)
        return peer

    def session(self, peer, *, node=None, **options):
        endpoint = MainIngestEndpoint("127.0.0.1", peer.port if peer is not None else 9)
        session = IngestSession(self.store, endpoint, node or self.node, **options)
        self.addCleanup(session.close)
        return session

    def assertFails(self, session, reason, sequence=1):
        with self.assertRaises(IngestSessionError) as raised:
            session.send_heartbeat(heartbeat(sequence))
        self.assertEqual(raised.exception.reason, reason)
        self.assertIsNone(session.exchange_clock())
        return raised.exception

    # -- accepted round trip -----------------------------------------------

    def test_a_heartbeat_is_sent_and_its_ack_becomes_the_clock_exchange(self):
        peer = self.main()
        session = self.session(peer)
        self.assertTrue(session.authenticated)
        self.assertIsNone(session.exchange_clock())
        before = time.time()
        session.send_heartbeat(heartbeat(3))
        exchange = session.exchange_clock()
        self.assertIsNotNone(exchange)
        self.assertLessEqual(before, exchange.local_send_utc)
        self.assertLessEqual(exchange.remote_receive_utc, exchange.remote_send_utc)
        self.assertLessEqual(exchange.local_send_monotonic, exchange.local_receive_monotonic)
        self.assertEqual(peer.received, [(FrameType.HEARTBEAT, heartbeat(3))])
        self.assertEqual(peer.alpn, [INGEST_ALPN])
        # Issue #369: stop-and-wait heartbeats without Nagle's delay.
        self.assertTrue(session._connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        session.send_heartbeat(heartbeat(4))
        self.assertEqual(peer.connections, 1)

    def test_an_unpaired_runtime_is_not_authenticated(self):
        empty = self.root / "empty"
        empty.mkdir(mode=0o700)
        session = IngestSession(NodeCredentialStore(empty), MainIngestEndpoint("127.0.0.1", 9),
                                self.node)
        self.assertFalse(session.authenticated)

    # -- refusals and failures -----------------------------------------------

    def test_an_ack_for_another_sequence_drops_the_session(self):
        def wrong(tls, received):
            frame = read_frame(tls)
            ack(tls, frame, sequence=frame[1]["sequence"] + 1)
            read_frame(tls)

        session = self.session(self.main(wrong))
        self.assertFails(session, "main_reply_invalid")
        self.assertIsNone(session._connection)

    def test_malformed_acks_are_refused(self):
        for changes in ({"receive_utc": "now"}, {"extra": 1}, {"send_utc": True}):
            with self.subTest(changes=changes):
                def malformed(tls, received, changes=changes):
                    ack(tls, read_frame(tls), **changes)
                    read_frame(tls)

                self.assertFails(self.session(self.main(malformed)), "main_reply_invalid")

    def test_a_close_frame_keeps_only_a_fixed_word(self):
        for word, kept in (("rate_limited", "rate_limited"), ("Not A Word!", "other")):
            with self.subTest(word=word):
                def close(tls, received, word=word):
                    read_frame(tls)
                    tls.sendall(encode_frame(FrameType.CLOSE, {"reason": word}))

                session = self.session(self.main(close))
                self.assertFails(session, "main_closed")
                self.assertEqual(session.last_close_reason, kept)

    def test_an_oversized_or_unknown_reply_is_refused_before_its_body(self):
        def oversized(tls, received):
            read_frame(tls)
            tls.sendall(HEADER.pack(ingest_session.MAXIMUM_REPLY_BYTES + 1,
                                    FrameType.HEARTBEAT_ACK))
            read_frame(tls)

        def unknown(tls, received):
            read_frame(tls)
            tls.sendall(HEADER.pack(2, 0x10) + b"{}")
            read_frame(tls)

        for handler in (oversized, unknown):
            with self.subTest(handler=handler.__name__):
                self.assertFails(self.session(self.main(handler)), "main_reply_invalid")

    def test_a_missing_reply_times_out(self):
        def silent(tls, received):
            read_frame(tls)
            read_frame(tls)

        session = self.session(self.main(silent))
        with patch.object(ingest_session, "REPLY_TIMEOUT_SECONDS", 0.3):
            started = time.monotonic()
            self.assertFails(session, "main_reply_timeout")
        self.assertLess(time.monotonic() - started, 5)

    def test_a_main_without_the_ingest_alpn_is_refused(self):
        session = self.session(self.main(acknowledge_all, alpn=False))
        self.assertFails(session, "main_alpn_refused")

    def test_a_credential_for_another_node_never_connects(self):
        peer = self.main()
        session = self.session(peer, node=uuid4())
        self.assertFails(session, "node_identity_mismatch")
        self.assertEqual(peer.connections, 0)

    def test_an_unreachable_main_backs_off_without_traffic(self):
        clock = [100.0]
        attempts = []

        def connect(*args, **kwargs):
            attempts.append(kwargs["timeout_seconds"])
            from media_capture_agent.pairing import PairingRefused
            raise PairingRefused("main_unreachable")

        session = self.session(None, connect=connect, monotonic=lambda: clock[0])
        self.assertFails(session, "main_unreachable")
        self.assertEqual(attempts, [ingest_session.CONNECT_TIMEOUT_SECONDS])
        delays = []
        for _ in range(8):
            # While waiting no connection is tried.
            self.assertFails(session, "main_retry_wait")
            waited = 0.0
            while True:
                clock[0] += 0.5
                waited += 0.5
                try:
                    session.send_heartbeat(heartbeat())
                except IngestSessionError as failure:
                    if failure.reason == "main_unreachable":
                        break
            delays.append(waited)
        self.assertEqual(delays, [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0])
        self.assertEqual(len(attempts), 9)

    def test_a_main_that_closed_while_idle_is_reconnected_in_the_same_tick(self):
        def once_then_close(tls, received):
            frame = read_frame(tls)
            received.append(frame)
            ack(tls, frame)
            tls.sendall(encode_frame(FrameType.CLOSE, {"reason": "idle_timeout"}))

        peer = self.main(once_then_close, acknowledge_all)
        session = self.session(peer)
        session.send_heartbeat(heartbeat(1))
        # The Main's CLOSE arrives while the Agent waits for its next tick.
        self.assertTrue(select.select([session._connection], [], [], 5)[0])
        session.send_heartbeat(heartbeat(2))
        self.assertEqual(peer.connections, 2)
        self.assertEqual(session.last_close_reason, None)
        self.assertEqual([frame[1]["sequence"] for frame in peer.received], [1, 2])
        self.assertIsNotNone(session.exchange_clock())

    def test_a_readable_socket_without_application_data_keeps_the_session(self):
        # TLS 1.3 post-handshake records (session tickets) wake `select`
        # without application data; the session must stay, without waiting
        # for a reply or reconnecting.
        peer = self.main()
        session = self.session(peer)
        session.send_heartbeat(heartbeat(1))
        with patch.object(select, "select", return_value=([session._connection], [], [])), \
                patch.object(ingest_session, "REPLY_TIMEOUT_SECONDS", 3):
            started = time.monotonic()
            session.send_heartbeat(heartbeat(2))
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(peer.connections, 1)
        self.assertEqual([frame[1]["sequence"] for frame in peer.received], [1, 2])

    # -- live frames (Issue #14, option A) ------------------------------------

    def test_a_live_frame_is_sent_raw_on_the_open_connection_without_a_reply(self):
        raw = []

        def heartbeat_then_raw(tls, received):
            frame = read_frame(tls)
            received.append(frame)
            ack(tls, frame)
            header = b""
            while len(header) < 5:
                header += tls.recv(5 - len(header))
            length, kind = HEADER.unpack(header)
            body = b""
            while len(body) < length:
                body += tls.recv(length - len(body))
            raw.append((kind, body))
            acknowledge_all(tls, received)

        peer = self.main(heartbeat_then_raw)
        session = self.session(peer)
        source = uuid4()
        jpeg = b"\xff\xd8" + b"synthetic" * 10 + b"\xff\xd9"
        # Never connects by itself: the heartbeat owns the connection.
        self.assertFalse(session.send_live_frame(source, jpeg))
        self.assertEqual(peer.connections, 0)
        session.send_heartbeat(heartbeat(1))
        self.assertTrue(session.send_live_frame(source, jpeg))
        session.send_heartbeat(heartbeat(2))
        self.assertEqual(raw, [(0x10, source.bytes + jpeg)])
        self.assertEqual(peer.connections, 1)

    def test_a_frame_that_is_not_one_bounded_jpeg_is_skipped(self):
        peer = self.main()
        session = self.session(peer)
        session.send_heartbeat(heartbeat(1))
        source = uuid4()
        for jpeg in (b"", b"\xff\xd8", b"not a jpeg", b"\xff\xd8xx",
                     b"\xff\xd8" + bytes(ingest_session.MAXIMUM_LIVE_FRAME_BYTES) + b"\xff\xd9"):
            with self.subTest(size=len(jpeg)):
                self.assertFalse(session.send_live_frame(source, jpeg))
        self.assertFalse(session.send_live_frame("camera", b"\xff\xd8\xff\xd9"))

    def test_a_live_frame_type_from_the_main_is_refused(self):
        def wrong(tls, received):
            read_frame(tls)
            tls.sendall(HEADER.pack(2, 0x10) + b"{}")
            read_frame(tls)

        self.assertFails(self.session(self.main(wrong)), "main_reply_invalid")

    def test_errors_hold_no_peer_bytes(self):
        def close(tls, received):
            read_frame(tls)
            tls.sendall(encode_frame(FrameType.CLOSE, {"reason": "x" * 70}))

        session = self.session(self.main(close))
        failure = self.assertFails(session, "main_closed")
        self.assertEqual(str(failure), "main_closed")
        self.assertEqual(session.last_close_reason, "other")
        self.assertNotIn("x" * 10, self.log.getvalue())


class AgentSessionTests(NodeTlsHarness):
    """``Agent.tick`` with the real session (the runtime's clock refresh)."""

    def setUp(self):
        super().setUp()
        _, _, _, material = self._enrolled()
        settings_root = self.root / "agent"
        settings_root.mkdir()
        value = support.configuration(settings_root)
        value["node_id"] = str(material.node_id)
        self.settings = Settings.parse(value, code_root=settings_root / "code")
        self.store = NodeCredentialStore(self.settings.runtime_root)
        self.store.install(material)
        certificate, key = self.authority.server_files(self.root / "main")
        self.peer = ScriptedMain(certificate, key, self.bundle.ca_certificate_pem,
                                 (acknowledge_all,))
        self.addCleanup(self.peer.stop)

    def agent(self, session):
        agent = Agent(self.settings, FreeStore(), capture=support.SyntheticCapture(),
                      session=session)
        self.addCleanup(agent.close)
        return agent

    def test_the_first_ack_of_a_session_asks_for_an_immediate_second_heartbeat(self):
        session = IngestSession(self.store, MainIngestEndpoint("127.0.0.1", self.peer.port),
                                self.settings.node_id)
        agent = self.agent(session)
        first = agent.tick()
        self.assertIn("clock_unavailable", first["node_reasons"])
        self.assertTrue(agent.clock_refresh_due)
        second = agent.tick()
        self.assertEqual(second["clock"]["state"], "online")
        self.assertNotIn("clock_unavailable", second["node_reasons"])
        self.assertFalse(agent.clock_refresh_due)
        self.assertEqual([frame[1]["sequence"] for frame in self.peer.received], [1, 2])

    def test_an_unconfigured_endpoint_is_its_own_reason(self):
        heartbeat = self.agent(UnconfiguredIngestSession(self.store)).tick()
        self.assertIn("main_ingest_unconfigured", heartbeat["node_reasons"])
        self.assertNotIn("pairing_required", heartbeat["node_reasons"])

    def test_an_unpaired_node_without_an_endpoint_still_reports_pairing_required(self):
        # PR #406 review: pairing is the Owner's first step.
        empty = self.root / "unpaired"
        empty.mkdir(mode=0o700)
        session = UnconfiguredIngestSession(NodeCredentialStore(empty))
        self.assertEqual(session.unavailable_reason, "pairing_required")


class LiveSenderTests(unittest.TestCase):
    def test_only_new_frames_are_sent_at_most_five_per_second_per_source(self):
        from media_capture_agent.live_sender import LiveSender
        from media_capture_agent.preview import PreviewFrame
        sources = (uuid4(), uuid4())
        frames = {sources[0]: PreviewFrame(sources[0], b"\xff\xd8a\xff\xd9", 1, 0.0)}
        sent, lock = [], threading.Lock()

        class Session:
            def send_live_frame(self, source, data):
                with lock:
                    sent.append((source, data))
                return True

        class Preview:
            def latest(self, source):
                return frames.get(source)

        sender = LiveSender(Session(), Preview(), sources)
        self.addCleanup(sender.close)
        time.sleep(0.5)
        with lock:
            self.assertEqual(sent, [(sources[0], b"\xff\xd8a\xff\xd9")])
        # A newer frame of the same source, and the other source starting.
        frames[sources[0]] = PreviewFrame(sources[0], b"\xff\xd8b\xff\xd9", 2, 0.0)
        frames[sources[1]] = PreviewFrame(sources[1], b"\xff\xd8c\xff\xd9", 7, 0.0)
        time.sleep(0.5)
        with lock:
            self.assertEqual(sorted(sent[1:]), sorted([(sources[0], b"\xff\xd8b\xff\xd9"),
                                                       (sources[1], b"\xff\xd8c\xff\xd9")]))
        # A frame per pass at most: a source that changes every time is
        # capped at five per second.
        sent.clear()
        stop = threading.Event()

        def churn():
            sequence = 10
            while not stop.is_set():
                sequence += 1
                frames[sources[0]] = PreviewFrame(sources[0], b"\xff\xd8d\xff\xd9",
                                                  sequence, 0.0)
                time.sleep(0.001)

        worker = threading.Thread(target=churn)
        worker.start()
        time.sleep(1.0)
        stop.set()
        worker.join()
        with lock:
            count = sum(1 for source, _ in sent if source == sources[0])
        self.assertLessEqual(count, 6)
        self.assertGreaterEqual(count, 3)

    def test_unsent_frames_are_counted_and_retried_when_newer(self):
        from media_capture_agent.live_sender import LiveSender
        from media_capture_agent.preview import PreviewFrame
        source = uuid4()

        class Session:
            def __init__(self):
                self.calls = 0

            def send_live_frame(self, source, data):
                self.calls += 1
                return False

        class Preview:
            def latest(self, source):
                return PreviewFrame(source, b"\xff\xd8a\xff\xd9", 1, 0.0)

        session = Session()
        sender = LiveSender(session, Preview(), (source,))
        time.sleep(0.5)
        sender.close()
        self.assertGreaterEqual(sender.frames_not_sent, 2)
        self.assertEqual(sender.frames_sent, 0)

    def test_invalid_senders_are_refused(self):
        from media_capture_agent.live_sender import LiveSender
        for arguments in ((object(), object(), (uuid4(),)),):
            with self.assertRaises(ValueError):
                LiveSender(*arguments)


class MainIngestSettingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-ingest-config-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # An ingest session needs at least 1 s (`MINIMUM_INGEST_HEARTBEAT_SECONDS`).
        self.value = dict(support.configuration(self.root), heartbeat_seconds=1)

    def parse(self, **changes):
        value = dict(self.value, **changes)
        return Settings.parse(value, code_root=self.root / "code")

    def test_the_endpoint_is_optional(self):
        self.assertIsNone(self.parse().main_ingest)
        self.assertIsNone(self.parse(main_ingest=None).main_ingest)
        endpoint = self.parse(main_ingest={"host": "192.0.2.10", "port": 7444}).main_ingest
        self.assertEqual((endpoint.host, endpoint.port), ("192.0.2.10", 7444))
        self.assertEqual(self.parse(main_ingest={"host": "capture-main.example.test",
                                                 "port": 7444}).main_ingest.port, 7444)

    def test_invalid_and_tailscale_endpoints_are_refused(self):
        for endpoint in ({"host": "192.0.2.10"}, {"host": "192.0.2.10", "port": 0},
                         {"host": "192.0.2.10", "port": 65536},
                         {"host": "192.0.2.10", "port": "7444"},
                         {"host": "192.0.2.10", "port": 7444, "tls": False},
                         {"host": "0.0.0.0", "port": 7444}, {"host": "", "port": 7444},
                         {"host": "100.64.0.1", "port": 7444},
                         {"host": "fd7a:115c:a1e0::1", "port": 7444},
                         {"host": "::ffff:100.100.1.1", "port": 7444}, "192.0.2.10:7444"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ConfigurationError):
                    self.parse(main_ingest=endpoint)

    def test_an_ingest_session_needs_a_heartbeat_within_the_main_rate_budget(self):
        # PR #406 review: the Main closes a session above 10 frames per second.
        endpoint = {"host": "192.0.2.10", "port": 7444}
        for refused in (0.01, 0.5, 0.999):
            with self.subTest(heartbeat=refused):
                with self.assertRaises(ConfigurationError):
                    self.parse(main_ingest=endpoint, heartbeat_seconds=refused)
        for accepted in (1, 1.0, 5):
            with self.subTest(heartbeat=accepted):
                self.assertEqual(self.parse(main_ingest=endpoint,
                                            heartbeat_seconds=accepted).heartbeat_seconds,
                                 accepted)
        # Without an ingest session the interval keeps its old range.
        self.assertEqual(self.parse(heartbeat_seconds=0.01).heartbeat_seconds, 0.01)

    def test_unknown_keys_are_still_refused(self):
        with self.assertRaises(ConfigurationError):
            self.parse(main_endpoint={"host": "192.0.2.10", "port": 7444})


class StdlibOnlyServiceTests(unittest.TestCase):
    def test_the_service_cli_and_session_import_without_cryptography(self):
        # The release zipapp runs on the system interpreter, which has no
        # `cryptography` (build_artifact.py): the service path must not need it.
        agent_root = Path(__file__).resolve().parents[1]
        code = ("import sys\n"
                f"sys.path.insert(0, {str(agent_root)!r})\n"
                "class Block:\n"
                "    def find_spec(self, name, path=None, target=None):\n"
                "        if name == 'cryptography' or name.startswith('cryptography.'):\n"
                "            raise ImportError('blocked')\n"
                "sys.meta_path.insert(0, Block())\n"
                "import media_capture_agent.cli, media_capture_agent.ingest_session\n"
                "import media_capture_agent.capture_admin, media_capture_agent.preview\n"
                "import media_capture_agent.uvc_capture\n"
                "assert not any(m.startswith('cryptography') for m in sys.modules)\n")
        result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
