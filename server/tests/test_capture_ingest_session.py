"""Issue #14: the real Agent ingest session against the real Main ingest listener.

The Agent's ``IngestSession`` (``agent/media_capture_agent/ingest_session.py``)
and the heartbeat its ``Agent.tick`` builds are run against
``CaptureIngestServer`` over loopback TLS 1.3 mTLS, with a pairing ledger and
CA generated per test (``CaptureTlsHarness``). A change of the wire protocol,
the ALPN or the ack on either side fails here. No real host, credential or
media is used.
"""
from pathlib import Path
import socket
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.cameras.remote_agent.ingest_config import CaptureIngestLimits
from app.cameras.remote_agent.ingest_server import CaptureIngestServer
from app.cameras.remote_agent.ingest_tls import CaptureIngestAcceptor
from app.cameras.remote_agent import ingest_wire
from tests.test_capture_mtls import SERVER_NAME, CaptureTlsHarness, Owner


AGENT = str(Path(__file__).resolve().parents[2] / "agent")
agent = None


def setUpModule():
    # Issue #284: a module adds a path only while its tests run.
    global agent
    sys.path.insert(0, AGENT)
    unittest.addModuleCleanup(lambda: sys.path.remove(AGENT))
    from media_capture_agent import config, health, ingest_session, runtime
    agent = SimpleNamespace(config=config, health=health, ingest_session=ingest_session,
                            runtime=runtime)


class Store:
    """The Agent's media store stand-in (its mount checks have their own tests)."""

    device_numbers_stale = False

    def check(self):
        return 10 ** 9

    def close(self):
        pass


class InstalledStore:
    def installed(self):
        return True


class Capture:
    def poll(self):
        return ()

    def close(self):
        pass


class AgentIngestSessionTests(CaptureTlsHarness):
    def setUp(self):
        super().setUp()
        self.claim, _, self.certificate, self.key = self._paired_node("a")
        self.node = self.claim.node_id
        listener = socket.create_server(("127.0.0.1", 0))
        self.port = listener.getsockname()[1]
        acceptor = CaptureIngestAcceptor(self.context, self.admission,
                                         handshake_timeout_seconds=10, log_refusals=False,
                                         required_alpn=ingest_wire.INGEST_ALPN)
        self.accepted = []
        original = acceptor.accept

        def accept(connection, **kwargs):
            self.accepted.append(connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
            return original(connection, **kwargs)

        acceptor.accept = accept
        self.server = CaptureIngestServer(
            listener, acceptor,
            limits=CaptureIngestLimits(idle_timeout_seconds=5, frames_per_second=10))
        self.server.start()
        self.addCleanup(lambda: (self.server.stop(), self.server.join(10)))

    def credential(self, _store):
        return SimpleNamespace(ca_certificate_pem=self.ca_path.read_bytes(),
                               certificate_path=self.certificate, key_path=self.key,
                               server_name=SERVER_NAME, node_id=self.node)

    def session(self):
        session = agent.ingest_session.IngestSession(
            InstalledStore(), agent.config.MainIngestEndpoint("127.0.0.1", self.port), self.node,
            credential=self.credential)
        self.addCleanup(session.close)
        return session

    def node_agent(self, session):
        # `Agent.__init__` checks a real runtime root; `tick` is the real code.
        instance = agent.runtime.Agent.__new__(agent.runtime.Agent)
        instance.settings = SimpleNamespace(
            node_id=self.node, safety_reserve_bytes=4096, clock_offset_limit_seconds=2,
            clock_uncertainty_limit_seconds=0.5, clock_step_limit_seconds=0.5)
        instance.store = Store()
        instance.capture = Capture()
        instance.session = session
        instance.utc = time.time
        instance.monotonic = time.monotonic
        instance.sequence = 0
        instance.clock_refresh_due = False
        return instance

    def test_the_agent_heartbeat_is_accepted_and_its_ack_sets_the_clock(self):
        node = self.node_agent(self.session())
        first = node.tick()
        self.assertNotIn("main_unavailable", first["node_reasons"])
        self.assertIn("clock_unavailable", first["node_reasons"])
        self.assertTrue(node.clock_refresh_due)
        self.assertEqual(self.server.registry.state(self.node), "degraded")
        second = node.tick()
        self.assertEqual(second["clock"]["state"], "online", second["clock"])
        self.assertEqual((second["node_state"], second["node_reasons"]), ("online", []))
        self.assertEqual(self.server.registry.state(self.node), "online")
        snapshot = self.server.registry.snapshot()
        self.assertEqual((snapshot.connected_nodes, snapshot.known_nodes), (1, 1))
        # One session, both sides without Nagle's delay (Issue #369).
        self.assertEqual(self.server.status().open_connections, 1)
        self.assertEqual(self.accepted, [1])
        self.assertTrue(node.session._connection.getsockopt(socket.IPPROTO_TCP,
                                                            socket.TCP_NODELAY))

    def test_a_revoked_node_loses_its_session_and_cannot_reconnect(self):
        session = self.session()
        node = self.node_agent(session)
        node.tick()
        self.ledger.revoke(Owner(), "owner", node_id=self.node)
        revoked = node.tick()
        self.assertIn("main_unavailable", revoked["node_reasons"])
        self.assertIsNone(session.exchange_clock())
        self.assertTrue(self.wait_for(lambda: self.server.registry.state(self.node) is None))
        # The reconnect after the back-off is refused at admission.
        with patch.object(agent.ingest_session, "RETRY_FIRST_SECONDS", 0):
            session._retry_at = None
            again = node.tick()
        self.assertIn("main_unavailable", again["node_reasons"])
        self.assertEqual(self.server.registry.snapshot().known_nodes, 0)

    def test_a_superseded_session_reconnects_on_its_next_heartbeat(self):
        # ADR-0007 item 2: the newer session wins and the Main shuts the
        # older down; the older finds its socket closed before sending and
        # reconnects within the same call (as after a Main restart).
        older, newer = self.session(), self.session()
        older.send_heartbeat(self.heartbeat(1))
        newer.send_heartbeat(self.heartbeat(1))
        self.assertTrue(self.wait_for(lambda: "superseded" in self.server.last_close_reasons()))
        older.send_heartbeat(self.heartbeat(2))
        self.assertIsNotNone(older.exchange_clock())
        self.assertEqual(len(self.accepted), 3)
        self.assertEqual(self.server.registry.state(self.node), "online")

    def heartbeat(self, sequence):
        clock = {"state": "online", "reason": "clock_within_limit", "offset_seconds": 0.0,
                 "uncertainty_seconds": 0.001}
        return {"schema_version": 1, "node_id": str(self.node), "sequence": sequence,
                "utc_seconds": 1.0, "monotonic_seconds": 1.0, "node_state": "online",
                "node_reasons": [], "clock": clock, "storage": {"state": "online"},
                "sources": []}

    def wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()

    def test_the_two_wire_copies_agree(self):
        # The Agent cannot import the server: its copy of the framing is
        # checked against the Main's here.
        session = agent.ingest_session
        self.assertEqual(session.INGEST_ALPN, ingest_wire.INGEST_ALPN)
        self.assertEqual(session.HEADER.format, ingest_wire.HEADER.format)
        self.assertEqual({kind.name: int(kind) for kind in session.FrameType},
                         {kind.name: int(kind) for kind in ingest_wire.FrameType})
        self.assertLessEqual(session.MAXIMUM_HEARTBEAT_BYTES,
                             CaptureIngestLimits().maximum_frame_bytes)
        # One tick's network work fits the slow-tick allowance of the idle
        # timeout (`config.MAXIMUM_HEARTBEAT_SECONDS`, 15 s).
        # PR #406 review: the shortest interval with a session, plus the one
        # immediate clock-refresh heartbeat, stays within the rate budget.
        minimum = agent.config.MINIMUM_INGEST_HEARTBEAT_SECONDS
        self.assertLessEqual(2 * max(1, int(1 / minimum)),
                             CaptureIngestLimits().frames_per_second)
        self.assertLessEqual(minimum, agent.config.MAXIMUM_HEARTBEAT_SECONDS)
        self.assertLessEqual(session.CONNECT_TIMEOUT_SECONDS * 2
                             + session.REPLY_TIMEOUT_SECONDS, 15)


if __name__ == "__main__":
    unittest.main()
