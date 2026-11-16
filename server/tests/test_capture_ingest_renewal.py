"""Issue #109: certificate renewal over the capture ingest session (mock/loopback only).

The Main's ``CaptureIngestServer`` is run over real loopback TLS 1.3 mTLS with
a real pairing ledger, and ``SessionRenewal`` reaches the renewal-only
signer (``RenewalSigner`` behind ``serve_connection``, in this process) over
a real Unix socket. A CA created 400 days ago and nodes enrolled through the
CA-account issuer 380 days ago make every node due (17 days left). Fake
signer connections cover unavailable, refused and slow signers. The Agent
side is a synthetic in-test client; the real Agent session is run against
this listener in ``test_capture_ingest_session``. No real host, credential
or media is used.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.audit.store import AuditStore
from app.cameras.remote_agent.ingest_config import CaptureIngestLimits
from app.cameras.remote_agent.ingest_server import CaptureIngestServer
from app.cameras.remote_agent.ingest_tls import (
    CaptureIngestAcceptor, CaptureNodeAdmission, build_ingest_server_context,
)
from app.cameras.remote_agent.ingest_wire import (
    HEADER, INGEST_ALPN, MAXIMUM_RENEWAL_REPLY_BODY_BYTES, MAXIMUM_RENEWAL_REQUEST_BODY_BYTES,
    RENEWAL_REFUSALS, FrameType, PeerClosed, WireRefused, encode_frame, encode_renewal_reply,
    parse_renewal_request, read_frame,
)
from app.cameras.remote_agent.node_ca import (
    DeploymentAuthority, PrivateDirectory, listener_material, public_key_digest,
)
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.cameras.remote_agent.renewal import RenewalRefused, SessionRenewal
from app.cameras.remote_agent.renewal_signer import RenewalSigner, serve_connection
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.test_capture_ingest_wire import heartbeat
from tests.test_renewal_signer import (
    DAY, SERVER_NAME, Owner, SocketHarness, renewal_csr,
)


# Built, so the repository's secret-format scan does not mistake it for a PEM.
PEM_CERTIFICATE_LINE = "-" * 5 + "BEGIN CERTIFICATE" + "-" * 5


def _limits():
    return {FrameType.RENEWAL_REPLY: MAXIMUM_RENEWAL_REPLY_BODY_BYTES}


class RenewalWireTests(unittest.TestCase):
    def test_a_request_is_one_ascii_pem_csr_and_nothing_else(self):
        _, csr = renewal_csr()
        body = json.dumps({"csr": csr.decode()}).encode()
        self.assertEqual(parse_renewal_request(body), csr)
        for bad in (b"{}", b"[]", b"not json", json.dumps({"csr": csr.decode(), "node_id": "x"}).encode(),
                    json.dumps({"csr": 1}).encode(), json.dumps({"csr": PEM_CERTIFICATE_LINE}).encode(),
                    json.dumps({"csr": csr.decode() + "é"}).encode(),
                    json.dumps({"csr": "x" * MAXIMUM_RENEWAL_REQUEST_BODY_BYTES}).encode()):
            with self.subTest(bad=bad[:24]):
                with self.assertRaises(WireRefused) as refused:
                    parse_renewal_request(bad)
                self.assertEqual(refused.exception.reason, "renewal_request_invalid")

    def test_a_reply_is_a_certificate_or_a_fixed_word(self):
        certificate = (PEM_CERTIFICATE_LINE + "\nAAAA\n" + "-" * 5 + "END CERTIFICATE"
                       + "-" * 5 + "\n").encode()
        frame = encode_renewal_reply(certificate_pem=certificate)
        length, kind = HEADER.unpack(frame[:HEADER.size])
        self.assertEqual((kind, length), (FrameType.RENEWAL_REPLY, len(frame) - HEADER.size))
        self.assertEqual(json.loads(frame[HEADER.size:]),
                         {"status": "issued", "certificate": certificate.decode()})
        for word in RENEWAL_REFUSALS:
            self.assertEqual(json.loads(encode_renewal_reply(reason=word)[HEADER.size:]),
                             {"status": "refused", "reason": word})
        for bad in ({"reason": "free text"}, {"reason": "renewal_not_due"},
                    {"certificate_pem": ("-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5).encode()},
                    {"certificate_pem": certificate, "reason": "renewal_busy"}, {},
                    {"certificate_pem": certificate + b"A" * MAXIMUM_RENEWAL_REPLY_BODY_BYTES}):
            with self.subTest(bad=str(bad)[:30]):
                with self.assertRaises(ValueError):
                    encode_renewal_reply(**bad)

    def test_the_request_limit_is_applied_from_the_header(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        right.settimeout(5)
        # Only the header: a reader that waited for the body would time out.
        left.sendall(struct.pack(">IB", MAXIMUM_RENEWAL_REQUEST_BODY_BYTES + 1,
                                 FrameType.RENEWAL_REQUEST))
        with self.assertRaises(WireRefused) as refused:
            read_frame(right, 16 * 1024, type_limits={
                FrameType.RENEWAL_REQUEST: MAXIMUM_RENEWAL_REQUEST_BODY_BYTES})
        self.assertEqual(refused.exception.reason, "frame_too_large")


class SignerSocket:
    """A Unix socket served by ``serve_connection`` for every connection until closed."""

    def __init__(self, path: Path, signer: RenewalSigner):
        self.path = path
        self.outcomes = []
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(path))
        self._listener.listen(4)
        self._thread = threading.Thread(target=self._run, args=(signer,), daemon=True)
        self._thread.start()

    def _run(self, signer):
        while True:
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return
            with connection:
                self.outcomes.append(serve_connection(connection, signer,
                                                      service_uid=os.getuid()))

    def close(self):
        try:
            socket.socket.shutdown(self._listener, socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()
        self._thread.join(10)


class IngestRenewalHarness(SocketHarness):
    """A listener of this CA, an activated due node and a signer socket; no tests."""

    def setUp(self):
        super().setUp()
        database = Database(self.root / "state.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)),
                                    audit=AuditStore(database))
        self.admission = CaptureNodeAdmission(self.ledger, self.deployment)
        # The listener certificate is issued with the real clock.
        authority = DeploymentAuthority.load(PrivateDirectory(self.authority_dir), self.deployment)
        listener = PrivateDirectory(self.root / "listener")
        authority.issue_main_server_credential(listener, server_name=SERVER_NAME,
                                               validity=30 * DAY)
        material = listener_material(listener)
        self.context = build_ingest_server_context(authority.ca_certificate_pem(),
                                                   material.certificate_path, material.key_path)
        del authority
        self.ca_path = self.root / "ca.pem"
        self.ca_path.write_bytes(self.trust.ca_certificate_pem())
        self.node, self.certificate, self.key = self.activated_node("a")
        socket_directory = self.root / "signer"
        socket_directory.mkdir(mode=0o700)
        self.signer_socket = SignerSocket(socket_directory / "signer.sock", self.signer)
        self.addCleanup(self.signer_socket.close)

    def activated_node(self, name):
        """Enroll through the CA-account issuer and activate it in the ledger."""
        node, certificate, key = self.enroll()
        digest = public_key_digest(key.public_key())
        approval, code = self.ledger.approve(Owner(), "owner", node_id=node,
                                             public_key_digest=digest)
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=digest, code=code.value)
        identity, _ = self.identity(certificate)
        self.ledger.activate(claim, credential_serial_digest=identity.credential_digest,
                             not_after=identity.not_valid_after.timestamp())
        return node, self.write_credential(name, certificate.encode(), key), key

    def write_credential(self, name, certificate_pem, key):
        directory = self.root / ("node-" + name + "-" + uuid4().hex[:6])
        directory.mkdir(mode=0o700)
        certificate_path = directory / "certificate.pem"
        certificate_path.write_bytes(certificate_pem)
        key_path = directory / "key.pem"
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        return certificate_path, key_path

    def renewal(self, **options):
        options.setdefault("socket_path", self.signer_socket.path)
        options.setdefault("timeout", 5)
        return SessionRenewal(self.trust, self.ledger, self.admission, **options)

    def serve(self, *, renewal="default", **options):
        listener = socket.create_server(("127.0.0.1", 0))
        self.address = listener.getsockname()
        limits = dict(idle_timeout_seconds=5, frames_per_second=10)
        limits.update(options.pop("limits", {}))
        acceptor = CaptureIngestAcceptor(self.context, self.admission,
                                         handshake_timeout_seconds=10, log_refusals=False,
                                         required_alpn=INGEST_ALPN)
        server = CaptureIngestServer(
            listener, acceptor, limits=CaptureIngestLimits(**limits),
            renewal=self.renewal() if renewal == "default" else renewal, **options)
        server.start()
        self.addCleanup(lambda: (server.stop(), server.join(10)))
        return server

    def connect(self, credential=None):
        certificate, key = credential or self.certificate
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.ca_path))
        context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
        context.set_alpn_protocols([INGEST_ALPN])
        raw = socket.create_connection(self.address, timeout=10)
        tls = context.wrap_socket(raw, server_hostname=SERVER_NAME)
        self.addCleanup(tls.close)
        return tls

    def beat(self, tls, node=None, sequence=1):
        """One heartbeat; every frame up to its ack, as (kind, value)."""
        tls.sendall(encode_frame(FrameType.HEARTBEAT,
                                 heartbeat(node or self.node, sequence=sequence)))
        frames = []
        while True:
            frame = read_frame(tls, 4096, type_limits=_limits())
            frames.append((frame.kind, json.loads(frame.body)))
            if frame.kind in (FrameType.HEARTBEAT_ACK, FrameType.CLOSE):
                return frames

    @staticmethod
    def request(tls, csr):
        tls.sendall(encode_frame(FrameType.RENEWAL_REQUEST, {"csr": csr.decode()}))

    def answered(self, tls, node=None, timeout=10.0):
        """Heartbeats until one carries the renewal reply; returns that reply."""
        deadline = time.monotonic() + timeout
        sequence = 10
        while time.monotonic() < deadline:
            sequence += 1
            frames = self.beat(tls, node, sequence)
            self.assertIs(frames[-1][0], FrameType.HEARTBEAT_ACK, frames)
            if len(frames) == 2:
                self.assertIs(frames[0][0], FrameType.RENEWAL_REPLY)
                return frames[0][1]
            self.assertEqual(len(frames), 1, frames)
            time.sleep(0.05)
        self.fail("no renewal reply")

    def closed_with(self, tls):
        frame = read_frame(tls, 4096)
        self.assertIs(frame.kind, FrameType.CLOSE)
        return json.loads(frame.body)["reason"]

    def wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()


class IngestRenewalTests(IngestRenewalHarness):
    def test_a_due_node_renews_over_its_session_and_the_new_certificate_is_admitted(self):
        server = self.serve()
        tls = self.connect()
        self.assertEqual(len(self.beat(tls)), 1)
        new_key, csr = renewal_csr()
        self.request(tls, csr)
        reply = self.answered(tls)
        self.assertEqual(reply["status"], "issued")
        issued = x509.load_pem_x509_certificate(reply["certificate"].encode())
        self.assertEqual(public_key_digest(issued.public_key()),
                         public_key_digest(new_key.public_key()))
        uris = issued.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
        self.assertIn(f"urn:serversentinel:capture-node:{self.node}", uris)
        # The CA log records it as a renewal of the presented certificate.
        self.assertEqual(["signed"], self.signer_socket.outcomes)
        self.assertIn("renewal_of", self.records()[-1])
        status = server.status()
        self.assertEqual((status.renewals_issued, status.renewals_refused), (1, 0))
        # The session goes on with the old certificate; the next connection
        # with the new one promotes it, and the old one is then refused.
        self.assertEqual(len(self.beat(tls, sequence=99)), 1)
        renewed = self.write_credential("a", reply["certificate"].encode(), new_key)
        fresh = self.connect(renewed)
        self.assertEqual(self.beat(fresh)[-1][0], FrameType.HEARTBEAT_ACK)
        self.assertTrue(self.wait_for(
            lambda: "not_admitted" in server.last_close_reasons()
            or self._old_refused(tls)))

    def _old_refused(self, tls):
        try:
            return self.beat(tls, sequence=100)[-1][0] is FrameType.CLOSE
        except (PeerClosed, OSError, ssl.SSLError):
            return True

    def test_a_lost_reply_is_answered_again_from_the_ledger_with_the_same_key(self):
        server = self.serve(renewal_interval_seconds=0)
        tls = self.connect()
        self.beat(tls)
        key, csr = renewal_csr()
        self.request(tls, csr)
        # The reply waits for an ack that never comes: the session ends first.
        self.assertTrue(self.wait_for(lambda: server.status().renewals_issued == 1))
        tls.close()
        self.signer_socket.close()
        again = self.connect()
        self.beat(again)
        self.request(again, csr)
        reply = self.answered(again)
        self.assertEqual(reply["status"], "issued")
        issued = x509.load_pem_x509_certificate(reply["certificate"].encode())
        self.assertEqual(public_key_digest(issued.public_key()),
                         public_key_digest(key.public_key()))
        self.assertEqual(server.status().renewals_issued, 2)

    def test_one_request_per_session_until_its_reply_is_sent(self):
        self.serve()
        tls = self.connect()
        self.beat(tls)
        _, csr = renewal_csr()
        self.request(tls, csr)
        self.request(tls, csr)
        self.assertEqual(self.closed_with(tls), "renewal_in_flight")

    def test_signer_unavailable_or_refused_is_a_fixed_word_and_the_session_goes_on(self):
        cases = (
            (self.renewal(socket_path=self.root / "absent.sock"), "renewal_signer_unavailable",
             (0, 1)),
            (self.renewal(connect=SocketHarness.replying(
                {"status": "refused", "reason": "renewal_rate_limited"})),
             "renewal_signer_refused", (1, 0)),
            (self.renewal(connect=SocketHarness.replying(
                {"status": "refused", "reason": "issuance_log_unavailable"})),
             "renewal_signer_unavailable", (0, 1)),
            (None, "renewal_unavailable", (0, 1)),
        )
        for renewal, word, counts in cases:
            with self.subTest(word=word):
                server = self.serve(renewal=renewal)
                tls = self.connect()
                self.beat(tls)
                before = self.records()
                self.request(tls, renewal_csr()[1])
                self.assertEqual(self.answered(tls), {"status": "refused", "reason": word})
                self.assertEqual(self.beat(tls, sequence=50)[-1][0], FrameType.HEARTBEAT_ACK)
                status = server.status()
                # Refused and unavailable are counted apart (PR #425 review).
                self.assertEqual((status.renewals_issued, status.renewals_refused,
                                  status.renewals_unavailable), (0, *counts))
                self.assertEqual(status.renewal_refusals, ((word, 1),))
                self.assertEqual(before, self.records())
                server.stop()
                server.join(10)

    def test_a_not_due_or_invalid_csr_is_refused_by_the_renewal_not_by_closing(self):
        server = self.serve()
        tls = self.connect()
        self.beat(tls)
        tls.sendall(encode_frame(FrameType.RENEWAL_REQUEST, {
            "csr": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"}))
        self.assertEqual(self.answered(tls),
                         {"status": "refused", "reason": "renewal_request_invalid"})
        self.assertEqual(server.status().renewal_refusals, (("renewal_request_invalid", 1),))

    def test_a_malformed_or_oversized_request_closes_the_session(self):
        self.serve()
        tls = self.connect()
        self.beat(tls)
        tls.sendall(encode_frame(FrameType.RENEWAL_REQUEST, {"csr": "x", "node_id": "y"}))
        self.assertEqual(self.closed_with(tls), "renewal_request_invalid")
        tls = self.connect()
        tls.sendall(HEADER.pack(MAXIMUM_RENEWAL_REQUEST_BODY_BYTES + 1, FrameType.RENEWAL_REQUEST))
        self.assertEqual(self.closed_with(tls), "frame_too_large")
        # A Main-to-Agent type from the Agent is refused like any other.
        tls = self.connect()
        tls.sendall(encode_frame(FrameType.RENEWAL_REPLY, {"status": "refused"}))
        self.assertEqual(self.closed_with(tls), "frame_type_refused")

    def test_requests_are_charged_to_the_node_rate_budget(self):
        server = self.serve(limits={"frames_per_second": 2})
        tls = self.connect()
        self.beat(tls)
        self.beat(tls, sequence=2)
        with patch.object(server, "_renewal_request", wraps=server._renewal_request) as started:
            self.request(tls, renewal_csr()[1])
            self.assertEqual(self.closed_with(tls), "rate_limited")
        started.assert_not_called()

    def test_a_revoked_session_cannot_renew(self):
        server = self.serve()
        tls = self.connect()
        self.beat(tls)
        self.ledger.revoke(Owner(), "owner", node_id=self.node)
        before = self.records()
        self.request(tls, renewal_csr()[1])
        with self.assertRaises((PeerClosed, OSError, ssl.SSLError)):
            while True:
                read_frame(tls, 4096)
        self.assertTrue(self.wait_for(lambda: "not_admitted" in server.last_close_reasons()))
        self.assertEqual(before, self.records())
        self.assertEqual(self.signer_socket.outcomes, [])
        self.assertEqual(server.status().renewals_issued, 0)

    def test_each_session_renews_only_its_own_node(self):
        # The node is the session's; the request names none, and the
        # presented certificate must be the session's own.
        other_node, other_credential, _ = self.activated_node("b")
        server = self.serve()
        tls = self.connect(other_credential)
        self.beat(tls, node=other_node)
        key, csr = renewal_csr()
        self.request(tls, csr)
        reply = self.answered(tls, node=other_node)
        issued = x509.load_pem_x509_certificate(reply["certificate"].encode())
        uris = issued.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
        self.assertIn(f"urn:serversentinel:capture-node:{other_node}", uris)
        self.assertNotIn(f"urn:serversentinel:capture-node:{self.node}", uris)
        self.assertEqual(server.status().renewals_issued, 1)
        # Another certificate than the session's is refused before the signer.
        identity, _ = self.identity(self.certificate[0].read_text())
        _, other_der = self.identity(other_credential[0].read_text())
        with self.assertRaises(RenewalRefused) as refused:
            self.renewal()(identity, other_der, renewal_csr()[1])
        self.assertEqual(refused.exception.reason, "renewal_identity_invalid")
        with self.assertRaises(ValueError):
            SessionRenewal(DeploymentAuthority.load(PrivateDirectory(self.authority_dir),
                                                    self.deployment),
                           self.ledger, self.admission)

    def test_a_slow_signer_blocks_neither_heartbeats_nor_other_sessions(self):
        release = threading.Event()
        calls = []

        def slow(path, timeout):
            calls.append(path)
            release.wait(10)
            raise OSError("synthetic unavailable signer")

        other_node, other_credential, _ = self.activated_node("b")
        server = self.serve(renewal=self.renewal(connect=slow), maximum_concurrent_renewals=1)
        tls = self.connect()
        self.beat(tls)
        self.request(tls, renewal_csr()[1])
        self.assertTrue(self.wait_for(lambda: calls))
        started = time.monotonic()
        # The renewing session's heartbeats are acknowledged meanwhile.
        for sequence in range(2, 5):
            self.assertEqual(len(self.beat(tls, sequence=sequence)), 1)
        # Another node connects, heartbeats, and beyond the concurrency
        # bound is answered `renewal_busy` at once.
        other = self.connect(other_credential)
        self.beat(other, node=other_node)
        self.request(other, renewal_csr()[1])
        self.assertEqual(self.answered(other, node=other_node),
                         {"status": "refused", "reason": "renewal_busy"})
        self.assertLess(time.monotonic() - started, 5)
        release.set()
        self.assertEqual(self.answered(tls),
                         {"status": "refused", "reason": "renewal_signer_unavailable"})
        self.assertEqual(server.status().renewal_refusals,
                         (("renewal_busy", 1), ("renewal_signer_unavailable", 1)))
        self.assertEqual((server.status().renewals_refused, server.status().renewals_unavailable),
                         (0, 2))

    def slow_signer(self):
        release = threading.Event()
        calls = []

        def slow(path, timeout):
            calls.append(path)
            release.wait(10)
            raise OSError("synthetic unavailable signer")
        self.addCleanup(release.set)
        return slow, calls, release

    def test_the_default_bound_lets_two_nodes_renew_at_once_and_holds_a_third(self):
        slow, calls, release = self.slow_signer()
        nodes = [(self.node, self.certificate)] + [
            self.activated_node(name)[:2] for name in ("b", "c")]
        server = self.serve(renewal=self.renewal(connect=slow))
        sessions = []
        for node, credential in nodes:
            tls = self.connect(credential)
            self.beat(tls, node=node)
            sessions.append(tls)
        for (node, _), tls in zip(nodes[:2], sessions[:2]):
            self.request(tls, renewal_csr()[1])
        self.assertTrue(self.wait_for(lambda: len(calls) == 2))
        self.request(sessions[2], renewal_csr()[1])
        self.assertEqual(self.answered(sessions[2], node=nodes[2][0]),
                         {"status": "refused", "reason": "renewal_busy"})
        self.assertEqual(len(calls), 2)
        release.set()
        for (node, _), tls in zip(nodes[:2], sessions[:2]):
            self.assertEqual(self.answered(tls, node=node)["reason"],
                             "renewal_signer_unavailable")
        self.assertEqual(server.status().renewal_refusals,
                         (("renewal_busy", 1), ("renewal_signer_unavailable", 2)))

    def test_a_superseded_session_s_renewal_keeps_the_node_busy_and_its_reply_is_dropped(self):
        slow, calls, release = self.slow_signer()
        server = self.serve(renewal=self.renewal(connect=slow))
        older = self.connect()
        self.beat(older)
        self.request(older, renewal_csr()[1])
        self.assertTrue(self.wait_for(lambda: calls))
        newer = self.connect()
        self.beat(newer)
        self.assertTrue(self.wait_for(lambda: "superseded" in server.last_close_reasons()))
        # One renewal per node, also across its sessions.
        self.request(newer, renewal_csr()[1])
        self.assertEqual(self.answered(newer), {"status": "refused", "reason": "renewal_busy"})
        release.set()
        # The older session's reply has nowhere to go: it never reaches the
        # newer session, whose acks carry nothing more.
        self.assertTrue(self.wait_for(lambda: server.status().renewals_unavailable == 2))
        for sequence in (20, 21):
            self.assertEqual(len(self.beat(newer, sequence=sequence)), 1)

    def test_a_node_is_held_to_its_renewal_interval_and_hourly_cap_without_the_signer(self):
        clock = [10 ** 12]
        server = self.serve(renewal_interval_seconds=600, renewals_per_hour=2,
                            monotonic_ns=lambda: clock[0],
                            # The frozen clock also drives the frame budget.
                            limits={"frames_per_second": 1000})
        tls = self.connect()
        self.beat(tls)
        key, csr = renewal_csr()
        self.request(tls, csr)
        self.assertEqual(self.answered(tls)["status"], "issued")
        signed = list(self.signer_socket.outcomes)
        # Within 10 min the same request is answered without the signer.
        clock[0] += 599 * 10 ** 9
        self.request(tls, csr)
        self.assertEqual(self.answered(tls),
                         {"status": "refused", "reason": "renewal_rate_limited"})
        # After the interval it is admitted (the same key: from the ledger).
        clock[0] += 2 * 10 ** 9
        self.request(tls, csr)
        self.assertEqual(self.answered(tls)["status"], "issued")
        # The hourly cap (2 here) holds the third start in the same hour.
        clock[0] += 601 * 10 ** 9
        self.request(tls, csr)
        self.assertEqual(self.answered(tls)["reason"], "renewal_rate_limited")
        clock[0] += 3600 * 10 ** 9
        self.request(tls, csr)
        self.assertEqual(self.answered(tls)["status"], "issued")
        self.assertEqual(self.signer_socket.outcomes, signed)
        status = server.status()
        self.assertEqual((status.renewals_issued, status.renewals_refused,
                          status.renewals_unavailable), (3, 2, 0))
        self.assertIn(("renewal_rate_limited", 2), status.renewal_refusals)

    def test_logs_hold_no_certificate_or_request(self):
        self.serve()
        with self.assertLogs("serversentinel.capture_ingest", level="INFO") as logs:
            tls = self.connect()
            self.beat(tls)
            self.request(tls, renewal_csr()[1])
            self.answered(tls)
        text = "\n".join(logs.output)
        self.assertIn("capture_ingest_renewal_issued", text)
        self.assertNotIn("BEGIN", text)
        self.assertNotIn(str(self.node), text)


if __name__ == "__main__":
    unittest.main()
