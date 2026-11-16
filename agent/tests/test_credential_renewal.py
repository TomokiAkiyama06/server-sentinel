"""Issue #109: the Agent's credential renewal over its ingest session (mock/loopback only).

``CredentialRenewal`` runs against the real ``node_tls`` renewal steps and a
real credential store with an injected clock. ``IngestSession`` carries the
request on the heartbeat's connection to a scripted Main peer over real
loopback TLS 1.3 mTLS (``test_ingest_session.ScriptedMain``); the real Main
listener and signer are exercised in
``server/tests/test_capture_ingest_session.py`` and
``server/tests/test_capture_ingest_renewal.py``. All keys and certificates
are synthetic and generated per test.
"""
import datetime
import hashlib
import json
import select
import ssl
import time
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509

from media_capture_agent import ingest_session
from media_capture_agent.credential_renewal import CredentialRenewal
from media_capture_agent.ingest_session import FrameType, IngestSessionError, encode_frame
from media_capture_agent.node_tls import installed_certificate_expiry, installed_credential
from media_capture_agent.pairing import EnrollmentLock, NodeCredentialStore
from media_capture_agent.config import MainIngestEndpoint
from media_capture_agent.ingest_session import IngestSession
from tests.test_ingest_session import HEADER, ScriptedMain, acknowledge_all, heartbeat
from tests.test_node_tls import NodeTlsHarness
from tests.tls_support import DAY, pem


class Clock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


def read_raw(tls):
    """One frame as (kind, body bytes), or None at the end of the stream."""
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
    return kind, body


def ack_frame(sequence):
    return encode_frame(FrameType.HEARTBEAT_ACK, {"sequence": sequence, "receive_utc": time.time(),
                                                  "send_utc": time.time()})


class FakeRenewal:
    """Records the session's calls; ``due`` hands out the queued CSRs."""

    def __init__(self, *csrs, install=True):
        self.csrs = list(csrs)
        self.install = install
        self.calls = []
        self.status = None

    def due(self):
        self.calls.append("due")
        return self.csrs.pop(0) if self.csrs else None

    def issued(self, certificate):
        self.calls.append(("issued", certificate))
        return self.install

    def failed(self, reason):
        self.calls.append(("failed", reason))
        self.status = reason


CSR = b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"


class RenewalHarness(NodeTlsHarness):
    """An installed credential that is due (30 days left) and a scripted Main; no tests."""

    def setUp(self):
        super().setUp()
        _, _, self.node, material = self._enrolled()
        self.store = NodeCredentialStore(self.runtime)
        self.store.install(material)
        self.server_certificate, self.server_key = self.authority.server_files(
            self.root / "main")

    def main(self, *handlers):
        peer = ScriptedMain(self.server_certificate, self.server_key,
                            self.bundle.ca_certificate_pem, handlers or (acknowledge_all,))
        self.addCleanup(peer.stop)
        return peer

    def session(self, peer, **options):
        session = IngestSession(self.store, MainIngestEndpoint("127.0.0.1", peer.port),
                                self.node, **options)
        self.addCleanup(session.close)
        return session

    def wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    def assertFails(self, session, reason, sequence=1):
        with self.assertRaises(IngestSessionError) as raised:
            session.send_heartbeat(heartbeat(sequence))
        self.assertEqual(raised.exception.reason, reason)


class CredentialRenewalTests(RenewalHarness):
    """The schedule and install over the real ``node_tls`` steps."""

    def renewal(self, clock):
        return CredentialRenewal(self.store, clock=clock)

    def test_not_due_until_30_days_before_expiry_then_one_reused_key(self):
        expiry = installed_certificate_expiry(self.store)
        clock = Clock(expiry - 40 * DAY)
        renewal = self.renewal(clock)
        self.assertIsNone(renewal.due())
        self.assertFalse((self.runtime / "pending-renewal").exists())
        clock.value = expiry - 10 * DAY
        first = renewal.due()
        self.assertEqual(0, len(x509.load_pem_x509_csr(first).subject))
        self.assertEqual(renewal.status, "renewal_requested")
        # A failure waits for the back-off (1 h, then 2 h); the retry uses
        # the same pending key, so the Main can answer it from its ledger.
        renewal.failed("renewal_signer_unavailable")
        self.assertEqual(renewal.status, "renewal_signer_unavailable")
        clock.value += datetime.timedelta(minutes=59)
        self.assertIsNone(renewal.due())
        clock.value += datetime.timedelta(minutes=2)
        again = renewal.due()
        self.assertEqual(x509.load_pem_x509_csr(again).public_key(),
                         x509.load_pem_x509_csr(first).public_key())
        renewal.failed("renewal_reply_lost")
        clock.value += datetime.timedelta(minutes=90)
        self.assertIsNone(renewal.due())
        clock.value += datetime.timedelta(minutes=31)
        self.assertIsNotNone(renewal.due())

    def test_an_issued_certificate_is_installed_as_a_new_generation(self):
        expiry = installed_certificate_expiry(self.store)
        renewal = self.renewal(Clock(expiry - 10 * DAY))
        before = installed_credential(self.store)
        csr = renewal.due()
        # A certificate that is not for the pending key is not installed.
        self.assertFalse(renewal.issued(pem(self.authority.node_certificate(
            self._other_csr(), self.node, lifetime=397 * DAY))))
        self.assertEqual(renewal.status, "renewal_install_failed")
        self.assertEqual(installed_credential(self.store).certificate_path,
                         before.certificate_path)
        issued = pem(self.authority.node_certificate(csr, self.node, lifetime=397 * DAY))
        self.assertTrue(renewal.issued(issued))
        self.assertEqual(renewal.status, "renewal_installed")
        after = installed_credential(self.store)
        self.assertEqual(after.node_id, before.node_id)
        self.assertNotEqual(after.key_path, before.key_path)
        self.assertEqual(after.certificate_path.read_bytes(), issued)
        # The new expiry is read again: no further renewal is due.
        self.assertIsNone(renewal.due())

    def _other_csr(self):
        from media_capture_agent.node_tls import build_enrollment_request, generate_node_key
        return build_enrollment_request(generate_node_key()).csr_pem

    def test_a_held_pairing_lock_an_expired_credential_and_a_missing_dependency(self):
        expiry = installed_certificate_expiry(self.store)
        renewal = self.renewal(Clock(expiry - 10 * DAY))
        with EnrollmentLock(self.runtime):
            self.assertIsNone(renewal.due())
        self.assertEqual(renewal.status, "renewal_pairing_in_progress")
        expired = self.renewal(Clock(expiry + DAY))
        self.assertIsNone(expired.due())
        self.assertEqual(expired.status, "renewal_credential_expired")

        def missing():
            raise ImportError("synthetic missing cryptography")

        unavailable = CredentialRenewal(self.store, tls=missing)
        self.assertIsNone(unavailable.due())
        self.assertFalse(unavailable.issued(b"unused"))
        self.assertEqual(unavailable.status, "renewal_dependency_unavailable")
        unreadable = CredentialRenewal(NodeCredentialStore(self.root / "missing"))
        self.assertIsNone(unreadable.due())
        self.assertEqual(unreadable.status, "renewal_credential_unavailable")


class SessionRenewalTests(RenewalHarness):
    """The request and reply on the heartbeat's connection."""

    def renewing(self, answer, *, after=1, frames=None, presented=None):
        """A Main that answers the request ``after`` heartbeats later, before their ack."""

        def handler(tls, received):
            if presented is not None:
                presented.append(tls.getpeercert(binary_form=True))
            pending = None
            countdown = None
            while (frame := read_raw(tls)) is not None:
                kind, body = frame
                if frames is not None:
                    frames.append(kind)
                if kind == FrameType.LIVE_FRAME:
                    continue
                value = json.loads(body)
                received.append((kind, value))
                if kind == FrameType.RENEWAL_REQUEST:
                    pending = answer(value["csr"].encode("ascii"))
                    countdown = after
                    continue
                prefix = b""
                if pending is not None:
                    countdown -= 1
                    if countdown <= 0:
                        prefix = encode_frame(FrameType.RENEWAL_REPLY, pending)
                        pending = None
                tls.sendall(prefix + ack_frame(value["sequence"]))
        return handler

    def kinds(self, peer):
        return [kind for kind, _ in peer.received]

    def test_the_request_rides_the_heartbeat_connection_and_the_new_credential_reconnects(self):
        expiry = installed_certificate_expiry(self.store)
        presented = []
        issued = []

        def sign(csr):
            issued.append(pem(self.authority.node_certificate(csr, self.node, lifetime=397 * DAY)))
            return {"status": "issued", "certificate": issued[-1].decode("ascii")}

        peer = self.main(self.renewing(sign, presented=presented),
                         lambda tls, received: (presented.append(tls.getpeercert(True)),
                                                acknowledge_all(tls, received)))
        renewal = CredentialRenewal(self.store, clock=Clock(expiry - 10 * DAY))
        session = self.session(peer, renewal=renewal)
        session.send_heartbeat(heartbeat(1))
        self.assertTrue(self.wait_for(lambda: self.kinds(peer) == [FrameType.HEARTBEAT,
                                                                   FrameType.RENEWAL_REQUEST]))
        self.assertEqual(peer.connections, 1)
        session.send_heartbeat(heartbeat(2))
        self.assertEqual(session.renewal_status, "renewal_installed")
        # Installed as the next generation and presented on a new connection
        # at once; the clock exchange of the acknowledged heartbeat is kept.
        self.assertIsNotNone(session.exchange_clock())
        session.send_heartbeat(heartbeat(3))
        self.assertEqual(peer.connections, 2)
        new_der = ssl.PEM_cert_to_DER_cert(issued[0].decode("ascii"))
        self.assertEqual([hashlib.sha256(value).hexdigest() for value in presented][1],
                         hashlib.sha256(new_der).hexdigest())
        self.assertNotEqual(presented[0], presented[1])
        self.assertEqual(installed_credential(self.store).certificate_path.read_bytes(), issued[0])
        self.assertEqual(self.kinds(peer).count(FrameType.RENEWAL_REQUEST), 1)

    def test_heartbeats_and_live_frames_go_on_while_a_request_is_outstanding(self):
        frames = []
        peer = self.main(self.renewing(lambda csr: {"status": "refused",
                                                    "reason": "renewal_signer_unavailable"},
                                       after=3, frames=frames))
        renewal = FakeRenewal(CSR)
        session = self.session(peer, renewal=renewal)
        jpeg = b"\xff\xd8" + b"synthetic" * 4 + b"\xff\xd9"
        session.send_heartbeat(heartbeat(1))
        for sequence in (2, 3):
            self.assertTrue(session.send_live_frame(uuid4(), jpeg))
            session.send_heartbeat(heartbeat(sequence))
            self.assertIsNotNone(session.exchange_clock())
            # No second request while one is outstanding.
            self.assertNotIn("due", renewal.calls[1:])
        session.send_heartbeat(heartbeat(4))
        self.assertEqual(renewal.calls, ["due", ("failed", "renewal_signer_unavailable"),
                                         "due"])
        self.assertTrue(self.wait_for(lambda: frames.count(FrameType.HEARTBEAT) == 4))
        self.assertEqual(frames.count(FrameType.LIVE_FRAME), 2)
        self.assertEqual(frames.count(FrameType.RENEWAL_REQUEST), 1)
        self.assertEqual(peer.connections, 1)

    def test_a_refusal_keeps_the_credential_and_the_connection_and_backs_off(self):
        expiry = installed_certificate_expiry(self.store)
        before = installed_credential(self.store)
        peer = self.main(self.renewing(lambda csr: {"status": "refused",
                                                    "reason": "renewal_signer_refused"}))
        session = self.session(peer, renewal=CredentialRenewal(
            self.store, clock=Clock(expiry - 10 * DAY)))
        for sequence in range(1, 5):
            session.send_heartbeat(heartbeat(sequence))
        self.assertEqual(session.renewal_status, "renewal_signer_refused")
        self.assertEqual(self.kinds(peer).count(FrameType.RENEWAL_REQUEST), 1)
        self.assertEqual(peer.connections, 1)
        self.assertEqual(installed_credential(self.store).certificate_path,
                         before.certificate_path)

    def test_a_lost_connection_or_an_older_main_fails_the_attempt(self):
        def close_after_request(word):
            def handler(tls, received):
                kind, body = read_raw(tls)
                tls.sendall(ack_frame(json.loads(body)["sequence"]))
                read_raw(tls)  # the request
                if word is not None:
                    tls.sendall(encode_frame(FrameType.CLOSE, {"reason": word}))
            return handler

        for word, failure in ((None, "renewal_reply_lost"),
                              ("frame_type_refused", "renewal_unsupported_by_main")):
            with self.subTest(word=word):
                peer = self.main(close_after_request(word), acknowledge_all)
                renewal = FakeRenewal(CSR)
                session = self.session(peer, renewal=renewal)
                session.send_heartbeat(heartbeat(1))
                # The Main's close (or CLOSE) arrives while the Agent is idle.
                self.assertTrue(self.wait_for(
                    lambda: select.select([session._connection], [], [], 0)[0]))
                try:
                    session.send_heartbeat(heartbeat(2))
                except IngestSessionError:
                    pass
                self.assertIn(("failed", failure), renewal.calls)

    def test_a_reply_that_never_comes_times_out(self):
        peer = self.main(self.renewing(lambda csr: None))
        renewal = FakeRenewal(CSR)
        session = self.session(peer, renewal=renewal)
        session.send_heartbeat(heartbeat(1))
        with patch.object(ingest_session, "RENEWAL_REPLY_TIMEOUT_SECONDS", 0):
            session._renewal_deadline = time.monotonic()
            session.send_heartbeat(heartbeat(2))
        self.assertIn(("failed", "renewal_reply_timeout"), renewal.calls)
        self.assertEqual(peer.connections, 1)

    def test_malformed_replies_drop_the_connection(self):
        replies = (
            HEADER.pack(ingest_session.MAXIMUM_RENEWAL_REPLY_BYTES + 1, FrameType.RENEWAL_REPLY),
            encode_frame(FrameType.RENEWAL_REPLY, {"status": "issued"}),
            encode_frame(FrameType.RENEWAL_REPLY, {"status": "issued", "certificate": "x"}),
            encode_frame(FrameType.RENEWAL_REPLY, {"status": "refused", "reason": "Free Text"}),
            encode_frame(FrameType.RENEWAL_REPLY, {"status": "refused", "reason": "x", "y": 1}),
            encode_frame(FrameType.RENEWAL_REQUEST, {"csr": "x"}),
            encode_frame(FrameType.RENEWAL_REPLY, {"status": "refused", "reason": "a"}) * 2,
        )
        for reply in replies:
            with self.subTest(reply=reply[:24]):
                def handler(tls, received, reply=reply):
                    kind, body = read_raw(tls)
                    tls.sendall(ack_frame(json.loads(body)["sequence"]))
                    read_raw(tls)
                    kind, body = read_raw(tls)
                    tls.sendall(reply + ack_frame(json.loads(body)["sequence"]))
                    read_raw(tls)

                renewal = FakeRenewal(CSR)
                session = self.session(self.main(handler), renewal=renewal)
                session.send_heartbeat(heartbeat(1))
                self.assertFails(session, "main_reply_invalid", sequence=2)
                self.assertNotIn("issued", [call[0] for call in renewal.calls[1:]
                                            if isinstance(call, tuple)])
        # Without a renewal configured any reply is unexpected.
        def unsolicited(tls, received):
            kind, body = read_raw(tls)
            tls.sendall(encode_frame(FrameType.RENEWAL_REPLY, {"status": "refused",
                                                               "reason": "renewal_busy"})
                        + ack_frame(json.loads(body)["sequence"]))
            read_raw(tls)

        self.assertFails(self.session(self.main(unsolicited)), "main_reply_invalid")

    def test_the_status_holds_only_fixed_words(self):
        peer = self.main(self.renewing(lambda csr: {"status": "refused",
                                                    "reason": "renewal_not_eligible"}))
        renewal = FakeRenewal(CSR)
        session = self.session(peer, renewal=renewal)
        session.send_heartbeat(heartbeat(1))
        session.send_heartbeat(heartbeat(2))
        self.assertEqual(session.renewal_status, "renewal_not_eligible")
        self.assertIsNone(self.session(peer).renewal_status)
        self.assertNotIn("BEGIN", self.log.getvalue())
        with self.assertRaises(ValueError):
            self.session(peer, renewal=object())

    def test_an_oversized_request_is_not_sent(self):
        peer = self.main()
        renewal = FakeRenewal(b"-----BEGIN CERTIFICATE REQUEST-----" + b"A" * (
            ingest_session.MAXIMUM_RENEWAL_REQUEST_BYTES))
        session = self.session(peer, renewal=renewal)
        session.send_heartbeat(heartbeat(1))
        session.send_heartbeat(heartbeat(2))
        self.assertIn(("failed", "renewal_request_too_large"), renewal.calls)
        self.assertEqual(self.kinds(peer), [FrameType.HEARTBEAT] * 2)
        self.assertEqual(peer.connections, 1)
