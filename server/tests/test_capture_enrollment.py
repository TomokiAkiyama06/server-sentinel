"""Real loopback TLS tests for the bootstrap enrollment listener and Main CLI (#13).

All CAs, keys and codes are generated per test in temporary directories. The
listener runs in a thread of this process; clients are real TLS 1.3 sockets.
"""
from contextlib import closing
import datetime
import errno
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.audit.service import OwnerAuthorizationError
from app.audit.store import AuditStore
from app.cameras.remote_agent import pairing_cli
from app.cameras.remote_agent.enrollment import (
    ENROLLMENT_ALPN, MAX_REQUEST_BYTES, EnrollmentConfigurationError, EnrollmentLimits,
    EnrollmentListener, EnrollmentListenerConfig, EnrollmentService,
    build_enrollment_server_context,
)
from app.cameras.remote_agent.node_ca import (
    DeploymentAuthority, PrivateDirectory, deployment_id_of, listener_material,
    main_server_name, public_key_digest,
)
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingError, PairingLedger
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


SERVER_NAME = "capture-main.serversentinel.test"
DAY = datetime.timedelta(days=1)
FRAME = struct.Struct(">I")


class Owner:
    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


def node_request(key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM), public_key_digest(key.public_key())


class EnrollmentHarness(unittest.TestCase):
    """Temporary CA, ledger and a running enrollment listener; defines no tests."""

    limits = EnrollmentLimits(connection_deadline_seconds=1.0)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="capture-enroll-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(os.path.realpath(self.temporary.name))
        os.chmod(self.root, 0o700)
        self.database = Database(self.root / "state.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.clock = Clock()
        self.ledger = PairingLedger(self.database, HmacCodeVerifier(os.urandom(32)),
                                    audit=AuditStore(self.database), clock=self.clock)
        self.deployment = uuid4()
        self.authority = DeploymentAuthority.create(PrivateDirectory(self.root / "ca"),
                                                    self.deployment, validity=3650 * DAY)
        self.listener_directory = PrivateDirectory(self.root / "listener")
        self.authority.issue_main_server_credential(self.listener_directory,
                                                    server_name=SERVER_NAME, validity=30 * DAY)
        material = listener_material(self.listener_directory)
        self.context = build_enrollment_server_context(material.certificate_path, material.key_path)
        self.log = io.StringIO()
        handler = logging.StreamHandler(self.log)
        logger = logging.getLogger("serversentinel.capture_enrollment")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        self.addCleanup(logger.removeHandler, handler)

    def approve(self):
        key, csr, digest = node_request()
        approval, code = self.ledger.approve(Owner(), "owner", node_id=uuid4(),
                                             public_key_digest=digest)
        return key, csr, approval, code.value

    def serve(self, approvals, *, limits=None, expires_in=30.0):
        with socket.create_server(("127.0.0.1", 0)) as probe:
            free = probe.getsockname()[1]
        listener = EnrollmentListener(EnrollmentListenerConfig("127.0.0.1", free), self.context,
                                      limits=limits or self.limits)
        listener.open()
        self.port = listener.address[1]
        service = EnrollmentService(self.ledger, self.authority, tuple(approvals))
        self.stop = threading.Event()
        self.outcome = None

        def run():
            self.outcome = listener.serve(service, expires_at_monotonic=time.monotonic() + expires_in,
                                          stop=self.stop)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.addCleanup(self.finish)
        return service

    def finish(self):
        self.stop.set()
        self.thread.join(10)
        return self.outcome

    def client_context(self, *, alpn=True, ca=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=(ca or self.authority.ca_certificate_pem()).decode())
        if alpn:
            context.set_alpn_protocols([ENROLLMENT_ALPN])
        return context

    def connect(self, **kwargs):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        return self.client_context(**kwargs).wrap_socket(raw, server_hostname=SERVER_NAME)

    def exchange(self, body: bytes, *, header=None):
        with self.connect() as tls:
            tls.sendall((header if header is not None else FRAME.pack(len(body))) + body)
            return self.read_frame(tls)

    @staticmethod
    def read_frame(tls):
        data = b""
        try:
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (ssl.SSLError, OSError):
            pass
        if len(data) < 4:
            return None
        (length,) = FRAME.unpack(data[:4])
        return json.loads(data[4:4 + length])

    def request(self, code, csr, deployment=None, **changes):
        value = {"version": 1, "deployment_id": str(deployment or self.deployment),
                 "code": code, "csr": csr.decode()}
        value.update(changes)
        return json.dumps(value).encode()


class EnrollmentProtocolTests(EnrollmentHarness):
    def test_issues_once_then_admits_only_the_approved_key(self):
        key, csr, approval, code = self.approve()
        _other_key, other_csr, other_approval, other_code = self.approve()
        self.serve([approval, other_approval])
        response = self.exchange(self.request(code, csr))
        self.assertEqual("issued", response["status"])
        certificate = x509.load_pem_x509_certificate(response["certificate"].encode())
        certificate.verify_directly_issued_by(self.authority.certificate)
        self.assertEqual(public_key_digest(key.public_key()),
                         public_key_digest(certificate.public_key()))
        uris = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
        self.assertIn("urn:serversentinel:capture-node:" + str(approval.node_id), uris)
        self.assertTrue(self.ledger.admits(
            node_id=approval.node_id, public_key_digest=public_key_digest(key.public_key()),
            credential_serial_digest=hashlib.sha256(
                certificate.public_bytes(serialization.Encoding.DER)).hexdigest()))
        # A replay of the same code, even with the same CSR, is refused.
        self.assertEqual({"status": "refused"}, self.exchange(self.request(code, csr)))
        # The other approval still works, so the listener stayed open for it.
        self.assertEqual("issued", self.exchange(self.request(other_code, other_csr))["status"])
        self.assertEqual("completed", self.finish().reason)

    def test_wrong_code_does_not_burn_the_approval_and_refusals_are_generic(self):
        _key, csr, approval, code = self.approve()
        self.serve([approval], limits=EnrollmentLimits(
            max_attempts_per_source_per_minute=30, max_refused_requests=32,
            connection_deadline_seconds=2.0))
        wrong = "A" * 26 if code != "A" * 26 else "B" * 26
        _, stolen_csr, _ = node_request()
        cases = [
            self.request(wrong, csr),
            self.request(code, stolen_csr),                 # stolen code, other key
            self.request(code, csr, deployment=uuid4()),    # other deployment
            self.request(code.lower(), csr),
            self.request(code, csr, version=True),
            self.request(code, csr, extra="x"),
            self.request(code, b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n"),
            b"not json",
            b"[]",
        ]
        for body in cases:
            self.assertEqual({"status": "refused"}, self.exchange(body), body[:40])
        self.assertEqual("issued", self.exchange(self.request(code, csr))["status"])
        self.assertNotIn(code, self.log.getvalue())
        self.assertNotIn("127.0.0.1", self.log.getvalue())

    def test_expired_code_is_refused(self):
        _key, csr, approval, code = self.approve()
        self.serve([approval])
        self.clock.value += 5 * 60
        self.assertEqual({"status": "refused"}, self.exchange(self.request(code, csr)))
        self.clock.value -= 5 * 60
        self.assertEqual({"status": "refused"}, self.exchange(self.request(code, csr)),
                         "expiry is permanent")

    def test_concurrent_redemptions_issue_one_credential(self):
        _key, csr, approval, code = self.approve()
        _other, _other_csr, spare, _spare_code = self.approve()
        self.serve([approval, spare], limits=EnrollmentLimits(
            max_concurrent_connections=8, max_attempts_per_source_per_minute=20,
            connection_deadline_seconds=5.0))
        results = []
        barrier = threading.Barrier(6)

        def attempt():
            barrier.wait()
            results.append(self.exchange(self.request(code, csr))["status"])
        threads = [threading.Thread(target=attempt) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(20)
        self.assertEqual(1, results.count("issued"), results)
        with closing(self.database.connect()) as connection:
            active = connection.execute(
                "SELECT COUNT(*) FROM pairing_node_credentials WHERE state = 'active'").fetchone()[0]
        self.assertEqual(1, active)

    def test_oversized_and_empty_frames_are_refused_without_reading_the_body(self):
        _key, csr, approval, code = self.approve()
        self.serve([approval])
        for header in (FRAME.pack(MAX_REQUEST_BYTES + 1), FRAME.pack(0xFFFFFFFF), FRAME.pack(0)):
            self.assertEqual({"status": "refused"}, self.exchange(b"", header=header))
        self.assertIn("reason=request_size_refused", self.log.getvalue())

    def test_slow_or_silent_peers_are_closed_at_the_deadline(self):
        _key, csr, approval, code = self.approve()
        self.serve([approval])
        started = time.monotonic()
        with self.connect() as tls:
            tls.sendall(FRAME.pack(100) + b"{")  # then stall
            self.assertIsNone(self.read_frame(tls))
        self.assertLess(time.monotonic() - started, 4)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            self.assertEqual(b"", raw.recv(10))  # no ClientHello: closed at deadline
        self.assertIn("reason=connection_deadline", self.log.getvalue())
        self.assertEqual("issued", self.exchange(self.request(code, csr))["status"])

    def test_plaintext_and_other_protocols_get_no_response(self):
        _key, csr, approval, code = self.approve()
        self.serve([approval])
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            raw.sendall(b"GET / HTTP/1.1\r\nHost: capture\r\n\r\n")
            try:
                reply = raw.recv(64)
            except ConnectionResetError:
                reply = b""
        self.assertFalse(reply.startswith(b"HTTP/"))
        with self.connect(alpn=False) as tls:
            tls.sendall(FRAME.pack(len(b"{}")) + b"{}")
            self.assertIsNone(self.read_frame(tls))
        self.assertIn("reason=protocol_refused", self.log.getvalue())

    def test_connection_and_source_rate_limits(self):
        _key, csr, approval, code = self.approve()
        self.serve([approval], limits=EnrollmentLimits(
            max_concurrent_connections=1, max_attempts_per_source_per_minute=2,
            connection_deadline_seconds=2.0))
        holder = self.connect()
        self.addCleanup(holder.close)
        time.sleep(0.3)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            self.assertEqual(b"", raw.recv(10))
        holder.close()
        time.sleep(0.5)
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            self.assertEqual(b"", raw.recv(10))  # third attempt this minute from this source
        self.assertIn("reason=connection_limit", self.log.getvalue())
        self.assertIn("reason=source_rate_limited", self.log.getvalue())

    def test_refusal_cap_and_expiry_close_the_listener(self):
        _key, csr, approval, code = self.approve()
        self.serve([approval], limits=EnrollmentLimits(max_refused_requests=2,
                                                       connection_deadline_seconds=1.0))
        for _ in range(2):
            self.assertEqual({"status": "refused"}, self.exchange(self.request("A" * 26, csr)))
        self.thread.join(5)
        self.assertEqual("attempt_limit", self.outcome.reason)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=2).close()

    def test_listener_closes_when_the_approval_window_ends(self):
        _key, _csr, approval, _code = self.approve()
        self.serve([approval], expires_in=0.3)
        self.thread.join(5)
        self.assertEqual("expired", self.outcome.reason)
        self.assertEqual((), self.outcome.issued_nodes)


class EnrollmentConfigurationTests(unittest.TestCase):
    def test_bind_must_be_an_explicit_private_ip_distinct_from_other_listeners(self):
        for host, reason in (("0.0.0.0", "wildcard"), ("::", "wildcard"),
                             ("8.8.8.8", "private"), ("capture-main.local", "ip_literal"),
                             ("224.0.0.1", "wildcard")):
            with self.assertRaisesRegex(EnrollmentConfigurationError, reason):
                EnrollmentListenerConfig(host, 7443)
        with self.assertRaisesRegex(EnrollmentConfigurationError, "differ"):
            EnrollmentListenerConfig("127.0.0.1", 8000, reserved=(("127.0.0.1", 8000),))
        with self.assertRaisesRegex(EnrollmentConfigurationError, "differ"):
            EnrollmentListenerConfig("10.0.0.5", 7443, reserved=(("0.0.0.0", 7443),))
        EnrollmentListenerConfig("10.0.0.5", 7443, reserved=(("127.0.0.1", 8000),))
        # Linux treats an IPv4-mapped IPv6 address and its IPv4 form as the same
        # socket, so the reservation compares them as equal in either direction.
        for bind, other in (("::ffff:127.0.0.1", "127.0.0.1"), ("127.0.0.1", "::ffff:127.0.0.1"),
                            ("::ffff:10.0.0.5", "10.0.0.5"), ("10.0.0.5", "::ffff:0.0.0.0")):
            with self.subTest(bind=bind, other=other):
                with self.assertRaisesRegex(EnrollmentConfigurationError, "differ"):
                    EnrollmentListenerConfig(bind, 8000, reserved=((other, 8000),))
        EnrollmentListenerConfig("192.168.1.2", 7443)
        EnrollmentListenerConfig("fd00::2", 7443)

    def test_limits_are_bounded(self):
        for changes in ({"max_concurrent_connections": 0}, {"connection_deadline_seconds": 0},
                        {"connection_deadline_seconds": 61}, {"max_refused_requests": True},
                        {"max_attempts_per_source_per_minute": 1000}):
            with self.assertRaises(EnrollmentConfigurationError):
                EnrollmentLimits(**changes)


class PairingCliTests(EnrollmentHarness):
    def request_file(self, **changes):
        _key, csr, digest = node_request()
        value = {"format_version": 1, "csr": csr.decode(), "public_key_digest": digest}
        value.update(changes)
        path = self.root / f"request-{uuid4()}.json"
        path.write_text(json.dumps(value))
        return path, digest

    def test_approve_refuses_without_a_controlling_terminal_before_any_state(self):
        path, _digest = self.request_file()
        database = self.root / "fresh.sqlite3"
        stderr = io.StringIO()
        with patch.object(pairing_cli.os, "open", side_effect=OSError), \
                patch("sys.stderr", stderr):
            status = pairing_cli.main([
                "approve", "--database", str(database), "--authority-dir", str(self.root / "ca"),
                "--listener-dir", str(self.root / "listener"), "--request", str(path),
                "--listen", "127.0.0.1:7443"])
        self.assertEqual(2, status)
        self.assertIn("controlling_terminal_required", stderr.getvalue())
        self.assertFalse(database.exists())

    def test_request_file_must_prove_the_key_it_names(self):
        path, digest = self.request_file()
        csr, parsed = pairing_cli.parse_enrollment_request(path.read_bytes())
        self.assertEqual(digest, parsed)
        mismatched, _ = self.request_file(public_key_digest="0" * 64)
        for content in (mismatched.read_bytes(), b"{}", b"\xff", b"[]",
                        self.request_file(format_version=True)[0].read_bytes()):
            with self.assertRaises(pairing_cli.CliRefused):
                pairing_cli.parse_enrollment_request(content)

    def test_console_owner_grant_is_single_use(self):
        owner = pairing_cli.LocalConsoleOwner()

        class Terminal:
            def __init__(self, answer):
                self.answer = answer
                self.written = ""

            def write(self, text):
                self.written += text

            def read_line(self):
                return self.answer
        grant = owner.confirm(Terminal("APPROVE"), "prompt", "APPROVE")
        owner.require_owner(grant)
        with self.assertRaises(OwnerAuthorizationError):
            owner.require_owner(grant)
        with self.assertRaises(OwnerAuthorizationError):
            owner.require_owner(object())
        with self.assertRaises(pairing_cli.CliRefused):
            owner.confirm(Terminal("approve please"), "prompt", "APPROVE")

    def test_code_is_grouped_for_display_only(self):
        self.assertEqual("ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ", pairing_cli._group("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))

    def test_deployment_and_server_name_are_derived_from_issuer_material(self):
        self.assertEqual(self.deployment, deployment_id_of(PrivateDirectory(self.root / "ca")))
        self.assertEqual(SERVER_NAME, main_server_name(self.listener_directory))

    def init(self, authority, listener, *extra):
        stderr, stdout = io.StringIO(), io.StringIO()
        with patch("sys.stderr", stderr), patch("sys.stdout", stdout):
            status = pairing_cli.main(["init", "--authority-dir", str(authority),
                                       "--listener-dir", str(listener), *extra])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_init_validates_every_input_before_persisting_the_ca(self):
        occupied = self.root / f"init-occupied-{uuid4()}"
        occupied.mkdir(mode=0o700)
        (occupied / "main-server-key.pem").write_bytes(b"x")
        os.chmod(occupied / "main-server-key.pem", 0o600)
        shared = self.root / f"init-shared-{uuid4()}"
        shared.mkdir(mode=0o755)
        same = object()
        bad_inputs = (
            (None, "--server-name", "Not_A-DNS-Name"),
            (None, "--server-name", "10.0.0.1"),
            (None, "--server-name", SERVER_NAME, "--server-validity-days", "0"),
            (None, "--server-name", SERVER_NAME, "--server-validity-days", "398"),
            (None, "--server-name", SERVER_NAME, "--server-validity-days", str(10 ** 12)),
            (None, "--server-name", SERVER_NAME, "--ca-validity-days", str(10 ** 12)),
            (None, "--server-name", SERVER_NAME, "--ca-validity-days", "30"),
            (occupied, "--server-name", SERVER_NAME),
            (shared, "--server-name", SERVER_NAME),
            (same, "--server-name", SERVER_NAME),
        )
        for target, *extra in bad_inputs:
            authority = self.root / f"init-ca-{uuid4()}"
            listener = self.root / f"init-listener-{uuid4()}"
            target = listener if target is None else authority if target is same else target
            with self.subTest(extra=extra, target=target.name):
                status, stdout, stderr = self.init(authority, target, *extra)
                self.assertEqual(2, status, stderr)
                self.assertEqual("", stdout)
                self.assertIn("refused", stderr)
                self.assertFalse((authority / "ca-key.pem").exists())
                self.assertFalse((authority / "ca-certificate.pem").exists())
                self.assertFalse((listener / "main-server-key.pem").exists())
                # A corrected rerun on the same directories completes.
                status, stdout, stderr = self.init(authority, listener, "--server-name", SERVER_NAME)
                self.assertEqual(0, status, stderr)
                deployment = deployment_id_of(PrivateDirectory(authority))
                self.assertEqual(f"deployment_id={deployment}\n", stdout)
                self.assertEqual(SERVER_NAME, main_server_name(PrivateDirectory(listener)))
        self.assertEqual(b"x", (occupied / "main-server-key.pem").read_bytes())

    def test_init_rolls_back_the_new_ca_when_listener_issuance_fails(self):
        authority = self.root / f"init-ca-{uuid4()}"
        listener = self.root / f"init-listener-{uuid4()}"
        real_write = PrivateDirectory.write_new

        def failing_write(directory, name, value):
            if name == "main-server-certificate.pem":
                raise pairing_cli.CaptureAuthorityError("issuer material could not be written")
            return real_write(directory, name, value)
        with patch.object(PrivateDirectory, "write_new", failing_write):
            status, _stdout, stderr = self.init(authority, listener, "--server-name", SERVER_NAME)
        self.assertEqual(2, status)
        self.assertIn("issuer_material_rejected", stderr)
        self.assertEqual([], sorted(os.listdir(authority)))
        self.assertEqual([], sorted(os.listdir(listener)))
        status, _stdout, stderr = self.init(authority, listener, "--server-name", SERVER_NAME)
        self.assertEqual(0, status, stderr)
        self.assertEqual(SERVER_NAME, main_server_name(PrivateDirectory(listener)))

    def test_init_rolls_back_the_ca_key_when_the_ca_certificate_write_fails(self):
        authority = self.root / f"init-ca-{uuid4()}"
        listener = self.root / f"init-listener-{uuid4()}"
        real_write = PrivateDirectory.write_new

        def failing_write(directory, name, value):
            if name == "ca-certificate.pem":
                raise pairing_cli.CaptureAuthorityError("issuer material could not be written")
            return real_write(directory, name, value)
        with patch.object(PrivateDirectory, "write_new", failing_write):
            status, _stdout, stderr = self.init(authority, listener, "--server-name", SERVER_NAME)
        self.assertEqual(2, status)
        self.assertIn("issuer_material_rejected", stderr)
        self.assertEqual([], sorted(os.listdir(authority)))
        self.assertEqual([], sorted(os.listdir(listener)))
        status, _stdout, stderr = self.init(authority, listener, "--server-name", SERVER_NAME)
        self.assertEqual(0, status, stderr)

    @staticmethod
    def _failing_directory_fsync():
        real_fsync = os.fsync

        def fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "synthetic directory fsync failure")
            return real_fsync(descriptor)
        return patch("app.cameras.remote_agent.node_ca.os.fsync", fsync)

    def test_directory_fsync_failure_removes_the_new_issuer_file(self):
        directory = PrivateDirectory(self.root / f"dir-fsync-{uuid4()}")
        directory.ensure()
        with self._failing_directory_fsync():
            with self.assertRaises(pairing_cli.CaptureAuthorityError):
                directory.write_new("ca-certificate.pem", b"x")
        self.assertFalse(directory.exists("ca-certificate.pem"))
        directory.write_new("ca-certificate.pem", b"x")

    def test_init_rolls_back_the_ca_when_the_certificate_directory_fsync_fails(self):
        authority = self.root / f"init-ca-{uuid4()}"
        listener = self.root / f"init-listener-{uuid4()}"
        real_write = PrivateDirectory.write_new
        failing_directory_fsync = self._failing_directory_fsync

        def failing_write(directory, name, value):
            if name == "ca-certificate.pem":
                with failing_directory_fsync():
                    return real_write(directory, name, value)
            return real_write(directory, name, value)
        with patch.object(PrivateDirectory, "write_new", failing_write):
            status, _stdout, stderr = self.init(authority, listener, "--server-name", SERVER_NAME)
        self.assertEqual(2, status)
        self.assertIn("issuer_material_rejected", stderr)
        self.assertEqual([], sorted(os.listdir(authority)))
        self.assertEqual([], sorted(os.listdir(listener)))
        status, _stdout, stderr = self.init(authority, listener, "--server-name", SERVER_NAME)
        self.assertEqual(0, status, stderr)

    def test_issuer_file_open_failure_is_a_bounded_refusal(self):
        directory = PrivateDirectory(self.root / f"open-fail-{uuid4()}")
        directory.ensure()
        real_open = os.open

        def refusing_open(path, flags, *args, **kwargs):
            if path == "ca-key.pem":
                raise PermissionError(13, "synthetic")
            return real_open(path, flags, *args, **kwargs)
        with patch("app.cameras.remote_agent.node_ca.os.open", refusing_open):
            with self.assertRaises(pairing_cli.CaptureAuthorityError):
                directory.write_new("ca-key.pem", b"x")
        self.assertFalse(directory.exists("ca-key.pem"))

    def fake_terminal(self, answer="APPROVE"):
        written = []

        class Terminal:
            def __init__(self, *args, **kwargs):
                pass

            def write(self, text):
                written.append(text)

            def read_line(self):
                return answer

            def close(self):
                pass
        return Terminal, written

    def test_approve_reserves_the_configured_ipv6_loopback_human_listener(self):
        path, _digest = self.request_file()
        database = self.root / f"fresh-{uuid4()}.sqlite3"
        terminal, _written = self.fake_terminal()
        base = ["approve", "--database", str(database), "--authority-dir", str(self.root / "ca"),
                "--listener-dir", str(self.root / "listener"), "--request", str(path)]
        cases = (
            (["--listen", "[::1]:8000", "--human-host", "::1", "--human-port", "8000"],
             "enrollment_listener_must_differ_from_other_listeners"),
            (["--listen", "[::ffff:127.0.0.1]:8000", "--human-host", "127.0.0.1",
              "--human-port", "8000"],
             "enrollment_listener_must_differ_from_other_listeners"),
            (["--listen", "127.0.0.1:8000", "--human-host", "::ffff:127.0.0.1",
              "--human-port", "8000"],
             "enrollment_listener_must_differ_from_other_listeners"),
            (["--listen", "[::1]:8000", "--human-host", "10.0.0.5", "--human-port", "8000"],
             "human_listener_must_be_loopback"),
            (["--listen", "[::1]:8000", "--human-host", "localhost", "--human-port", "8000"],
             "human_listener_must_be_loopback"),
        )
        for extra, reason in cases:
            with self.subTest(extra=extra):
                stderr = io.StringIO()
                with patch.object(pairing_cli, "ControllingTerminal", terminal), \
                        patch("sys.stderr", stderr):
                    status = pairing_cli.main(base + extra)
                self.assertEqual(2, status)
                self.assertIn(reason, stderr.getvalue())
                self.assertFalse(database.exists())

    def test_ledger_reports_the_live_node_bound_to_a_key(self):
        _key, _csr, digest = node_request()
        self.assertIsNone(self.ledger.bound_node(digest))
        node = uuid4()
        self.ledger.approve(Owner(), "owner", node_id=node, public_key_digest=digest)
        self.assertEqual(node, self.ledger.bound_node(digest))
        # A retried approval for the same node and key is accepted.
        self.ledger.approve(Owner(), "owner", node_id=node, public_key_digest=digest)
        self.ledger.revoke(Owner(), "owner", node_id=node)
        self.assertIsNone(self.ledger.bound_node(digest))
        with self.assertRaises(PairingError):
            self.ledger.bound_node("not-a-digest")

    def test_revoked_node_repairs_only_as_a_new_node_with_a_new_key(self):
        # Owner policy 2026-10-01 (#116): a revoked node never reuses its key or
        # node; it re-pairs as a new node, and the old node's ledger history is
        # kept (not deleted) so its recordings stay attributed to it.
        _key, _csr, old_digest = node_request()
        old_node = uuid4()
        self.ledger.approve(Owner(), "owner", node_id=old_node, public_key_digest=old_digest)
        self.assertFalse(self.ledger.key_revoked(old_digest))
        self.ledger.revoke(Owner(), "owner", node_id=old_node)
        self.assertTrue(self.ledger.key_revoked(old_digest))
        for node in (old_node, uuid4()):
            with self.assertRaises(PairingError):
                self.ledger.approve(Owner(), "owner", node_id=node, public_key_digest=old_digest)
        _key, _csr, new_digest = node_request()
        self.assertFalse(self.ledger.key_revoked(new_digest))
        self.assertIsNone(self.ledger.bound_node(new_digest))
        new_node = uuid4()
        self.ledger.approve(Owner(), "owner", node_id=new_node, public_key_digest=new_digest)
        # The new key is unique to the new node: it cannot be re-bound to the old one.
        with self.assertRaises(PairingError):
            self.ledger.approve(Owner(), "owner", node_id=old_node, public_key_digest=new_digest)
        states = {row.node_id: row.enrollment_state for row in self.ledger.pairing_summaries()}
        self.assertEqual({old_node: "revoked", new_node: "pending"}, states)
        with self.assertRaises(PairingError):
            self.ledger.key_revoked("not-a-digest")

    def test_approve_refuses_a_revoked_key_before_prompting_or_listening(self):
        path, digest = self.request_file()
        node = uuid4()
        self.ledger.approve(Owner(), "owner", node_id=node, public_key_digest=digest)
        self.ledger.revoke(Owner(), "owner", node_id=node)
        terminal, written = self.fake_terminal()
        stderr = io.StringIO()
        with patch.object(pairing_cli, "ControllingTerminal", terminal), \
                patch.object(pairing_cli.EnrollmentListener, "open") as opened, \
                patch("sys.stderr", stderr):
            status = pairing_cli.main([
                "approve", "--database", str(self.database.path),
                "--authority-dir", str(self.root / "ca"),
                "--listener-dir", str(self.root / "listener"), "--request", str(path),
                "--listen", "127.0.0.1:18443"])
        self.assertEqual(2, status)
        self.assertIn("public_key_revoked", stderr.getvalue())
        self.assertEqual([], written, "no Owner prompt for a revoked key")
        opened.assert_not_called()

    def test_list_shows_states_without_digests(self):
        _key, _csr, approval, _code = self.approve()
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            self.assertEqual(0, pairing_cli.main(["list", "--database", str(self.database.path)]))
        self.assertIn(f"node_id={approval.node_id} enrollment=pending credential=-", stdout.getvalue())
        self.assertNotIn(approval.public_key_digest, stdout.getvalue())
        with closing(sqlite3.connect(self.database.path)) as connection:
            self.assertEqual(1, connection.execute(
                "SELECT COUNT(*) FROM pairing_enrollments").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
