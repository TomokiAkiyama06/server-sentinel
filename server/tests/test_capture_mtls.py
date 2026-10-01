"""Real loopback TLS 1.3 tests for the ADR-0006 capture-node CA and ingest adapter.

Every key, CA and certificate is generated in a temporary directory; the node
peer runs as a separate process that receives only file paths.
"""
from contextlib import closing
import datetime
import io
import logging
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.audit.store import AuditStore
from app.cameras.remote_agent.ingest_tls import (
    CaptureIngestAcceptor, CaptureNodeAdmission, IngestConfigurationError,
    IngestListenerConfig, IngestTlsError, build_ingest_server_context, open_ingest_listener,
)
from app.cameras.remote_agent.node_ca import (
    CaptureAuthorityError, DeploymentAuthority, PrivateDirectory, listener_material,
    public_key_digest,
)
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingError, PairingLedger
from app.cameras.remote_agent.renewal import (
    CaptureCredentialMonitor, RenewalRefused, renew_node_credential,
)
from app.notifications.service import NotificationKind
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


SERVER_ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "capture-main.serversentinel.test"
DAY = datetime.timedelta(days=1)


class Owner:
    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def fixed_clock(value):
    return lambda: value


class CaptureTlsHarness(unittest.TestCase):
    """Shared temporary CA, ledger and listener material; defines no tests."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="capture-mtls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.database = Database(self.root / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.ledger = PairingLedger(self.database, HmacCodeVerifier(os.urandom(32)),
                                    audit=AuditStore(self.database))
        self.deployment = uuid4()
        # The CA predates the tests so an already-expired leaf can be issued.
        DeploymentAuthority.create(PrivateDirectory(self.root / "authority"), self.deployment,
                                   validity=3650 * DAY, clock=fixed_clock(utc_now() - 60 * DAY))
        self.authority = DeploymentAuthority.load(PrivateDirectory(self.root / "authority"),
                                                  self.deployment)
        listener_directory = PrivateDirectory(self.root / "listener")
        self.authority.issue_main_server_credential(listener_directory, server_name=SERVER_NAME,
                                                    validity=30 * DAY)
        self.listener_material = listener_material(listener_directory)
        self.ca_path = self._public_file("ca.pem", self.authority.ca_certificate_pem())
        self.context = build_ingest_server_context(self.authority.ca_certificate_pem(),
                                                   self.listener_material.certificate_path,
                                                   self.listener_material.key_path)
        self.admission = CaptureNodeAdmission(self.ledger, self.deployment)
        self.acceptor = CaptureIngestAcceptor(self.context, self.admission,
                                              handshake_timeout_seconds=10)
        self.log_stream = io.StringIO()
        handler = logging.StreamHandler(self.log_stream)
        handler.setLevel(logging.DEBUG)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.setLevel, previous)
        self.addCleanup(root.removeHandler, handler)
        self.secrets = []

    # -- helpers -------------------------------------------------------------

    def _public_file(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return path

    def _node_key(self, name):
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        self.secrets.append(pem)
        directory = self.root / ("node-" + name)
        directory.mkdir(mode=0o700)
        path = directory / "key.pem"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(pem)
        return key, path

    @staticmethod
    def _csr(key):
        return (x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "requested-admin")]))
                .sign(key, hashes.SHA256())
                .public_bytes(serialization.Encoding.PEM))

    def _paired_node(self, name="a", *, authority=None, activate=True, validity=30 * DAY):
        """Pair a node; ``validity=None`` uses the Owner-decided 397-day default."""
        key, key_path = self._node_key(name)
        digest = public_key_digest(key.public_key())
        approval, code = self.ledger.approve(Owner(), "owner", node_id=uuid4(),
                                             public_key_digest=digest)
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=digest, code=code.value)
        issuer = authority or self.authority
        options = {} if validity is None else {"validity": validity}
        if activate:
            issued = issuer.issue_and_activate(self.ledger, claim, self._csr(key), **options)
        else:
            issued = issuer.issue_node_certificate(claim, self._csr(key), **options)
        certificate_path = self._public_file(f"node-{name}.pem", issued.certificate_pem)
        return claim, issued, certificate_path, key_path

    def _exchange(self, certificate="-", key="-", *, server_name=SERVER_NAME, ca_path=None,
                  context=None, payload="tls"):
        acceptor = self.acceptor if context is None else CaptureIngestAcceptor(
            context, self.admission, handshake_timeout_seconds=10)
        arguments = [sys.executable, "-m", "tests.tls_peer", "0", str(ca_path or self.ca_path),
                     server_name, str(certificate), str(key), payload]
        environment = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1",
                       "SSLKEYLOGFILE": str(self.root / "keylog.txt")}
        with socket.create_server(("127.0.0.1", 0)) as listener:
            listener.settimeout(20)
            arguments[3] = str(listener.getsockname()[1])
            peer = subprocess.Popen(arguments, cwd=SERVER_ROOT, env=environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.addCleanup(lambda: peer.poll() is None and peer.kill())
            connection, _ = listener.accept()
            try:
                session = acceptor.accept(connection)
            except IngestTlsError as error:
                result = error.reason
            else:
                if session.connection.recv(4) == b"ping":
                    session.connection.sendall(b"pong")
                result = session
            output, errors = peer.communicate(timeout=20)
        for secret in self.secrets:
            body = b"".join(secret.splitlines()[1:-1])
            for value in (*arguments, *environment.values()):
                self.assertNotIn(body[:40].decode(), value)
            self.assertNotIn(body[:40], output + errors)
        self.assertFalse((self.root / "keylog.txt").exists(), "TLS key log must never be written")
        return result, output.decode().strip()

    def tearDown(self):
        logs = self.log_stream.getvalue()
        self.assertNotIn("PRIVATE KEY", logs)
        self.assertNotIn("CERTIFICATE", logs)
        for secret in self.secrets:
            self.assertNotIn(b"".join(secret.splitlines()[1:-1])[:40].decode(), logs)


class CaptureMtlsTests(CaptureTlsHarness):
    # -- positive path -------------------------------------------------------

    def test_mutual_tls13_handshake_admits_the_activated_node(self):
        claim, issued, certificate, key = self._paired_node()
        session, output = self._exchange(certificate, key)
        self.assertEqual("ok", output)
        self.assertNotIsInstance(session, str, session)
        self.addCleanup(session.close)
        self.assertEqual(claim.node_id, session.identity.node_id)
        self.assertEqual(issued.credential_digest, session.identity.credential_digest)
        self.assertEqual("TLSv1.3", session.connection.version())
        self.assertNotIn(str(claim.node_id), repr(session))
        self.assertTrue(session.still_admitted())

    def test_admitted_session_does_not_inherit_the_handshake_timeout(self):
        # A camera/data pause longer than the handshake bound must not surface
        # as a transport failure on an otherwise healthy session.
        _, _, certificate, key = self._paired_node()
        session, output = self._exchange(certificate, key)
        self.assertEqual("ok", output)
        self.assertNotIsInstance(session, str, session)
        self.addCleanup(session.close)
        self.assertIsNone(session.connection.gettimeout())

    # -- negative paths ------------------------------------------------------

    def test_missing_client_certificate_is_rejected(self):
        result, output = self._exchange()
        self.assertEqual("tls_handshake_failed", result)
        self.assertNotEqual("ok", output)

    def test_plaintext_client_gets_no_response(self):
        result, output = self._exchange(payload="plaintext")
        self.assertEqual("tls_handshake_failed", result)
        self.assertEqual("no-http-response", output)

    def test_client_certificate_from_another_ca_is_rejected(self):
        other = DeploymentAuthority.create(PrivateDirectory(self.root / "attacker"), self.deployment,
                                           validity=3650 * DAY)
        _, _, certificate, key = self._paired_node("foreign", authority=other)
        result, output = self._exchange(certificate, key)
        self.assertEqual("tls_handshake_failed", result)
        self.assertNotEqual("ok", output)

    def test_expired_client_certificate_is_rejected(self):
        past = utc_now() - 30 * DAY
        issuer = DeploymentAuthority.load(PrivateDirectory(self.root / "authority"),
                                          self.deployment, clock=fixed_clock(past + 10 * DAY))
        _, _, certificate, key = self._paired_node("expired", authority=issuer, validity=DAY)
        result, output = self._exchange(certificate, key)
        self.assertEqual("tls_handshake_failed", result)
        self.assertNotEqual("ok", output)

    def test_revoked_node_cannot_reconnect_and_open_session_is_dropped(self):
        claim, _, certificate, key = self._paired_node()
        session, output = self._exchange(certificate, key)
        self.assertEqual("ok", output)
        self.addCleanup(session.close)
        self.ledger.revoke(Owner(), "owner", node_id=claim.node_id)
        self.assertFalse(session.still_admitted())
        result, _ = self._exchange(certificate, key)
        self.assertEqual("capture_node_not_admitted", result)

    def test_open_session_is_dropped_once_its_certificate_expires(self):
        # OpenSSL checks validity only during the handshake; admission must
        # re-check expiry with the server clock on an already-open session.
        current = [utc_now()]
        self.admission = CaptureNodeAdmission(self.ledger, self.deployment,
                                              clock=lambda: current[0])
        self.acceptor = CaptureIngestAcceptor(self.context, self.admission,
                                              handshake_timeout_seconds=10)
        _, _, certificate, key = self._paired_node(validity=DAY)
        session, output = self._exchange(certificate, key)
        self.assertEqual("ok", output)
        self.addCleanup(session.close)
        self.assertTrue(session.still_admitted())
        current[0] = session.identity.not_valid_after
        self.assertFalse(session.still_admitted())
        self.assertEqual(-1, session.connection.fileno(), "expired session must be closed")
        broken = CaptureNodeAdmission(self.ledger, self.deployment,
                                      clock=lambda: datetime.datetime(2000, 1, 1))
        self.assertFalse(broken.is_admitted(session.identity), "a naive clock denies")

    def test_orphan_certificate_without_activation_is_not_admitted(self):
        _, _, certificate, key = self._paired_node(activate=False)
        result, _ = self._exchange(certificate, key)
        self.assertEqual("capture_node_not_admitted", result)

    def test_client_rejects_wrong_server_name(self):
        _, _, certificate, key = self._paired_node()
        result, output = self._exchange(certificate, key, server_name="other-main.serversentinel.test")
        self.assertEqual("server-rejected", output)
        self.assertEqual("tls_handshake_failed", result)

    def test_client_rejects_main_certificate_from_another_ca(self):
        _, _, certificate, key = self._paired_node()
        other = DeploymentAuthority.create(PrivateDirectory(self.root / "impostor"), uuid4(),
                                           validity=3650 * DAY)
        result, output = self._exchange(certificate, key,
                                        ca_path=self._public_file("impostor-ca.pem",
                                                                  other.ca_certificate_pem()))
        self.assertEqual("server-rejected", output)
        self.assertEqual("tls_handshake_failed", result)

    def test_main_server_certificate_cannot_act_as_node(self):
        result, _ = self._exchange(self.listener_material.certificate_path,
                                   self.listener_material.key_path)
        self.assertIn(result, {"tls_handshake_failed", "capture_node_certificate_invalid"})

    def test_certificate_for_another_deployment_is_not_admitted(self):
        _, issued, _, _ = self._paired_node()
        other = CaptureNodeAdmission(self.ledger, uuid4())
        der = x509.load_pem_x509_certificate(issued.certificate_pem).public_bytes(
            serialization.Encoding.DER)
        with self.assertRaises(IngestTlsError) as raised:
            other.authorize(der)
        self.assertEqual("capture_node_certificate_invalid", raised.exception.reason)

    # -- issuance boundaries -------------------------------------------------

    def test_csr_cannot_choose_identity_or_substitute_a_key(self):
        claim, issued, _, _ = self._paired_node()
        certificate = x509.load_pem_x509_certificate(issued.certificate_pem)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual({f"urn:serversentinel:capture-node:{claim.node_id}",
                          f"urn:serversentinel:deployment:{self.deployment}"},
                         set(names.get_values_for_type(x509.UniformResourceIdentifier)))
        self.assertNotIn("requested-admin", certificate.subject.rfc4514_string())
        stranger = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(CaptureAuthorityError):
            self.authority.issue_node_certificate(claim, self._csr(stranger), validity=DAY)
        weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(CaptureAuthorityError):
            self.authority.issue_node_certificate(claim, self._csr(weak), validity=DAY)
        with self.assertRaises(CaptureAuthorityError):
            self.authority.issue_node_certificate(claim, b"-----BEGIN CERTIFICATE REQUEST-----\n",
                                                  validity=DAY)
        with self.assertRaises(CaptureAuthorityError):
            self.authority.issue_node_certificate(claim, self._csr(stranger), validity=400 * DAY)

    def test_issuer_material_is_owner_only_and_never_replaced(self):
        for directory in ("authority", "listener"):
            path = self.root / directory
            self.assertEqual(0o700, stat.S_IMODE(os.lstat(path).st_mode))
            for entry in path.iterdir():
                self.assertEqual(0o600, stat.S_IMODE(os.lstat(entry).st_mode), entry.name)
        with self.assertRaises(CaptureAuthorityError):
            DeploymentAuthority.create(PrivateDirectory(self.root / "authority"), self.deployment,
                                       validity=DAY)
        with self.assertRaises(CaptureAuthorityError):
            self.authority.issue_main_server_credential(PrivateDirectory(self.root / "authority"),
                                                        server_name=SERVER_NAME, validity=DAY)
        os.chmod(self.root / "authority", 0o750)
        with self.assertRaises(CaptureAuthorityError):
            DeploymentAuthority.load(PrivateDirectory(self.root / "authority"), self.deployment)
        os.chmod(self.root / "authority", 0o700)
        os.chmod(self.root / "authority" / "ca-key.pem", 0o640)
        with self.assertRaises(CaptureAuthorityError):
            DeploymentAuthority.load(PrivateDirectory(self.root / "authority"), self.deployment)
        os.chmod(self.root / "authority" / "ca-key.pem", 0o600)
        (self.root / "linked").symlink_to(self.root / "authority")
        with self.assertRaises(CaptureAuthorityError):
            DeploymentAuthority.load(PrivateDirectory(self.root / "linked"), self.deployment)
        (self.root / "parent-link").symlink_to(self.root)
        with self.assertRaises(CaptureAuthorityError):
            PrivateDirectory(self.root / "parent-link" / "authority")
        self.assertNotIn("PRIVATE", repr(self.authority))

    def test_trust_bundle_is_public_and_digest_is_exact(self):
        bundle = self.authority.export_trust_bundle(server_name=SERVER_NAME,
                                                    endpoint_host="192.0.2.10", endpoint_port=7443)
        self.assertNotIn(b"PRIVATE KEY", bundle.content)
        self.assertEqual(64, len(bundle.sha256))
        self.assertNotIn(bundle.content.decode()[:20], repr(bundle))
        for host in ("0.0.0.0", "bad host", "*.serversentinel.test"):
            with self.assertRaises(CaptureAuthorityError):
                self.authority.export_trust_bundle(server_name=SERVER_NAME,
                                                   endpoint_host=host, endpoint_port=7443)

    # -- listener separation -------------------------------------------------

    def test_listener_configuration_is_explicit_and_separate_from_human_listener(self):
        for kwargs in ({"bind_host": "0.0.0.0", "port": 7443},
                       {"bind_host": "::", "port": 7443},
                       {"bind_host": "capture.local", "port": 7443},
                       {"bind_host": "127.0.0.1", "port": 8000},
                       {"bind_host": "127.0.0.1", "port": 0}):
            with self.subTest(**kwargs), self.assertRaises(IngestConfigurationError):
                IngestListenerConfig(human_host="127.0.0.1", human_port=8000, **kwargs)
        with socket.create_server(("127.0.0.1", 0)) as probe:
            port = probe.getsockname()[1]
        config = IngestListenerConfig(bind_host="127.0.0.1", port=port,
                                      human_host="127.0.0.1", human_port=8000)
        with open_ingest_listener(config) as listener:
            self.assertEqual(("127.0.0.1", port), listener.getsockname())

    def test_acceptor_refuses_contexts_without_mutual_tls13(self):
        permissive = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with self.assertRaises(IngestConfigurationError):
            CaptureIngestAcceptor(permissive, self.admission)
        self.assertEqual(ssl.TLSVersion.TLSv1_3, self.context.minimum_version)
        self.assertEqual(ssl.CERT_REQUIRED, self.context.verify_mode)
        self.assertEqual(0, self.context.num_tickets)

    def test_application_does_not_start_or_import_the_ingest_listener(self):
        source = (SERVER_ROOT / "app" / "main.py").read_text()
        self.assertNotIn("ingest_tls", source)
        self.assertNotIn("node_ca", source)
        auth_sources = "".join(path.read_text() for path in (SERVER_ROOT / "app" / "auth").glob("*.py"))
        self.assertNotIn("remote_agent", auth_sources)

    def test_concurrent_admission_checks_follow_revocation(self):
        claim, issued, _, _ = self._paired_node()
        der = x509.load_pem_x509_certificate(issued.certificate_pem).public_bytes(
            serialization.Encoding.DER)
        identity = self.admission.authorize(der)
        self.ledger.revoke(Owner(), "owner", node_id=claim.node_id)
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.admission.is_admitted(identity)))
                   for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual([False] * 4, results)


class CaptureRenewalTests(CaptureTlsHarness):
    """Automatic renewal (Owner decision 2026-09-30) over a real admitted session."""

    def setUp(self):
        super().setUp()
        self.notifications = []
        self.monitor = CaptureCredentialMonitor(
            self.ledger, lambda kind, at: self.notifications.append((kind, at)))

    @staticmethod
    def _empty_csr(key, *names):
        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(name) for name in names]), critical=False)
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def _session(self, certificate, key):
        session, output = self._exchange(certificate, key)
        self.assertEqual("ok", output)
        self.assertNotIsInstance(session, str, session)
        self.addCleanup(session.close)
        return session

    def _renew(self, identity, key, **kwargs):
        return renew_node_credential(self.authority, self.ledger, self.admission, identity,
                                     self._empty_csr(key), monitor=self.monitor, **kwargs)

    def test_default_node_validity_is_397_days_and_recorded(self):
        _, issued, _, _ = self._paired_node(validity=None)
        remaining = issued.not_after - utc_now()
        self.assertGreater(remaining, 396 * DAY)
        self.assertLessEqual(remaining, 397 * DAY)
        (expiry,) = self.ledger.credential_expiries()
        self.assertAlmostEqual(issued.not_after.timestamp(), expiry.not_after, delta=1)

    def test_renewal_over_admitted_session_supersedes_old_certificate_on_first_use(self):
        claim, _, old_certificate, old_key = self._paired_node(validity=None)
        session = self._session(old_certificate, old_key)
        new_key, new_key_path = self._node_key("renewed")
        renewed = self._renew(session.identity, new_key)
        self.assertEqual(claim.node_id, renewed.node_id)
        self.assertEqual(0o600, stat.S_IMODE(os.lstat(new_key_path).st_mode))
        certificate = x509.load_pem_x509_certificate(renewed.certificate_pem)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn(f"urn:serversentinel:capture-node:{claim.node_id}",
                      names.get_values_for_type(x509.UniformResourceIdentifier))
        # Until the new certificate is used, the old one is still admitted.
        self.assertTrue(session.still_admitted())
        self._session(old_certificate, old_key)
        new_certificate = self._public_file("renewed.pem", renewed.certificate_pem)
        promoted = self._session(new_certificate, new_key_path)
        self.assertEqual(renewed.credential_digest, promoted.identity.credential_digest)
        # First use promoted the renewal; the old certificate is superseded.
        result, _ = self._exchange(old_certificate, old_key)
        self.assertEqual("capture_node_not_admitted", result)
        self.assertFalse(session.still_admitted())
        self.assertEqual([], self.notifications)

    def test_revoked_node_cannot_renew_or_promote_a_staged_renewal(self):
        claim, _, certificate, key = self._paired_node()
        session = self._session(certificate, key)
        new_key, new_key_path = self._node_key("staged")
        staged = self._renew(session.identity, new_key)
        self.ledger.revoke(Owner(), "owner", node_id=claim.node_id)
        with self.assertRaises(RenewalRefused) as raised:
            self._renew(session.identity, ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual("renewal_credential_not_admitted", raised.exception.reason)
        result, _ = self._exchange(self._public_file("staged.pem", staged.certificate_pem),
                                   new_key_path)
        self.assertEqual("capture_node_not_admitted", result)
        self.assertEqual([NotificationKind.CAPTURE_CREDENTIAL_WARNING],
                         [kind for kind, _ in self.notifications])

    def test_expired_certificate_cannot_renew(self):
        past = utc_now() - 30 * DAY
        issuer = DeploymentAuthority.load(PrivateDirectory(self.root / "authority"),
                                          self.deployment, clock=fixed_clock(past))
        _, issued, _, _ = self._paired_node("expired", authority=issuer, validity=DAY)
        der = x509.load_pem_x509_certificate(issued.certificate_pem).public_bytes(
            serialization.Encoding.DER)
        identity = self.admission.identify(der)
        with self.assertRaises(RenewalRefused) as raised:
            self._renew(identity, ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual("renewal_credential_expired", raised.exception.reason)
        self.assertEqual(1, len(self.notifications))

    def test_renewal_request_cannot_change_identity_or_reuse_keys(self):
        claim, _, certificate, key = self._paired_node("a")
        _, other_issued, _, _ = self._paired_node("b")
        session = self._session(certificate, key)
        current_key = serialization.load_pem_private_key(key.read_bytes(), password=None)
        other = ec.generate_private_key(ec.SECP256R1())
        cases = {
            "renewal_request_invalid": [
                self._empty_csr(other, f"urn:serversentinel:capture-node:{uuid4()}"),
                self._csr(other),
                b"-----BEGIN CERTIFICATE REQUEST-----\n",
                self._empty_csr(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            ],
            "renewal_not_eligible": [self._empty_csr(current_key)],
        }
        for reason, requests in cases.items():
            for request in requests:
                with self.subTest(reason), self.assertRaises(RenewalRefused) as raised:
                    renew_node_credential(self.authority, self.ledger, self.admission,
                                          session.identity, request)
                self.assertEqual(reason, raised.exception.reason)
        # A key already bound to another node cannot be staged for this one,
        # including a key bound only by another node's not-yet-activated
        # (consumed or pending) enrollment.
        _, consumed, _, _ = self._paired_node("c", activate=False)
        pending = public_key_digest(ec.generate_private_key(ec.SECP256R1()).public_key())
        self.ledger.approve(Owner(), "owner", node_id=uuid4(), public_key_digest=pending)
        for reused in (other_issued.public_key_digest, consumed.public_key_digest, pending):
            self.assertNotEqual(reused, session.identity.public_key_digest)
            with self.subTest(reused=reused[:8]), self.assertRaises(PairingError):
                self.ledger.stage_renewal(
                    node_id=claim.node_id,
                    current_public_key_digest=session.identity.public_key_digest,
                    current_credential_digest=session.identity.credential_digest,
                    public_key_digest=reused, credential_serial_digest="e" * 64,
                    not_after=utc_now().timestamp() + 1000)
        self.assertTrue(session.still_admitted())

    def test_node_key_is_never_bound_to_a_second_node_or_reused_after_revocation(self):
        # Owner decision 2026-09-30: a node public key is unique across all
        # nodes and all credential states; a revoked key is never reused.
        claim, _, certificate, key = self._paired_node("a")
        original = public_key_digest(serialization.load_pem_private_key(
            key.read_bytes(), password=None).public_key())
        session = self._session(certificate, key)
        new_key, new_key_path = self._node_key("renewed")
        renewed_key = public_key_digest(new_key.public_key())
        renewed = self._renew(session.identity, new_key)

        def approve_elsewhere(digest, node=None):
            with self.assertRaises(PairingError):
                self.ledger.approve(Owner(), "owner", node_id=node or uuid4(),
                                    public_key_digest=digest)

        approve_elsewhere(renewed_key)  # staged for A, not yet promoted
        self._session(self._public_file("renewed.pem", renewed.certificate_pem), new_key_path)
        approve_elsewhere(renewed_key)  # promoted: A's active key
        approve_elsewhere(original)  # superseded key of A

        # Activation re-checks inside its transaction: an enrollment whose key
        # became bound to A in the meantime (e.g. a pre-migration row) is refused.
        other = ec.generate_private_key(ec.SECP256R1())
        other_digest = public_key_digest(other.public_key())
        approval, code = self.ledger.approve(Owner(), "owner", node_id=uuid4(),
                                             public_key_digest=other_digest)
        pending = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                     public_key_digest=other_digest, code=code.value)
        with closing(self.database.connect()) as connection, connection:
            connection.execute("UPDATE pairing_key_bindings SET node_id = ? "
                               "WHERE public_key_digest = ?", (str(claim.node_id), other_digest))
        with self.assertRaises(PairingError):
            self.authority.issue_and_activate(self.ledger, pending, self._csr(other))
        self.assertFalse(self.ledger.admits(node_id=pending.node_id, public_key_digest=other_digest,
                                            credential_serial_digest="e" * 64))

        # After revocation none of A's keys can be bound again, even to A.
        self.ledger.revoke(Owner(), "owner", node_id=claim.node_id)
        for digest in (original, renewed_key):
            approve_elsewhere(digest)
            approve_elsewhere(digest, claim.node_id)

    def test_staged_renewal_key_stays_bound_after_replacement_or_revocation(self):
        # Main issued a certificate for every staged key, so replacing the
        # staged row with a retry, or revoking the node before promotion, must
        # never free that key for another node (Owner decision 2026-09-30).
        claim, _, certificate, key = self._paired_node("a")
        session = self._session(certificate, key)
        first, _ = self._node_key("first")
        first_digest = public_key_digest(first.public_key())
        self._renew(session.identity, first)
        second, _ = self._node_key("second")
        second_digest = public_key_digest(second.public_key())
        self._renew(session.identity, second)  # replaces the staged row
        with closing(self.database.connect()) as connection:
            staged = connection.execute("SELECT public_key_digest FROM pairing_node_renewals "
                                        "WHERE node_id = ?", (str(claim.node_id),)).fetchone()
        self.assertEqual(second_digest, staged[0])
        with self.assertRaises(PairingError):
            self.ledger.approve(Owner(), "owner", node_id=uuid4(), public_key_digest=first_digest)
        self.ledger.revoke(Owner(), "owner", node_id=claim.node_id)
        for digest in (first_digest, second_digest):
            for node in (uuid4(), claim.node_id):
                with self.subTest(digest=digest[:8]), self.assertRaises(PairingError):
                    self.ledger.approve(Owner(), "owner", node_id=node, public_key_digest=digest)

    def test_staged_retry_with_same_key_is_idempotent_and_bindings_are_capped(self):
        from app.cameras.remote_agent import pairing as pairing_module
        claim, _, certificate, key = self._paired_node("a")
        session = self._session(certificate, key)

        def stage(digest):
            self.ledger.stage_renewal(
                node_id=claim.node_id,
                current_public_key_digest=session.identity.public_key_digest,
                current_credential_digest=session.identity.credential_digest,
                public_key_digest=digest, credential_serial_digest="e" * 64,
                not_after=utc_now().timestamp() + 1000)

        def bindings():
            with closing(self.database.connect()) as connection:
                return connection.execute("SELECT COUNT(*) FROM pairing_key_bindings "
                                          "WHERE node_id = ?", (str(claim.node_id),)).fetchone()[0]

        stage("a" * 64)
        stage("a" * 64)
        held = bindings()
        self.assertEqual(2, held)  # paired key + staged key
        with mock.patch.object(pairing_module, "_MAX_KEY_BINDINGS_PER_NODE", held + 1):
            stage("b" * 64)
            with self.assertRaises(PairingError):
                stage("c" * 64)
            stage("b" * 64)  # already bound: a retry is still accepted
        self.assertEqual(held + 1, bindings())
        self.assertTrue(session.still_admitted())

    def test_near_expiry_without_renewal_raises_owner_signal_once(self):
        self._paired_node("soon", validity=10 * DAY)
        self._paired_node("later", validity=None)
        self.assertEqual(["credential_expiring_without_renewal"],
                         [signal.reason for signal in self.monitor.check()])
        self.monitor.check()
        self.assertEqual([NotificationKind.CAPTURE_CREDENTIAL_WARNING],
                         [kind for kind, _ in self.notifications])
        expired = CaptureCredentialMonitor(self.ledger, lambda kind, at: self.notifications.append(kind),
                                           clock=lambda: utc_now() + 20 * DAY)
        self.assertEqual(["credential_expired"], [signal.reason for signal in expired.check()])
        self.assertEqual(NotificationKind.CAPTURE_CREDENTIAL_WARNING, self.notifications[-1])


if __name__ == "__main__":
    unittest.main()
