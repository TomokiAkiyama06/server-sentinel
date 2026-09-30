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
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
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


class CaptureMtlsTests(unittest.TestCase):
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
        key, key_path = self._node_key(name)
        digest = public_key_digest(key.public_key())
        approval, code = self.ledger.approve(Owner(), "owner", node_id=uuid4(),
                                             public_key_digest=digest)
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=digest, code=code.value)
        issuer = authority or self.authority
        if activate:
            issued = issuer.issue_and_activate(self.ledger, claim, self._csr(key), validity=validity)
        else:
            issued = issuer.issue_node_certificate(claim, self._csr(key), validity=validity)
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


if __name__ == "__main__":
    unittest.main()
