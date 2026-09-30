"""Agent node key, enrollment request, trust pinning and real TLS client tests."""
import io
import json
import logging
import re
import os
from pathlib import Path
import ssl
import stat
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from media_capture_agent.node_tls import (
    PendingNodeKeyStore, TrustBundle, build_capture_client_context, build_enrollment_request,
    connect_to_main, public_key_digest, validate_issued_credential,
)
from media_capture_agent.pairing import NodeCredentialStore, PairingRefused
from tests.tls_support import DAY, SERVER_NAME, MainPeer, SyntheticAuthority, key_pem, now, pem


class NodeTlsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agent-node-tls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "state"
        self.runtime.mkdir(mode=0o700)
        self.authority = SyntheticAuthority()
        self.bundle = TrustBundle.parse(self.authority.bundle())
        self.log = io.StringIO()
        handler = logging.StreamHandler(self.log)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)

    def _enrolled(self):
        store = PendingNodeKeyStore(self.runtime)
        key = store.create()
        request = build_enrollment_request(key)
        node = uuid4()
        certificate = pem(self.authority.node_certificate(request.csr_pem, node))
        material = validate_issued_credential(self.bundle, store.load(), certificate)
        return store, key, node, material

    def _client_files(self, material):
        directory = self.root / "client"
        directory.mkdir(mode=0o700)
        certificate = directory / "cert.pem"
        key = directory / "key.pem"
        for path, content in ((certificate, material.client_certificate), (key, material.private_key)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
        return certificate, key

    def _connect(self, context, peer):
        return connect_to_main(context, server_name=self.bundle.server_name, host="127.0.0.1",
                               port=peer.port, timeout_seconds=10)

    # -- key and request -----------------------------------------------------

    def test_pending_key_is_private_write_once_and_matches_request(self):
        store = PendingNodeKeyStore(self.runtime)
        key = store.create()
        directory = self.runtime / "pending-enrollment"
        self.assertEqual(0o700, stat.S_IMODE(os.lstat(directory).st_mode))
        self.assertEqual(0o600, stat.S_IMODE(os.lstat(directory / "node-key.pem").st_mode))
        with self.assertRaisesRegex(PairingRefused, "pending_node_key_exists"):
            store.create()
        self.assertEqual(public_key_digest(key.public_key()),
                         public_key_digest(store.load().public_key()))
        request = build_enrollment_request(key)
        csr = x509.load_pem_x509_csr(request.csr_pem)
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(0, len(csr.subject))
        self.assertEqual(public_key_digest(key.public_key()), request.public_key_digest)
        self.assertNotIn("PRIVATE", request.csr_pem.decode())
        self.assertNotIn(request.csr_pem.decode()[40:80], repr(request))
        store.discard()
        with self.assertRaisesRegex(PairingRefused, "pending_node_key_unavailable"):
            store.load()

    def test_pending_key_refuses_group_accessible_or_symlinked_state(self):
        os.chmod(self.runtime, 0o750)
        with self.assertRaises(PairingRefused):
            PendingNodeKeyStore(self.runtime).create()
        os.chmod(self.runtime, 0o700)
        (self.root / "linked").symlink_to(self.runtime)
        with self.assertRaises(PairingRefused):
            PendingNodeKeyStore(self.root / "linked").create()

    def test_existing_identity_is_never_replaced_by_a_new_pending_key(self):
        store, _, _, material = self._enrolled()
        NodeCredentialStore(self.runtime).install(material)
        store.discard()
        with self.assertRaisesRegex(PairingRefused, "node_identity_already_exists"):
            store.create()

    # -- trust bundle and issued credential ------------------------------------

    def test_trust_bundle_digest_and_shape_are_enforced(self):
        content = self.authority.bundle()
        self.assertEqual(self.bundle.sha256, TrustBundle.parse(
            content, expected_sha256=self.bundle.sha256.upper()).sha256)
        with self.assertRaisesRegex(PairingRefused, "trust_bundle_digest_mismatch"):
            TrustBundle.parse(content, expected_sha256="0" * 64)
        for tampered in (content.replace(b'"format_version":1', b'"format_version":2'),
                         content.replace(SERVER_NAME.encode(), b"0.0.0.0"),
                         content[:-10], b"{}"):
            with self.assertRaisesRegex(PairingRefused, "trust_bundle_rejected"):
                TrustBundle.parse(tampered)
        other = SyntheticAuthority()
        swapped = content.replace(str(self.authority.deployment).encode(),
                                  str(other.deployment).encode())
        with self.assertRaisesRegex(PairingRefused, "trust_bundle_rejected"):
            TrustBundle.parse(swapped)

    def test_issued_credential_must_match_key_ca_scope_and_deployment(self):
        store = PendingNodeKeyStore(self.runtime)
        key = store.create()
        request = build_enrollment_request(key)
        node = uuid4()
        good = pem(self.authority.node_certificate(request.csr_pem, node))
        material = validate_issued_credential(self.bundle, key, good)
        self.assertEqual(node, material.node_id)
        self.assertEqual(self.authority.deployment, material.deployment_id)
        other_key = ec.generate_private_key(ec.SECP256R1())
        foreign = SyntheticAuthority(self.authority.deployment)
        server_scoped = pem(self.authority.leaf(key.public_key(), usage=ExtendedKeyUsageOID.SERVER_AUTH,
                                                names=[x509.DNSName(SERVER_NAME)]))
        for certificate, private in ((good, other_key),
                                     (pem(foreign.node_certificate(request.csr_pem, node)), key),
                                     (server_scoped, key), (b"not a certificate", key)):
            with self.assertRaisesRegex(PairingRefused, "issued_credential_rejected"):
                validate_issued_credential(self.bundle, private, certificate)

    # -- real TLS ------------------------------------------------------------

    def test_mutual_tls13_to_pinned_main_succeeds(self):
        _, _, node, material = self._enrolled()
        certificate, key = self._client_files(material)
        server_certificate, server_key = self.authority.server_files(self.root / "main")
        peer = MainPeer(server_certificate, server_key, pem(self.authority.certificate))
        context = build_capture_client_context(self.bundle.ca_certificate_pem,
                                               certificate_path=certificate, key_path=key)
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(self.root / "keylog")}):
            with self._connect(context, peer) as connection:
                self.assertEqual("TLSv1.3", connection.version())
                connection.sendall(b"ping")
                self.assertEqual(b"pong", connection.recv(4))
        peer.join()
        self.assertEqual(b"ping", peer.received)
        uris = x509.load_der_x509_certificate(peer.peer_certificate).extensions \
            .get_extension_for_class(x509.SubjectAlternativeName).value \
            .get_values_for_type(x509.UniformResourceIdentifier)
        self.assertIn("urn:serversentinel:capture-node:" + str(node), uris)
        self.assertFalse((self.root / "keylog").exists())

    def test_client_rejects_wrong_ca_name_expiry_and_downgrade_before_sending(self):
        _, _, _, material = self._enrolled()
        certificate, key = self._client_files(material)
        context = build_capture_client_context(self.bundle.ca_certificate_pem,
                                               certificate_path=certificate, key_path=key)
        attacker = SyntheticAuthority(self.authority.deployment)
        cases = {
            "wrong_ca": (attacker.server_files(self.root / "attacker"), {},
                         "main_identity_rejected"),
            "wrong_name": (self.authority.server_files(
                self.root / "other-name", server_name="other-main.serversentinel.test"), {},
                "main_identity_rejected"),
            "expired": (self.authority.server_files(
                self.root / "expired", start=now() - 10 * DAY, lifetime=DAY), {},
                "main_identity_rejected"),
            "tls12": (self.authority.server_files(self.root / "tls12"), {"tls12_only": True},
                      "main_handshake_failed"),
        }
        for label, ((server_certificate, server_key), options, reason) in cases.items():
            with self.subTest(label):
                peer = MainPeer(server_certificate, server_key, pem(self.authority.certificate),
                                **options)
                with self.assertRaisesRegex(PairingRefused, "^" + reason + "$"):
                    self._connect(context, peer)
                peer.join()
                self.assertEqual(b"", peer.received)

    def test_node_certificate_cannot_serve_as_main_identity(self):
        _, _, _, material = self._enrolled()
        certificate, key = self._client_files(material)
        peer = MainPeer(certificate, key, pem(self.authority.certificate))
        context = build_capture_client_context(self.bundle.ca_certificate_pem)
        with self.assertRaisesRegex(PairingRefused, "^main_identity_rejected$"):
            connect_to_main(context, server_name=SERVER_NAME, host="127.0.0.1", port=peer.port)
        peer.join()

    def test_client_context_is_pinned_and_rejects_partial_credentials(self):
        context = build_capture_client_context(self.bundle.ca_certificate_pem)
        self.assertEqual(ssl.TLSVersion.TLSv1_3, context.minimum_version)
        self.assertTrue(context.check_hostname)
        self.assertEqual(1, len(context.get_ca_certs()))
        self.assertIsNone(context.keylog_filename)
        with self.assertRaisesRegex(PairingRefused, "client_credential_incomplete"):
            build_capture_client_context(self.bundle.ca_certificate_pem,
                                         certificate_path=self.root / "x")

    def test_no_private_key_material_in_logs_errors_or_reprs(self):
        store, key, _, material = self._enrolled()
        secret = key_pem(key).decode()
        body = "".join(secret.splitlines()[1:-1])[:48]
        failures = []
        for call in (lambda: validate_issued_credential(self.bundle, key, b"x"),
                     lambda: store.create(),
                     lambda: TrustBundle.parse(b"{" + secret.encode() + b"}")):
            try:
                call()
            except PairingRefused as error:
                failures.append(str(error) + repr(error))
        joined = "".join(failures) + repr(material) + repr(self.bundle) + self.log.getvalue()
        self.assertNotIn(body, joined)
        self.assertNotIn("PRIVATE KEY", joined)
        self.assertFalse(any(body in value for value in os.environ.values()))


class AgentLockAuditTests(unittest.TestCase):
    def test_every_agent_lock_hash_has_wheel_audit_provenance(self):
        root = Path(__file__).resolve().parents[1]
        lock = (root / "requirements.lock").read_text().replace("\\\n", " ")
        permitted = set()
        for line in lock.splitlines():
            pin = re.match(r"([a-z0-9-]+)==(\S+)\s", line)
            if pin:
                permitted.update((pin.group(1), pin.group(2), digest)
                                 for digest in re.findall(r"--hash=sha256:([0-9a-f]{64})", line))
        rows = json.loads((root / "docs/cryptography-wheel-audit.json").read_text())
        self.assertEqual(permitted, {(row["name"], row["version"], row["sha256"]) for row in rows})
        for row in rows:
            self.assertTrue(row["license_files"])
            self.assertEqual(set(row["license_files"]), set(row["license_sha256"]))


if __name__ == "__main__":
    unittest.main()
