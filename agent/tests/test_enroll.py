"""Agent pairing CLI / enrollment client tests against real loopback TLS peers.

The Main is a synthetic stand-in (``tests.tls_support``) so these tests do not
import server code; the real cross-process exchange is
``tests/e2e/test_capture_enrollment_scenarios.py``.
"""
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from media_capture_agent import enroll
from media_capture_agent.node_tls import TrustBundle
from media_capture_agent.pairing import (
    NodeCredentialStore, PairingCode, PairingRefused, prompt_pairing_code,
)
from tests.tls_support import SERVER_NAME, SyntheticAuthority, key_pem, pem, write_private


FRAME = struct.Struct(">I")
CODE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class EnrollmentPeer:
    """Synthetic Main enrollment listener that records every application byte."""

    def __init__(self, authority, directory: Path, *, alpn=True, names=None,
                 respond=None):
        key = ec.generate_private_key(ec.SECP256R1())
        names = names if names is not None else [
            x509.DNSName(SERVER_NAME),
            x509.UniformResourceIdentifier("urn:serversentinel:deployment:" + str(authority.deployment)),
        ]
        certificate = authority.leaf(key.public_key(), usage=ExtendedKeyUsageOID.SERVER_AUTH,
                                     names=names)
        directory.mkdir(mode=0o700)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if alpn:
            context.set_alpn_protocols([enroll.ENROLLMENT_ALPN])
        context.load_cert_chain(str(write_private(directory / "cert.pem", pem(certificate))),
                                str(write_private(directory / "key.pem", key_pem(key))))
        self.context = context
        self.authority = authority
        self.respond = respond
        self.node = uuid4()
        self.connections = 0
        self.received = bytearray()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            self.connections += 1
            raw.settimeout(5)
            try:
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    header = tls.recv(4)
                    if len(header) < 4:
                        continue
                    self.received += header
                    (length,) = FRAME.unpack(header)
                    body = b""
                    while len(body) < length:
                        chunk = tls.recv(length - len(body))
                        if not chunk:
                            break
                        body += chunk
                    self.received += body
                    reply = self.reply(json.loads(body))
                    tls.sendall(reply)
            except (ssl.SSLError, OSError, ValueError):
                pass
            finally:
                raw.close()

    def reply(self, request):
        if self.respond is not None:
            return self.respond(request)
        certificate = self.authority.node_certificate(request["csr"].encode(), self.node)
        body = json.dumps({"status": "issued", "certificate": pem(certificate).decode()}).encode()
        return FRAME.pack(len(body)) + body

    def close(self):
        self._stop.set()
        self.listener.close()
        self._thread.join(5)


class EnrollClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agent-enroll-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "state"
        self.runtime.mkdir(mode=0o700)
        self.authority = SyntheticAuthority()
        self.request_path = self.root / "request.json"
        self.digest = enroll.create_enrollment_request(self.runtime, self.request_path)
        self.prompts = []

    def peer(self, **kwargs):
        peer = EnrollmentPeer(kwargs.pop("authority", self.authority),
                              self.root / f"peer-{uuid4()}", **kwargs)
        self.addCleanup(peer.close)
        return peer

    def bundle(self, port):
        return TrustBundle.parse(self.authority.bundle(port=port))

    def prompt_after(self, peer):
        def prompt():
            # The Main has been contacted (and verified) before the code exists.
            self.prompts.append(peer.connections)
            return PairingCode(CODE)
        return prompt

    def test_request_file_is_public_and_key_stays_private(self):
        value = json.loads(self.request_path.read_text())
        self.assertEqual({"format_version", "csr", "public_key_digest"}, set(value))
        self.assertEqual(self.digest, value["public_key_digest"])
        self.assertNotIn("PRIVATE KEY", self.request_path.read_text())
        key_file = self.runtime / "pending-enrollment" / "node-key.pem"
        self.assertEqual(0o600, stat.S_IMODE(os.lstat(key_file).st_mode))
        self.assertEqual(0o700, stat.S_IMODE(os.lstat(key_file.parent).st_mode))
        with self.assertRaisesRegex(PairingRefused, "pending_node_key_exists"):
            enroll.create_enrollment_request(self.runtime, self.root / "second.json")

    def test_pairs_after_verifying_main_and_installs_private_credential(self):
        peer = self.peer()
        node = enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))
        self.assertEqual(peer.node, node)
        self.assertEqual([1], self.prompts, "prompt only after one verified connection")
        self.assertEqual(2, peer.connections, "reconnects with full verification")
        self.assertTrue(NodeCredentialStore(self.runtime).installed())
        self.assertFalse((self.runtime / "pending-enrollment" / "node-key.pem").exists())
        request = json.loads(bytes(peer.received)[4:])
        self.assertEqual({"version", "deployment_id", "code", "csr"}, set(request))
        with self.assertRaisesRegex(PairingRefused, "node_identity_already_exists"):
            enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))

    def test_untrusted_peers_receive_nothing_and_no_prompt_happens(self):
        other = SyntheticAuthority(self.authority.deployment)
        peers = (
            self.peer(authority=other),                       # attacker CA, same name
            self.peer(alpn=False),                            # not the enrollment protocol
            self.peer(names=[x509.DNSName(SERVER_NAME)]),     # no deployment identity
            self.peer(names=[x509.DNSName(SERVER_NAME), x509.UniformResourceIdentifier(
                "urn:serversentinel:deployment:" + str(uuid4()))]),
            self.peer(names=[x509.DNSName("other.serversentinel.test")]),
        )
        for peer in peers:
            with self.assertRaisesRegex(PairingRefused, "main_identity_rejected"):
                enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))
            self.assertEqual(b"", bytes(peer.received))
        self.assertEqual([], self.prompts)
        self.assertFalse(NodeCredentialStore(self.runtime).installed())

    def test_refused_or_malformed_responses_install_nothing(self):
        responses = (
            b'\x00\x00\x00\x14{"status":"refused"}',
            FRAME.pack(10 ** 6),
            b"\x00\x00",
            FRAME.pack(4) + b"null",
        )
        for response in responses:
            peer = self.peer(respond=lambda _request, value=response: value)
            with self.assertRaisesRegex(PairingRefused, "enrollment_refused"):
                enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))
        # A certificate for another key is rejected by credential validation.
        stranger = ec.generate_private_key(ec.SECP256R1())

        def foreign(_request):
            certificate = self.authority.leaf(
                stranger.public_key(), usage=ExtendedKeyUsageOID.CLIENT_AUTH,
                names=[x509.UniformResourceIdentifier("urn:serversentinel:capture-node:" + str(uuid4())),
                       x509.UniformResourceIdentifier(
                           "urn:serversentinel:deployment:" + str(self.authority.deployment))])
            body = json.dumps({"status": "issued", "certificate": pem(certificate).decode()}).encode()
            return FRAME.pack(len(body)) + body
        peer = self.peer(respond=foreign)
        with self.assertRaisesRegex(PairingRefused, "issued_credential_rejected"):
            enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))
        self.assertFalse(NodeCredentialStore(self.runtime).installed())
        self.assertTrue((self.runtime / "pending-enrollment" / "node-key.pem").exists())

    def test_cli_refuses_root_and_unverified_bundles_without_network(self):
        peer = self.peer()
        bundle = self.root / "bundle.json"
        bundle.write_bytes(self.authority.bundle(port=peer.port))
        arguments = ["pair", "--runtime-root", str(self.runtime), "--trust-bundle", str(bundle)]
        stderr = io.StringIO()
        with patch("sys.stderr", stderr), patch.object(enroll.os, "geteuid", return_value=0):
            self.assertEqual(1, enroll.main(arguments + ["--bundle-sha256", "0" * 64]))
        self.assertIn("root_refused", stderr.getvalue())
        stderr = io.StringIO()
        with patch("sys.stderr", stderr), patch.object(enroll.os, "geteuid", return_value=1000):
            self.assertEqual(1, enroll.main(arguments + ["--bundle-sha256", "0" * 64]))
        self.assertIn("trust_bundle_digest_mismatch", stderr.getvalue())
        self.assertEqual(0, peer.connections)
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", io.StringIO()):
                enroll.main(arguments + ["--bundle-sha256", "0" * 64, "--code", CODE])


class PromptTerminalTests(unittest.TestCase):
    def test_real_pseudo_terminal_accepts_grouped_code(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        os.write(master, b"abcde-FGHIJ-KLMNO-PQRST-UVWXYZ\n")

        def reader(prompt, stream):
            stream.write(prompt)
            stream.flush()
            return stream.readline().rstrip("\n")
        code = prompt_pairing_code(opener=lambda *_args: slave, reader=reader)
        self.assertEqual(CODE, code.value)
        with self.assertRaises(OSError):
            os.fstat(slave)  # the prompt closed its terminal descriptor


if __name__ == "__main__":
    unittest.main()
