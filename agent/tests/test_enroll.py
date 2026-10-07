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
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from media_capture_agent import enroll, node_tls
from media_capture_agent.node_tls import (
    PendingNodeKeyStore, TrustBundle, installed_certificate_expiry, installed_credential,
    prepare_renewal, public_key_digest,
)
from media_capture_agent.pairing import (
    EnrollmentLock, NodeCredentialStore, PairingCode, PairingRefused, prompt_pairing_code,
)
from tests.tls_support import DAY, SERVER_NAME, SyntheticAuthority, key_pem, pem, write_private


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


class EnrollFixture(unittest.TestCase):
    """Runtime root with a pending request and a synthetic Main; defines no tests."""

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


class EnrollClientTests(EnrollFixture):
    def test_request_file_is_public_and_key_stays_private(self):
        value = json.loads(self.request_path.read_text())
        self.assertEqual({"format_version", "csr", "public_key_digest"}, set(value))
        self.assertEqual(self.digest, value["public_key_digest"])
        self.assertNotIn("PRIVATE KEY", self.request_path.read_text())
        key_file = self.runtime / "pending-enrollment" / "node-key.pem"
        self.assertEqual(0o600, stat.S_IMODE(os.lstat(key_file).st_mode))
        self.assertEqual(0o700, stat.S_IMODE(os.lstat(key_file.parent).st_mode))
        # Re-running ``request`` re-exports the same pending key; it never makes a second key.
        second = self.root / "second.json"
        self.assertEqual(self.digest, enroll.create_enrollment_request(self.runtime, second))
        again = json.loads(second.read_text())
        self.assertEqual(set(value), set(again))
        self.assertEqual(self.digest, again["public_key_digest"])
        self.assertEqual(
            x509.load_pem_x509_csr(value["csr"].encode()).public_key(),
            x509.load_pem_x509_csr(again["csr"].encode()).public_key())

    def test_failed_request_file_leaves_a_retry_path_for_the_same_key(self):
        runtime = self.root / "state-retry"
        runtime.mkdir(mode=0o700)
        taken = self.root / "taken.json"
        taken.write_text("operator file")
        with self.assertRaisesRegex(PairingRefused, "output_file_unavailable"):
            enroll.create_enrollment_request(runtime, taken)
        self.assertEqual("operator file", taken.read_text(), "existing output is never replaced")
        key_file = runtime / "pending-enrollment" / "node-key.pem"
        key_before = key_file.read_bytes()
        retry = self.root / "retry.json"
        digest = enroll.create_enrollment_request(runtime, retry)
        self.assertEqual(key_before, key_file.read_bytes(), "the pending key is reused, not replaced")
        self.assertEqual(digest, json.loads(retry.read_text())["public_key_digest"])
        peer = self.peer()
        enroll.pair(runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))
        with self.assertRaisesRegex(PairingRefused, "node_identity_already_exists"):
            enroll.create_enrollment_request(runtime, self.root / "after-pairing.json")
        self.assertFalse((self.root / "after-pairing.json").exists())

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

    def test_cli_refuses_a_tailscale_endpoint_override_without_network(self):
        # Issue #150: ``--endpoint`` cannot redirect pairing onto Tailscale.
        peer = self.peer()
        content = self.authority.bundle(port=peer.port)
        bundle = self.root / "bundle.json"
        bundle.write_bytes(content)
        digest = TrustBundle.parse(content).sha256
        # Like the other CLI tests, this runs as the real (non-root) test
        # account that owns the runtime root; ``os.geteuid`` is not patched
        # because the runtime-root owner check reads the same function.
        for host in ("100.64.0.1", "fd7a:115c:a1e0::1"):
            with self.subTest(layer="pair", host=host):
                with self.assertRaisesRegex(PairingRefused,
                                            "^main_endpoint_tailscale_address_refused$"):
                    enroll.pair(self.runtime, TrustBundle.parse(content), host=host,
                                port=peer.port, prompt=self.prompt_after(peer))
        self.assertEqual([], self.prompts)
        for endpoint in ("100.64.0.1:7443", "[fd7a:115c:a1e0::1]:7443"):
            stderr = io.StringIO()
            with self.subTest(endpoint=endpoint), patch("sys.stderr", stderr):
                self.assertEqual(1, enroll.main([
                    "pair", "--runtime-root", str(self.runtime), "--trust-bundle", str(bundle),
                    "--bundle-sha256", digest, "--endpoint", endpoint]))
                self.assertIn("refused: main_endpoint_tailscale_address_refused",
                              stderr.getvalue())
        self.assertEqual(0, peer.connections)
        self.assertFalse(NodeCredentialStore(self.runtime).installed())


def issuing(authority, node, *, lifetime=400 * DAY):
    """A synthetic Main response issuing ``node`` a certificate for the request's key."""
    def respond(request):
        certificate = authority.node_certificate(request["csr"].encode(), node, lifetime=lifetime)
        body = json.dumps({"status": "issued", "certificate": pem(certificate).decode()}).encode()
        return FRAME.pack(len(body)) + body
    return respond


def installed_key_digest(runtime):
    credential = installed_credential(NodeCredentialStore(runtime))
    return public_key_digest(x509.load_pem_x509_certificate(
        credential.certificate_path.read_bytes()).public_key())


class EnrollmentLockTests(EnrollFixture):
    """#117: one runtime-wide interprocess lock serializes enrollment."""

    def test_concurrent_pair_runs_are_serialized_by_the_runtime_lock(self):
        peer = self.peer()
        bundle = self.bundle(peer.port)
        in_prompt, release = threading.Event(), threading.Event()
        results = {}

        def first_prompt():
            in_prompt.set()
            self.assertTrue(release.wait(10))
            return PairingCode(CODE)

        def first():
            try:
                results["first"] = enroll.pair(self.runtime, bundle, prompt=first_prompt)
            except BaseException as error:  # surfaced below
                results["first"] = error
        thread = threading.Thread(target=first)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.assertTrue(in_prompt.wait(10))
        connections = peer.connections
        # A second run while the first sits between its installed check and
        # its install is refused before any network traffic or prompt.
        with self.assertRaisesRegex(PairingRefused, "enrollment_in_progress"):
            enroll.pair(self.runtime, bundle, prompt=self.prompt_after(peer))
        with self.assertRaisesRegex(PairingRefused, "enrollment_in_progress"):
            enroll.create_enrollment_request(self.runtime, self.root / "racing.json")
        self.assertEqual(connections, peer.connections)
        self.assertEqual([], self.prompts)
        self.assertFalse((self.root / "racing.json").exists())
        release.set()
        thread.join(10)
        self.assertEqual(peer.node, results["first"])
        self.assertEqual(1, peer.received.count(b'"code"'), "exactly one code was submitted")
        self.assertTrue(NodeCredentialStore(self.runtime).installed())
        # The lock is released afterwards: the next run gets the normal refusal.
        with self.assertRaisesRegex(PairingRefused, "node_identity_already_exists"):
            enroll.pair(self.runtime, bundle, prompt=self.prompt_after(peer))

    def test_request_file_is_written_while_the_lock_is_held(self):
        attempts = []
        original = enroll._write_public_file

        def racing_write(path, content):
            # A concurrent run reaching this point must still be refused.
            try:
                with EnrollmentLock(self.runtime):
                    attempts.append("acquired")
            except PairingRefused as error:
                attempts.append(str(error))
            original(path, content)
        with patch.object(enroll, "_write_public_file", racing_write):
            enroll.create_enrollment_request(self.runtime, self.root / "locked.json")
        self.assertEqual(["enrollment_in_progress"], attempts)

    def test_lock_held_by_another_process_refuses_pairing(self):
        peer = self.peer()
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import sys; from pathlib import Path\n"
             "from media_capture_agent.pairing import EnrollmentLock\n"
             "with EnrollmentLock(Path(sys.argv[1])):\n"
             "    print('held', flush=True); sys.stdin.readline()\n",
             str(self.runtime)],
            cwd=Path(__file__).resolve().parents[1], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True)
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.wait, 10)
        try:
            self.assertEqual("held\n", holder.stdout.readline())
            with self.assertRaisesRegex(PairingRefused, "enrollment_in_progress"):
                enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))
            self.assertEqual(0, peer.connections)
        finally:
            holder.stdin.write("\n")
            holder.stdin.close()
        holder.wait(10)
        enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer))
        self.assertTrue(NodeCredentialStore(self.runtime).installed())

    def test_lock_file_is_private_and_unsafe_lock_files_are_refused(self):
        with EnrollmentLock(self.runtime):
            lock = self.runtime / "node-enrollment.lock"
            info = os.lstat(lock)
            self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
            self.assertEqual(os.geteuid(), info.st_uid)
        os.chmod(lock, 0o660)
        with self.assertRaisesRegex(PairingRefused, "credential_lock_rejected"):
            enroll.create_enrollment_request(self.runtime, self.root / "unsafe.json")
        lock.unlink()
        lock.symlink_to(self.root / "elsewhere")
        with self.assertRaisesRegex(PairingRefused, "credential_storage_unavailable"):
            enroll.create_enrollment_request(self.runtime, self.root / "unsafe.json")
        self.assertFalse((self.root / "elsewhere").exists())


class RepairTests(EnrollFixture):
    """#116: re-pairing an expired (same key/node) or revoked (new key/node) identity."""

    def setUp(self):
        super().setUp()
        self.first = self.peer(respond=None)
        self.old_node = enroll.pair(self.runtime, self.bundle(self.first.port),
                                    prompt=self.prompt_after(self.first))
        self.old_key = installed_key_digest(self.runtime)
        self.old_files = sorted(p.name for p in (self.runtime / "node-credentials").iterdir())
        self.expired = lambda: installed_certificate_expiry(NodeCredentialStore(self.runtime)) + DAY

    def generations(self):
        return sorted(p.name for p in (self.runtime / "node-credentials").glob("private-key-*.pem"))

    def test_expired_identity_repairs_with_the_same_key_and_node(self):
        with self.assertRaisesRegex(PairingRefused, "node_identity_not_expired"):
            enroll.create_enrollment_request(self.runtime, self.root / "early.json",
                                             repair="expired")
        peer = self.peer(respond=issuing(self.authority, self.old_node))
        with self.assertRaisesRegex(PairingRefused, "node_identity_not_expired"):
            enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer),
                        repair="expired")
        self.assertEqual(0, peer.connections)
        digest = enroll.create_enrollment_request(self.runtime, self.root / "repair.json",
                                                  repair="expired", now=self.expired)
        self.assertEqual(self.old_key, digest, "an expired node proves its same key")
        self.assertNotIn("PRIVATE KEY", (self.root / "repair.json").read_text())
        # A renewal key staged before expiry is stale once the node re-pairs.
        renewal = prepare_renewal(NodeCredentialStore(self.runtime))
        self.assertNotEqual(self.old_key, renewal.public_key_digest)
        old_expiry = installed_certificate_expiry(NodeCredentialStore(self.runtime))
        node = enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer),
                           repair="expired", now=self.expired)
        self.assertEqual(self.old_node, node)
        self.assertEqual(self.old_key, installed_key_digest(self.runtime))
        self.assertGreater(installed_certificate_expiry(NodeCredentialStore(self.runtime)),
                           old_expiry)
        current = sorted(p.name for p in (self.runtime / "node-credentials").iterdir())
        self.assertEqual(1, len(self.generations()))
        self.assertFalse(set(self.old_files) - {".pairing.lock", "current.json"} & set(current),
                         "the expired generation is deleted after the swap")
        self.assertFalse((self.runtime / "pending-renewal" / "node-key.pem").exists())

    def test_expired_repair_rejects_another_node_or_a_certificate_that_does_not_outlive(self):
        for respond in (issuing(self.authority, uuid4()),
                        issuing(self.authority, self.old_node, lifetime=DAY)):
            peer = self.peer(respond=respond)
            with self.assertRaisesRegex(PairingRefused, "issued_credential_rejected"):
                enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer),
                            repair="expired", now=self.expired)
        self.assertEqual(self.old_files,
                         sorted(p.name for p in (self.runtime / "node-credentials").iterdir()))
        self.assertEqual(self.old_key, installed_key_digest(self.runtime))

    def test_revoked_identity_repairs_with_a_new_key_and_a_new_node(self):
        new_node = uuid4()
        digest = enroll.create_enrollment_request(self.runtime, self.root / "revoked.json",
                                                  repair="revoked")
        self.assertNotEqual(self.old_key, digest, "a revoked key is never reused")
        self.assertEqual(digest, enroll.create_enrollment_request(
            self.runtime, self.root / "revoked-again.json", repair="revoked"),
            "a retry re-exports the same pending repair key")
        pending = self.runtime / "pending-repair" / "node-key.pem"
        self.assertEqual(0o600, stat.S_IMODE(os.lstat(pending).st_mode))
        self.assertEqual(0o700, stat.S_IMODE(os.lstat(pending.parent).st_mode))
        prepare_renewal(NodeCredentialStore(self.runtime))
        peer = self.peer(respond=issuing(self.authority, new_node))
        node = enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer),
                           repair="revoked")
        self.assertEqual(new_node, node)
        self.assertEqual(new_node, installed_credential(NodeCredentialStore(self.runtime)).node_id)
        self.assertEqual(digest, installed_key_digest(self.runtime))
        self.assertEqual(1, len(self.generations()))
        current = set(p.name for p in (self.runtime / "node-credentials").iterdir())
        self.assertFalse((set(self.old_files) - {".pairing.lock", "current.json"}) & current,
                         "the revoked generation is deleted after the swap")
        self.assertFalse(pending.exists())
        self.assertFalse((self.runtime / "pending-renewal" / "node-key.pem").exists())

    def test_revoked_repair_refuses_the_same_node_and_other_deployments(self):
        enroll.create_enrollment_request(self.runtime, self.root / "revoked.json", repair="revoked")
        peer = self.peer(respond=issuing(self.authority, self.old_node))
        with self.assertRaisesRegex(PairingRefused, "issued_credential_rejected"):
            enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer),
                        repair="revoked")
        other = SyntheticAuthority()
        foreign = self.peer(authority=other, respond=issuing(other, uuid4()))
        with self.assertRaisesRegex(PairingRefused, "repair_deployment_mismatch"):
            enroll.pair(self.runtime, TrustBundle.parse(other.bundle(port=foreign.port)),
                        prompt=self.prompt_after(foreign), repair="revoked")
        self.assertEqual(0, foreign.connections, "refused before any network traffic")
        self.assertEqual(self.old_files,
                         sorted(p.name for p in (self.runtime / "node-credentials").iterdir()))
        self.assertTrue((self.runtime / "pending-repair" / "node-key.pem").exists())

    def test_repair_refuses_a_different_ca_for_the_same_deployment(self):
        # Same deployment UUID, different CA key: _same_certificate refuses it
        # before any network traffic, for both repair modes.
        enroll.create_enrollment_request(self.runtime, self.root / "revoked.json", repair="revoked")
        impostor = SyntheticAuthority(self.authority.deployment)
        prompts = list(self.prompts)
        foreign = self.peer(authority=impostor, respond=issuing(impostor, uuid4()))
        bundle = TrustBundle.parse(impostor.bundle(port=foreign.port))
        self.assertEqual(self.authority.deployment, bundle.deployment_id)
        for mode, now in (("revoked", None), ("expired", self.expired)):
            with self.subTest(mode=mode):
                options = {} if now is None else {"now": now}
                with self.assertRaisesRegex(PairingRefused, "repair_deployment_mismatch"):
                    enroll.pair(self.runtime, bundle, prompt=self.prompt_after(foreign),
                                repair=mode, **options)
        self.assertEqual(0, foreign.connections, "refused before any network traffic")
        self.assertEqual(prompts, self.prompts, "no code prompt")
        self.assertEqual(self.old_files,
                         sorted(p.name for p in (self.runtime / "node-credentials").iterdir()))

    def test_renewal_steps_hold_the_enrollment_lock(self):
        # A pair racing prepare_renewal / complete_renewal is refused at once.
        prompts = list(self.prompts)
        peer = self.peer()
        outcomes = []

        def racing_pair():
            try:
                enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer),
                            repair="expired", now=self.expired)
                outcomes.append("paired")
            except PairingRefused as error:
                outcomes.append(str(error))

        original_build = node_tls.build_enrollment_request

        def racing_build(key):
            racing_pair()
            return original_build(key)
        with patch.object(node_tls, "build_enrollment_request", racing_build):
            prepare_renewal(NodeCredentialStore(self.runtime))

        def racing_complete(store, certificate_pem):
            racing_pair()
            raise PairingRefused("renewed_credential_rejected")
        with patch.object(node_tls, "_complete_renewal_locked", racing_complete):
            with self.assertRaisesRegex(PairingRefused, "renewed_credential_rejected"):
                node_tls.complete_renewal(NodeCredentialStore(self.runtime), b"unused")
        self.assertEqual(["enrollment_in_progress"] * 2, outcomes)
        self.assertEqual(0, peer.connections)
        self.assertEqual(prompts, self.prompts, "no code prompt")

    def test_revoked_repair_request_is_written_before_a_concurrent_pair_can_run(self):
        # PR #139 review: a pair --repair revoked racing request must not
        # consume the pending repair key before the request file is written.
        new_node = uuid4()
        peer = self.peer(respond=issuing(self.authority, new_node))
        outcomes = []
        original = enroll._write_public_file

        def racing_write(path, content):
            try:
                enroll.pair(self.runtime, self.bundle(peer.port),
                            prompt=self.prompt_after(peer), repair="revoked")
                outcomes.append("paired")
            except PairingRefused as error:
                outcomes.append(str(error))
            original(path, content)
        with patch.object(enroll, "_write_public_file", racing_write):
            enroll.create_enrollment_request(self.runtime, self.root / "revoked.json",
                                             repair="revoked")
        self.assertEqual(["enrollment_in_progress"], outcomes)
        self.assertEqual(0, peer.connections)
        self.assertTrue((self.runtime / "pending-repair" / "node-key.pem").exists())
        self.assertEqual(new_node, enroll.pair(self.runtime, self.bundle(peer.port),
                                               prompt=self.prompt_after(peer), repair="revoked"))

    def test_interrupted_revoked_repair_completes_without_a_second_new_node(self):
        enroll.create_enrollment_request(self.runtime, self.root / "revoked.json", repair="revoked")
        new_node = uuid4()
        peer = self.peer(respond=issuing(self.authority, new_node))
        original = PendingNodeKeyStore.discard

        def interrupted(store):
            if store._name == "pending-repair":
                raise PairingRefused("credential_storage_unavailable")
            original(store)
        with patch.object(PendingNodeKeyStore, "discard", interrupted):
            with self.assertRaisesRegex(PairingRefused, "credential_storage_unavailable"):
                enroll.pair(self.runtime, self.bundle(peer.port), prompt=self.prompt_after(peer),
                            repair="revoked")
        self.assertEqual(new_node, installed_credential(NodeCredentialStore(self.runtime)).node_id)
        connections = peer.connections
        self.assertEqual(new_node, enroll.pair(self.runtime, self.bundle(peer.port),
                                               prompt=self.prompt_after(peer), repair="revoked"))
        self.assertEqual(connections, peer.connections, "no second enrollment exchange")
        self.assertFalse((self.runtime / "pending-repair" / "node-key.pem").exists())

    def test_cli_prints_the_new_node_and_the_exact_config_change_after_revoked_repair(self):
        bundle = self.root / "bundle.json"
        bundle.write_bytes(self.authority.bundle(port=self.first.port))
        digest = TrustBundle.parse(bundle.read_bytes()).sha256
        new_node = uuid4()
        arguments = ["pair", "--runtime-root", str(self.runtime), "--trust-bundle", str(bundle),
                     "--bundle-sha256", digest]
        for repair, expected in (("revoked", True), ("expired", False), (None, False)):
            stdout = io.StringIO()
            extra = [] if repair is None else ["--repair", repair]
            with patch.object(enroll, "pair", return_value=new_node) as paired, \
                    patch("sys.stdout", stdout):
                self.assertEqual(0, enroll.main(arguments + extra))
            self.assertEqual(repair, paired.call_args.kwargs["repair"])
            lines = stdout.getvalue().splitlines()
            self.assertEqual(f"paired: node_id={new_node}", lines[0])
            if expected:
                self.assertEqual([enroll.config_update_instruction(new_node)], lines[1:])
                self.assertIn(f'set "node_id": "{new_node}"', lines[1])
                self.assertIn("node_identity_mismatch", lines[1])
            else:
                self.assertEqual([], lines[1:])

    def test_repair_requires_an_installed_identity_and_a_known_mode(self):
        runtime = self.root / "fresh"
        runtime.mkdir(mode=0o700)
        for mode in ("expired", "revoked"):
            with self.assertRaisesRegex(PairingRefused, "node_identity_unavailable"):
                enroll.create_enrollment_request(runtime, self.root / f"{mode}.json", repair=mode)
        with self.assertRaisesRegex(PairingRefused, "repair_mode_rejected"):
            enroll.pair(self.runtime, self.bundle(self.first.port), prompt=self.prompt_after(self.first),
                        repair="other")
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", io.StringIO()):
                enroll.main(["request", "--runtime-root", str(self.runtime), "--output",
                             str(self.root / "x.json"), "--repair", "other"])
        self.assertFalse((runtime / "pending-repair").exists())


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
