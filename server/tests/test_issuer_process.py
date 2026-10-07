"""CA key separation for capture-node issuance (Issue #109, PR1).

Covers the public/signing split of the deployment CA, the CA-account issuer
(its issuance log, one operation per run, fail-closed refusals), the approval
CLI's ordering (fork, drop, then request and database; the code only after a
verified certificate; activation of the pre-signed certificate on
redemption), revocation in the CA log, the real forked child with the same
account (descriptor and session isolation, reaping) and the service's
refusal to start while it can open the CA directory. Two real accounts are
covered by ``test_ca_privilege_separation_root`` (root only). All keys and
CAs are generated per test.
"""
from __future__ import annotations

from contextlib import closing
import datetime
import errno
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.audit.store import AuditStore
from app.cameras.remote_agent import issuer_process, node_ca, pairing_cli
from app.cameras.remote_agent.enrollment import (
    EnrollmentConfigurationError, EnrollmentService, PresignedEnrollment,
)
from app.cameras.remote_agent.ingest_tls import CaptureNodeAdmission, CaptureNodeIdentity
from app.cameras.remote_agent.issuer_process import (
    ISSUANCE_LOG, Account, CaIssuer, IssuerUnavailable, OsPrivileges,
    PrivilegeSeparationError, checked_reply,
)
from app.cameras.remote_agent.node_ca import (
    CaptureAuthorityError, DeploymentAuthority, DeploymentTrust, IssuedCertificateRejected,
    PrivateDirectory, public_key_digest,
)
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.deployment import capture_ca_directory_accessible
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests import issuer_fakes


SERVER_NAME = "capture-main.serversentinel.test"
DAY = datetime.timedelta(days=1)
SERVER_ROOT = Path(__file__).resolve().parents[1]


def node_request(key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(
        key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM), public_key_digest(key.public_key())


class Owner:
    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


class Harness(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="capture-issuer-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        os.chmod(self.root, 0o700)
        self.deployment = uuid4()
        self.authority_dir = self.root / "ca"
        self.listener_dir = self.root / "listener"
        self.authority = DeploymentAuthority.create(PrivateDirectory(self.authority_dir),
                                                    self.deployment, validity=3650 * DAY)
        self.authority.issue_main_server_credential(PrivateDirectory(self.listener_dir),
                                                    server_name=SERVER_NAME, validity=30 * DAY)
        self.trust = self.authority.public_trust()

    def database(self):
        path = self.root / f"state-{uuid4()}.sqlite3"
        with closing(Database(path).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        return path

    def issuer(self):
        return CaIssuer(PrivateDirectory(self.authority_dir))

    def log_records(self):
        path = self.authority_dir / ISSUANCE_LOG
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]


class PublicTrustTests(Harness):
    def test_public_trust_holds_no_private_key_and_cannot_sign(self):
        self.assertIs(DeploymentTrust, type(self.trust))
        self.assertFalse(hasattr(self.trust, "_private_key"))
        for name in ("issue_approved_node_certificate", "issue_renewal_certificate",
                     "sign_listener_request", "issue_and_activate", "_sign_node"):
            self.assertFalse(hasattr(self.trust, name), name)
        loaded = DeploymentTrust.load_public(PrivateDirectory(self.listener_dir))
        self.assertIs(DeploymentTrust, type(loaded))
        self.assertEqual(self.deployment, loaded.deployment_id)
        self.assertNotIn("PRIVATE", repr(loaded))

    def test_ca_certificate_must_be_a_self_signed_ca_of_the_deployment(self):
        _key, csr, digest = node_request()
        leaf = self.authority.issue_approved_node_certificate(uuid4(), csr, digest)
        for pem in (leaf.certificate_pem, b"", b"x" * 10, b"-----BEGIN " + b"CERTIFICATE-----\n"):
            with self.subTest(pem=pem[:20]), self.assertRaises(CaptureAuthorityError):
                DeploymentTrust.from_certificate_pem(pem)
        with self.assertRaises(CaptureAuthorityError):
            DeploymentTrust.from_certificate_pem(self.trust.ca_certificate_pem(),
                                                 deployment_id=uuid4())

    def test_returned_node_certificate_must_match_the_fixed_profile(self):
        node = uuid4()
        key, csr, digest = node_request()
        issued = self.authority.issue_approved_node_certificate(node, csr, digest)
        verified = self.trust.verify_issued_node_certificate(
            issued.certificate_pem, node_id=node, public_key_digest_value=digest)
        self.assertEqual(issued.credential_digest, verified.credential_digest)
        other = DeploymentAuthority.create(PrivateDirectory(self.root / "other-ca"),
                                           self.deployment, validity=3650 * DAY)
        foreign = other.issue_approved_node_certificate(node, csr, digest)
        listener_pem = (self.listener_dir / "main-server-certificate.pem").read_bytes()
        _other_key, other_csr, other_digest = node_request()
        cases = (
            ("another node", issued.certificate_pem, uuid4(), digest),
            ("another key", issued.certificate_pem, node, other_digest),
            ("another CA", foreign.certificate_pem, node, digest),
            ("serverAuth leaf", listener_pem, node, digest),
            ("the CA itself", self.trust.ca_certificate_pem(), node, digest),
            ("not a certificate", csr, node, digest),
        )
        for label, pem, node_id, key_digest in cases:
            with self.subTest(label), self.assertRaises(IssuedCertificateRejected) as raised:
                self.trust.verify_issued_node_certificate(pem, node_id=node_id,
                                                          public_key_digest_value=key_digest)
            self.assertEqual("issuer_unavailable", raised.exception.reason)
        later = DeploymentTrust(self.deployment, self.trust.certificate,
                                clock=lambda: issued.not_after + DAY)
        with self.assertRaises(IssuedCertificateRejected):
            later.verify_issued_node_certificate(issued.certificate_pem, node_id=node,
                                                 public_key_digest_value=digest)

    def test_returned_listener_certificate_must_match_the_fixed_profile(self):
        key, csr = node_ca.new_listener_key()
        digest = public_key_digest(key.public_key())
        certificate = self.authority.sign_listener_request(csr, server_name=SERVER_NAME,
                                                           validity=30 * DAY)
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        self.trust.verify_issued_listener_certificate(pem, server_name=SERVER_NAME,
                                                      public_key_digest_value=digest)
        _node_key, node_csr, node_digest = node_request()
        node_pem = self.authority.issue_approved_node_certificate(
            uuid4(), node_csr, node_digest).certificate_pem
        for label, value, name, key_digest in (
                ("other name", pem, "other.serversentinel.test", digest),
                ("other key", pem, SERVER_NAME, node_digest),
                ("clientAuth leaf", node_pem, SERVER_NAME, node_digest)):
            with self.subTest(label), self.assertRaises(CaptureAuthorityError):
                self.trust.verify_issued_listener_certificate(
                    value, server_name=name, public_key_digest_value=key_digest)
        # A listener CSR asking for anything itself is refused by the CA side.
        requested = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "chosen")])).sign(key, hashes.SHA256())
        with self.assertRaises(CaptureAuthorityError):
            self.authority.sign_listener_request(
                requested.public_bytes(serialization.Encoding.PEM), server_name=SERVER_NAME,
                validity=30 * DAY)

    def test_public_ca_copy_from_another_deployment_is_refused(self):
        other = DeploymentAuthority.create(PrivateDirectory(self.root / "other-ca"),
                                           uuid4(), validity=3650 * DAY)
        with self.assertRaises(node_ca.ListenerAuthorityMismatch):
            node_ca.publish_public_certificate(PrivateDirectory(self.listener_dir),
                                               other.ca_certificate_pem())
        self.assertFalse(node_ca.publish_public_certificate(PrivateDirectory(self.listener_dir),
                                                            self.trust.ca_certificate_pem()))


class PresignedEnrollmentTests(Harness):
    def setUp(self):
        super().setUp()
        database = Database(self.database())
        self.ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)),
                                    audit=AuditStore(database))

    def approved(self):
        key, csr, digest = node_request()
        approval, code = self.ledger.approve(Owner(), "owner", node_id=uuid4(),
                                             public_key_digest=digest)
        issued = self.authority.issue_approved_node_certificate(approval.node_id, csr, digest)
        return key, csr, approval, code.value, issued

    def test_the_network_service_is_refused_the_signing_authority(self):
        _key, _csr, approval, _code, issued = self.approved()
        entry = PresignedEnrollment(approval, issued)
        with self.assertRaises(EnrollmentConfigurationError):
            EnrollmentService(self.ledger, self.authority, (entry,))
        EnrollmentService(self.ledger, self.trust, (entry,))

    def test_presigned_certificate_must_be_for_the_approved_node_and_key(self):
        _key, _csr, approval, _code, issued = self.approved()
        _other_key, other_csr, other_digest = node_request()
        for credential in (
                self.authority.issue_approved_node_certificate(uuid4(), other_csr, other_digest),
                self.authority.issue_approved_node_certificate(approval.node_id, other_csr,
                                                               other_digest)):
            with self.subTest(), self.assertRaises(EnrollmentConfigurationError):
                EnrollmentService(self.ledger, self.trust,
                                  (PresignedEnrollment(approval, credential),))

    def test_redemption_activates_exactly_the_presigned_certificate(self):
        key, csr, approval, code, issued = self.approved()
        admission = CaptureNodeAdmission(self.ledger, self.deployment)
        identity = CaptureNodeIdentity(approval.node_id, issued.public_key_digest,
                                       issued.credential_digest, issued.not_after)
        # Signed but unredeemed: no activation exists, so nothing is admitted.
        self.assertFalse(admission.is_admitted(identity))
        service = EnrollmentService(self.ledger, self.trust,
                                    (PresignedEnrollment(approval, issued),))
        body = json.dumps({"version": 1, "deployment_id": str(self.deployment), "code": code,
                           "csr": csr.decode()}).encode()
        response, credential = service.handle(body)
        self.assertEqual(issued, credential)
        self.assertEqual(issued.certificate_pem.decode(), json.loads(response)["certificate"])
        self.assertTrue(admission.is_admitted(identity))
        # The CSR proves possession only; a CSR for another key is refused.
        _other, other_csr, _digest = node_request()
        again = json.dumps({"version": 1, "deployment_id": str(self.deployment), "code": code,
                            "csr": other_csr.decode()}).encode()
        self.assertEqual(b'{"status":"refused"}', service.handle(again)[0])


class IssuerTests(Harness):
    def sign(self, issuer, node, csr, digest):
        return issuer.handle({"op": "sign_node", "node_id": str(node),
                              "public_key_digest": digest, "csr": csr.decode()})

    def test_hello_returns_only_the_public_certificate(self):
        issuer = self.issuer()
        reply = issuer.handle({"op": "hello"})
        self.assertEqual("ok", reply["status"])
        self.assertEqual(self.trust.ca_certificate_pem().decode(), reply["ca_certificate"])
        self.assertEqual(str(self.deployment), reply["deployment_id"])
        self.assertNotIn("PRIVATE", json.dumps(reply))
        self.assertFalse(issuer.done)

    def test_one_node_leaf_per_run_and_it_is_logged_before_it_is_returned(self):
        issuer = self.issuer()
        issuer.handle({"op": "hello"})
        node = uuid4()
        _key, csr, digest = node_request()
        reply = self.sign(issuer, node, csr, digest)
        self.assertEqual("ok", reply["status"], reply)
        self.assertTrue(issuer.done)
        verified = self.trust.verify_issued_node_certificate(
            reply["certificate"].encode(), node_id=node, public_key_digest_value=digest)
        records = self.log_records()
        self.assertEqual(1, len(records))
        self.assertEqual({"type": "node", "node_id": str(node), "public_key_digest": digest,
                          "credential_digest": verified.credential_digest},
                         {key: records[0][key] for key in
                          ("type", "node_id", "public_key_digest", "credential_digest")})
        self.assertEqual(0o600, stat.S_IMODE(os.lstat(self.authority_dir / ISSUANCE_LOG).st_mode))
        self.assertNotIn(b"PRIVATE", (self.authority_dir / ISSUANCE_LOG).read_bytes())
        self.assertNotIn(b"CERTIFICATE", (self.authority_dir / ISSUANCE_LOG).read_bytes())
        # A second operation in the same run is refused.
        _key, csr2, digest2 = node_request()
        self.assertEqual("refused", self.sign(issuer, uuid4(), csr2, digest2)["status"])
        self.assertEqual(1, len(self.log_records()))

    def test_requests_without_hello_or_with_a_wrong_key_are_refused(self):
        _key, csr, digest = node_request()
        self.assertEqual("refused", self.sign(self.issuer(), uuid4(), csr, digest)["status"])
        issuer = self.issuer()
        issuer.handle({"op": "hello"})
        _other_key, _other_csr, other_digest = node_request()
        self.assertEqual("refused", self.sign(issuer, uuid4(), csr, other_digest)["status"])
        for message in ({"op": "sign_node", "node_id": "not-a-uuid", "csr": csr.decode(),
                         "public_key_digest": digest}, {"op": "unknown"}, ["op"]):
            fresh = self.issuer()
            fresh.handle({"op": "hello"})
            with self.subTest(message=message):
                self.assertEqual("refused", fresh.handle(message)["status"])
        self.assertEqual([], self.log_records())

    def test_log_decides_revoked_nodes_and_keys_bound_elsewhere(self):
        node = uuid4()
        _key, csr, digest = node_request()
        first = self.issuer()
        first.handle({"op": "hello"})
        self.assertEqual("ok", self.sign(first, node, csr, digest)["status"])
        first.close()
        # A retry for the same node and key is allowed (#139 expired re-pair).
        retry = self.issuer()
        retry.handle({"op": "hello"})
        self.assertEqual("ok", self.sign(retry, node, csr, digest)["status"])
        retry.close()
        # The same key for another node is refused by the CA log alone.
        other = self.issuer()
        other.handle({"op": "hello"})
        reply = self.sign(other, uuid4(), csr, digest)
        other.close()
        self.assertEqual(("refused", "issuer_refused_request"), (reply["status"], reply["reason"]))
        revoke = self.issuer()
        revoke.handle({"op": "hello"})
        self.assertEqual("ok", revoke.handle({"op": "revoke", "node_id": str(node)})["status"])
        revoke.close()
        # After the CA-side revocation neither the node nor its key is signed.
        _key2, csr2, digest2 = node_request()
        for target, request, key_digest in ((node, csr2, digest2), (node, csr, digest)):
            later = self.issuer()
            later.handle({"op": "hello"})
            reply = self.sign(later, target, request, key_digest)
            later.close()
            self.assertEqual(("refused", "issuer_refused_request"),
                             (reply["status"], reply["reason"]))
        self.assertEqual(["node", "node", "node_revocation"],
                         [record["type"] for record in self.log_records()])

    def test_the_ca_lock_spans_hello_through_the_logged_operation(self):
        # Codex P2 (PR #177, round 3): two runs approving the same key for
        # different nodes -- exactly one is signed.
        _key, csr, digest = node_request()
        first, second = self.issuer(), self.issuer()
        self.assertEqual("ok", first.handle({"op": "hello"})["status"])
        busy = second.handle({"op": "hello"})
        self.assertEqual(("refused", "issuer_material_busy"), (busy["status"], busy["reason"]))
        self.assertEqual("ok", self.sign(first, uuid4(), csr, digest)["status"])
        first.close()
        second.close()
        late = self.issuer()
        late.handle({"op": "hello"})
        reply = self.sign(late, uuid4(), csr, digest)
        late.close()
        self.assertEqual(("refused", "issuer_refused_request"), (reply["status"], reply["reason"]))
        self.assertEqual(1, len([r for r in self.log_records() if r["type"] == "node"]))

    def test_concurrent_approvals_of_one_key_sign_exactly_once(self):
        import threading
        _key, csr, digest = node_request()
        barrier = threading.Barrier(2)
        results = []

        def run():
            issuer = self.issuer()
            try:
                barrier.wait(5)
                reply = issuer.handle({"op": "hello"})
                if reply["status"] == "ok":
                    reply = self.sign(issuer, uuid4(), csr, digest)
                results.append(reply)
            finally:
                issuer.close()
        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(1, sum(1 for reply in results if reply["status"] == "ok"), results)
        self.assertEqual(1, len([r for r in self.log_records() if r["type"] == "node"]))

    def test_unwritable_log_means_no_certificate(self):
        issuer = self.issuer()
        issuer.handle({"op": "hello"})
        _key, csr, digest = node_request()
        real_write = os.write

        def failing(descriptor, data):
            if os.path.basename(os.readlink(f"/proc/self/fd/{descriptor}")) == ISSUANCE_LOG:
                raise OSError(errno.ENOSPC, "synthetic full disk")
            return real_write(descriptor, data)
        with patch.object(node_ca.os, "write", failing):
            reply = self.sign(issuer, uuid4(), csr, digest)
        self.assertEqual(("refused", "issuance_log_unavailable"), (reply["status"], reply["reason"]))
        self.assertNotIn("certificate", reply)
        self.assertFalse((self.authority_dir / ISSUANCE_LOG).exists())

    def test_short_write_is_truncated_and_never_leaves_a_torn_record(self):
        first = self.issuer()
        first.handle({"op": "hello"})
        _key, csr, digest = node_request()
        self.assertEqual("ok", self.sign(first, uuid4(), csr, digest)["status"])
        before = (self.authority_dir / ISSUANCE_LOG).read_bytes()
        real_write = os.write
        calls = []

        def short(descriptor, data):
            if os.path.basename(os.readlink(f"/proc/self/fd/{descriptor}")) == ISSUANCE_LOG:
                calls.append(1)
                if len(calls) == 1:
                    return real_write(descriptor, bytes(data)[:7])
                raise OSError(errno.EIO, "synthetic")
            return real_write(descriptor, data)
        issuer = self.issuer()
        issuer.handle({"op": "hello"})
        _key2, csr2, digest2 = node_request()
        with patch.object(node_ca.os, "write", short):
            reply = self.sign(issuer, uuid4(), csr2, digest2)
        self.assertEqual("refused", reply["status"])
        self.assertEqual(before, (self.authority_dir / ISSUANCE_LOG).read_bytes())

    def test_damaged_or_exposed_log_refuses_before_any_prompt(self):
        log = self.authority_dir / ISSUANCE_LOG
        for content, mode in ((b'{"format":1,"type":"node"', 0o600), (b"not json\n", 0o600),
                              (b'{"format":2,"type":"node"}\n', 0o600),
                              (b'{"format":1,"type":"node_revocation","node_id":"x"}\n', 0o600),
                              (b"", 0o644)):
            with self.subTest(content=content, mode=oct(mode)):
                if log.exists():
                    log.unlink()
                PrivateDirectory(self.authority_dir).write_new(ISSUANCE_LOG, content or b"\n")
                os.chmod(log, mode)
                reply = self.issuer().handle({"op": "hello"})
                self.assertEqual("refused", reply["status"])
                self.assertNotIn("ca_certificate", reply)

    def test_initialize_is_provisional_until_committed(self):
        for ending in ("abort", "close", "commit"):
            with self.subTest(ending=ending):
                directory = self.root / f"new-ca-{ending}"
                issuer = CaIssuer(PrivateDirectory(directory))
                key, csr = node_ca.new_listener_key()
                deployment = uuid4()
                reply = issuer.handle({"op": "initialize", "deployment_id": str(deployment),
                                       "csr": csr.decode(), "server_name": SERVER_NAME,
                                       "ca_validity_days": 3650, "server_validity_days": 30})
                self.assertEqual("ok", reply["status"], reply)
                trust = DeploymentTrust.from_certificate_pem(reply["ca_certificate"].encode(),
                                                             deployment_id=deployment)
                trust.verify_issued_listener_certificate(
                    reply["certificate"].encode(), server_name=SERVER_NAME,
                    public_key_digest_value=public_key_digest(key.public_key()))
                self.assertFalse(issuer.done)
                # Nothing else is accepted while the CA is provisional.
                self.assertEqual("refused", issuer.handle({"op": "revoke",
                                                           "node_id": str(uuid4())})["status"])
                if ending == "close":
                    issuer.close()
                else:
                    self.assertEqual("ok", issuer.handle({"op": ending})["status"])
                    issuer.close()
                names = sorted(os.listdir(directory))
                if ending == "commit":
                    self.assertEqual(["ca-certificate.pem", "ca-key.pem", ISSUANCE_LOG], names)
                    types = [json.loads(line)["type"] for line in
                             (directory / ISSUANCE_LOG).read_text().splitlines()]
                    self.assertEqual(["deployment_ca", "listener"], types)
                else:
                    self.assertEqual([], names)

    def test_checked_reply_keeps_only_fixed_refusal_words(self):
        class Channel:
            def __init__(self, reply):
                self.reply = reply

            def request(self, message):
                return self.reply
        for reply, reason, detail in (
                ({"status": "refused", "reason": "issuer_refused_request"},
                 "issuer_refused_request", "issuer_refused_request"),
                ({"status": "refused", "reason": "issuer_material_rejected"},
                 "issuer_material_rejected", "issuer_material_rejected"),
                ({"status": "refused", "reason": "something_else"}, "issuer_unavailable",
                 "something_else"),
                ({"status": "refused", "reason": "Bad Word /etc/passwd"}, "issuer_unavailable",
                 None),
                ({"status": "maybe"}, "issuer_unavailable", None), ("x", "issuer_unavailable", None)):
            with self.subTest(reply=reply), self.assertRaises(IssuerUnavailable) as raised:
                checked_reply(Channel(reply), {"op": "hello"})
            self.assertEqual((reason, detail), (raised.exception.reason, raised.exception.detail))


class Terminal:
    """A fake controlling terminal that records everything shown."""

    def __init__(self, events, answers=("APPROVE",)):
        self.events = events
        self.answers = list(answers)
        self.written = []

    def __call__(self, *args, **kwargs):
        return self

    def write(self, text):
        self.written.append(text)
        if "One-time pairing code" in text:
            self.events.append("code_shown")

    def read_line(self):
        return self.answers.pop(0)

    def close(self):
        pass

    def code(self):
        for text in self.written:
            if "One-time pairing code" in text:
                return text.split("\n\n")[1].strip().replace("-", "")
        return None


class ApproveOrderingTests(Harness):
    def setUp(self):
        super().setUp()
        self.privileges = issuer_fakes.install(self)
        self.events = self.privileges.events
        self.key, self.csr, self.digest = node_request()
        self.request = self.root / f"request-{uuid4()}.json"
        self.request.write_text(json.dumps({"format_version": 1, "csr": self.csr.decode(),
                                            "public_key_digest": self.digest}))
        self.database_path = self.database()
        real_existing = pairing_cli._existing_database
        real_read = pairing_cli._read_public_file

        def opening_database(path):
            self.events.append("database_opened")
            return real_existing(path)

        def reading_request(path, maximum):
            self.events.append("request_opened")
            return real_read(path, maximum)
        for name, value in (("_existing_database", opening_database),
                            ("_read_public_file", reading_request)):
            patcher = patch.object(pairing_cli, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_approve(self, terminal, serve=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        served = {}

        def fake_serve(listener, service, *, expires_at_monotonic, stop=None):
            self.events.append("serving")
            served["service"] = service
            served["alive"] = [instance for instance in issuer_fakes.InProcessIssuer.instances
                               if not instance.closed]
            if serve is not None:
                return serve(service)
            from app.cameras.remote_agent.enrollment import EnrollmentOutcome
            return EnrollmentOutcome("expired", ())
        with patch.object(pairing_cli, "ControllingTerminal", terminal), \
                patch.object(pairing_cli.EnrollmentListener, "open", lambda listener: None), \
                patch.object(pairing_cli.EnrollmentListener, "close", lambda listener: None), \
                patch.object(pairing_cli.EnrollmentListener, "serve", fake_serve), \
                patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            status = pairing_cli.main([
                "approve", "--database", str(self.database_path),
                "--authority-dir", str(self.authority_dir),
                "--listener-dir", str(self.listener_dir), "--request", str(self.request),
                "--listen", "127.0.0.1:18443"])
        return status, stdout.getvalue(), stderr.getvalue(), served

    def test_drop_precedes_request_and_database_and_the_code_follows_a_verified_leaf(self):
        terminal = Terminal(self.events)

        def redeem(service):
            body = json.dumps({"version": 1, "deployment_id": str(self.deployment),
                               "code": terminal.code(), "csr": self.csr.decode()}).encode()
            response, issued = service.handle(body)
            self.assertIsNotNone(issued, response)
            from app.cameras.remote_agent.enrollment import EnrollmentOutcome
            return EnrollmentOutcome("completed", (issued.node_id,))
        status, stdout, stderr, served = self.run_approve(terminal, redeem)
        self.assertEqual(0, status, stderr)
        order = self.events
        for earlier, later in (("start", "fork"), ("fork", "issuer:hello"),
                               ("issuer:hello", "drop"), ("drop", "ca_closed"),
                               ("ca_closed", "request_opened"), ("drop", "database_opened"),
                               ("database_opened", "issuer:sign_node"),
                               ("issuer:sign_node", "issuer:exited"),
                               ("issuer:exited", "code_shown"), ("code_shown", "serving")):
            with self.subTest(earlier=earlier, later=later):
                self.assertLess(order.index(earlier), order.index(later), order)
        self.assertEqual([], served["alive"], "no CA-key process is alive while serving")
        self.assertIsInstance(served["service"]._trust, DeploymentTrust)
        self.assertIs(DeploymentTrust, type(served["service"]._trust))
        # The activated credential is exactly the one the CA logged.
        logged = [record for record in self.log_records() if record["type"] == "node"]
        self.assertEqual(1, len(logged))
        with closing(sqlite3.connect(self.database_path)) as connection:
            activated = connection.execute(
                "SELECT node_id, credential_serial_digest, state FROM pairing_node_credentials"
            ).fetchall()
        self.assertEqual([(logged[0]["node_id"], logged[0]["credential_digest"], "active")],
                         activated)

    def test_failed_drop_aborts_before_the_request_or_database(self):
        def failing(account):
            self.events.append("drop")
            raise PrivilegeSeparationError("privilege_drop_failed")
        self.privileges.drop = failing
        terminal = Terminal(self.events)
        status, _stdout, stderr, served = self.run_approve(terminal)
        self.assertEqual(2, status)
        self.assertIn("refused: privilege_drop_failed", stderr)
        self.assertNotIn("request_opened", self.events)
        self.assertNotIn("database_opened", self.events)
        self.assertEqual([], terminal.written)
        self.assertEqual({}, served)
        self.assertTrue(all(instance.closed for instance in issuer_fakes.InProcessIssuer.instances))

    def test_an_open_ca_directory_after_the_drop_aborts(self):
        def exposed(path, **options):
            raise PrivilegeSeparationError("ca_directory_exposed")
        self.privileges.require_ca_directory_closed = exposed
        status, _stdout, stderr, _served = self.run_approve(Terminal(self.events))
        self.assertEqual(2, status)
        self.assertIn("refused: ca_directory_exposed", stderr)
        self.assertNotIn("database_opened", self.events)

    def test_issuer_refusal_after_approval_never_shows_the_code(self):
        terminal = Terminal(self.events)
        with patch.object(CaIssuer, "_sign_node",
                          lambda issuer, message: {"status": "refused",
                                                   "reason": "issuance_log_unavailable"}):
            status, stdout, stderr, served = self.run_approve(terminal)
        self.assertEqual(2, status)
        self.assertIn("refused: issuer_unavailable", stderr)
        self.assertIn("issuer_detail=issuance_log_unavailable", stderr)
        self.assertNotIn("code_shown", self.events)
        self.assertEqual({}, served)
        self.assertNotIn("enrollment listening", stdout)

    def test_a_certificate_that_does_not_verify_never_shows_the_code(self):
        other = DeploymentAuthority.create(PrivateDirectory(self.root / "rogue-ca"),
                                           self.deployment, validity=3650 * DAY)
        node_for = {}
        real = CaIssuer._sign_node

        def wrong(kind):
            def sign(issuer, message):
                reply = real(issuer, message)
                node = message["node_id"]
                node_for["node"] = node
                if kind == "other node":
                    reply["certificate"] = self.authority.issue_approved_node_certificate(
                        uuid4(), self.csr, self.digest).certificate_pem.decode()
                elif kind == "other CA":
                    reply["certificate"] = other.issue_approved_node_certificate(
                        __import__("uuid").UUID(node), self.csr,
                        self.digest).certificate_pem.decode()
                else:
                    reply["certificate"] = "garbage"
                return reply
            return sign
        for kind in ("other node", "other CA", "garbage"):
            with self.subTest(kind=kind):
                self.events.clear()
                terminal = Terminal(self.events)
                with patch.object(CaIssuer, "_sign_node", wrong(kind)):
                    status, _stdout, stderr, served = self.run_approve(terminal)
                self.assertEqual(2, status)
                self.assertIn("refused: issuer_unavailable", stderr)
                self.assertNotIn("code_shown", self.events)
                self.assertEqual({}, served)

    def test_revoked_key_is_refused_before_the_prompt_and_before_signing(self):
        database = Database(self.database_path)
        ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)),
                               audit=AuditStore(database))
        node = uuid4()
        ledger.approve(Owner(), "owner", node_id=node, public_key_digest=self.digest)
        ledger.revoke(Owner(), "owner", node_id=node)
        terminal = Terminal(self.events)
        status, _stdout, stderr, _served = self.run_approve(terminal)
        self.assertEqual(2, status)
        self.assertIn("public_key_revoked", stderr)
        self.assertNotIn("issuer:sign_node", self.events)
        self.assertEqual([], terminal.written)


class RevokeTests(Harness):
    def setUp(self):
        super().setUp()
        self.privileges = issuer_fakes.install(self)
        self.database_path = self.database()
        database = Database(self.database_path)
        self.ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)),
                                    audit=AuditStore(database))
        _key, _csr, digest = node_request()
        self.node = uuid4()
        self.ledger.approve(Owner(), "owner", node_id=self.node, public_key_digest=digest)

    def revoke(self, authority):
        stdout, stderr = io.StringIO(), io.StringIO()
        terminal = Terminal(self.privileges.events, answers=("REVOKE",))
        with patch.object(pairing_cli, "ControllingTerminal", terminal), \
                patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            status = pairing_cli.main(["revoke", "--database", str(self.database_path),
                                       "--authority-dir", str(authority),
                                       "--node", str(self.node)])
        return status, stdout.getvalue(), stderr.getvalue()

    def states(self):
        return {row.node_id: row.credential_state or row.enrollment_state
                for row in self.ledger.pairing_summaries()}

    def test_revoke_is_recorded_in_the_ca_log(self):
        status, stdout, stderr = self.revoke(self.authority_dir)
        self.assertEqual((0, f"revoked: node_id={self.node}\n"), (status, stdout), stderr)
        self.assertEqual([{"type": "node_revocation", "node_id": str(self.node)}],
                         [{key: record[key] for key in ("type", "node_id")}
                          for record in self.log_records()])
        self.assertEqual("revoked", self.states()[self.node])

    def test_unavailable_ca_still_revokes_and_a_rerun_records_it(self):
        broken = self.root / "missing-ca"
        status, stdout, stderr = self.revoke(broken)
        self.assertEqual(1, status)
        self.assertEqual(f"revoked: node_id={self.node}\n", stdout)
        self.assertIn("warning: ca_revocation_unrecorded", stderr)
        self.assertEqual("revoked", self.states()[self.node])
        self.assertEqual([], self.log_records())
        status, stdout, stderr = self.revoke(self.authority_dir)
        self.assertEqual(0, status, stderr)
        self.assertEqual(["node_revocation"], [record["type"] for record in self.log_records()])


class ForkedIssuerTests(Harness):
    """The real fork and pipes, as one account, in a separate interpreter."""

    SCRIPT = r'''
import json, os, sys, threading, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from app.cameras.remote_agent import issuer_process
from app.cameras.remote_agent.issuer_process import Account, ForkedIssuer, checked_reply

class Same:
    def require_start(self): pass
    def account(self, name): return Account(os.getuid(), os.getgid())
    def check_accounts(self, ca, service): pass
    def drop(self, account): pass
    def harden_child(self): pass
    def require_ca_directory_closed(self, path): pass

mode = sys.argv[3]
held = os.open(sys.argv[4], os.O_RDONLY)  # stands in for the terminal / a database
if mode == "thread":
    threading.Thread(target=time.sleep, args=(2,), daemon=True).start()
    try:
        ForkedIssuer.start(Path(sys.argv[2]), Account(os.getuid(), os.getgid()), Same())
    except issuer_process.IssuerUnavailable as error:
        print(json.dumps({"refused": error.reason}))
    sys.exit(0)
issuer = ForkedIssuer.start(Path(sys.argv[2]), Account(os.getuid(), os.getgid()), Same())
reply = checked_reply(issuer, {"op": "hello"})
fds = sorted(os.readlink(f"/proc/{issuer.pid}/fd/{name}")
             for name in os.listdir(f"/proc/{issuer.pid}/fd"))
session = os.getsid(issuer.pid) != os.getsid(0)
if mode == "eof":
    issuer.close()
    print(json.dumps({"fds": fds, "new_session": session, "alive": issuer.alive()}))
    sys.exit(0)
signed = checked_reply(issuer, {"op": "revoke", "node_id": "00000000-0000-4000-8000-000000000001"})
issuer.finish()
try:
    os.waitpid(issuer.pid, os.WNOHANG)
    reaped = False
except ChildProcessError:
    reaped = True
print(json.dumps({"fds": fds, "new_session": session, "reaped": reaped,
                  "ca": reply["ca_certificate"][:27], "status": signed["status"]}))
'''

    def run_script(self, mode):
        held = self.root / "held-file"
        held.write_bytes(b"synthetic")
        result = subprocess.run(
            [sys.executable, "-c", self.SCRIPT, str(SERVER_ROOT), str(self.authority_dir), mode,
             str(held)], capture_output=True, timeout=60, check=False, cwd=SERVER_ROOT)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        return json.loads(result.stdout)

    def test_child_holds_only_its_pipes_and_dev_null_in_a_new_session(self):
        outcome = self.run_script("revoke")
        self.assertEqual("ok", outcome["status"])
        self.assertEqual("-----BEGIN " + "CERTIFICATE-----", outcome["ca"])
        self.assertTrue(outcome["new_session"], "the child has no controlling terminal")
        self.assertTrue(outcome["reaped"])
        for target in outcome["fds"]:
            # Pipes, /dev/null and the CA directory itself (its flock, held for
            # the whole conversation; Issue #109 round 3).
            self.assertTrue(target == "/dev/null" or target.startswith("pipe:")
                            or target == str(self.authority_dir), outcome["fds"])
        self.assertEqual(3, outcome["fds"].count("/dev/null"))
        self.assertEqual(["node_revocation"], [record["type"] for record in self.log_records()])

    def test_end_of_stream_ends_the_child(self):
        outcome = self.run_script("eof")
        self.assertFalse(outcome["alive"])

    def test_fork_is_refused_once_a_thread_exists(self):
        self.assertEqual({"refused": "issuer_unavailable"}, self.run_script("thread"))


class PrivilegeTests(unittest.TestCase):
    def test_real_start_requires_root_and_distinct_non_root_accounts(self):
        privileges = OsPrivileges()
        if os.getresuid() != (0, 0, 0):
            with self.assertRaises(PrivilegeSeparationError) as raised:
                privileges.require_start()
            self.assertEqual("privilege_separation_requires_root", raised.exception.reason)
        for ca, service, reason in (
                (Account(0, 0), Account(1001, 1001), "account_must_not_be_root"),
                (Account(1001, 1001), Account(0, 1002), "account_must_not_be_root"),
                (Account(1001, 1001), Account(1001, 1002),
                 "ca_account_must_differ_from_service_account"),
                (Account(1001, 1001), Account(1002, 1001),
                 "ca_account_must_differ_from_service_account")):
            with self.subTest(ca=ca, service=service), \
                    self.assertRaises(PrivilegeSeparationError) as raised:
                privileges.check_accounts(ca, service)
            self.assertEqual(reason, raised.exception.reason)
        privileges.check_accounts(Account(1001, 1001), Account(1002, 1002))

    def test_verification_refuses_a_process_that_is_not_exactly_the_account(self):
        with self.assertRaises(PrivilegeSeparationError):
            issuer_process.verify_dropped(Account(os.getuid() + 1, os.getgid()))

    def test_ca_directory_probe_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertTrue(capture_ca_directory_accessible(root))
            self.assertTrue(capture_ca_directory_accessible(root / "missing"))
            self.assertTrue(capture_ca_directory_accessible(
                Path("/") / f"serversentinel-test-missing-{uuid4()}"))
            self.assertTrue(capture_ca_directory_accessible(Path("relative")))


class ServiceStartTests(unittest.TestCase):
    def test_launcher_refuses_when_it_can_open_the_ca_directory(self):
        from app import deployment
        with tempfile.TemporaryDirectory() as temporary:
            open_directory = Path(temporary)
            for path, accessible in ((open_directory, True), (open_directory / "gone", True)):
                with self.subTest(path=path):
                    loaded = deployment.Deployment.__new__(deployment.Deployment)
                    object.__setattr__(loaded, "service_uid", os.geteuid())
                    object.__setattr__(loaded, "monitoring", type(
                        "Monitoring", (), {"storage_configured": True})())
                    object.__setattr__(loaded, "capture_ca_directory", path)
                    stderr = io.StringIO()
                    with patch.object(deployment, "_runtime_roots", return_value=(None, None)), \
                            patch.object(deployment.Deployment, "load", return_value=loaded), \
                            patch("sys.stderr", stderr), self.assertRaises(SystemExit) as stopped:
                        deployment.main(["--config", "/unused", "--check"])
                    self.assertEqual(1, stopped.exception.code)
                    self.assertIn("validation failed", stderr.getvalue())

    def test_capture_ca_directory_setting_is_absolute_and_outside_runtime_data(self):
        from app import deployment
        for value in ("relative/ca", "", "/srv/../etc", 5, None):
            with self.subTest(value=value), self.assertRaises(deployment.ConfigurationError):
                deployment._capture_ca_directory(value)
        self.assertEqual(Path("/var/lib/serversentinel-ca"),
                         deployment._capture_ca_directory("/var/lib/serversentinel-ca"))


class RevokeWithoutCaTests(RevokeTests):
    """Codex P1 (PR #177): a lost CA directory must not block the ledger revocation."""

    def use_real_probe(self):
        # The real post-drop probe, as the unprivileged test account.
        self.privileges.require_ca_directory_closed = \
            OsPrivileges().require_ca_directory_closed

    def test_missing_ca_directory_still_revokes_in_the_ledger(self):
        self.use_real_probe()
        # Under a root-owned, non-writable ancestor: the test account controls
        # no component, so only "missing" decides.
        lost = Path("/") / f"serversentinel-test-missing-{uuid4()}"
        for missing in (lost, lost / "ca"):
            with self.subTest(missing=missing.name):
                status, stdout, stderr = self.revoke(missing)
                self.assertEqual(1, status, stderr)
                self.assertEqual(f"revoked: node_id={self.node}\n", stdout)
                self.assertNotIn("ca_directory_exposed", stderr)
                self.assertIn("warning: ca_revocation_unrecorded", stderr)
                self.assertEqual("revoked", self.states()[self.node])
        # Idempotent rerun once the CA directory is back.
        self.privileges.require_ca_directory_closed = lambda path, **options: None
        status, _stdout, stderr = self.revoke(self.authority_dir)
        self.assertEqual(0, status, stderr)
        self.assertEqual(["node_revocation"], [record["type"] for record in self.log_records()])

    def test_an_existing_accessible_ca_directory_is_still_refused(self):
        self.use_real_probe()
        # The test account owns this CA directory, so it can open it: exposed.
        status, stdout, stderr = self.revoke(self.authority_dir)
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("refused: ca_directory_exposed", stderr)
        self.assertNotEqual("revoked", self.states()[self.node])
        self.assertEqual([], self.log_records())

    def test_exposure_probe_distinguishes_missing_from_reachable(self):
        lost = Path("/") / f"serversentinel-test-missing-{uuid4()}"
        # Missing is not exposure only for revoke (missing_ok).
        self.assertFalse(issuer_process.ca_directory_exposed(lost, missing_ok=True))
        self.assertFalse(issuer_process.ca_directory_exposed(lost / "ca", missing_ok=True))
        self.assertTrue(issuer_process.ca_directory_exposed(lost))
        # A missing directory under a parent this account controls is exposed:
        # the account could create it.
        self.assertTrue(issuer_process.ca_directory_exposed(self.root / "missing",
                                                            missing_ok=True))
        self.assertTrue(issuer_process.ca_directory_exposed(self.authority_dir))
        link = self.root / "linked-ca"
        link.symlink_to(self.authority_dir)
        self.assertTrue(issuer_process.ca_directory_exposed(link))
        afile = self.root / "a-file"
        afile.write_text("x")
        self.assertTrue(issuer_process.ca_directory_exposed(afile / "ca", missing_ok=True))


class ControlledCaPathTests(unittest.TestCase):
    """Codex P1 (PR #177, round 3): a CA path the service controls is exposed."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="capture-control-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))

    def probes(self, path):
        return (capture_ca_directory_accessible(path),
                issuer_process.ca_directory_exposed(path),
                issuer_process.ca_directory_exposed(path, missing_ok=True))

    def test_service_owned_directory_with_mode_000_is_exposed(self):
        # Chowned to the service by mistake: EACCES now, but the owner can
        # chmod it back and read its key.
        ca = self.root / "ca"
        ca.mkdir(mode=0o700)
        (ca / "ca-key.pem").write_text("synthetic")
        os.chmod(ca / "ca-key.pem", 0o600)
        os.chmod(ca, 0)
        try:
            self.assertEqual((True, True, True), self.probes(ca))
            with self.assertRaises(PrivilegeSeparationError) as raised:
                OsPrivileges().require_ca_directory_closed(ca, missing_ok=True)
            self.assertEqual("ca_directory_exposed", raised.exception.reason)
        finally:
            os.chmod(ca, 0o700)

    def as_other_account(self):
        # This process stands for a service account that owns none of the
        # paths (it cannot chown as non-root): only write access decides.
        uid = os.geteuid() + 4242
        return (patch("app.deployment.os.geteuid", return_value=uid),
                patch("app.deployment.os.getegid", return_value=uid),
                patch("app.deployment.os.getgroups", return_value=[]))

    def test_service_writable_parent_is_exposed_even_when_access_is_denied(self):
        parent = self.root / "shared"
        parent.mkdir()
        os.chmod(parent, 0o777)  # writable by the service, not sticky
        ca = parent / "ca"
        ca.mkdir(mode=0o700)
        os.chmod(ca, 0)
        first, second, third = self.as_other_account()
        try:
            with first, second, third:
                self.assertEqual((True, True, True), self.probes(ca))
                # A sticky ancestor (like /tmp) cannot have its entries
                # replaced: with nothing else controlled, the closed CA is
                # not exposed (as root the open itself would succeed).
                os.chmod(parent, 0o1777)
                if os.getuid() != 0:
                    self.assertEqual((False, False, False), self.probes(ca))
        finally:
            os.chmod(ca, 0o700)

    def test_service_writable_ca_file_is_exposed(self):
        ca = self.root / "ca"
        ca.mkdir(mode=0o755)
        (ca / "issuance-log.jsonl").write_text("{}\n")
        os.chmod(ca / "issuance-log.jsonl", 0o666)
        first, second, third = self.as_other_account()
        with first, second, third:
            self.assertTrue(capture_ca_directory_accessible(ca))
            os.chmod(ca / "issuance-log.jsonl", 0o600)
            # Still exposed: the directory itself can be opened.
            self.assertTrue(capture_ca_directory_accessible(ca))


class InitRecoveryTests(unittest.TestCase):
    """Codex P2 (PR #177): a lost ``commit`` reply leaves a recoverable state."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="capture-init-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        os.chmod(self.root, 0o700)
        self.privileges = issuer_fakes.install(self)
        self.authority = self.root / "ca"
        self.listener = self.root / "listener"

    def init(self, server_name=SERVER_NAME):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            status = pairing_cli.main(["init", "--authority-dir", str(self.authority),
                                       "--listener-dir", str(self.listener),
                                       "--server-name", server_name])
        return status, stdout.getvalue(), stderr.getvalue()

    def ca_state(self):
        return {name: (self.authority / name).read_bytes()
                for name in ("ca-key.pem", "ca-certificate.pem")}

    def log_types(self):
        return [json.loads(line)["type"] for line in
                (self.authority / ISSUANCE_LOG).read_text().splitlines()]

    def lose_commit_reply(self):
        real = issuer_fakes.InProcessIssuer.request

        def request(issuer, message):
            reply = real(issuer, message)
            if message.get("op") == "commit":
                raise IssuerUnavailable("synthetic: commit reply lost")
            return reply
        return patch.object(issuer_fakes.InProcessIssuer, "request", request)

    def test_rerun_after_a_lost_commit_reply_keeps_the_ca_and_completes(self):
        with self.lose_commit_reply():
            status, stdout, stderr = self.init()
        self.assertEqual(2, status)
        self.assertIn("refused: issuer_unavailable", stderr)
        # The CA was committed; the listener side removed its own files.
        kept = self.ca_state()
        deployment = node_ca.deployment_id_of(PrivateDirectory(self.authority))
        self.assertEqual([], os.listdir(self.listener))
        status, stdout, stderr = self.init()
        self.assertEqual(0, status, stderr)
        self.assertEqual(f"deployment_id={deployment}\n", stdout)
        self.assertIn("init recovered", stderr)
        self.assertEqual(kept, self.ca_state(), "CA material is never replaced")
        self.assertEqual(["deployment_ca", "listener", "listener"], self.log_types())
        trust = DeploymentTrust.load_public(PrivateDirectory(self.listener))
        self.assertEqual(deployment, trust.deployment_id)
        trust.issued_listener_certificate(PrivateDirectory(self.listener))
        # A further rerun is a no-op that reports the same deployment.
        before = {name: (self.listener / name).read_bytes() for name in os.listdir(self.listener)}
        status, stdout, stderr = self.init()
        self.assertEqual((0, f"deployment_id={deployment}\n"), (status, stdout), stderr)
        self.assertIn("init already complete", stderr)
        self.assertEqual(before, {name: (self.listener / name).read_bytes()
                                  for name in os.listdir(self.listener)})
        self.assertEqual(kept, self.ca_state())

    def test_recovery_refuses_another_server_name_and_never_touches_the_ca(self):
        with self.lose_commit_reply():
            self.init()
        kept = self.ca_state()
        status, stdout, stderr = self.init("other.serversentinel.test")
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("refused: issuer_refused_request", stderr)
        self.assertEqual([], os.listdir(self.listener))
        self.assertEqual(kept, self.ca_state())

    def test_a_listener_of_another_ca_is_refused_without_changes(self):
        self.assertEqual(0, self.init()[0])
        other = DeploymentAuthority.create(PrivateDirectory(self.root / "other-ca"), uuid4(),
                                           validity=3650 * DAY)
        foreign = self.root / "foreign-listener"
        other.issue_main_server_credential(PrivateDirectory(foreign), server_name=SERVER_NAME,
                                           validity=30 * DAY)
        before = {name: (foreign / name).read_bytes() for name in os.listdir(foreign)}
        self.listener = foreign
        status, _stdout, stderr = self.init()
        self.assertEqual(2, status)
        self.assertIn("refused: listener_authority_mismatch", stderr)
        self.assertEqual(before, {name: (foreign / name).read_bytes()
                                  for name in os.listdir(foreign)})


class InterruptedListenerWriteTests(InitRecoveryTests):
    """Codex P2 (PR #177, round 3): any partial listener write is redone; a
    complete credential is never removed."""

    def complete_files(self):
        self.assertEqual(0, self.init()[0])
        return {name: (self.listener / name).read_bytes() for name in
                ("deployment-ca-certificate.pem", "main-server-certificate.pem",
                 "main-server-key.pem")}

    def build(self, files, entries):
        self.listener = self.root / f"listener-{uuid4()}"
        directory = PrivateDirectory(self.listener).ensure()
        for entry in entries:
            if " = " in entry:  # second name on the same inode
                staged, final = entry.split(" = ")
                os.link(self.listener / final, self.listener / staged)
                continue
            final = entry[:-len(".init")] if entry.endswith(".init") else entry
            directory.write_new(entry, files[final])

    def test_every_incomplete_subset_is_cleaned_and_redone(self):
        files = self.complete_files()
        kept = self.ca_state()
        cases = (
            ["deployment-ca-certificate.pem.init"],
            ["deployment-ca-certificate.pem.init", "main-server-certificate.pem.init"],
            ["deployment-ca-certificate.pem.init", "main-server-certificate.pem.init",
             "main-server-key.pem.init"],
            ["deployment-ca-certificate.pem", "main-server-certificate.pem.init",
             "main-server-key.pem.init"],
            ["deployment-ca-certificate.pem"],
            ["deployment-ca-certificate.pem", "main-server-certificate.pem"],
            ["deployment-ca-certificate.pem", "main-server-certificate.pem",
             "main-server-key.pem.init"],
            ["deployment-ca-certificate.pem", "main-server-certificate.pem",
             "main-server-certificate.pem.init = main-server-certificate.pem",
             "main-server-key.pem.init"],
            ["main-server-certificate.pem"],
        )
        for entries in cases:
            with self.subTest(entries=entries):
                self.build(files, entries)
                status, stdout, stderr = self.init()
                self.assertEqual(0, status, stderr)
                self.assertIn("removed an incomplete listener credential", stderr)
                self.assertIn("init recovered", stderr)
                self.assertEqual(sorted(files), sorted(os.listdir(self.listener)))
                trust = DeploymentTrust.load_public(PrivateDirectory(self.listener))
                trust.issued_listener_certificate(PrivateDirectory(self.listener))
                self.assertEqual(kept, self.ca_state())

    def test_a_complete_credential_is_never_removed(self):
        files = self.complete_files()
        for extra in ([], ["main-server-key.pem.init = main-server-key.pem"]):
            with self.subTest(extra=extra):
                self.build(files, sorted(files) + extra)
                status, stdout, stderr = self.init()
                self.assertEqual(0, status, stderr)
                self.assertIn("init already complete", stderr)
                self.assertEqual(files, {name: (self.listener / name).read_bytes()
                                         for name in os.listdir(self.listener)})

    def test_writer_stops_at_every_step_and_the_rerun_completes(self):
        # A real interruption of write_listener_credential after each staged
        # write and each install (no rollback runs, as after a crash).
        steps = []
        real_write, real_install = PrivateDirectory.write_new, PrivateDirectory.install_new

        class Stop(BaseException):
            pass

        def stop_after(limit):
            def counting(function):
                def wrapper(directory, *args):
                    result = function(directory, *args)
                    if directory.path == self.listener and args[0].startswith(("main-", "deployment-")):
                        steps.append(args)
                        if len(steps) == limit:
                            raise Stop()
                    return result
                return wrapper
            return counting
        for limit in range(1, 6):
            with self.subTest(limit=limit):
                steps.clear()
                self.authority = self.root / f"ca-{limit}"
                self.listener = self.root / f"listener-{limit}"
                counting = stop_after(limit)
                with patch.object(PrivateDirectory, "write_new", counting(real_write)), \
                        patch.object(PrivateDirectory, "install_new", counting(real_install)), \
                        patch.object(PrivateDirectory, "discard_created", lambda *args: None), \
                        self.assertRaises(Stop):
                    self.init()
                status, _stdout, stderr = self.init()
                self.assertEqual(0, status, stderr)
                trust = DeploymentTrust.load_public(PrivateDirectory(self.listener))
                trust.issued_listener_certificate(PrivateDirectory(self.listener))


class PublicCopyValidationTests(Harness):
    """Codex P2 (PR #177): a wrong --authority-dir never leaves its CA copy behind."""

    def setUp(self):
        super().setUp()
        self.privileges = issuer_fakes.install(self)
        # A listener directory written before Issue #109: no public copy.
        (self.listener_dir / "deployment-ca-certificate.pem").unlink()
        self.other_dir = self.root / "other-ca"
        DeploymentAuthority.create(PrivateDirectory(self.other_dir), uuid4(),
                                   validity=3650 * DAY)

    def rotate(self, authority):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            status = pairing_cli.main(["rotate-listener", "--authority-dir", str(authority),
                                       "--listener-dir", str(self.listener_dir)])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_wrong_authority_is_refused_before_the_copy_is_written(self):
        before = {name: (self.listener_dir / name).read_bytes()
                  for name in os.listdir(self.listener_dir)}
        status, _stdout, stderr = self.rotate(self.other_dir)
        self.assertEqual(2, status)
        self.assertIn("refused: listener_authority_mismatch", stderr)
        self.assertEqual(before, {name: (self.listener_dir / name).read_bytes()
                                  for name in os.listdir(self.listener_dir)})
        # The correct authority then still works, and publishes the copy.
        status, stdout, stderr = self.rotate(self.authority_dir)
        self.assertEqual(0, status, stderr)
        self.assertEqual(self.trust.ca_certificate_pem(),
                         (self.listener_dir / "deployment-ca-certificate.pem").read_bytes())

    def test_wrong_authority_during_interrupted_rotation_recovery_writes_nothing(self):
        directory = PrivateDirectory(self.listener_dir)
        directory.write_new("main-server-key.pem.next", b"stale")
        directory.write_new("main-server-certificate.pem.next", b"stale")
        status, _stdout, stderr = self.rotate(self.other_dir)
        self.assertEqual(2, status)
        self.assertFalse((self.listener_dir / "deployment-ca-certificate.pem").exists())
        self.assertTrue((self.listener_dir / "main-server-key.pem.next").exists())


class CaptureCaSettingTests(unittest.TestCase):
    """Owner decision 2026-10-07: ``capture_ca_directory`` must be present (path or null)."""

    def run_check(self, value):
        from app import deployment
        stderr = io.StringIO()
        with patch.object(deployment, "_runtime_roots", return_value=(Path("/nonexistent"), None)), \
                patch.object(deployment, "_read_configuration",
                             return_value=(value, Path(__file__).stat())), \
                patch("sys.stderr", stderr), self.assertRaises(SystemExit) as stopped:
            deployment.main(["--config", "/unused", "--check"])
        return stopped.exception.code, stderr.getvalue()

    def test_missing_setting_is_refused_with_its_reason(self):
        base = {"runtime_root": "/srv/x", "runtime_mount_point": "/srv", "runtime_device": [8, 1],
                "runtime_filesystem_uuid": "00000000-1111-2222-3333-444444444444",
                "service_uid": 991, "human_host": "127.0.0.1", "human_port": 880,
                "log_level": "INFO"}
        code, stderr = self.run_check(dict(base))
        self.assertEqual(1, code)
        self.assertIn("capture_ca_directory is required", stderr)
        self.assertIn("or null", stderr)
        # Present (null or a path): this check passes and later ones decide.
        for value in (None, "/var/lib/serversentinel-ca"):
            with self.subTest(value=value):
                code, stderr = self.run_check(dict(base, capture_ca_directory=value))
                self.assertEqual(1, code)
                self.assertNotIn("capture_ca_directory is required", stderr)


if __name__ == "__main__":
    unittest.main()
