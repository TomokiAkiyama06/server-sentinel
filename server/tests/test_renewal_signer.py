"""Renewal-only capture-node signer (Issue #109 PR2).

Covers the CA-side decision from the chain and the CA-only issuance log
(only ``renew`` requests; logged, current, unsuperseded, unrevoked and due
certificates; fresh keys; rate limits; fail-closed log and lock handling),
the service-side ``SignerRenewalIssuer`` (public trust only, verified
answers, fixed refusal words), a real Unix-socket conversation with the
``SO_PEERCRED`` check, ``renew_node_credential`` end to end with the ledger,
a memory scan showing the CA key never enters the requesting process, and
the ``renewal-signer`` CLI entry. Two real accounts are covered by
``test_ca_privilege_separation_root`` (root only). All keys, CAs and nodes
are generated per test.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
import datetime
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.audit.store import AuditStore
from app.cameras.remote_agent import renewal_signer
from app.cameras.remote_agent.ingest_tls import CaptureNodeAdmission, CaptureNodeIdentity
from app.cameras.remote_agent.issuer_process import (
    ISSUANCE_LOG, CaIssuer, IssuanceLog, read_frame, write_frame,
)
from app.cameras.remote_agent.node_ca import (
    AuthorityValidityExceeded, CaptureAuthorityError, DeploymentAuthority, DeploymentTrust,
    IssuanceLogUnavailable, PrivateDirectory, certificate_digest, public_key_digest,
)
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.cameras.remote_agent.renewal import RenewalRefused, renew_node_credential
from app.cameras.remote_agent.renewal_signer import (
    MAX_DEPLOYMENT_RENEWALS_PER_DAY, MAX_NODE_RENEWALS, MIN_NODE_RENEWAL_INTERVAL,
    RenewalSigner, RenewalSignerRefused, RenewalSignerUnavailable, SignerRenewalIssuer,
    serve_connection,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


DAY = datetime.timedelta(days=1)
SERVER_ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "capture-main.serversentinel.test"


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class Clock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class Owner:
    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


def renewal_csr(key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(
        key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM)


class SignerHarness(unittest.TestCase):
    """A CA created 400 days ago; nodes enrolled 380 days ago are due (17 days left)."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="capture-renewal-signer-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        os.chmod(self.root, 0o700)
        self.now = utc_now()
        self.deployment = uuid4()
        self.authority_dir = self.root / "ca"
        self.authority = DeploymentAuthority.create(
            PrivateDirectory(self.authority_dir), self.deployment, validity=3650 * DAY,
            clock=Clock(self.now - 400 * DAY))
        # The service side verifies with the real clock.
        self.trust = DeploymentTrust.from_certificate_pem(self.authority.ca_certificate_pem())
        self.clock = Clock(self.now)
        self.signer = RenewalSigner(PrivateDirectory(self.authority_dir), clock=self.clock,
                                    lock_wait=0.2)

    def enroll(self, node=None, key=None, *, days_ago=380):
        """Sign and log one node leaf through the PR1 CA-account issuer."""
        node = node or uuid4()
        key, csr = renewal_csr(key)
        issuer = CaIssuer(PrivateDirectory(self.authority_dir),
                          clock=Clock(self.now - days_ago * DAY))
        try:
            self.assertEqual("ok", issuer.handle({"op": "hello"})["status"])
            reply = issuer.handle({"op": "sign_node", "node_id": str(node), "csr": csr.decode(),
                                   "public_key_digest": public_key_digest(key.public_key())})
        finally:
            issuer.close()
        self.assertEqual("ok", reply["status"], reply)
        return node, reply["certificate"], key

    def revoke(self, node):
        issuer = CaIssuer(PrivateDirectory(self.authority_dir))
        try:
            issuer.handle({"op": "hello"})
            self.assertEqual("ok", issuer.handle({"op": "revoke", "node_id": str(node)})["status"])
        finally:
            issuer.close()

    def request(self, node, certificate, csr):
        return {"op": "renew", "node_id": str(node), "current_certificate": certificate,
                "csr": csr.decode() if isinstance(csr, bytes) else csr}

    def renew(self, node, certificate, key=None):
        key, csr = renewal_csr(key)
        return self.signer.handle(self.request(node, certificate, csr)), key

    def records(self):
        path = self.authority_dir / ISSUANCE_LOG
        return [json.loads(line) for line in path.read_text().splitlines()]

    def refused(self, reply, reason="issuer_refused_request"):
        self.assertEqual({"status": "refused", "reason": reason}, reply)


class SignerDecisionTests(SignerHarness):
    def test_renews_a_logged_due_certificate_with_the_fixed_profile_and_logs_it(self):
        node, certificate, _ = self.enroll()
        before = len(self.records())
        reply, key = self.renew(node, certificate)
        self.assertEqual({"status", "certificate"}, set(reply))
        issued = self.trust.verify_issued_node_certificate(
            reply["certificate"].encode(), node_id=node,
            public_key_digest_value=public_key_digest(key.public_key()))
        leaf = x509.load_pem_x509_certificate(issued.certificate_pem)
        usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertEqual([ExtendedKeyUsageOID.CLIENT_AUTH], list(usages))
        self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertAlmostEqual(397 * DAY.total_seconds(),
                               (issued.not_after - self.now).total_seconds(), delta=1)
        (record,) = self.records()[before:]
        presented = certificate_digest(x509.load_pem_x509_certificate(certificate.encode()))
        self.assertEqual({"type": "node", "node_id": str(node),
                          "public_key_digest": issued.public_key_digest,
                          "credential_digest": issued.credential_digest,
                          "renewal_of": presented},
                         {name: record[name] for name in ("type", "node_id", "public_key_digest",
                                                          "credential_digest", "renewal_of")})
        self.assertNotIn("PRIVATE", json.dumps(reply))

    def test_accepts_only_the_renew_request_with_exactly_its_fields(self):
        node, certificate, key = self.enroll()
        _, csr = renewal_csr()
        valid = self.request(node, certificate, csr)
        before = self.records()
        for message in ({"op": "hello"},
                        {"op": "sign_node", "node_id": str(node), "csr": csr.decode(),
                         "public_key_digest": public_key_digest(key.public_key())},
                        {"op": "sign_listener", "csr": csr.decode(), "server_name": SERVER_NAME,
                         "validity_days": 30},
                        {"op": "initialize"}, {"op": "revoke", "node_id": str(node)},
                        {"op": "commit"}, dict(valid, op="sign_node"),
                        dict(valid, validity_days=3650), dict(valid, server_name=SERVER_NAME),
                        {name: value for name, value in valid.items() if name != "csr"},
                        dict(valid, node_id=node.hex), dict(valid, csr=7), [valid], None):
            with self.subTest(message=str(message)[:60]):
                self.refused(self.signer.handle(message))
        self.assertEqual(before, self.records())

    def test_presented_certificate_must_be_this_cas_logged_current_leaf_for_that_node(self):
        node, certificate, _ = self.enroll()
        other, other_certificate, _ = self.enroll()
        # Signed by this CA but never logged (as before Issue #109).
        unlogged = DeploymentAuthority.load(PrivateDirectory(self.authority_dir), self.deployment,
                                            clock=Clock(self.now - 380 * DAY))
        _, csr = renewal_csr()
        silent = unlogged.issue_renewal_certificate(node, csr).certificate_pem.decode()
        foreign_dir = self.root / "foreign"
        foreign = DeploymentAuthority.create(PrivateDirectory(foreign_dir), self.deployment,
                                             validity=3650 * DAY,
                                             clock=Clock(self.now - 400 * DAY))
        foreign = DeploymentAuthority.load(PrivateDirectory(foreign_dir), self.deployment,
                                           clock=Clock(self.now - 380 * DAY))
        _, csr = renewal_csr()
        alien = foreign.issue_renewal_certificate(node, csr).certificate_pem.decode()
        listener_dir = self.root / "listener"
        self.authority.issue_main_server_credential(PrivateDirectory(listener_dir),
                                                    server_name=SERVER_NAME, validity=10 * DAY)
        listener = (listener_dir / "main-server-certificate.pem").read_text()
        ca = self.trust.ca_certificate_pem().decode()
        before = self.records()
        for presented, claimed in ((silent, node), (alien, node), (listener, node), (ca, node),
                                   (other_certificate, node), (certificate, other),
                                   ("-" * 5 + "BEGIN CERTIFICATE" + "-" * 5 + "\n", node)):
            with self.subTest(claimed=claimed == node):
                reply, _ = self.renew(claimed, presented)
                self.refused(reply)
        self.assertEqual(before, self.records())

    def test_expired_or_not_yet_due_certificates_are_not_renewed(self):
        node, certificate, _ = self.enroll(days_ago=398)
        reply, _ = self.renew(node, certificate)
        self.refused(reply)
        fresh, fresh_certificate, _ = self.enroll(days_ago=300)
        reply, _ = self.renew(fresh, fresh_certificate)
        self.refused(reply, "renewal_not_due")
        # 31 days before expiry is the earliest moment (Agent window + 1 day).
        due, due_certificate, _ = self.enroll(days_ago=397 - 31 + 1)
        reply, _ = self.renew(due, due_certificate)
        self.assertEqual("ok", reply["status"], reply)

    def test_revoked_node_is_refused_from_the_issuance_log(self):
        node, certificate, _ = self.enroll()
        self.revoke(node)
        reply, _ = self.renew(node, certificate)
        self.refused(reply)

    def test_superseded_certificate_cannot_renew(self):
        node, old, key = self.enroll()
        # A later enrollment of the same node (re-approval) supersedes it.
        _, newer, _ = self.enroll(node, days_ago=379)
        reply, _ = self.renew(node, old)
        self.refused(reply)
        # So does a renewal of the newer certificate: the older one is then
        # two steps behind, never a sibling retry.
        reply, _ = self.renew(node, newer)
        self.assertEqual("ok", reply["status"])
        self.clock.value += MIN_NODE_RENEWAL_INTERVAL
        reply, _ = self.renew(node, old)
        self.refused(reply)

    def test_sibling_renewals_of_one_parent_each_stay_renewable(self):
        # Two same-key requests signed B1 and B2 (both renewing A) before
        # either was staged; the ledger keeps one of them (Codex P2, PR #420).
        node, parent, _ = self.enroll()
        first, key = self.renew(node, parent)
        second, _ = self.renew(node, parent, key)
        self.assertEqual(("ok", "ok"), (first["status"], second["status"]))
        b1, b2 = first["certificate"], second["certificate"]
        path = self.authority_dir / ISSUANCE_LOG
        siblings = path.read_bytes()
        self.clock.value = self.now + 370 * DAY  # B1 and B2 are now due.
        for kept in (b1, b2):
            with self.subTest(kept=kept == b1):
                path.write_bytes(siblings)
                reply, _ = self.renew(node, kept)
                self.assertEqual("ok", reply["status"], reply)
        # Once B2 is renewed to C, B1 (a renewal of A, not of B2) is superseded.
        path.write_bytes(siblings)
        reply, _ = self.renew(node, b2)
        self.assertEqual("ok", reply["status"])
        self.clock.value += MIN_NODE_RENEWAL_INTERVAL
        reply, _ = self.renew(node, b1)
        self.refused(reply)
        # A re-enrollment of the node supersedes every sibling.
        path.write_bytes(siblings)
        self.enroll(node, days_ago=-1)
        for kept in (b1, b2):
            with self.subTest(repaired=kept == b1):
                reply, _ = self.renew(node, kept)
                self.refused(reply)

    def test_a_sibling_key_is_not_fresh_for_the_other_sibling(self):
        # B1 and B2 renew A with different keys (an answer lost, then a new
        # key): B1 cannot renew to B2's key, a key the log gave a sibling.
        node, parent, _ = self.enroll()
        first, _ = self.renew(node, parent)
        self.clock.value += MIN_NODE_RENEWAL_INTERVAL
        second, second_key = self.renew(node, parent)
        self.assertEqual(("ok", "ok"), (first["status"], second["status"]))
        self.clock.value = self.now + 370 * DAY
        reply, _ = self.renew(node, first["certificate"], second_key)
        self.refused(reply)
        reply, _ = self.renew(node, first["certificate"])
        self.assertEqual("ok", reply["status"])

    def test_a_lost_answer_may_be_asked_again_with_the_same_certificate(self):
        node, certificate, _ = self.enroll()
        first, key = self.renew(node, certificate)
        self.assertEqual("ok", first["status"])
        # Owner decision 2026-11-16: the same key (an answer lost after
        # signing) is re-signed at once, without the 50-minute interval ...
        reply, _ = self.renew(node, certificate, key)
        self.assertEqual("ok", reply["status"], reply)
        # ... and is counted: the log now holds two renewals.
        self.assertEqual(2, sum("renewal_of" in record for record in self.records()))
        # A different key inside the interval is still rate-limited.
        reply, _ = self.renew(node, certificate)
        self.refused(reply, "renewal_rate_limited")
        self.clock.value += MIN_NODE_RENEWAL_INTERVAL
        reply, _ = self.renew(node, certificate)
        self.assertEqual("ok", reply["status"])

    def test_a_same_key_retry_still_counts_and_is_refused_at_the_caps(self):
        node, certificate, _ = self.enroll()
        first, key = self.renew(node, certificate)
        self.assertEqual("ok", first["status"])
        renewed = certificate_digest(x509.load_pem_x509_certificate(certificate.encode()))
        log = IssuanceLog(PrivateDirectory(self.authority_dir), clock=self.clock)

        def synthetic(owner, at):
            log._clock = Clock(at)
            log.append({"type": "node", "node_id": str(owner),
                        "public_key_digest": os.urandom(32).hex(),
                        "credential_digest": os.urandom(32).hex(),
                        "not_after": self.now.isoformat(), "renewal_of": renewed})

        # The per-node 30-day cap (one real renewal plus 47 synthetic ones).
        for index in range(MAX_NODE_RENEWALS - 1):
            synthetic(node, self.now - 29 * DAY + index * datetime.timedelta(hours=1))
        reply, _ = self.renew(node, certificate, key)
        self.refused(reply, "renewal_rate_limited")
        # The deployment-wide daily cap refuses a retry of another node too.
        second, second_certificate, _ = self.enroll()
        reply, second_key = self.renew(second, second_certificate)
        self.assertEqual("ok", reply["status"])
        for _ in range(MAX_DEPLOYMENT_RENEWALS_PER_DAY - 1):
            synthetic(uuid4(), self.now - datetime.timedelta(hours=2))
        reply, _ = self.renew(second, second_certificate, second_key)
        self.refused(reply, "renewal_rate_limited")

    def test_new_key_must_be_fresh_at_the_issuer(self):
        node, certificate, key = self.enroll()
        other, _, other_key = self.enroll()
        revoked, _, revoked_key = self.enroll()
        self.revoke(revoked)
        older_node, older, older_key = self.enroll(days_ago=385)
        self.enroll(older_node, days_ago=381)
        for reused in (key, other_key, revoked_key, older_key):
            with self.subTest():
                reply, _ = self.renew(node, certificate, reused)
                self.refused(reply)

    def test_per_node_and_deployment_rate_limits_come_from_the_log(self):
        node, certificate, _ = self.enroll()
        log = IssuanceLog(PrivateDirectory(self.authority_dir), clock=self.clock)
        # Earlier renewals of this same certificate (lost answers), so only
        # the counts refuse, not supersession.
        renewed = certificate_digest(x509.load_pem_x509_certificate(certificate.encode()))

        def synthetic(owner, at):
            log._clock = Clock(at)
            log.append({"type": "node", "node_id": str(owner),
                        "public_key_digest": os.urandom(32).hex(),
                        "credential_digest": os.urandom(32).hex(),
                        "not_after": self.now.isoformat(), "renewal_of": renewed})

        for index in range(MAX_NODE_RENEWALS):
            synthetic(node, self.now - 29 * DAY + index * datetime.timedelta(hours=1))
        reply, _ = self.renew(node, certificate)
        self.refused(reply, "renewal_rate_limited")
        # Another node is limited by the deployment-wide daily cap.
        second, second_certificate, _ = self.enroll()
        for _ in range(MAX_DEPLOYMENT_RENEWALS_PER_DAY):
            synthetic(uuid4(), self.now - datetime.timedelta(hours=2))
        reply, _ = self.renew(second, second_certificate)
        self.refused(reply, "renewal_rate_limited")
        self.clock.value += DAY
        reply, _ = self.renew(second, second_certificate)
        self.assertEqual("ok", reply["status"], reply)

    def test_a_record_time_ahead_of_the_clock_counts_as_recent(self):
        node, certificate, _ = self.enroll()
        reply, _ = self.renew(node, certificate)
        self.assertEqual("ok", reply["status"])
        self.clock.value -= DAY
        reply, _ = self.renew(node, certificate)
        self.refused(reply, "renewal_rate_limited")

    def test_unwritable_or_damaged_log_signs_nothing(self):
        node, certificate, _ = self.enroll()
        with patch.object(IssuanceLog, "append",
                          side_effect=IssuanceLogUnavailable("synthetic")):
            reply, _ = self.renew(node, certificate)
        self.refused(reply, "issuance_log_unavailable")
        path = self.authority_dir / ISSUANCE_LOG
        good = path.read_bytes()
        for damage in (b'{"format":1,"type":"node","node_id":"%s","public_key_digest":"%s",'
                       b'"renewal_of":"x"}\n' % (str(node).encode(), b"a" * 64),
                       b"not json\n"):
            with self.subTest(damage=damage[:20]):
                path.write_bytes(good + damage)
                reply, _ = self.renew(node, certificate)
                self.refused(reply, "issuance_log_unavailable")
        path.write_bytes(good)
        reply, _ = self.renew(node, certificate)
        self.assertEqual("ok", reply["status"])

    def test_waits_briefly_for_the_ca_lock_then_refuses_busy(self):
        node, certificate, _ = self.enroll()
        with PrivateDirectory(self.authority_dir).locked():
            reply, _ = self.renew(node, certificate)
        self.refused(reply, "issuer_material_busy")
        # A pairing CLI conversation that ends within the wait lets it through.
        holder = ExitStack()
        holder.enter_context(PrivateDirectory(self.authority_dir).locked())
        self.addCleanup(holder.close)
        signer = RenewalSigner(PrivateDirectory(self.authority_dir), clock=self.clock,
                               lock_wait=5.0, sleep=lambda _: holder.close())
        reply = signer.handle(self.request(node, certificate, renewal_csr()[1]))
        self.assertEqual("ok", reply["status"], reply)

    def test_ca_too_close_to_expiry_keeps_its_dedicated_word(self):
        # 380 days of CA left: the node leaf (17 days left) is due, but a new
        # 397-day leaf would outlive the CA (Issue #127).
        short_dir = self.root / "short"
        DeploymentAuthority.create(PrivateDirectory(short_dir), self.deployment,
                                   validity=780 * DAY, clock=Clock(self.now - 400 * DAY))
        self.authority_dir = short_dir
        node, certificate, _ = self.enroll()
        self.signer = RenewalSigner(PrivateDirectory(short_dir), clock=self.clock)
        before = self.records()
        reply, _ = self.renew(node, certificate)
        self.refused(reply, "deployment_ca_validity_insufficient")
        self.assertEqual(before, self.records())


class SocketHarness(SignerHarness):
    """A real listening Unix socket served once by ``serve_connection``; no tests."""

    def serve_once(self, *, service_uid):
        directory = self.root / "socket"
        directory.mkdir(mode=0o700)
        path = directory / "signer.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        self.addCleanup(listener.close)
        outcome = []

        def accept():
            connection, _ = listener.accept()
            with connection:
                outcome.append(serve_connection(connection, self.signer, service_uid=service_uid))
        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 10)
        return path, outcome, thread

    def identity(self, certificate):
        der = x509.load_pem_x509_certificate(certificate.encode()).public_bytes(
            serialization.Encoding.DER)
        leaf = x509.load_der_x509_certificate(der)
        node = UUID([uri for uri in leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
            if "capture-node" in uri][0].rsplit(":", 1)[1])
        return CaptureNodeIdentity(node_id=node, public_key_digest=public_key_digest(
            leaf.public_key()), credential_digest=certificate_digest(leaf),
            not_valid_after=leaf.not_valid_after_utc), der

    @staticmethod
    def replying(answer):
        def connect(path, timeout):
            ours, theirs = socket.socketpair()

            def respond():
                with theirs:
                    read_frame(theirs.fileno(), timeout=5)
                    write_frame(theirs.fileno(), answer)
            threading.Thread(target=respond, daemon=True).start()
            return ours
        return connect


class PeerSocketTests(SocketHarness):
    def test_service_account_peer_gets_a_verified_renewal(self):
        node, certificate, _ = self.enroll()
        path, outcome, thread = self.serve_once(service_uid=os.getuid())
        identity, der = self.identity(certificate)
        issuer = SignerRenewalIssuer(self.trust, identity, der, socket_path=path)
        key, csr = renewal_csr()
        issued = issuer.issue_renewal_certificate(node, csr)
        thread.join(10)
        self.assertEqual(["signed"], outcome)
        self.assertEqual(public_key_digest(key.public_key()), issued.public_key_digest)

    def test_other_peer_uid_is_refused_before_the_request_is_read(self):
        node, certificate, _ = self.enroll()
        path, outcome, thread = self.serve_once(service_uid=os.getuid() + 1)
        identity, der = self.identity(certificate)
        issuer = SignerRenewalIssuer(self.trust, identity, der, socket_path=path)
        before = self.records()
        with self.assertRaises(RenewalSignerRefused) as raised:
            issuer.issue_renewal_certificate(node, renewal_csr()[1])
        thread.join(10)
        self.assertEqual("renewal_signer_peer_refused", raised.exception.detail)
        self.assertEqual(["renewal_signer_peer_refused"], outcome)
        self.assertEqual(before, self.records())

    def test_missing_signer_and_bad_answers_are_unavailable(self):
        node, certificate, _ = self.enroll()
        identity, der = self.identity(certificate)
        issuer = SignerRenewalIssuer(self.trust, identity, der,
                                     socket_path=self.root / "absent.sock")
        with self.assertRaises(RenewalSignerUnavailable):
            issuer.issue_renewal_certificate(node, renewal_csr()[1])
        # An answer that is not a leaf for the requested key never verifies.
        other_key, other_csr = renewal_csr()
        signed = self.signer.handle(self.request(node, certificate, other_csr))
        for answer in ({"status": "ok", "certificate": signed["certificate"]},
                       {"status": "ok", "certificate": self.trust.ca_certificate_pem().decode()},
                       {"status": "ok"}, {"status": "refused", "reason": "../../etc"}):
            with self.subTest(answer=str(answer)[:30]):
                fake = SignerRenewalIssuer(self.trust, identity, der,
                                           connect=self.replying(answer))
                with self.assertRaises(RenewalSignerUnavailable):
                    fake.issue_renewal_certificate(node, renewal_csr()[1])
        validity = SignerRenewalIssuer(self.trust, identity, der, connect=self.replying(
            {"status": "refused", "reason": "deployment_ca_validity_insufficient"}))
        with self.assertRaises(AuthorityValidityExceeded):
            validity.issue_renewal_certificate(node, renewal_csr()[1])

    def test_service_side_holds_only_public_trust_for_its_own_session(self):
        node, certificate, _ = self.enroll()
        _, other_certificate, _ = self.enroll()
        identity, der = self.identity(certificate)
        _, other_der = self.identity(other_certificate)
        with self.assertRaises(ValueError):
            SignerRenewalIssuer(self.authority, identity, der)
        with self.assertRaises(ValueError):
            SignerRenewalIssuer(self.trust, identity, other_der)
        issuer = SignerRenewalIssuer(self.trust, identity, der, connect=self.replying({}))
        self.assertFalse(hasattr(issuer, "_private_key"))
        with self.assertRaises(CaptureAuthorityError):
            issuer.issue_renewal_certificate(uuid4(), renewal_csr()[1])
        with self.assertRaises(CaptureAuthorityError):
            issuer.issue_renewal_certificate(node, renewal_csr()[1], validity=30 * DAY)


class LedgerRenewalTests(SocketHarness):
    """``renew_node_credential`` with the signer: ledger rules in the service, CA rules in the signer."""

    def test_renewal_end_to_end_stages_and_promotes_the_signer_certificate(self):
        database = Database(self.root / "state.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)),
                               audit=AuditStore(database))
        node, certificate, key = self.enroll()
        digest = public_key_digest(key.public_key())
        approval, code = ledger.approve(Owner(), "owner", node_id=node, public_key_digest=digest)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest=digest,
                              code=code.value)
        identity, der = self.identity(certificate)
        ledger.activate(claim, credential_serial_digest=identity.credential_digest,
                        not_after=identity.not_valid_after.timestamp())
        admission = CaptureNodeAdmission(ledger, self.deployment)
        self.assertTrue(admission.is_admitted(identity))
        path, outcome, thread = self.serve_once(service_uid=os.getuid())
        issuer = SignerRenewalIssuer(self.trust, identity, der, socket_path=path)
        new_key, csr = renewal_csr()
        renewed = renew_node_credential(issuer, ledger, admission, identity, csr)
        thread.join(10)
        self.assertEqual(["signed"], outcome)
        # A same-key retry is answered from the ledger without the signer.
        retried = renew_node_credential(
            SignerRenewalIssuer(self.trust, identity, der, socket_path=self.root / "none"),
            ledger, admission, identity, csr)
        self.assertEqual(renewed.certificate_pem, retried.certificate_pem)
        renewed_der = x509.load_pem_x509_certificate(renewed.certificate_pem).public_bytes(
            serialization.Encoding.DER)
        self.assertTrue(admission.is_admitted(admission.identify(renewed_der)))
        self.assertFalse(admission.is_admitted(identity))
        # A fresh key with an unreachable signer is an Owner-visible refusal.
        with self.assertRaises(RenewalRefused) as raised:
            renew_node_credential(
                SignerRenewalIssuer(self.trust, admission.identify(renewed_der), renewed_der,
                                    socket_path=self.root / "none"),
                ledger, admission, admission.identify(renewed_der), renewal_csr()[1])
        self.assertEqual("renewal_signer_unavailable", raised.exception.reason)


_CLIENT = r"""
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from app.cameras.remote_agent.ingest_tls import CaptureNodeIdentity
from app.cameras.remote_agent.node_ca import DeploymentTrust, certificate_digest, public_key_digest
from app.cameras.remote_agent.renewal_signer import SignerRenewalIssuer
from uuid import UUID

socket_path, ca_path, presented_path, csr_path, node = sys.argv[1:6]
trust = DeploymentTrust.from_certificate_pem(Path(ca_path).read_bytes())
leaf = x509.load_pem_x509_certificate(Path(presented_path).read_bytes())
der = leaf.public_bytes(serialization.Encoding.DER)
identity = CaptureNodeIdentity(node_id=UUID(node), public_key_digest=public_key_digest(
    leaf.public_key()), credential_digest=certificate_digest(leaf),
    not_valid_after=leaf.not_valid_after_utc)
issued = SignerRenewalIssuer(trust, identity, der, socket_path=Path(socket_path)
                             ).issue_renewal_certificate(UUID(node), Path(csr_path).read_bytes())
print("renewed", issued.credential_digest, flush=True)
sys.stdin.read()
"""


def _memory_contains(pid: int, needles: list[bytes]) -> list[bytes]:
    hits = set()
    with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as memory:
        for line in maps:
            fields = line.split()
            if "r" not in fields[1]:
                continue
            start, end = (int(value, 16) for value in fields[0].split("-"))
            try:
                memory.seek(start)
                chunk = memory.read(end - start)
            except (OSError, OverflowError, ValueError):
                continue
            hits.update(needle for needle in needles if needle in chunk)
    return sorted(hits)


class RequesterMemoryTests(SocketHarness):
    """The requesting (listener-side) process never holds the CA key."""

    def spawn(self, *arguments, script=_CLIENT):
        environment = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1",
                       "PYTHONPATH": str(SERVER_ROOT)}
        process = subprocess.Popen([sys.executable, "-c", script, *map(str, arguments)],
                                   cwd=SERVER_ROOT, env=environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        return process

    def test_ca_key_never_enters_the_requesting_process_memory_or_output(self):
        node, certificate, _ = self.enroll()
        path, outcome, thread = self.serve_once(service_uid=os.getuid())
        public = self.root / "public"
        public.mkdir()
        (public / "ca.pem").write_bytes(self.trust.ca_certificate_pem())
        (public / "presented.pem").write_text(certificate)
        (public / "renewal.csr").write_bytes(renewal_csr()[1])
        client = self.spawn(path, public / "ca.pem", public / "presented.pem",
                            public / "renewal.csr", node)
        line = client.stdout.readline().decode()
        self.assertTrue(line.startswith("renewed "), client.stderr.read() if not line else line)
        thread.join(10)
        self.assertEqual(["signed"], outcome)
        key_path = self.authority_dir / "ca-key.pem"
        ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        scalar = ca_key.private_numbers().private_value.to_bytes(32, "big")
        der = ca_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption())
        body = "".join(key_path.read_text().splitlines()[1:-1])
        needles = [scalar, scalar[::-1], der, body[:40].encode()]
        try:
            found = _memory_contains(client.pid, needles)
            holder = self.spawn(key_path, script=(
                "import sys\n"
                "from cryptography.hazmat.primitives import serialization\n"
                "key = serialization.load_pem_private_key(open(sys.argv[1], 'rb').read(), None)\n"
                "print('ready', flush=True)\n"
                "sys.stdin.read()\n"))
            holder.stdout.readline()
            control = _memory_contains(holder.pid, needles)
            holder.communicate(b"", timeout=10)
        except PermissionError:
            self.skipTest("reading another process's memory is not permitted here")
        stdout, stderr = client.communicate(b"", timeout=10)
        self.assertEqual([], found)
        # Positive control: the same scan finds the key where it was loaded.
        self.assertNotEqual([], control)
        output = line.encode() + stdout + stderr
        for needle in needles + [b"PRIVATE KEY", scalar.hex().encode()]:
            self.assertNotIn(needle, output)


class SignerCommandTests(SignerHarness):
    def run_signer(self, service_user, stdin):
        environment = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run(
            [sys.executable, "-m", "app.cameras.remote_agent.pairing_cli", "renewal-signer",
             "--authority-dir", str(self.authority_dir), "--service-user", service_user],
            cwd=SERVER_ROOT, env=environment, stdin=stdin, capture_output=True, timeout=60,
            check=False)

    def test_refuses_to_run_as_the_service_account_or_root(self):
        result = self.run_signer(str(os.getuid()), subprocess.DEVNULL)
        self.assertEqual(2, result.returncode)
        expected = ("account_must_not_be_root" if os.getuid() == 0
                    else "ca_account_must_differ_from_service_account")
        self.assertEqual(f"serversentinel-pairing: refused: {expected}\n",
                         result.stderr.decode())

    def test_another_service_account_cannot_be_the_peer(self):
        if os.getuid() == 0:
            self.skipTest("covered as root by test_ca_privilege_separation_root")
        try:
            service = pwd.getpwnam("nobody")
        except KeyError:
            self.skipTest("no 'nobody' account")
        if service.pw_uid == os.getuid() or service.pw_gid == os.getgid():
            self.skipTest("'nobody' is this account")
        ours, theirs = socket.socketpair()
        with ours, theirs:
            write_frame(ours.fileno(), {"op": "renew"})
            result = self.run_signer("nobody", theirs)
        if os.getgroups() not in ([], [os.getgid()]):
            # Supplementary groups are never acceptable for the CA account;
            # systemd gives the instance only its own group.
            self.assertEqual("serversentinel-pairing: refused: privilege_drop_failed\n",
                             result.stderr.decode())
            return
        self.assertEqual(0, result.returncode, result.stderr)
        # The socket pair's peer is this test process, not 'nobody'.
        self.assertEqual("serversentinel-pairing: renewal-signer: renewal_signer_peer_refused\n",
                         result.stderr.decode())

    def test_stdin_must_be_a_unix_stream_connection(self):
        saved = os.dup(0)
        self.addCleanup(os.close, saved)
        self.addCleanup(os.dup2, saved, 0)
        ours, theirs = socket.socketpair()
        datagram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        null = os.open(os.devnull, os.O_RDONLY)
        with ours, theirs, datagram:
            for descriptor in (null, datagram.fileno()):
                os.dup2(descriptor, 0)
                with self.assertRaises(renewal_signer.SignerNotSocketActivated):
                    renewal_signer._connection_from_stdin()
            os.dup2(theirs.fileno(), 0)
            with renewal_signer._connection_from_stdin() as connection:
                self.assertEqual(socket.AF_UNIX, connection.family)
        os.close(null)


class UnitFileTests(unittest.TestCase):
    """The Owner-installed units keep the decided account, socket and hardening."""

    UNITS = SERVER_ROOT.parent / "infra" / "systemd"

    @staticmethod
    def directives(path):
        found = {}
        for line in path.read_text().splitlines():
            if line and not line.startswith(("#", "[")) and "=" in line:
                name, value = line.split("=", 1)
                found.setdefault(name, []).append(value)
        return found

    def test_socket_is_local_group_restricted_and_per_connection(self):
        socket_unit = self.directives(self.UNITS / "serversentinel-renewal-signer.socket")
        self.assertEqual(["/run/serversentinel-renewal-signer.sock"], socket_unit["ListenStream"])
        self.assertEqual(str(renewal_signer.RENEWAL_SIGNER_SOCKET), socket_unit["ListenStream"][0])
        self.assertEqual(["0660"], socket_unit["SocketMode"])
        self.assertEqual(["root"], socket_unit["SocketUser"])
        self.assertEqual(["yes"], socket_unit["Accept"])
        self.assertNotIn("ListenDatagram", socket_unit)

    def test_service_runs_as_the_ca_account_without_network_or_capabilities(self):
        service = self.directives(self.UNITS / "serversentinel-renewal-signer@.service")
        for name, value in (("User", "serversentinel-ca"), ("Group", "serversentinel-ca"),
                            ("StandardInput", "socket"), ("StandardOutput", "socket"),
                            ("NoNewPrivileges", "yes"), ("CapabilityBoundingSet", ""),
                            ("PrivateNetwork", "yes"), ("RestrictAddressFamilies", "AF_UNIX"),
                            ("ProtectSystem", "strict"), ("LimitCORE", "0"),
                            ("ReadWritePaths", "/var/lib/serversentinel-ca")):
            self.assertEqual([value], service.get(name), name)
        self.assertIn(" renewal-signer ", service["ExecStart"][0])
        self.assertNotIn("DynamicUser", service)


if __name__ == "__main__":
    unittest.main()
