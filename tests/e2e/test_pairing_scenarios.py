"""Capture-node pairing: expired/reused codes and revoked nodes are refused.

Admission is decided only by the production ``PairingLedger`` (``redeem`` /
``activate`` / ``admits``) on a disposable SQLite database; the code reaches
the Agent side through the production non-echoing ``prompt_pairing_code``
with an injected terminal. The HMAC key, pairing code and every digest are
generated per run. No TLS, transport, ingest listener or network is used, so
this is not acceptance of the ADR-0006 bootstrap exchange or of missing /
mismatched Main trust (those belong to the transport adapter and
``MANUAL_TEST.md``).
"""

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import logging
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.audit.store import AuditStore
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingError, PairingLedger
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from media_capture_agent.pairing import PairingRefused, prompt_pairing_code

from tests.e2e.harness import MixedSourceTopology, NetworkGuard, SyntheticClock


UNAVAILABLE = "pairing enrollment is unavailable"
CODE_LIFETIME_SECONDS = 5 * 60


class Owner:
    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


class CapturedOutput:
    """Collect every log record (all loggers, DEBUG) and stdout/stderr text."""

    def __init__(self):
        self.stream = io.StringIO()
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setLevel(logging.DEBUG)
        self.handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s %(args)r"))

    def __enter__(self):
        self.root = logging.getLogger()
        self.level = self.root.level
        self.root.addHandler(self.handler)
        self.root.setLevel(logging.DEBUG)
        self.redirects = (redirect_stdout(self.stdout), redirect_stderr(self.stderr))
        for redirect in self.redirects:
            redirect.__enter__()
        return self

    def __exit__(self, *exc):
        for redirect in reversed(self.redirects):
            redirect.__exit__(*exc)
        self.root.removeHandler(self.handler)
        self.root.setLevel(self.level)
        return False

    def text(self):
        return self.stream.getvalue() + self.stdout.getvalue() + self.stderr.getvalue()


class PairingScenarios(unittest.TestCase):
    def setUp(self):
        self.network = NetworkGuard().__enter__()
        self.addCleanup(self.network.__exit__)
        self.addCleanup(lambda: self.assertEqual([], self.network.attempts))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.database = Database(self.root / "main.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.audit = AuditStore(self.database, clock=self.clock.utcnow)
        self.key = secrets.token_bytes(32)
        self.ledger = self.open_ledger()
        self.owner = Owner()
        self.nodes = [item.node_id for item in self.topology.sources if item.node_id is not None]

    def open_ledger(self, process_epoch=None):
        # A new ledger models a Main restart: a fresh process epoch.
        return PairingLedger(self.database, HmacCodeVerifier(self.key), audit=self.audit,
                             clock=self.clock.monotonic, process_epoch=process_epoch or uuid4())

    def approve(self, node, key_digest):
        return self.ledger.approve(self.owner, "owner", node_id=node, public_key_digest=key_digest)

    def agent_reads(self, code):
        """The Agent obtains the code only from a non-echoing controlling terminal."""
        descriptor = os.open(os.devnull, os.O_RDWR)
        with patch("media_capture_agent.pairing.os.isatty", return_value=True):
            return prompt_pairing_code(opener=lambda *_args: descriptor,
                                       reader=lambda *_args, **_kwargs: code.value)

    def refused(self, callable_, *args, **kwargs):
        with self.assertRaises(PairingError) as raised:
            callable_(*args, **kwargs)
        self.assertEqual(UNAVAILABLE, str(raised.exception))

    def audit_rows(self):
        with closing(self.database.connect()) as connection:
            return [tuple(row) for row in connection.execute(
                "SELECT * FROM security_admin_audit_records ORDER BY rowid")]

    def enrollment_state(self, enrollment_id):
        with closing(self.database.connect()) as connection:
            return connection.execute("SELECT state FROM pairing_enrollments WHERE id = ?",
                                      (str(enrollment_id),)).fetchone()[0]

    def test_expired_code_is_refused_and_never_admits_the_node(self):
        node, key = self.nodes[0], secrets.token_hex(32)
        approval, code = self.approve(node, key)
        agent_code = self.agent_reads(code)
        self.clock.advance(CODE_LIFETIME_SECONDS)
        self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                     public_key_digest=key, code=agent_code.value)
        self.assertEqual("expired", self.enrollment_state(approval.enrollment_id))
        # Expiry is terminal: a later retry with the same code stays refused.
        self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                     public_key_digest=key, code=agent_code.value)
        self.assertFalse(self.ledger.admits(node_id=node, public_key_digest=key,
                                            credential_serial_digest=secrets.token_hex(32)))

    def test_code_from_before_a_main_restart_is_refused(self):
        node, key = self.nodes[0], secrets.token_hex(32)
        approval, code = self.approve(node, key)
        self.ledger = self.open_ledger()
        # Well inside the lifetime, but a monotonic deadline is not trusted
        # across process epochs.
        self.clock.advance(1)
        self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                     public_key_digest=key, code=code.value)

    def test_reused_code_and_claim_are_refused_after_single_use(self):
        node, key, serial = self.nodes[0], secrets.token_hex(32), secrets.token_hex(32)
        approval, code = self.approve(node, key)
        agent_code = self.agent_reads(code)
        # The code is bound to the approved Agent public-key digest.
        self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                     public_key_digest=secrets.token_hex(32), code=agent_code.value)
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=key, code=agent_code.value)
        self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                     public_key_digest=key, code=agent_code.value)
        self.ledger.activate(claim, credential_serial_digest=serial)
        with self.assertRaises(PairingError):
            self.ledger.activate(claim, credential_serial_digest=secrets.token_hex(32))
        self.assertTrue(self.ledger.admits(node_id=node, public_key_digest=key,
                                           credential_serial_digest=serial))
        # Only the exact activated credential is admitted.
        for other_key, other_serial in ((secrets.token_hex(32), serial),
                                        (key, secrets.token_hex(32))):
            self.assertFalse(self.ledger.admits(node_id=node, public_key_digest=other_key,
                                                credential_serial_digest=other_serial))
        self.assertFalse(self.ledger.admits(node_id=self.nodes[1], public_key_digest=key,
                                            credential_serial_digest=serial))

    def test_revoked_node_is_refused_until_a_new_owner_approved_pairing(self):
        node, key, serial = self.nodes[0], secrets.token_hex(32), secrets.token_hex(32)
        approval, code = self.approve(node, key)
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=key, code=self.agent_reads(code).value)
        self.ledger.activate(claim, credential_serial_digest=serial)
        other_node, other_key, other_serial = self.nodes[1], secrets.token_hex(32), secrets.token_hex(32)
        other, other_code = self.approve(other_node, other_key)
        self.ledger.activate(self.ledger.redeem(enrollment_id=other.enrollment_id,
                                                public_key_digest=other_key, code=other_code.value),
                             credential_serial_digest=other_serial)

        self.ledger.revoke(self.owner, "owner", node_id=node)
        self.assertFalse(self.ledger.admits(node_id=node, public_key_digest=key,
                                            credential_serial_digest=serial))
        # Revocation is per node: the other capture node stays admitted.
        self.assertTrue(self.ledger.admits(node_id=other_node, public_key_digest=other_key,
                                           credential_serial_digest=other_serial))
        # The consumed code and old claim cannot restore the revoked credential.
        self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                     public_key_digest=key, code=code.value)
        with self.assertRaises(PairingError):
            self.ledger.activate(claim, credential_serial_digest=serial)
        self.assertFalse(self.ledger.admits(node_id=node, public_key_digest=key,
                                            credential_serial_digest=serial))
        # A non-Owner context cannot approve a replacement pairing.
        with self.assertRaises(PairingError):
            self.ledger.approve(self.owner, "capture-node", node_id=node, public_key_digest=key)
        # A fresh Owner approval issues a new credential; the old one stays out.
        new_key, new_serial = secrets.token_hex(32), secrets.token_hex(32)
        renewed, renewed_code = self.approve(node, new_key)
        self.ledger.activate(self.ledger.redeem(enrollment_id=renewed.enrollment_id,
                                                public_key_digest=new_key, code=renewed_code.value),
                             credential_serial_digest=new_serial)
        self.assertTrue(self.ledger.admits(node_id=node, public_key_digest=new_key,
                                           credential_serial_digest=new_serial))
        self.assertFalse(self.ledger.admits(node_id=node, public_key_digest=key,
                                            credential_serial_digest=serial))

    def test_code_never_enters_argv_environment_or_an_unattended_input(self):
        _approval, code = self.approve(self.nodes[0], secrets.token_hex(32))
        # A code placed in argv or the environment is never read: without a
        # controlling terminal the prompt refuses before any reader runs.
        reads = []
        with patch.object(sys, "argv", ["media-capture-agent", "pair", code.value]), \
                patch.dict(os.environ, {"SERVERSENTINEL_PAIRING_CODE": code.value,
                                        "PAIRING_CODE": code.value}), \
                self.assertRaisesRegex(PairingRefused, "^secure_pairing_input_unavailable$"):
            prompt_pairing_code(opener=lambda *_args: (_ for _ in ()).throw(OSError()),
                                reader=lambda *args, **kwargs: reads.append(1) or code.value)
        self.assertEqual([], reads)
        # The Agent CLI accepts no code/secret argument at all.
        from media_capture_agent import cli
        help_text = io.StringIO()
        with redirect_stdout(help_text), self.assertRaises(SystemExit) as exited:
            cli.main(["--help"])
        self.assertEqual(0, exited.exception.code)
        for word in ("code", "secret", "token", "pair"):
            self.assertNotIn(word, help_text.getvalue().lower())
        # The real process argv/environment never carried the code either.
        agent_code = self.agent_reads(code)
        self.assertEqual(code.value, agent_code.value)
        self.assertNotIn(code.value, " ".join(sys.argv))
        self.assertNotIn(code.value, "".join(os.environ.values()))
        for name in ("cmdline", "environ"):
            try:
                content = Path("/proc/self", name).read_bytes()
            except OSError:
                continue
            self.assertNotIn(code.value.encode("ascii"), content, name)

    def test_pairing_lifecycle_writes_no_secret_to_logs_output_audit_or_database(self):
        node, key, serial = self.nodes[0], secrets.token_hex(32), secrets.token_hex(32)
        with CapturedOutput() as output:
            approval, code = self.approve(node, key)
            agent_code = self.agent_reads(code)
            self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                         public_key_digest=secrets.token_hex(32), code=agent_code.value)
            claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                       public_key_digest=key, code=agent_code.value)
            self.refused(self.ledger.redeem, enrollment_id=approval.enrollment_id,
                         public_key_digest=key, code=agent_code.value)
            self.ledger.activate(claim, credential_serial_digest=serial)
            expired, expired_code = self.approve(self.nodes[1], secrets.token_hex(32))
            self.clock.advance(CODE_LIFETIME_SECONDS)
            self.refused(self.ledger.redeem, enrollment_id=expired.enrollment_id,
                         public_key_digest=key, code=expired_code.value)
            self.ledger.revoke(self.owner, "owner", node_id=node)
            with self.assertRaises(PairingError):
                self.ledger.revoke(self.owner, "not-owner", node_id=node)
            logging.getLogger("app").debug("synthetic canary %s", "marker")
        captured = output.text()
        # The capture itself works (a canary record reaches it).
        self.assertIn("synthetic canary", captured)
        code_digest = HmacCodeVerifier(self.key).digest(code.value)
        expired_digest = HmacCodeVerifier(self.key).digest(expired_code.value)
        secrets_ = {
            "pairing code": code.value, "expired code": expired_code.value,
            "verifier key": self.key.hex(), "verifier key bytes": repr(self.key),
            "code digest": code_digest, "expired code digest": expired_digest,
        }
        reprs = "".join(repr(value) for value in (code, agent_code, claim, approval,
                                                  expired, expired_code))
        for label, value in secrets_.items():
            self.assertNotIn(value, captured, label)
            self.assertNotIn(value, reprs, label)
        # Audit rows carry only bounded categories and the node's logical UUID.
        audit = repr(self.audit_rows())
        self.assertIn(str(node), audit)
        for label, value in {**secrets_, "key digest": key, "serial digest": serial,
                             "enrollment id": str(approval.enrollment_id)}.items():
            self.assertNotIn(value, audit, label)
        # The durable database holds only the keyed HMAC code digest (in
        # pairing_enrollments.code_digest), never a plaintext code or the key.
        with closing(self.database.connect()) as connection:
            for enrollment, digest in ((approval, code_digest), (expired, expired_digest)):
                self.assertEqual(digest, connection.execute(
                    "SELECT code_digest FROM pairing_enrollments WHERE id = ?",
                    (str(enrollment.enrollment_id),)).fetchone()[0])
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        stored = b"".join(path.read_bytes() for path in self.root.glob("main.sqlite3*"))
        for value in (code.value, expired_code.value):
            self.assertNotIn(value.encode("ascii"), stored)
        self.assertNotIn(self.key, stored)
        self.assertNotIn(self.key.hex().encode("ascii"), stored)


if __name__ == "__main__":
    unittest.main()
