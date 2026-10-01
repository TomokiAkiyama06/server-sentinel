"""Hardware-free Main/Agent capture-node pairing and mTLS scenario (Issue #13).

The Main side runs in this process with the real CA, pairing ledger and ingest
acceptor. The Agent runs as separate processes with the real
``media_capture_agent.node_tls`` code and a private runtime directory. All
identities are generated in temporary directories over loopback; the pairing
code is redeemed in-process because the bootstrap listener is not part of this
change. This is not a LAN or real-host verification (see MANUAL_TEST.md).
"""
from contextlib import closing
import datetime
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

from app.audit.store import AuditStore
from app.cameras.remote_agent.ingest_tls import (
    CaptureIngestAcceptor, CaptureNodeAdmission, IngestTlsError, build_ingest_server_context,
)
from app.cameras.remote_agent.node_ca import DeploymentAuthority, PrivateDirectory, listener_material
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.cameras.remote_agent.renewal import renew_node_credential
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


ROOT = Path(__file__).resolve().parents[2]
SERVER_NAME = "capture-main.serversentinel.test"
DAY = datetime.timedelta(days=1)


class Owner:
    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


class CaptureMtlsScenario(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="capture-mtls-e2e-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.runtime = self.root / "agent-state"
        self.runtime.mkdir(mode=0o700)
        self.public = self.root / "exchange"
        self.public.mkdir()
        database = Database(self.root / "main.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)),
                                    audit=AuditStore(database))
        self.deployment = uuid4()
        self.authority = DeploymentAuthority.create(PrivateDirectory(self.root / "main-ca"),
                                                    self.deployment, validity=3650 * DAY)
        listener_directory = PrivateDirectory(self.root / "main-listener")
        self.authority.issue_main_server_credential(listener_directory, server_name=SERVER_NAME,
                                                    validity=30 * DAY)
        material = listener_material(listener_directory)
        context = build_ingest_server_context(self.authority.ca_certificate_pem(),
                                              material.certificate_path, material.key_path)
        self.admission = CaptureNodeAdmission(self.ledger, self.deployment)
        self.acceptor = CaptureIngestAcceptor(context, self.admission)
        self.environment = {
            "PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(str(ROOT / part) for part in ("agent", ".")),
            "SSLKEYLOGFILE": str(self.root / "keylog"),
        }
        self.arguments = []

    def agent(self, *arguments, timeout=30):
        command = [sys.executable, "-m", "tests.e2e.capture_node_process", *map(str, arguments)]
        self.arguments.append(command)
        result = subprocess.run(command, cwd=ROOT, env=self.environment, capture_output=True,
                                timeout=timeout, check=False)
        return result.stdout.decode().strip(), result.stderr.decode()

    def connect(self):
        with socket.create_server(("127.0.0.1", 0)) as listener:
            listener.settimeout(20)
            command = [sys.executable, "-m", "tests.e2e.capture_node_process", "connect",
                       str(self.runtime), str(listener.getsockname()[1])]
            self.arguments.append(command)
            peer = subprocess.Popen(command, cwd=ROOT, env=self.environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            connection, _ = listener.accept()
            try:
                session = self.acceptor.accept(connection)
            except IngestTlsError as error:
                result = error.reason
            else:
                if session.connection.recv(4) == b"ping":
                    session.connection.sendall(b"pong")
                result = session
            output, _ = peer.communicate(timeout=20)
        return result, output.decode().strip()

    def test_pair_connect_revoke_across_processes(self):
        csr_path, digest_path = self.public / "request.csr", self.public / "request.digest"
        self.assertEqual(("done", ""), self.agent("request", self.runtime, csr_path, digest_path))
        approval, code = self.ledger.approve(Owner(), "owner", node_id=uuid4(),
                                             public_key_digest=digest_path.read_text())
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=digest_path.read_text(), code=code.value)
        # The renewal below uses the Owner-decided 397-day default. Certificate
        # times have one-second precision and the Agent requires a renewal to
        # outlive the current certificate, so this one is a day shorter; in
        # service renewal starts 30 days before expiry and cannot tie.
        issued = self.authority.issue_and_activate(self.ledger, claim, csr_path.read_bytes(),
                                                   validity=396 * DAY)
        certificate_path = self.public / "node.pem"
        certificate_path.write_bytes(issued.certificate_pem)
        bundle = self.authority.export_trust_bundle(server_name=SERVER_NAME,
                                                    endpoint_host="127.0.0.1", endpoint_port=7443)
        bundle_path = self.public / "bundle.json"
        bundle_path.write_bytes(bundle.content)

        tampered = self.public / "tampered.json"
        tampered.write_bytes(bundle.content.replace(SERVER_NAME.encode(), b"other.serversentinel.test"))
        self.assertEqual(("trust_bundle_digest_mismatch", ""),
                         self.agent("install", self.runtime, tampered, certificate_path, bundle.sha256))
        self.assertEqual(("done", ""),
                         self.agent("install", self.runtime, bundle_path, certificate_path, bundle.sha256))

        credentials = self.runtime / "node-credentials"
        self.assertEqual(0o700, stat.S_IMODE(os.lstat(credentials).st_mode))
        for entry in credentials.iterdir():
            self.assertEqual(0o600, stat.S_IMODE(os.lstat(entry).st_mode), entry.name)
        self.assertFalse((self.runtime / "pending-enrollment" / "node-key.pem").exists())

        session, output = self.connect()
        self.assertEqual("ok", output)
        self.assertNotIsInstance(session, str, session)
        self.addCleanup(session.close)
        self.assertEqual(claim.node_id, session.identity.node_id)

        # Automatic renewal over the admitted session: fresh Agent key, same node.
        renewal_csr = self.public / "renewal.csr"
        self.assertEqual(("done", ""), self.agent("renew-request", self.runtime, renewal_csr))
        renewed = renew_node_credential(self.authority, self.ledger, self.admission,
                                        session.identity, renewal_csr.read_bytes())
        renewed_path = self.public / "renewed.pem"
        renewed_path.write_bytes(renewed.certificate_pem)
        self.assertEqual(("done", ""), self.agent("renew-install", self.runtime, renewed_path))
        self.assertTrue(session.still_admitted(), "old certificate is valid until the new one is used")
        renewed_session, output = self.connect()
        self.assertEqual("ok", output)
        self.addCleanup(renewed_session.close)
        self.assertEqual(renewed.credential_digest, renewed_session.identity.credential_digest)
        self.assertEqual(claim.node_id, renewed_session.identity.node_id)
        self.assertFalse(session.still_admitted(), "first use of the renewal supersedes the old one")
        session = renewed_session

        self.ledger.revoke(Owner(), "owner", node_id=claim.node_id)
        self.assertFalse(session.still_admitted())
        result, output = self.connect()
        self.assertEqual("capture_node_not_admitted", result)
        self.assertNotEqual("ok", output)

        key_files = [entry for entry in credentials.iterdir() if entry.name.startswith("private-key-")]
        self.assertEqual(1, len(key_files))
        body = "".join(key_files[0].read_text().splitlines()[1:-1])[:48]
        exposed = " ".join(" ".join(command) for command in self.arguments)
        exposed += " ".join(self.environment.values())
        self.assertNotIn(body, exposed)
        self.assertNotIn(body, bundle.content.decode())
        self.assertFalse((self.root / "keylog").exists())


if __name__ == "__main__":
    unittest.main()
