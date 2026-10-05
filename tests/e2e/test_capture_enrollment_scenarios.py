"""Cross-process capture-node enrollment over the real bootstrap listener (Issue #13).

Every party is a separate process: the Main approval CLI
(``app.cameras.remote_agent.pairing_cli``) and the Agent pairing CLI
(``media_capture_agent.enroll``) each run with their own pseudo-terminal as the
controlling terminal, exactly as an Owner would use them. The test plays the
Owner: it reads the one-time code from the Main's terminal and types it into
the Agent's non-echoing prompt. A recording TCP relay sits between the Agent
and the Main listener so the test can inspect the bytes a LAN observer would
see. Everything runs over loopback with identities generated in temporary
directories; this is not a LAN or real-host verification (see MANUAL_TEST §B).
"""
from contextlib import closing
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import select
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from uuid import UUID, uuid4

from app.audit.store import AuditStore
from app.cameras.remote_agent.enrollment import ENROLLMENT_ALPN
from app.cameras.remote_agent.ingest_tls import (
    CaptureIngestAcceptor, CaptureNodeAdmission, IngestTlsError, build_ingest_server_context,
)
from app.cameras.remote_agent.node_ca import (
    DeploymentAuthority, PrivateDirectory, deployment_id_of, listener_material,
)
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.e2e.harness import require_non_root_agent


ROOT = Path(__file__).resolve().parents[2]
SERVER_NAME = "capture-main.serversentinel.test"
GROUPED_CODE = re.compile(rb"([A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{6})")


class _Owner:
    """In-process Owner gate for the one step the CLIs cannot shorten (expiry)."""

    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


def free_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as probe:
        return probe.getsockname()[1]


class TtyProcess:
    """A child whose controlling terminal is a fresh pty; stdout/stderr are pipes."""

    def __init__(self, command, *, env, cwd=ROOT, controlling_terminal=True):
        self.command = command
        self.master = None
        slave = None
        options = {}
        if controlling_terminal:
            self.master, slave = os.openpty()

            def attach():
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            options = {"pass_fds": (slave,), "preexec_fn": attach}
        self.process = subprocess.Popen(
            command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, **options)
        if slave is not None:
            os.close(slave)
        self.transcript = b""
        self.proc_views = []
        self._snapshot()

    def _snapshot(self):
        for name in ("cmdline", "environ"):
            try:
                self.proc_views.append(Path(f"/proc/{self.process.pid}/{name}").read_bytes())
            except OSError:
                pass

    def _pump(self, timeout):
        if self.master is None:
            time.sleep(timeout)
            return
        ready, _, _ = select.select([self.master], [], [], timeout)
        if ready:
            try:
                self.transcript += os.read(self.master, 4096)
            except OSError:
                time.sleep(timeout)

    def wait_for(self, pattern: bytes, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            match = re.search(pattern, self.transcript)
            if match:
                self._snapshot()
                return match
            if self.process.poll() is not None and self.master is None:
                break
            self._pump(0.05)
        status = self.process.poll()
        detail = self.process.stderr.read().decode() if status is not None else "running"
        raise AssertionError(f"terminal never showed {pattern!r}: {self.transcript!r} "
                             f"(exit {status}: {detail})")

    def type(self, text: bytes):
        os.write(self.master, text)

    def finish(self, timeout=40):
        deadline = time.monotonic() + timeout
        while self.process.poll() is None and time.monotonic() < deadline:
            self._snapshot()
            self._pump(0.05)
        stdout, stderr = self.process.communicate(timeout=max(deadline - time.monotonic(), 1))
        if self.master is not None:
            for _ in range(20):
                ready, _, _ = select.select([self.master], [], [], 0.01)
                if not ready:
                    break
                try:
                    chunk = os.read(self.master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                self.transcript += chunk
            os.close(self.master)
            self.master = None
        return self.process.returncode, stdout.decode(), stderr.decode()

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.communicate()
        if self.master is not None:
            os.close(self.master)
            self.master = None


class RecordingRelay:
    """TCP relay that records every byte in both directions (a LAN observer)."""

    def __init__(self, target_port: int):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.target = target_port
        self.captured = bytearray()
        self.connections = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []
        self._sockets = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self.listener.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            with self._lock:
                self.connections += 1
            try:
                upstream = socket.create_connection(("127.0.0.1", self.target), timeout=5)
            except OSError:
                client.close()
                continue
            self._sockets.extend((client, upstream))
            for source, sink in ((client, upstream), (upstream, client)):
                thread = threading.Thread(target=self._pipe, args=(source, sink), daemon=True)
                thread.start()
                self._threads.append(thread)

    def _pipe(self, source, sink):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                with self._lock:
                    self.captured += data
                sink.sendall(data)
        except OSError:
            pass
        finally:
            for side in (source, sink):
                try:
                    side.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self.listener.close()
        for thread in self._threads:
            thread.join(5)
        self._thread.join(5)
        for connection in self._sockets:
            connection.close()


class RecordingTlsPeer:
    """An impostor Main: accepts TLS with its own certificate and records app bytes."""

    def __init__(self, certificate_path=None, key_path=None, *, alpn=True, plaintext=False):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.application_bytes = bytearray()
        self.raw_bytes = bytearray()
        self.connections = 0
        self.plaintext = plaintext
        self.context = None
        if not plaintext:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            if alpn:
                context.set_alpn_protocols([ENROLLMENT_ALPN])
            context.load_cert_chain(str(certificate_path), str(key_path))
            self.context = context
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            self.connections += 1
            connection.settimeout(5)
            try:
                if self.plaintext:
                    while True:
                        data = connection.recv(65536)
                        if not data:
                            break
                        self.raw_bytes += data
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    continue
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    while True:
                        data = tls.recv(65536)
                        if not data:
                            break
                        self.application_bytes += data
            except (ssl.SSLError, OSError):
                pass
            finally:
                connection.close()

    def close(self):
        self._stop.set()
        self.listener.close()
        self._thread.join(5)


class CaptureEnrollmentScenario(unittest.TestCase):
    def setUp(self):
        # The Agent pairing CLI refuses UID 0 by design.
        require_non_root_agent()
        self.temporary = tempfile.TemporaryDirectory(prefix="capture-enroll-e2e-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(os.path.realpath(self.temporary.name))
        os.chmod(self.root, 0o700)
        self.authority_dir = self.root / "main-ca"
        self.listener_dir = self.root / "main-listener"
        self.database = self.root / "state.sqlite3"
        self.runtime = self.root / "agent-state"
        self.runtime.mkdir(mode=0o700)
        self.exchange = self.root / "exchange"
        self.exchange.mkdir()
        self.keylog = self.root / "keylog"
        self.environment = {
            "PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(str(ROOT / part) for part in ("server", "agent", ".")),
            # Inherited key-log and proxy settings must have no effect.
            "SSLKEYLOGFILE": str(self.keylog),
            "HTTPS_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "socks5://127.0.0.1:9",
            "LANG": "C.UTF-8",
        }
        self.processes = []
        self.human_port = free_port()

    def tearDown(self):
        for process in self.processes:
            process.kill()

    def run_cli(self, *arguments, module, tty=True):
        command = [sys.executable, "-m", module, *map(str, arguments)]
        process = TtyProcess(command, env=self.environment, controlling_terminal=tty)
        self.processes.append(process)
        return process

    def main_cli(self, *arguments, tty=True):
        return self.run_cli(*arguments, module="app.cameras.remote_agent.pairing_cli", tty=tty)

    def agent_cli(self, *arguments, tty=True):
        return self.run_cli(*arguments, module="media_capture_agent.enroll", tty=tty)

    def initialise_main(self, endpoint_port):
        code, output, error = self.main_cli(
            "init", "--authority-dir", self.authority_dir, "--listener-dir", self.listener_dir,
            "--server-name", SERVER_NAME, tty=False).finish()
        self.assertEqual(0, code, error)
        deployment = UUID(re.fullmatch(r"deployment_id=(\S+)\n", output).group(1))
        bundle = self.exchange / "bundle.json"
        code, output, error = self.main_cli(
            "export-bundle", "--authority-dir", self.authority_dir,
            "--listener-dir", self.listener_dir, "--endpoint", f"127.0.0.1:{endpoint_port}",
            "--output", bundle, tty=False).finish()
        self.assertEqual(0, code, error)
        digest = re.fullmatch(r"trust_bundle_sha256=([0-9a-f]{64})\n", output).group(1)
        return deployment, bundle, digest

    def agent_request(self, *extra, name="request.json"):
        request = self.exchange / name
        code, output, error = self.agent_cli("request", "--runtime-root", self.runtime,
                                             "--output", request, *extra, tty=False).finish()
        self.assertEqual(0, code, error)
        return request, re.fullmatch(r"public_key_sha256=([0-9a-f]{64})\n", output).group(1)

    def agent_pair(self, bundle, bundle_digest, grouped, *extra):
        agent = self.agent_cli("pair", "--runtime-root", self.runtime, "--trust-bundle", bundle,
                               "--bundle-sha256", bundle_digest, *extra)
        agent.wait_for(b"Pairing code: ")
        agent.type(grouped + b"\n")
        status, output, error = agent.finish()
        self.assertEqual(0, status, error)
        return UUID(re.fullmatch(r"paired: node_id=(\S+)\n", output).group(1))

    def start_approval(self, request, listen_port, key_digest):
        main = self.main_cli("approve", "--database", self.database,
                             "--authority-dir", self.authority_dir,
                             "--listener-dir", self.listener_dir, "--request", request,
                             "--listen", f"127.0.0.1:{listen_port}",
                             "--human-port", self.human_port)
        main.wait_for(b"Type APPROVE")
        self.assertIn(key_digest.encode(), main.transcript)
        main.type(b"APPROVE\n")
        grouped = main.wait_for(GROUPED_CODE).group(1)
        return main, grouped

    def ingest_connect(self, deployment):
        database = Database(self.database)
        ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)), audit=AuditStore(database))
        material = listener_material(PrivateDirectory(self.listener_dir))
        authority = DeploymentAuthority.load(PrivateDirectory(self.authority_dir), deployment)
        context = build_ingest_server_context(authority.ca_certificate_pem(),
                                              material.certificate_path, material.key_path)
        acceptor = CaptureIngestAcceptor(context, CaptureNodeAdmission(ledger, deployment))
        with socket.create_server(("127.0.0.1", 0)) as listener:
            listener.settimeout(20)
            command = [sys.executable, "-m", "tests.e2e.capture_node_process", "connect",
                       str(self.runtime), str(listener.getsockname()[1])]
            peer = subprocess.Popen(command, cwd=ROOT, env=self.environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            connection, _ = listener.accept()
            try:
                session = acceptor.accept(connection)
            except IngestTlsError as error:
                result = error.reason
            else:
                if session.connection.recv(4) == b"ping":
                    session.connection.sendall(b"pong")
                result = session
            output, _ = peer.communicate(timeout=20)
        return result, output.decode().strip()

    def test_enroll_over_bootstrap_listener_then_mtls_ingest(self):
        listen_port = free_port()
        relay = RecordingRelay(listen_port)
        self.addCleanup(relay.close)
        deployment, bundle, bundle_digest = self.initialise_main(relay.port)
        self.assertEqual(deployment, deployment_id_of(PrivateDirectory(self.authority_dir)))
        request, key_digest = self.agent_request()
        main, grouped = self.start_approval(request, listen_port, key_digest)
        code = grouped.replace(b"-", b"")
        main.wait_for(b"Type it only")

        # An Agent without a controlling terminal verifies the Main, then
        # refuses to read the code: nothing is submitted, the approval survives.
        no_tty = self.agent_cli("pair", "--runtime-root", self.runtime, "--trust-bundle", bundle,
                                "--bundle-sha256", bundle_digest, tty=False)
        status, output, error = no_tty.finish()
        self.assertEqual((1, ""), (status, output))
        self.assertIn("secure_pairing_input_unavailable", error)
        self.assertIsNone(main.process.poll(), "a refused prompt must not consume the approval")

        agent = self.agent_cli("pair", "--runtime-root", self.runtime, "--trust-bundle", bundle,
                               "--bundle-sha256", bundle_digest)
        agent.wait_for(b"Pairing code: ")
        connections_before_code = relay.connections
        self.assertGreaterEqual(connections_before_code, 1, "Main is verified before the prompt")
        agent.type(grouped + b"\n")
        status, output, error = agent.finish()
        self.assertEqual(0, status, error)
        node = UUID(re.fullmatch(r"paired: node_id=(\S+)\n", output).group(1))
        status, main_output, main_error = main.finish()
        self.assertEqual(0, status, main_error)
        self.assertIn(f"enrollment completed: node_id={node}", main_output)

        # mTLS ingest with the installed identity is admitted as that node.
        session, result = self.ingest_connect(deployment)
        self.assertEqual("ok", result)
        self.assertNotIsInstance(session, str, session)
        self.addCleanup(session.close)
        self.assertEqual(node, session.identity.node_id)

        # The code appears only on the Main's controlling terminal.
        self.assertIn(grouped, main.transcript)
        self.assertNotIn(code, agent.transcript, "the Agent prompt must not echo the code")
        self.assertNotIn(grouped, agent.transcript)
        observed = [bytes(relay.captured)]
        for process in self.processes:
            observed.append(" ".join(process.command).encode())
            observed.extend(process.proc_views)
        observed.append(" ".join(f"{key}={value}" for key, value in self.environment.items()).encode())
        observed.extend(text.encode() for text in (output, error, main_output, main_error))
        with closing(sqlite3.connect(self.database)) as connection:
            audit = connection.execute(
                "SELECT * FROM security_admin_audit_records ORDER BY rowid").fetchall()
            observed.append(repr(audit).encode())
            observed.append(repr(connection.execute(
                "SELECT * FROM pairing_enrollments").fetchall()).encode())
        self.assertGreaterEqual(len(audit), 3, "approve, redeem and activate are audited")
        key_files = list((self.runtime / "node-credentials").glob("private-key-*.pem"))
        self.assertEqual(1, len(key_files))
        key_body = "".join(key_files[0].read_text().splitlines()[1:-1])[:48].encode()
        for exposure in observed:
            self.assertNotIn(key_body, exposure)
        # Every file either side wrote (database, WAL, bundles, requests,
        # credentials) is also free of the code.
        for path in self.root.rglob("*"):
            if path.is_file() and path.name != "keylog":
                observed.append(path.read_bytes())
        for exposure in observed:
            for secret in (code, grouped, code.lower()):
                self.assertNotIn(secret, exposure)
        self.assertFalse(self.keylog.exists())
        self.assertFalse((self.runtime / "pending-enrollment" / "node-key.pem").exists())

        # Revoke locally; the old identity is refused and its key cannot re-enroll.
        revoke = self.main_cli("revoke", "--database", self.database, "--node", node)
        revoke.wait_for(b"Type REVOKE")
        revoke.type(b"REVOKE\n")
        status, output, error = revoke.finish()
        self.assertEqual((0, f"revoked: node_id={node}\n"), (status, output), error)
        result, output = self.ingest_connect(deployment)
        self.assertEqual("capture_node_not_admitted", result)
        again = self.main_cli("approve", "--database", self.database,
                              "--authority-dir", self.authority_dir,
                              "--listener-dir", self.listener_dir, "--request", request,
                              "--listen", f"127.0.0.1:{free_port()}",
                              "--human-port", self.human_port)
        status, output, error = again.finish()
        self.assertEqual(2, status)
        self.assertIn("public_key_revoked", error)
        self.assertNotIn(b"Type APPROVE", again.transcript, "refused before the Owner prompt")
        self.assertNotIn(b"One-time pairing code", again.transcript)
        listing = self.main_cli("list", "--database", self.database, tty=False)
        status, output, error = listing.finish()
        self.assertEqual(0, status, error)
        self.assertIn(f"node_id={node} enrollment=activated credential=revoked", output)
        self.assertEqual(1, output.count("node_id="), "a refused approval creates no pairing")
        self.assertNotIn(key_digest, output)

    def test_interrupted_approval_is_retried_for_the_same_bound_node(self):
        listen_port = free_port()
        deployment, bundle, bundle_digest = self.initialise_main(listen_port)
        request, key_digest = self.agent_request()
        first, _grouped = self.start_approval(request, listen_port, key_digest)
        first_node = UUID(first.process.stdout.readline().decode().split("node_id=")[1].strip())
        first.kill()  # interrupted before the Agent redeemed the code

        # The Agent re-exports the same pending key; the retried approval
        # reuses the node the key is already bound to instead of failing.
        main = self.main_cli("approve", "--database", self.database,
                             "--authority-dir", self.authority_dir,
                             "--listener-dir", self.listener_dir, "--request", request,
                             "--listen", f"127.0.0.1:{listen_port}",
                             "--human-port", self.human_port)
        main.wait_for(b"Type APPROVE")
        self.assertIn(f"existing capture node: {first_node}".encode(), main.transcript)
        main.type(b"APPROVE\n")
        grouped = main.wait_for(GROUPED_CODE).group(1)
        main.wait_for(b"Type it only")
        agent = self.agent_cli("pair", "--runtime-root", self.runtime, "--trust-bundle", bundle,
                               "--bundle-sha256", bundle_digest)
        agent.wait_for(b"Pairing code: ")
        agent.type(grouped + b"\n")
        status, output, error = agent.finish()
        self.assertEqual(0, status, error)
        self.assertEqual(f"paired: node_id={first_node}\n", output)
        status, main_output, main_error = main.finish()
        self.assertEqual(0, status, main_error)
        self.assertIn(f"enrollment completed: node_id={first_node}", main_output)
        session, result = self.ingest_connect(deployment)
        self.assertEqual("ok", result)
        self.assertNotIsInstance(session, str, session)
        self.addCleanup(session.close)
        self.assertEqual(first_node, session.identity.node_id)
        listing = self.main_cli("list", "--database", self.database, tty=False)
        status, output, error = listing.finish()
        self.assertEqual(0, status, error)
        self.assertEqual(1, output.count("node_id="), "a retry creates no second pairing")

    def test_expired_then_revoked_node_repairs_over_the_real_clis(self):
        # Issue #116, Owner policy 2026-10-01. The first credential is issued
        # in-process with a three-second lifetime so it really expires; every
        # re-pairing step then runs through the real Main and Agent CLIs.
        listen_port = free_port()
        deployment, bundle, bundle_digest = self.initialise_main(listen_port)
        request, key_digest = self.agent_request()
        database = Database(self.database)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)), audit=AuditStore(database))
        node = uuid4()
        approval, code = ledger.approve(_Owner(), "owner", node_id=node,
                                        public_key_digest=key_digest)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest=key_digest,
                              code=code.value)
        csr = json.loads(request.read_text())["csr"].encode()
        authority = DeploymentAuthority.load(PrivateDirectory(self.authority_dir), deployment)
        issued = authority.issue_and_activate(ledger, claim, csr,
                                              validity=datetime.timedelta(seconds=3))
        certificate = self.exchange / "short.pem"
        certificate.write_bytes(issued.certificate_pem)
        result = subprocess.run(
            [sys.executable, "-m", "tests.e2e.capture_node_process", "install", str(self.runtime),
             str(bundle), str(certificate), bundle_digest],
            cwd=ROOT, env=self.environment, capture_output=True, timeout=30, check=False)
        self.assertEqual(b"done", result.stdout.strip(), result.stderr)

        # Before expiry the same key cannot re-pair (it renews instead).
        early = self.agent_cli("request", "--runtime-root", self.runtime, "--output",
                               self.exchange / "early.json", "--repair", "expired", tty=False)
        status, _output, error = early.finish()
        self.assertEqual(1, status)
        self.assertIn("node_identity_not_expired", error)
        while datetime.datetime.now(datetime.timezone.utc) <= issued.not_after:
            time.sleep(0.2)
        result, _output = self.ingest_connect(deployment)
        self.assertIsInstance(result, str, "an expired certificate is not admitted")

        # Expired, not revoked: same key, same node, the Owner types APPROVE.
        repair, repair_digest = self.agent_request("--repair", "expired", name="expired.json")
        self.assertEqual(key_digest, repair_digest)
        main, grouped = self.start_approval(repair, listen_port, repair_digest)
        self.assertIn(f"existing capture node: {node}".encode(), main.transcript)
        main.wait_for(b"Type it only")
        self.assertEqual(node, self.agent_pair(bundle, bundle_digest, grouped, "--repair", "expired"))
        status, main_output, main_error = main.finish()
        self.assertEqual(0, status, main_error)
        session, result = self.ingest_connect(deployment)
        self.assertEqual("ok", result)
        self.assertNotIsInstance(session, str, session)
        self.assertEqual(node, session.identity.node_id)
        session.close()
        self.assertEqual(1, len(list((self.runtime / "node-credentials").glob("private-key-*.pem"))))

        # Revoked: the old key is refused, a new key pairs as a new node.
        revoke = self.main_cli("revoke", "--database", self.database, "--node", node)
        revoke.wait_for(b"Type REVOKE")
        revoke.type(b"REVOKE\n")
        self.assertEqual(0, revoke.finish()[0])
        refused = self.main_cli("approve", "--database", self.database,
                                "--authority-dir", self.authority_dir,
                                "--listener-dir", self.listener_dir, "--request", repair,
                                "--listen", f"127.0.0.1:{free_port()}",
                                "--human-port", self.human_port)
        status, _output, error = refused.finish()
        self.assertEqual(2, status)
        self.assertIn("public_key_revoked", error)
        revoked_request, new_digest = self.agent_request("--repair", "revoked", name="revoked.json")
        self.assertNotEqual(key_digest, new_digest)
        # A fresh port: the first listener's port may still be in TIME_WAIT.
        second_port = free_port()
        main, grouped = self.start_approval(revoked_request, second_port, new_digest)
        self.assertIn(b"new capture node", main.transcript)
        main.wait_for(b"Type it only")
        new_node = self.agent_pair(bundle, bundle_digest, grouped, "--repair", "revoked",
                                   "--endpoint", f"127.0.0.1:{second_port}")
        self.assertNotEqual(node, new_node)
        status, main_output, main_error = main.finish()
        self.assertEqual(0, status, main_error)
        self.assertIn(f"enrollment completed: node_id={new_node}", main_output)
        session, result = self.ingest_connect(deployment)
        self.assertEqual("ok", result)
        self.assertNotIsInstance(session, str, session)
        self.assertEqual(new_node, session.identity.node_id)
        session.close()
        self.assertEqual(1, len(list((self.runtime / "node-credentials").glob("private-key-*.pem"))))
        self.assertFalse((self.runtime / "pending-repair" / "node-key.pem").exists())
        listing = self.main_cli("list", "--database", self.database, tty=False)
        status, output, error = listing.finish()
        self.assertEqual(0, status, error)
        # The revoked node's history stays; the new node starts with no sources.
        self.assertIn(f"node_id={node} enrollment=activated credential=revoked", output)
        self.assertIn(f"node_id={new_node} enrollment=activated credential=active", output)
        self.assertEqual(2, output.count("node_id="))

    def test_untrusted_or_plaintext_main_never_receives_a_code(self):
        deployment, bundle, bundle_digest = self.initialise_main(free_port())
        self.agent_request()
        # An impostor with its own CA and the same server name and ALPN.
        impostor = DeploymentAuthority.create(PrivateDirectory(self.root / "impostor-ca"),
                                              deployment, validity=datetime.timedelta(days=365))
        impostor.issue_main_server_credential(PrivateDirectory(self.root / "impostor-listener"),
                                              server_name=SERVER_NAME,
                                              validity=datetime.timedelta(days=30))
        impostor_material = listener_material(PrivateDirectory(self.root / "impostor-listener"))
        genuine = listener_material(PrivateDirectory(self.listener_dir))
        peers = (
            ("main_identity_rejected", RecordingTlsPeer(impostor_material.certificate_path,
                                                        impostor_material.key_path)),
            # The genuine certificate on a peer that does not speak enrollment
            # (for example the ingest listener) is refused before the prompt.
            ("main_identity_rejected", RecordingTlsPeer(genuine.certificate_path,
                                                        genuine.key_path, alpn=False)),
            ("main_handshake_failed", RecordingTlsPeer(plaintext=True)),
        )
        for expected, peer in peers:
            self.addCleanup(peer.close)
            agent = self.agent_cli("pair", "--runtime-root", self.runtime, "--trust-bundle", bundle,
                                   "--bundle-sha256", bundle_digest,
                                   "--endpoint", f"127.0.0.1:{peer.port}")
            status, output, error = agent.finish()
            self.assertEqual((1, ""), (status, output))
            self.assertIn(expected, error)
            self.assertNotIn(b"Pairing code", agent.transcript, "prompt before verification")
            self.assertGreaterEqual(peer.connections, 1)
            self.assertEqual(b"", bytes(peer.application_bytes))
            if peer.plaintext:
                self.assertTrue(bytes(peer.raw_bytes).startswith(b"\x16\x03"),
                                "only a TLS ClientHello reaches a plaintext endpoint")

        # A bundle whose digest differs from the Owner-verified value never
        # leads to a connection at all.
        silent = RecordingTlsPeer(impostor_material.certificate_path, impostor_material.key_path)
        self.addCleanup(silent.close)
        agent = self.agent_cli("pair", "--runtime-root", self.runtime, "--trust-bundle", bundle,
                               "--bundle-sha256", "0" * 64, "--endpoint", f"127.0.0.1:{silent.port}")
        status, output, error = agent.finish()
        self.assertEqual(1, status)
        self.assertIn("trust_bundle_digest_mismatch", error)
        self.assertEqual(0, silent.connections)
        self.assertFalse(self.keylog.exists())

    def test_main_and_agent_share_one_protocol_contract(self):
        from app.cameras.remote_agent import enrollment, pairing_cli
        from media_capture_agent import enroll
        self.assertEqual(enrollment.ENROLLMENT_ALPN, enroll.ENROLLMENT_ALPN)
        self.assertEqual(enrollment.PROTOCOL_VERSION, enroll.PROTOCOL_VERSION)
        self.assertEqual(enrollment.FRAME_HEADER.format, enroll.FRAME_HEADER.format)
        self.assertEqual(enrollment.MAX_REQUEST_BYTES, enroll.MAX_REQUEST_BYTES)
        self.assertEqual(enrollment.MAX_RESPONSE_BYTES, enroll.MAX_RESPONSE_BYTES)
        self.assertEqual(pairing_cli.REQUEST_FORMAT, enroll.REQUEST_FORMAT)

    def test_main_approval_requires_a_controlling_terminal(self):
        self.initialise_main(free_port())
        request, _digest = self.agent_request()
        status, output, error = self.main_cli(
            "approve", "--database", self.database, "--authority-dir", self.authority_dir,
            "--listener-dir", self.listener_dir, "--request", request,
            "--listen", f"127.0.0.1:{free_port()}", "--human-port", self.human_port,
            tty=False).finish()
        self.assertEqual((2, ""), (status, output))
        self.assertIn("controlling_terminal_required", error)
        self.assertFalse(self.database.exists(), "no state before the code can be shown")


if __name__ == "__main__":
    unittest.main()
