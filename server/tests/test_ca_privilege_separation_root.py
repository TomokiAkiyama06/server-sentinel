"""Two real accounts for the CA key separation (Issue #109). Root only.

Skipped unless this process is root (a CI step with ``sudo`` or a container).
It never creates OS accounts: two unused numeric UIDs/GIDs stand for
``serversentinel-ca`` and the service account, through a launcher that maps
the account names to them and otherwise uses the real ``OsPrivileges`` (root
start, ``setgroups``/``setresgid``/``setresuid``, no_new_privs, dumpable 0,
post-drop verification). It checks, with real processes:

* ``init`` leaves the CA files owned by the CA account and the listener files
  (including the public CA copy) owned by the service account, all 0600;
* the service account gets ``EACCES`` on the CA key, and ``export-bundle``
  works as the service account with public material only;
* during ``approve`` the serving process is the service account with no
  capability, no CA-account process is alive, and a scan of the serving
  process's whole memory (``/proc/<pid>/mem``) finds no CA private key bytes;
  the enrollment then completes with the pre-signed certificate;
* ``revoke`` records the revocation in the CA issuance log;
* a CA directory owned by the wrong account is refused before the prompt.
"""
from __future__ import annotations

from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.cameras.remote_agent.node_ca import public_key_digest
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


SERVER_ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "capture-main.serversentinel.test"
CA_ID = 61001
SERVICE_ID = 61002
ALPN = "serversentinel-capture-enroll/1"
# Set by the CI root step: a skip (not root, or no memory access) is a failure.
REQUIRE_ROOT = "CA_SEPARATION_REQUIRE_ROOT"
REQUIRED = os.environ.get(REQUIRE_ROOT) == "1"
LAUNCHER = f"""
import sys
sys.path.insert(0, {str(SERVER_ROOT)!r})
from app.cameras.remote_agent import pairing_cli
from app.cameras.remote_agent.issuer_process import Account, OsPrivileges

class Mapped(OsPrivileges):
    def account(self, name):
        return {{"ca": Account({CA_ID}, {CA_ID}), "svc": Account({SERVICE_ID}, {SERVICE_ID})}}[name]

pairing_cli._PRIVILEGES = Mapped()
raise SystemExit(pairing_cli.main(sys.argv[1:]))
"""


def _status(pid: int) -> dict[str, str]:
    with open(f"/proc/{pid}/status") as status:
        return dict(line.rstrip("\n").split(":\t", 1) for line in status if ":\t" in line)


def _children(pid: int) -> list[int]:
    found = []
    for name in os.listdir("/proc"):
        if name.isdecimal():
            try:
                if _status(int(name)).get("PPid") == str(pid):
                    found.append(int(name))
            except OSError:
                continue
    return found


def _memory_contains(pid: int, needles: list[bytes]) -> list[bytes]:
    """Return the needles found anywhere in the readable memory of ``pid``."""
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
            for needle in needles:
                if needle in chunk:
                    hits.add(needle)
    return sorted(hits)


class TtyCommand:
    """A process with its own controlling pseudo-terminal (for approve/revoke)."""

    def __init__(self, command, env):
        self.master, slave = pty.openpty()

        def controlling():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=env, cwd=SERVER_ROOT,
                                        preexec_fn=controlling, pass_fds=(slave,))
        os.close(slave)
        self.transcript = b""

    def wait_for(self, pattern: bytes, timeout: float = 30.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            match = re.search(pattern, self.transcript)
            if match:
                return match
            ready, _, _ = select.select([self.master], [], [], 0.2)
            if ready:
                try:
                    self.transcript += os.read(self.master, 4096)
                except OSError:
                    break
        raise AssertionError(f"timed out waiting for {pattern!r}: {self.transcript!r}")

    def type(self, data: bytes) -> None:
        os.write(self.master, data)

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.communicate(timeout=10)
            os.close(self.master)

    def finish(self, timeout: float = 60.0):
        stdout, stderr = self.process.communicate(timeout=timeout)
        os.close(self.master)
        return self.process.returncode, stdout.decode(), stderr.decode()


class TwoAccountSeparationTests(unittest.TestCase):
    def skip_or_fail(self, reason: str) -> None:
        if REQUIRED:
            self.fail(reason)
        self.skipTest(reason)

    def setUp(self):
        if os.geteuid() != 0:
            self.skip_or_fail("needs root (CI sudo step or a container): two real accounts")
        self.root = Path(tempfile.mkdtemp(prefix="capture-two-uid-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        os.chmod(self.root, 0o711)
        self.authority = self.root / "ca"
        self.listener = self.root / "listener"
        for path, owner in ((self.authority, CA_ID), (self.listener, SERVICE_ID)):
            path.mkdir(mode=0o700)
            os.chown(path, owner, owner)
        # The service account's own state directory (SQLite writes its journal there).
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        os.chown(self.state, SERVICE_ID, SERVICE_ID)
        self.database = self.state / "state.sqlite3"
        with closing(Database(self.database).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        os.chown(self.database, SERVICE_ID, SERVICE_ID)
        os.chmod(self.database, 0o600)
        self.environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8",
                            "PYTHONDONTWRITEBYTECODE": "1"}

    def cli(self, *arguments):
        return [sys.executable, "-c", LAUNCHER, *map(str, arguments)]

    def run_cli(self, *arguments):
        result = subprocess.run(self.cli(*arguments), env=self.environment, cwd=SERVER_ROOT,
                                capture_output=True, timeout=60, check=False,
                                stdin=subprocess.DEVNULL)
        return result.returncode, result.stdout.decode(), result.stderr.decode()

    def as_service(self, *command):
        return subprocess.run(list(command), env=self.environment, cwd=SERVER_ROOT,
                              capture_output=True, timeout=60, check=False, user=SERVICE_ID,
                              group=SERVICE_ID, extra_groups=[])

    def init(self):
        status, stdout, stderr = self.run_cli(
            "init", "--authority-dir", self.authority, "--listener-dir", self.listener,
            "--server-name", SERVER_NAME, "--ca-user", "ca", "--service-user", "svc")
        self.assertEqual(0, status, stderr)
        return stdout

    def test_init_export_and_key_access_follow_the_account_split(self):
        self.init()
        for directory, owner, names in (
                (self.authority, CA_ID, ("ca-key.pem", "ca-certificate.pem", "issuance-log.jsonl")),
                (self.listener, SERVICE_ID, ("main-server-key.pem", "main-server-certificate.pem",
                                             "deployment-ca-certificate.pem"))):
            self.assertEqual(sorted(names), sorted(os.listdir(directory)))
            for name in names:
                info = os.lstat(directory / name)
                self.assertEqual((owner, owner, 0o600),
                                 (info.st_uid, info.st_gid, info.st_mode & 0o777), name)
        probe = self.as_service(sys.executable, "-c",
                                f"open({str(self.authority / 'ca-key.pem')!r}, 'rb')")
        self.assertNotEqual(0, probe.returncode)
        self.assertIn(b"PermissionError", probe.stderr)
        output = self.state / "bundle.json"
        exported = self.as_service(sys.executable, "-m", "app.cameras.remote_agent.pairing_cli",
                                   "export-bundle", "--listener-dir", str(self.listener),
                                   "--endpoint", "127.0.0.1:18443", "--output", str(output))
        self.assertEqual(0, exported.returncode, exported.stderr)
        bundle = json.loads(output.read_bytes())
        self.assertEqual((self.authority / "ca-certificate.pem").read_text(),
                         bundle["ca_certificate"])

    def test_approve_serves_as_the_service_account_without_the_ca_key(self):
        self.init()
        key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(
            key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
        digest = public_key_digest(key.public_key())
        request = self.root / "request.json"
        request.write_text(json.dumps({"format_version": 1, "csr": csr.decode(),
                                       "public_key_digest": digest}))
        os.chmod(request, 0o644)
        with socket.create_server(("127.0.0.1", 0)) as probe:
            port = probe.getsockname()[1]
        approve = TtyCommand(self.cli(
            "approve", "--database", self.database, "--authority-dir", self.authority,
            "--listener-dir", self.listener, "--request", request, "--listen",
            f"127.0.0.1:{port}", "--ca-user", "ca", "--service-user", "svc"), self.environment)
        self.addCleanup(approve.kill)
        approve.wait_for(b"Type APPROVE")
        approve.type(b"APPROVE\n")
        code = approve.wait_for(rb"\n    ([A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}-[A-Z2-7]{6})\r?\n"
                                ).group(1).replace(b"-", b"")
        approve.wait_for(b"Type it only")
        pid = approve.process.pid
        status = _status(pid)
        self.assertEqual([str(SERVICE_ID)] * 4, status["Uid"].split())
        self.assertEqual([str(SERVICE_ID)] * 4, status["Gid"].split())
        self.assertEqual("0" * 16, status["CapEff"])
        self.assertEqual("0" * 16, status["CapPrm"])
        self.assertEqual("1", status["NoNewPrivs"])
        self.assertEqual([], _children(pid), "the CA child has exited before serving")
        ca_key = serialization.load_pem_private_key(
            (self.authority / "ca-key.pem").read_bytes(), password=None)
        scalar = ca_key.private_numbers().private_value.to_bytes(32, "big")
        der = ca_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption())
        body = "".join((self.authority / "ca-key.pem").read_text().splitlines()[1:-1])
        needles = [scalar, scalar[::-1], der, body[:40].encode()]
        try:
            self.assertEqual([], _memory_contains(pid, needles))
            # Positive control: the same scan finds the key in a process
            # that did load it, so the empty result above is meaningful.
            holder = subprocess.Popen(
                [sys.executable, "-c",
                 "import sys, time\n"
                 "from cryptography.hazmat.primitives import serialization\n"
                 "key = serialization.load_pem_private_key(open(sys.argv[1], 'rb').read(), None)\n"
                 "print('ready', flush=True)\n"
                 "time.sleep(30)\n", str(self.authority / "ca-key.pem")],
                stdout=subprocess.PIPE, env=self.environment)
            try:
                holder.stdout.readline()
                self.assertNotEqual([], _memory_contains(holder.pid, needles))
            finally:
                holder.kill()
                holder.communicate(timeout=10)
            scanned = True
        except PermissionError:
            # A container without CAP_SYS_PTRACE cannot read a non-dumpable
            # process; the rest of the flow is still checked.
            scanned = False

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.authority / "ca-certificate.pem"))
        context.set_alpn_protocols([ALPN])
        deployment = re.search(
            r"urn:serversentinel:deployment:([0-9a-f-]{36})",
            x509.load_pem_x509_certificate((self.authority / "ca-certificate.pem").read_bytes())
            .extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            .get_values_for_type(x509.UniformResourceIdentifier)[0]).group(1)
        frame = json.dumps({"version": 1, "deployment_id": deployment, "code": code.decode(),
                            "csr": csr.decode()}).encode()
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw, \
                context.wrap_socket(raw, server_hostname=SERVER_NAME) as connection:
            connection.sendall(struct.pack(">I", len(frame)) + frame)
            (length,) = struct.unpack(">I", connection.recv(4))
            response = b""
            while len(response) < length:
                response += connection.recv(length - len(response))
        certificate = json.loads(response)["certificate"]
        status_code, stdout, stderr = approve.finish()
        self.assertEqual(0, status_code, stderr)
        self.assertIn("enrollment completed: node_id=", stdout)
        logged = [json.loads(line) for line in
                  (self.authority / "issuance-log.jsonl").read_text().splitlines()]
        issued = x509.load_pem_x509_certificate(certificate.encode())
        self.assertEqual(
            [r["credential_digest"] for r in logged if r["type"] == "node"],
            [__import__("hashlib").sha256(issued.public_bytes(serialization.Encoding.DER))
             .hexdigest()])

        node = re.search(r"node_id=(\S+)", stdout).group(1)
        revoke = TtyCommand(self.cli("revoke", "--database", self.database, "--authority-dir",
                                     self.authority, "--node", node, "--ca-user", "ca",
                                     "--service-user", "svc"), self.environment)
        revoke.wait_for(b"Type REVOKE")
        revoke.type(b"REVOKE\n")
        status_code, stdout, stderr = revoke.finish()
        self.assertEqual((0, f"revoked: node_id={node}\n"), (status_code, stdout), stderr)
        logged = [json.loads(line) for line in
                  (self.authority / "issuance-log.jsonl").read_text().splitlines()]
        self.assertEqual({"type": "node_revocation", "node_id": node},
                         {key: logged[-1][key] for key in ("type", "node_id")})
        if not scanned:
            self.skip_or_fail("memory scan needs CAP_SYS_PTRACE (docker run --cap-add SYS_PTRACE)")

    def test_a_ca_directory_owned_by_the_wrong_account_is_refused_before_the_prompt(self):
        self.init()
        for path in [self.authority, *self.authority.iterdir()]:
            os.chown(path, SERVICE_ID, SERVICE_ID)
        request = self.root / "request.json"
        request.write_text("{}")
        approve = TtyCommand(self.cli(
            "approve", "--database", self.database, "--authority-dir", self.authority,
            "--listener-dir", self.listener, "--request", request, "--listen", "127.0.0.1:18443",
            "--ca-user", "ca", "--service-user", "svc"), self.environment)
        status_code, _stdout, stderr = approve.finish()
        self.assertEqual(2, status_code)
        self.assertIn("refused: issuer_unavailable", stderr)
        self.assertNotIn(b"Type APPROVE", approve.transcript)

    def test_revoke_still_revokes_in_the_ledger_when_the_ca_directory_is_lost(self):
        # Codex P1 (PR #177): a missing CA directory is not "exposed".
        from app.audit.store import AuditStore
        from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
        database = Database(self.database)
        ledger = PairingLedger(database, HmacCodeVerifier(os.urandom(32)),
                               audit=AuditStore(database))

        class Owner:
            def require_owner(self, actor_context):
                pass
        key = ec.generate_private_key(ec.SECP256R1())
        node = __import__("uuid").uuid4()
        ledger.approve(Owner(), object(), node_id=node,
                       public_key_digest=public_key_digest(key.public_key()))
        for path in self.state.iterdir():
            os.chown(path, SERVICE_ID, SERVICE_ID)
        revoke = TtyCommand(self.cli("revoke", "--database", self.database, "--authority-dir",
                                     self.root / "lost-ca", "--node", node, "--ca-user", "ca",
                                     "--service-user", "svc"), self.environment)
        revoke.wait_for(b"Type REVOKE")
        revoke.type(b"REVOKE\n")
        status_code, stdout, stderr = revoke.finish()
        self.assertEqual((1, f"revoked: node_id={node}\n"), (status_code, stdout), stderr)
        self.assertIn("ca_revocation_unrecorded", stderr)
        self.assertNotIn("ca_directory_exposed", stderr)
        states = {row.node_id: row.enrollment_state for row in ledger.pairing_summaries()}
        self.assertEqual("revoked", states[node])

    def exposed_as_service(self, path, *, missing_ok=False):
        probe = self.as_service(sys.executable, "-c",
                                "import sys; from pathlib import Path\n"
                                "from app.deployment import capture_ca_path_exposed\n"
                                "print(capture_ca_path_exposed(Path(sys.argv[1]), "
                                "missing_is_exposed=sys.argv[2] != 'missing_ok'))",
                                str(path), "missing_ok" if missing_ok else "strict")
        self.assertEqual(0, probe.returncode, probe.stderr)
        return probe.stdout.decode().strip() == "True"

    def test_service_controlled_ca_paths_are_exposed_even_when_access_is_denied(self):
        # Codex P1 (PR #177, round 3), with two real accounts.
        self.init()
        self.assertFalse(self.exposed_as_service(self.authority))
        # Chowned to the service by mistake, mode 000: EACCES now, but the
        # owner could chmod it back and read the key.
        for path in [self.authority, *self.authority.iterdir()]:
            os.chown(path, SERVICE_ID, SERVICE_ID)
        os.chmod(self.authority, 0)
        self.assertTrue(self.exposed_as_service(self.authority))
        for path in [self.authority, *self.authority.iterdir()]:
            os.chown(path, CA_ID, CA_ID)
        os.chmod(self.authority, 0o700)
        self.assertFalse(self.exposed_as_service(self.authority))
        # A service-writable (non-sticky) parent could replace the directory.
        shared = self.root / "shared"
        shared.mkdir()
        os.chmod(shared, 0o777)
        moved = shared / "ca"
        os.rename(self.authority, moved)
        self.assertTrue(self.exposed_as_service(moved))
        self.assertTrue(self.exposed_as_service(shared / "lost", missing_ok=True))
        os.chmod(shared, 0o1777)  # sticky: entries cannot be replaced by others
        self.assertFalse(self.exposed_as_service(moved))
        # A service-owned CA file in an otherwise closed directory.
        os.chmod(shared, 0o755)
        os.chown(moved / "issuance-log.jsonl", SERVICE_ID, SERVICE_ID)
        os.chmod(moved, 0o711)
        self.assertTrue(self.exposed_as_service(moved))

    def test_same_account_for_ca_and_service_is_refused(self):
        status, _stdout, stderr = self.run_cli(
            "init", "--authority-dir", self.authority, "--listener-dir", self.listener,
            "--server-name", SERVER_NAME, "--ca-user", "svc", "--service-user", "svc")
        self.assertEqual(2, status)
        self.assertIn("refused: ca_account_must_differ_from_service_account", stderr)
        self.assertEqual([], os.listdir(self.authority))


if __name__ == "__main__":
    unittest.main()
