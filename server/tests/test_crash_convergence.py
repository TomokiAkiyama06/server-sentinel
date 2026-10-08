"""Crash convergence of init / rotate-listener / approve / revoke (Issue #109).

Every multi-file CA, listener, issuance-log and ledger step calls
``faults.reached(point)``. For each command, a clean run first records the
sequence of crash points it passes. Then, for every point and every way a
process can die there -- the command process (its CA child sees end of
stream and cleans up), the CA child (the command sees the issuer fail and
cleans up), or both (power loss: nobody cleans up) -- the command is
stopped exactly there, and the next runs of every command must converge:

    init -> rotate-listener -> export-bundle -> approve (with redemption)
    -> revoke

each completes (status 0), and committed CA material that existed before
the crashed run is byte-identical afterwards. Nothing may wedge and nothing
committed may be removed. The table in the PR #177 comment lists the
resulting states.
"""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack, closing
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.cameras.remote_agent import faults, pairing_cli
from app.cameras.remote_agent.enrollment import EnrollmentOutcome
from app.cameras.remote_agent.issuer_process import IssuerUnavailable
from app.cameras.remote_agent.node_ca import (
    DeploymentTrust, PrivateDirectory, public_key_digest,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests import issuer_fakes


SERVER_NAME = "capture-main.serversentinel.test"
CHILD_PREFIXES = ("child.", "ca.")


class Crash(BaseException):
    """A process dying at a crash point (never caught by product code)."""


def is_child_point(point: str) -> bool:
    return point.startswith(CHILD_PREFIXES)


class Deployment:
    """One temporary deployment driven through the real CLI with the fakes."""

    def __init__(self, root: Path):
        self.root = root
        self.authority = root / "ca"
        self.listener = root / "listener"
        self.database = root / "state.sqlite3"
        with closing(Database(self.database).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.requests = 0
        self.nodes: list[str] = []

    def cli(self, *argv, terminal=None, serve=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch("sys.stdout", stdout))
            stack.enter_context(patch("sys.stderr", stderr))
            if terminal is not None:
                stack.enter_context(patch.object(pairing_cli, "ControllingTerminal", terminal))
            stack.enter_context(patch.object(pairing_cli.EnrollmentListener, "open",
                                             lambda listener: None))
            stack.enter_context(patch.object(pairing_cli.EnrollmentListener, "close",
                                             lambda listener: None))
            if serve is not None:
                stack.enter_context(patch.object(pairing_cli.EnrollmentListener, "serve", serve))
            status = pairing_cli.main([str(part) for part in argv])
        return status, stdout.getvalue(), stderr.getvalue()

    def init(self):
        return self.cli("init", "--authority-dir", self.authority,
                        "--listener-dir", self.listener, "--server-name", SERVER_NAME)

    def rotate(self):
        return self.cli("rotate-listener", "--authority-dir", self.authority,
                        "--listener-dir", self.listener)

    def export(self):
        self.requests += 1
        return self.cli("export-bundle", "--listener-dir", self.listener,
                        "--endpoint", "10.0.0.5:8443",
                        "--output", self.root / f"bundle-{self.requests}.json")

    def new_request(self):
        key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(
            key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
        self.requests += 1
        path = self.root / f"request-{self.requests}.json"
        path.write_text(json.dumps({"format_version": 1, "csr": csr.decode(),
                                    "public_key_digest": public_key_digest(key.public_key())}))
        return path, csr

    def approve(self, request):
        path, csr = request
        terminal = Terminal()

        def serve(listener, service, *, expires_at_monotonic, stop=None):
            deployment = DeploymentTrust.load_public(PrivateDirectory(self.listener)).deployment_id
            body = json.dumps({"version": 1, "deployment_id": str(deployment),
                               "code": terminal.code(), "csr": csr.decode()}).encode()
            _response, issued = service.handle(body)
            if issued is None:
                return EnrollmentOutcome("expired", ())
            return EnrollmentOutcome("completed", (issued.node_id,))
        status, stdout, stderr = self.cli(
            "approve", "--database", self.database, "--authority-dir", self.authority,
            "--listener-dir", self.listener, "--request", path, "--listen", "127.0.0.1:18443",
            terminal=terminal, serve=serve)
        if status == 0:
            self.nodes.append(stdout.rsplit("node_id=", 1)[1].strip())
        return status, stdout, stderr

    def revoke(self, node):
        return self.cli("revoke", "--database", self.database, "--authority-dir",
                        self.authority, "--node", node, terminal=Terminal(("REVOKE",)))

    def ca_material(self):
        return {name: (self.authority / name).read_bytes()
                for name in ("ca-key.pem", "ca-certificate.pem")
                if (self.authority / name).exists()}


class Terminal:
    def __init__(self, answers=("APPROVE",)):
        self.answers = list(answers)
        self.written = []

    def __call__(self, *args, **kwargs):
        return self

    def write(self, text):
        self.written.append(text)

    def read_line(self):
        return self.answers.pop(0)

    def close(self):
        pass

    def code(self):
        for text in self.written:
            if "One-time pairing code" in text:
                return text.split("\n\n")[1].strip().replace("-", "")
        return None


def describe(deployment: Deployment) -> str:
    """CA dir x log x listener dir x public copy, for the PR table."""
    def names(directory):
        return sorted(os.listdir(directory)) if directory.exists() else []
    ca = [name for name in names(deployment.authority) if name.startswith("ca-")]
    log_path = deployment.authority / "issuance-log.jsonl"
    log = ([json.loads(line)["type"] for line in log_path.read_bytes().splitlines()
            if line.endswith(b"}")] if log_path.exists() else None)
    listener = [name for name in names(deployment.listener)
                if not name.startswith("deployment-ca-certificate")]
    copy = [name for name in names(deployment.listener)
            if name.startswith("deployment-ca-certificate")]
    return f"CA={ca or '-'} log={log if log is not None else '-'} listener={listener or '-'} copy={copy or '-'}"


class CrashConvergenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="capture-crash-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(os.path.realpath(temporary.name))
        os.chmod(self.base, 0o700)
        issuer_fakes.install(self)

    def deployment(self, label):
        root = self.base / label
        root.mkdir(mode=0o700)
        return Deployment(root)

    # -- preparing each command's starting state -------------------------

    def prepared(self, command, label):
        deployment = self.deployment(label)
        context = {}
        if command != "init":
            self.assertEqual(0, deployment.init()[0])
        if command == "approve":
            context["request"] = deployment.new_request()
        if command == "revoke":
            self.assertEqual(0, deployment.approve(deployment.new_request())[0])
            context["node"] = deployment.nodes[-1]
        return deployment, context

    def run_command(self, command, deployment, context):
        if command == "init":
            return deployment.init()
        if command == "rotate-listener":
            return deployment.rotate()
        if command == "approve":
            return deployment.approve(context["request"])
        return deployment.revoke(context["node"])

    # -- fault injection ---------------------------------------------------

    def points_of(self, command):
        deployment, context = self.prepared(command, f"probe-{command}")
        seen = []
        with patch.object(faults, "reached", seen.append):
            status, _stdout, stderr = self.run_command(command, deployment, context)
        self.assertEqual(0, status, stderr)
        counts, points = Counter(), []
        for point in seen:
            counts[point] += 1
            points.append((point, counts[point]))
        return points

    def crashing(self, deployment, target, mode):
        """Patches that stop the run at ``target`` the way ``mode`` dies."""
        name, occurrence = target
        counts = Counter()

        def reached(point):
            counts[point] += 1
            if point == name and counts[point] == occurrence:
                raise Crash(point)
        stack = ExitStack()
        stack.enter_context(patch.object(faults, "reached", reached))
        real_discard_created = PrivateDirectory.discard_created
        real_discard_stale = PrivateDirectory.discard_stale
        frozen = set()
        if mode in ("command", "both"):
            frozen.add(deployment.listener)  # the dead command cleans nothing up
        if mode in ("child", "both"):
            frozen.add(deployment.authority)  # the dead CA child cleans nothing up

        def guarded(real):
            def method(directory, name_):
                if directory.path in frozen:
                    return None
                return real(directory, name_)
            return method
        stack.enter_context(patch.object(PrivateDirectory, "discard_created",
                                         guarded(real_discard_created)))
        stack.enter_context(patch.object(PrivateDirectory, "discard_stale",
                                         guarded(real_discard_stale)))
        if mode == "child":
            # The command survives: it sees the issuer fail (end of stream).
            real_request = issuer_fakes.InProcessIssuer.request

            def request(issuer, message):
                try:
                    return real_request(issuer, message)
                except Crash:
                    # Died: no cleanup of its own, but the kernel closes its
                    # descriptors, which releases its CA directory lock.
                    issuer.closed = True
                    issuer.handler._resources.close()
                    raise IssuerUnavailable("issuer exited") from None
            stack.enter_context(patch.object(issuer_fakes.InProcessIssuer, "request", request))
        if mode == "command":
            # The CA child survives the command and cleans up on end of stream.
            real_close = issuer_fakes.InProcessIssuer.close

            def close(issuer):
                with patch.object(PrivateDirectory, "discard_created", real_discard_created), \
                        patch.object(PrivateDirectory, "discard_stale", real_discard_stale):
                    real_close(issuer)
            stack.enter_context(patch.object(issuer_fakes.InProcessIssuer, "close", close))
        return stack

    def converge(self, deployment, committed, label):
        """From any state: init, rotate, export, approve, revoke all complete."""
        for step, run in (("init", deployment.init), ("rotate-listener", deployment.rotate),
                          ("export-bundle", deployment.export)):
            status, _stdout, stderr = run()
            self.assertEqual(0, status, f"{label}: {step} did not converge: {stderr}")
        status, _stdout, stderr = deployment.approve(deployment.new_request())
        self.assertEqual(0, status, f"{label}: approve did not converge: {stderr}")
        status, _stdout, stderr = deployment.revoke(deployment.nodes[-1])
        self.assertEqual(0, status, f"{label}: revoke did not converge: {stderr}")
        for name, content in committed.items():
            self.assertEqual(content, (deployment.authority / name).read_bytes(),
                             f"{label}: committed {name} changed")
        trust = DeploymentTrust.load_public(PrivateDirectory(deployment.listener))
        trust.issued_listener_certificate(PrivateDirectory(deployment.listener))

    def first_run(self, command, deployment, context):
        """The next run of one command, straight from the crashed state."""
        if command == "init":
            return deployment.init()
        if command == "rotate-listener":
            return deployment.rotate()
        if command == "export-bundle":
            return deployment.export()
        if command == "approve":
            return deployment.approve(context.get("request") or deployment.new_request())
        node = context.get("node") or "00000000-0000-4000-8000-000000000001"
        return deployment.revoke(node)

    def check_command(self, command):
        points = self.points_of(command)
        self.assertTrue(points, command)
        for index, target in enumerate(points):
            point = target[0]
            modes = ("child", "both") if is_child_point(point) else ("command", "both")
            for mode in modes:
                label = f"{command}@{point}#{target[1]}/{mode}"
                with self.subTest(label):
                    deployment, context = self.prepared(command, f"{command}-{index}-{mode}")
                    with self.crashing(deployment, target, mode):
                        try:
                            self.run_command(command, deployment, context)
                        except Crash:
                            pass
                    # Material a later run must never change: the CA as it was
                    # before this run (other commands), and any complete CA the
                    # crash left behind (init) -- a complete CA is never removed.
                    committed = deployment.ca_material()
                    if len(committed) != 2:
                        committed = {}
                    state = describe(deployment)
                    for first in ("init", "rotate-listener", "export-bundle", "approve",
                                  "revoke"):
                        clone = self.clone(deployment, f"{command}-{index}-{mode}-{first}")
                        status, _stdout, stderr = self.first_run(first, clone, context)
                        # Each command either completes or refuses with a
                        # fixed reason; nothing committed is lost either way.
                        self.assertIn(status, (0, 1, 2), f"{label} then {first}: {stderr}")
                        if status != 0:
                            self.assertIn("serversentinel-pairing:", stderr, label)
                        for name, content in committed.items():
                            self.assertEqual(content, (clone.authority / name).read_bytes(),
                                             f"{label} then {first}: {name} changed")
                        if (first == "export-bundle" and status == 0
                                and not (clone.listener / "main-server-key.pem").exists()):
                            self.fail(f"{label}: exported a bundle for an incomplete init")
                        if command == "revoke" and first == "revoke":
                            self.assertEqual(0, status, f"{label}: revoke rerun: {stderr}")
                        if command == "approve" and first == "approve":
                            self.assertEqual(0, status, f"{label}: approve retry: {stderr}")
                        if command == "rotate-listener" and first == "approve":
                            # approve completes an interrupted rotation itself
                            # (Issue #183); converge() runs rotate first.
                            self.assertEqual(0, status, f"{label} then approve: {stderr}")
                        self.converge(clone, committed, f"{label} then {first}")
                        self.CRASH_STATES.append((label, state, first, status))

    CRASH_STATES: list = []

    def clone(self, deployment, label):
        """A copy of the crashed deployment, keeping hard links and modes."""
        target = self.base / label
        links = {}
        for source in sorted(deployment.root.rglob("*")):
            destination = target / source.relative_to(deployment.root)
            info = os.lstat(source)
            if source.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                os.chmod(destination, info.st_mode & 0o7777)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            key = (info.st_dev, info.st_ino)
            if key in links:
                os.link(links[key], destination)
                continue
            destination.write_bytes(source.read_bytes())
            os.chmod(destination, info.st_mode & 0o7777)
            links[key] = destination
        os.chmod(target, 0o700)
        clone = Deployment.__new__(Deployment)
        clone.root, clone.authority = target, target / "ca"
        clone.listener, clone.database = target / "listener", target / "state.sqlite3"
        clone.requests, clone.nodes = deployment.requests + 100, list(deployment.nodes)
        return clone

    def test_init(self):
        self.check_command("init")

    def test_rotate_listener(self):
        self.check_command("rotate-listener")

    def test_approve(self):
        self.check_command("approve")

    def test_revoke(self):
        self.check_command("revoke")

    def test_approve_first_completes_a_rotation_stopped_between_its_renames(self):
        # Issue #183: only the new key is renamed into place, so the pair no
        # longer matches. approve, run before any rotate-listener, finishes
        # the rotation (complete_interrupted_rotation) and enrolls.
        for mode in ("command", "both"):
            with self.subTest(mode=mode):
                deployment, context = self.prepared("rotate-listener", f"renamed-key-{mode}")
                before = (deployment.listener / "main-server-certificate.pem").read_bytes()
                with self.crashing(deployment, ("rotate.renamed_key", 1), mode):
                    with self.assertRaises(Crash):
                        deployment.rotate()
                # The new certificate is still staged next to the new key.
                self.assertTrue((deployment.listener / "main-server-certificate.pem.next")
                                .exists(), os.listdir(deployment.listener))
                status, stdout, stderr = deployment.approve(deployment.new_request())
                self.assertEqual(0, status, stderr)
                self.assertIn("enrollment completed", stdout)
                self.assertNotEqual(
                    before, (deployment.listener / "main-server-certificate.pem").read_bytes())
                trust = DeploymentTrust.load_public(PrivateDirectory(deployment.listener))
                trust.issued_listener_certificate(PrivateDirectory(deployment.listener))
                pairing_cli.listener_material(PrivateDirectory(deployment.listener))

    def test_every_command_passes_crash_points(self):
        expected = {
            "init": {"ca.staged.ca-certificate.pem", "ca.staged.ca-key.pem",
                     "ca.installed.ca-certificate.pem", "ca.installed.ca-key.pem",
                     "child.init.logged_ca", "child.init.logged_listener",
                     "listener.before_key", "child.init.committed", "init.committed",
                     "listener.installed.main-server-key.pem"},
            "rotate-listener": {"child.sign_listener.logged", "rotate.staged_key",
                                "rotate.staged_certificate", "rotate.renamed_key"},
            "approve": {"approve.approved", "child.sign_node.logged", "approve.signed"},
            "revoke": {"revoke.ledger_revoked", "child.revoke.logged"},
        }
        for command, names in expected.items():
            with self.subTest(command):
                self.assertLessEqual(names, {point for point, _ in self.points_of(command)})


if __name__ == "__main__":
    unittest.main()
