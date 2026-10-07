"""Main listener credential lifecycle tests (Issues #124, #125, #127).

Covers listener-certificate rotation that keeps the deployment CA (and so
every Agent trust bundle) unchanged, crash recovery of an interrupted
rotation, serialization and rollback of concurrent ``init``, listener files
owned by a separate account, the bootstrap listener's SO_REUSEADDR rebind and
the dedicated refusal when the CA is too close to expiry. Every CA and key is
generated per test in a temporary directory; no real host, account change or
network beyond loopback is involved.
"""
import argparse
from contextlib import closing
import datetime
import errno
import io
import json
import os
import pwd
from pathlib import Path
import socket
import sqlite3
import ssl
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.cameras.remote_agent import node_ca, pairing_cli
from app.cameras.remote_agent.enrollment import (
    ENROLLMENT_ALPN, EnrollmentConfigurationError, EnrollmentLimits, EnrollmentListener,
    EnrollmentListenerConfig, build_enrollment_server_context,
)
from app.cameras.remote_agent.node_ca import (
    AuthorityValidityExceeded, DeploymentAuthority, IssuerMaterialBusy,
    ListenerMaterialInconsistent, OwnershipPrivilegeRequired, PrivateDirectory,
    deployment_id_of, listener_material, main_server_name,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


SERVER_NAME = "capture-main.serversentinel.test"
DAY = datetime.timedelta(days=1)
LISTENER_FILES = ("main-server-certificate.pem", "main-server-key.pem")



def node_request():
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM), node_ca.public_key_digest(key.public_key())

def run_cli(*argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
        status = pairing_cli.main(list(argv))
    return status, stdout.getvalue(), stderr.getvalue()


def handshake(server_context: ssl.SSLContext, client_context: ssl.SSLContext) -> None:
    """Complete an in-memory TLS handshake; raise ``ssl.SSLError`` on refusal."""
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client = client_context.wrap_bio(client_in, client_out, server_hostname=SERVER_NAME)
    done = {"server": False, "client": False}
    for _ in range(20):
        for name, endpoint in (("client", client), ("server", server)):
            if done[name]:
                continue
            try:
                endpoint.do_handshake()
                done[name] = True
            except ssl.SSLWantReadError:
                pass
        server_in.write(client_out.read())
        client_in.write(server_out.read())
        if all(done.values()):
            return
    raise AssertionError("handshake did not finish")


class ListenerLifecycleHarness(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="capture-listener-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        os.chmod(self.root, 0o700)

    def fresh(self, label="a"):
        return self.root / f"ca-{label}-{uuid4()}", self.root / f"listener-{label}-{uuid4()}"

    def init(self, authority, listener, *extra):
        status, stdout, stderr = run_cli("init", "--authority-dir", str(authority),
                                         "--listener-dir", str(listener),
                                         "--server-name", SERVER_NAME, *extra)
        self.assertEqual(0, status, stderr)
        return stdout

    def rotate(self, authority, listener, *extra):
        return run_cli("rotate-listener", "--authority-dir", str(authority),
                       "--listener-dir", str(listener), *extra)

    @staticmethod
    def snapshot(directory):
        return {name: (directory / name).read_bytes() for name in sorted(os.listdir(directory))}

    def certificate(self, listener):
        return x509.load_pem_x509_certificate((listener / "main-server-certificate.pem").read_bytes())

    def agent_context(self, ca_pem: bytes) -> ssl.SSLContext:
        """What an Agent trusts: only the bundle's CA certificate and server name."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=ca_pem.decode("ascii"))
        context.set_alpn_protocols([ENROLLMENT_ALPN])
        return context


class ListenerRotationTests(ListenerLifecycleHarness):
    def test_rotation_replaces_the_leaf_and_keeps_ca_trust_and_server_name(self):
        authority, listener = self.fresh()
        self.init(authority, listener)
        ca_before = self.snapshot(authority)
        old = self.snapshot(listener)
        old_certificate = self.certificate(listener)
        bundle_ca = ca_before["ca-certificate.pem"]
        status, stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(0, status, stderr)
        self.assertIn("listener rotated: not_after=", stdout)
        self.assertNotIn("PRIVATE KEY", stdout + stderr)
        # The CA directory is untouched, so the exported trust bundle is too.
        self.assertEqual(ca_before, self.snapshot(authority))
        self.assertEqual(sorted(LISTENER_FILES), sorted(os.listdir(listener)))
        new = self.snapshot(listener)
        for name in LISTENER_FILES:
            self.assertNotEqual(old[name], new[name])
            info = os.lstat(listener / name)
            self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
            self.assertEqual(os.geteuid(), info.st_uid)
            self.assertEqual(1, info.st_nlink)
        rotated = self.certificate(listener)
        self.assertNotEqual(old_certificate.serial_number, rotated.serial_number)
        self.assertEqual(SERVER_NAME, main_server_name(PrivateDirectory(listener)))
        rotated.verify_directly_issued_by(x509.load_pem_x509_certificate(bundle_ca))
        self.assertGreater(rotated.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc),
                           396 * DAY)
        # An Agent holding only the original bundle CA authenticates the new leaf.
        material = listener_material(PrivateDirectory(listener))
        handshake(build_enrollment_server_context(material.certificate_path, material.key_path),
                  self.agent_context(bundle_ca))
        deployment = deployment_id_of(PrivateDirectory(authority))
        DeploymentAuthority.load(PrivateDirectory(authority), deployment)

    def test_rotation_refuses_a_listener_issued_by_another_deployment_ca(self):
        authority_a, listener_a = self.fresh("a")
        authority_b, listener_b = self.fresh("b")
        self.init(authority_a, listener_a)
        self.init(authority_b, listener_b)
        before = self.snapshot(listener_b)
        status, stdout, stderr = self.rotate(authority_a, listener_b)
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("refused: listener_authority_mismatch", stderr)
        self.assertEqual(before, self.snapshot(listener_b))

    def test_rotation_refuses_with_a_dedicated_reason_when_the_ca_is_too_close_to_expiry(self):
        authority, listener = self.fresh()
        self.init(authority, listener, "--ca-validity-days", "100", "--server-validity-days", "30")
        before = self.snapshot(listener)
        status, _stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(2, status)
        self.assertIn("refused: deployment_ca_validity_insufficient", stderr)
        self.assertEqual(before, self.snapshot(listener))
        # A shorter, CA-covered validity is still possible.
        status, stdout, stderr = self.rotate(authority, listener, "--server-validity-days", "30")
        self.assertEqual(0, status, stderr)
        self.assertIn("listener rotated", stdout)

    def test_rotation_interrupted_between_renames_is_refused_then_completed(self):
        authority, listener = self.fresh()
        self.init(authority, listener)
        real_replace = PrivateDirectory.replace_with
        calls = []

        def stop_after_key(directory, staged, name):
            calls.append(name)
            if name == "main-server-certificate.pem":
                raise node_ca.CaptureAuthorityError("issuer material could not be replaced")
            return real_replace(directory, staged, name)
        with patch.object(PrivateDirectory, "replace_with", stop_after_key):
            status, _stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(2, status)
        self.assertEqual(["main-server-key.pem", "main-server-certificate.pem"], calls)
        # The new key is current but the certificate is still the old one: a
        # reader refuses with a fixed reason instead of serving a broken pair.
        with self.assertRaises(ListenerMaterialInconsistent):
            listener_material(PrivateDirectory(listener))
        status, stdout, stderr = run_cli(
            "export-bundle", "--authority-dir", str(authority), "--listener-dir", str(listener),
            "--endpoint", "10.0.0.5:8443", "--output", str(self.root / f"bundle-{uuid4()}.json"))
        self.assertEqual(0, status, stderr)  # public bundle does not depend on the leaf pair
        status, stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(0, status, stderr)
        self.assertIn("listener rotation completed (interrupted run)", stdout)
        self.assertEqual(sorted(LISTENER_FILES), sorted(os.listdir(listener)))
        material = listener_material(PrivateDirectory(listener))
        handshake(build_enrollment_server_context(material.certificate_path, material.key_path),
                  self.agent_context((authority / "ca-certificate.pem").read_bytes()))

    def test_rotation_keeps_recovery_state_when_the_key_rename_is_not_durable(self):
        # Codex PR #141: the key rename succeeds but the directory fsync after
        # it fails. The new key is already current, so the staged certificate
        # must survive for the next rotation to complete the pair.
        authority, listener = self.fresh()
        self.init(authority, listener)
        old_certificate = (listener / "main-server-certificate.pem").read_bytes()
        real_replace = PrivateDirectory.replace_with
        real_fsync = os.fsync
        state = {"renaming": None}

        def tracking_replace(directory, staged, name):
            state["renaming"] = name
            try:
                return real_replace(directory, staged, name)
            finally:
                state["renaming"] = None

        def failing_fsync(descriptor):
            if state["renaming"] == "main-server-key.pem":
                raise OSError(errno.EIO, "simulated directory fsync failure")
            return real_fsync(descriptor)
        with patch.object(PrivateDirectory, "replace_with", tracking_replace), \
                patch.object(node_ca.os, "fsync", failing_fsync):
            status, _stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(2, status)
        self.assertIn("refused: issuer_material_replacement_unconfirmed", stderr)
        self.assertTrue((listener / "main-server-certificate.pem.next").exists())
        self.assertEqual(old_certificate, (listener / "main-server-certificate.pem").read_bytes())
        with self.assertRaises(ListenerMaterialInconsistent):
            listener_material(PrivateDirectory(listener))
        status, stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(0, status, stderr)
        self.assertIn("listener rotation completed (interrupted run)", stdout)
        self.assertEqual(sorted(LISTENER_FILES), sorted(os.listdir(listener)))
        material = listener_material(PrivateDirectory(listener))
        handshake(build_enrollment_server_context(material.certificate_path, material.key_path),
                  self.agent_context((authority / "ca-certificate.pem").read_bytes()))

    def test_replace_with_reports_a_completed_but_unsynced_rename(self):
        directory = PrivateDirectory(self.root / f"replace-{uuid4()}").ensure()
        directory.write_new("value.next", b"new")
        directory.write_new("value", b"old")
        real_fsync = os.fsync

        def failing_fsync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError(errno.EIO, "simulated directory fsync failure")
            return real_fsync(descriptor)
        with patch.object(node_ca.os, "fsync", failing_fsync):
            with self.assertRaises(node_ca.ReplacementNotDurable):
                directory.replace_with("value.next", "value")
        self.assertEqual(b"new", directory.read("value"))
        self.assertFalse(directory.exists("value.next"))

    def test_rotation_failing_before_the_first_rename_leaves_the_current_pair(self):
        authority, listener = self.fresh()
        self.init(authority, listener)
        before = self.snapshot(listener)

        def refuse(directory, staged, name):
            raise node_ca.CaptureAuthorityError("issuer material could not be replaced")
        with patch.object(PrivateDirectory, "replace_with", refuse):
            status, _stdout, _stderr = self.rotate(authority, listener)
        self.assertEqual(2, status)
        self.assertEqual(before, self.snapshot(listener))
        listener_material(PrivateDirectory(listener))

    def test_rotation_discards_staged_files_left_by_a_crashed_run(self):
        authority, listener = self.fresh()
        self.init(authority, listener)
        directory = PrivateDirectory(listener)
        directory.write_new("main-server-key.pem.next", b"stale")
        directory.write_new("main-server-certificate.pem.next", b"stale")
        status, stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(0, status, stderr)
        self.assertIn("listener rotated", stdout)
        self.assertEqual(sorted(LISTENER_FILES), sorted(os.listdir(listener)))
        listener_material(PrivateDirectory(listener))

    def test_rotation_is_refused_while_another_process_holds_the_listener(self):
        authority, listener = self.fresh()
        self.init(authority, listener)
        before = self.snapshot(listener)
        with PrivateDirectory(listener).locked():
            status, _stdout, stderr = self.rotate(authority, listener)
        self.assertEqual(2, status)
        self.assertIn("refused: issuer_material_busy", stderr)
        self.assertEqual(before, self.snapshot(listener))


class ConcurrentInitTests(ListenerLifecycleHarness):
    def test_init_is_refused_while_another_init_holds_the_listener_directory(self):
        authority, listener = self.fresh()
        holder = PrivateDirectory(listener).ensure()
        with holder.locked():
            status, stdout, stderr = run_cli("init", "--authority-dir", str(authority),
                                             "--listener-dir", str(listener),
                                             "--server-name", SERVER_NAME)
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("refused: issuer_material_busy", stderr)
        self.assertEqual([], os.listdir(authority))
        self.assertEqual([], os.listdir(listener))
        self.init(authority, listener)

    def test_rollback_removes_only_entries_this_run_created(self):
        # Another process creates the listener key between this run's checks
        # and its write (simulated, as the lock would normally prevent it).
        authority, listener = self.fresh()
        real_write = PrivateDirectory.write_new
        foreign = b"another process's key"

        def racing_write(directory, name, value):
            if name == "main-server-key.pem":
                descriptor = os.open(listener / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(foreign)
            return real_write(directory, name, value)
        with patch.object(PrivateDirectory, "write_new", racing_write):
            status, _stdout, stderr = run_cli("init", "--authority-dir", str(authority),
                                              "--listener-dir", str(listener),
                                              "--server-name", SERVER_NAME)
        self.assertEqual(2, status)
        self.assertIn("refused", stderr)
        self.assertEqual(foreign, (listener / "main-server-key.pem").read_bytes())
        self.assertEqual(["main-server-key.pem"], os.listdir(listener))
        self.assertEqual([], os.listdir(authority))

    def test_discard_created_ignores_a_replaced_entry(self):
        directory = PrivateDirectory(self.root / f"replaced-{uuid4()}").ensure()
        directory.write_new("ca-key.pem", b"mine")
        # Keep the unlinked original open so the filesystem cannot hand its
        # inode number to the replacement (tmpfs/ext4 reuse freed inodes at
        # once, which made this test flaky on CI runners).
        original = os.open(directory.path / "ca-key.pem", os.O_RDONLY)
        self.addCleanup(os.close, original)
        os.unlink(directory.path / "ca-key.pem")
        descriptor = os.open(directory.path / "ca-key.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b"theirs")
        directory.discard_created("ca-key.pem")
        self.assertEqual(b"theirs", (directory.path / "ca-key.pem").read_bytes())
        # An entry never created through this object is never removed.
        PrivateDirectory(directory.path).discard_created("ca-key.pem")
        self.assertTrue((directory.path / "ca-key.pem").exists())


class SeparateListenerAccountTests(ListenerLifecycleHarness):
    """Listener material owned by ``PrivateDirectory.owner_uid`` (Issue #124).

    The test process cannot change ownership to another account, so the
    "other account" is simulated by reporting a different effective UID while
    the real owner stays this process's UID; ``fchown`` to one's own UID is
    then a permitted no-op whose calls can be checked.
    """

    def test_new_listener_entries_are_handed_to_the_listener_owner(self):
        authority, listener = self.fresh()
        real_uid = os.geteuid()
        ca = DeploymentAuthority.create(PrivateDirectory(authority), uuid4(), validity=3650 * DAY)
        target = PrivateDirectory(listener, owner_uid=real_uid)
        calls = []
        real_fchown = os.fchown

        def recording_fchown(descriptor, uid, gid):
            calls.append((stat.S_ISDIR(os.fstat(descriptor).st_mode), uid, gid))
            return real_fchown(descriptor, uid, gid)
        with patch.object(node_ca, "_effective_uid", lambda: real_uid + 4242), \
                patch.object(node_ca, "ownership_privilege_available", lambda *, assign: True), \
                patch("app.cameras.remote_agent.node_ca.os.fchown", recording_fchown):
            ca.issue_main_server_credential(target, server_name=SERVER_NAME, validity=30 * DAY)
        # The new directory and both files, each before content was written.
        self.assertEqual([(True, real_uid, -1), (False, real_uid, -1), (False, real_uid, -1)], calls)
        # The listener account (here this process) reads it as its own.
        listener_material(PrivateDirectory(listener))

    def test_missing_privilege_is_refused_before_anything_is_written(self):
        authority, listener = self.fresh()
        other = os.geteuid() + 4242
        with patch.object(node_ca, "_effective_capabilities", lambda: 0):
            status, stdout, stderr = run_cli("init", "--authority-dir", str(authority),
                                             "--listener-dir", str(listener),
                                             "--server-name", SERVER_NAME,
                                             "--listener-owner", str(other))
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("refused: listener_owner_requires_privilege", stderr)
        self.assertFalse((authority / "ca-key.pem").exists())
        self.assertFalse(listener.exists())

    def test_reading_another_accounts_listener_requires_privilege(self):
        authority, listener = self.fresh()
        self.init(authority, listener)
        foreign = PrivateDirectory(listener, owner_uid=os.geteuid() + 4242)
        with patch.object(node_ca, "_effective_capabilities", lambda: 0):
            with self.assertRaises(OwnershipPrivilegeRequired):
                listener_material(foreign)
        with patch.object(node_ca, "_effective_capabilities", lambda: None):
            with self.assertRaises(OwnershipPrivilegeRequired):
                main_server_name(foreign)

    def test_failed_ownership_change_rolls_back_the_whole_init(self):
        authority, listener = self.fresh()
        PrivateDirectory(listener).ensure()  # pre-created by this account
        real_fchown = os.fchown

        def refusing_fchown(descriptor, uid, gid):
            # Only the listener account's files cannot be handed over.
            if os.readlink(f"/proc/self/fd/{descriptor}").startswith(str(listener) + "/"):
                raise PermissionError(errno.EPERM, "synthetic")
            return real_fchown(descriptor, uid, gid)
        real_uid = os.geteuid()
        with patch.object(node_ca, "ownership_privilege_available", lambda *, assign: True), \
                patch("app.cameras.remote_agent.node_ca.os.fchown", refusing_fchown):
            authority_directory = PrivateDirectory(authority)
            listener_directory = PrivateDirectory(listener, owner_uid=real_uid)
            with patch.object(node_ca, "_effective_uid", lambda: real_uid + 4242):
                # The CA is written first; the listener key's ownership change
                # then fails, and the CA this run created must be removed.
                with self.assertRaises(node_ca.CaptureAuthorityError):
                    DeploymentAuthority.initialize(
                        authority_directory, listener_directory, uuid4(),
                        validity=3650 * DAY, server_name=SERVER_NAME, server_validity=30 * DAY)
        self.assertEqual([], os.listdir(authority))
        self.assertEqual([], os.listdir(listener))

    def test_capability_mask_parsing(self):
        cases = ((0, True, False), (0, False, False), (0b011, True, True), (0b001, True, False),
                 (0b010, False, True), (0b100, False, True), (0b100, True, False))
        for mask, assign, expected in cases:
            with self.subTest(mask=mask, assign=assign), \
                    patch.object(node_ca, "_effective_capabilities", lambda mask=mask: mask):
                self.assertEqual(expected, node_ca.ownership_privilege_available(assign=assign))

    def test_listener_owner_argument_accepts_names_and_uids_only(self):
        self.assertEqual(1234, pairing_cli._account("1234"))
        name = pwd.getpwuid(os.geteuid()).pw_name
        self.assertEqual(os.geteuid(), pairing_cli._account(name))
        for bad in ("no-such-account-serversentinel", str(2 ** 32)):
            with self.subTest(bad=bad), self.assertRaises(argparse.ArgumentTypeError):
                pairing_cli._account(bad)


class AuthorityValidityTests(ListenerLifecycleHarness):
    def test_leaf_beyond_the_ca_is_a_dedicated_error(self):
        authority, _listener = self.fresh()
        ca = DeploymentAuthority.create(PrivateDirectory(authority), uuid4(), validity=100 * DAY)
        with self.assertRaises(AuthorityValidityExceeded) as raised:
            ca.check_leaf_validity(397 * DAY)
        self.assertEqual("deployment_ca_validity_insufficient", raised.exception.reason)
        ca.check_leaf_validity(30 * DAY)

    def test_approve_refuses_before_any_approval_when_the_ca_cannot_cover_a_node(self):
        authority, listener = self.fresh()
        self.init(authority, listener, "--ca-validity-days", "100", "--server-validity-days", "30")
        database = self.root / f"state-{uuid4()}.sqlite3"

        class Terminal:
            def __init__(self, *args, **kwargs):
                pass

            def write(self, text):
                raise AssertionError("nothing may be shown")

            def read_line(self):
                raise AssertionError("no confirmation may be requested")

            def close(self):
                pass
        with patch.object(pairing_cli, "ControllingTerminal", Terminal):
            status, _stdout, stderr = run_cli(
                "approve", "--database", str(database), "--authority-dir", str(authority),
                "--listener-dir", str(listener), "--request", str(self.root / "unused.json"),
                "--listen", "127.0.0.1:18443")
        self.assertEqual(2, status)
        self.assertIn("refused: deployment_ca_validity_insufficient", stderr)
        self.assertFalse(database.exists())


class EnrollmentListenerRebindTests(ListenerLifecycleHarness):
    def listener(self, port):
        authority, listener = self.fresh()
        self.init(authority, listener)
        material = listener_material(PrivateDirectory(listener))
        context = build_enrollment_server_context(material.certificate_path, material.key_path)
        return EnrollmentListener(EnrollmentListenerConfig("127.0.0.1", port), context,
                                  limits=EnrollmentLimits())

    @staticmethod
    def free_port():
        with socket.create_server(("127.0.0.1", 0)) as probe:
            return probe.getsockname()[1]

    def test_rerun_binds_while_the_previous_connection_is_in_time_wait(self):
        port = self.free_port()
        first = self.listener(port)
        first.open()
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        accepted, _ = first._socket.accept()
        accepted.close()  # the server closes first, so its side enters TIME_WAIT
        client.recv(1)
        client.close()
        first.close()
        time.sleep(0.05)
        second = self.listener(port)
        second.open()  # without SO_REUSEADDR: enrollment_listener_bind_failed
        self.addCleanup(second.close)
        self.assertEqual(port, second.address[1])

    def test_reuseaddr_never_lets_a_second_listener_take_a_live_port(self):
        port = self.free_port()
        first = self.listener(port)
        first.open()
        self.addCleanup(first.close)
        self.assertTrue(first._socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))
        self.assertFalse(first._socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT))
        second = self.listener(port)
        with self.assertRaises(EnrollmentConfigurationError) as raised:
            second.open()
        self.assertEqual("enrollment_listener_bind_failed", raised.exception.reason)
        # Nor can a plain socket that also sets SO_REUSEADDR.
        intruder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(intruder.close)
        intruder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with self.assertRaises(OSError):
            intruder.bind(("127.0.0.1", port))


class LockTests(ListenerLifecycleHarness):
    def test_lock_is_exclusive_across_open_descriptions_and_released(self):
        directory = PrivateDirectory(self.root / f"lock-{uuid4()}").ensure()
        with directory.locked():
            with self.assertRaises(IssuerMaterialBusy):
                with PrivateDirectory(directory.path).locked():
                    pass
        with PrivateDirectory(directory.path).locked():
            pass


class NoPromptTerminal:
    """A controlling terminal that fails the test if anything is shown or asked."""

    def __init__(self, *args, **kwargs):
        pass

    def write(self, text):
        raise AssertionError("nothing may be shown")

    def read_line(self):
        raise AssertionError("no confirmation may be requested")

    def close(self):
        pass


class AuthorityConsistencyTests(ListenerLifecycleHarness):
    """#125 item 4: a CA directory and a listener directory of different deployments."""

    def test_export_bundle_refuses_a_listener_from_another_deployment(self):
        authority_a, listener_a = self.fresh("a")
        authority_b, listener_b = self.fresh("b")
        self.init(authority_a, listener_a)
        self.init(authority_b, listener_b)
        output = self.root / f"bundle-{uuid4()}.json"
        status, stdout, stderr = run_cli(
            "export-bundle", "--authority-dir", str(authority_a), "--listener-dir", str(listener_b),
            "--endpoint", "10.0.0.5:8443", "--output", str(output))
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("refused: listener_authority_mismatch", stderr)
        self.assertFalse(output.exists())
        status, stdout, stderr = run_cli(
            "export-bundle", "--authority-dir", str(authority_a), "--listener-dir", str(listener_a),
            "--endpoint", "10.0.0.5:8443", "--output", str(output))
        self.assertEqual(0, status, stderr)
        self.assertRegex(stdout, r"^trust_bundle_sha256=[0-9a-f]{64}\n$")

    def test_approve_refuses_a_listener_from_another_deployment_before_any_approval(self):
        authority_a, listener_a = self.fresh("a")
        authority_b, listener_b = self.fresh("b")
        self.init(authority_a, listener_a)
        self.init(authority_b, listener_b)
        database = existing_database(self.root)
        with patch.object(pairing_cli, "ControllingTerminal", NoPromptTerminal):
            status, _stdout, stderr = run_cli(
                "approve", "--database", str(database), "--authority-dir", str(authority_a),
                "--listener-dir", str(listener_b), "--request", str(self.root / "unused.json"),
                "--listen", "127.0.0.1:18443")
        self.assertEqual(2, status)
        self.assertIn("refused: listener_authority_mismatch", stderr)


def existing_database(root):
    path = root / f"state-{uuid4()}.sqlite3"
    with closing(Database(path).connect()) as connection:
        migrate(connection, APPLICATION_MIGRATIONS)
    return path


class ExistingDatabaseTests(ListenerLifecycleHarness):
    """#125 item 5: approve/list/revoke never create or migrate a mistyped database."""

    def refused(self, database, *, command="list"):
        argv = {"list": ["list", "--database", str(database)],
                "revoke": ["revoke", "--database", str(database), "--node", str(uuid4())]}[command]
        with patch.object(pairing_cli, "ControllingTerminal", NoPromptTerminal):
            status, stdout, stderr = run_cli(*argv)
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        return stderr

    def test_missing_database_is_refused_and_not_created(self):
        missing = self.root / f"typo-{uuid4()}.sqlite3"
        for command in ("list", "revoke"):
            with self.subTest(command=command):
                self.assertIn("refused: database_not_found", self.refused(missing, command=command))
                self.assertFalse(missing.exists())

    def test_approve_with_a_missing_database_is_refused_before_any_approval(self):
        authority, listener = self.fresh()
        self.init(authority, listener)
        _key, csr, digest = node_request()
        request = self.root / f"request-{uuid4()}.json"
        request.write_text(json.dumps({"format_version": 1, "csr": csr.decode(),
                                       "public_key_digest": digest}))
        missing = self.root / f"typo-{uuid4()}.sqlite3"
        with patch.object(pairing_cli, "ControllingTerminal", NoPromptTerminal):
            status, _stdout, stderr = run_cli(
                "approve", "--database", str(missing), "--authority-dir", str(authority),
                "--listener-dir", str(listener), "--request", str(request),
                "--listen", "127.0.0.1:18443")
        self.assertEqual(2, status)
        self.assertIn("refused: database_not_found", stderr)
        self.assertFalse(missing.exists())

    def test_unsafe_database_paths_are_refused(self):
        real = existing_database(self.root)
        link = self.root / f"link-{uuid4()}.sqlite3"
        link.symlink_to(real)
        self.assertIn("refused: database_path_rejected", self.refused(link))
        self.assertIn("refused: database_path_rejected",
                      self.refused(Path("relative/state.sqlite3")))
        directory = self.root / f"dir-{uuid4()}.sqlite3"
        directory.mkdir()
        self.assertIn("refused: database_rejected", self.refused(directory))
        shared = existing_database(self.root)
        os.chmod(shared, 0o664)
        self.assertIn("refused: database_rejected", self.refused(shared))
        linked = existing_database(self.root)
        os.link(linked, self.root / f"hardlink-{uuid4()}")
        self.assertIn("refused: database_rejected", self.refused(linked))
        owned = existing_database(self.root)
        real_uid = os.geteuid()
        with patch.object(pairing_cli.os, "geteuid", lambda: real_uid + 4242):
            self.assertIn("refused: database_rejected", self.refused(owned))

    def test_outdated_schema_is_refused_and_never_migrated(self):
        # Codex PR #141: administrative commands must not apply migrations.
        database = self.root / f"old-{uuid4()}.sqlite3"
        with closing(Database(database).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS[:-1])
        before = database.read_bytes()
        for command in ("list", "revoke"):
            with self.subTest(command=command):
                self.assertIn("refused: database_schema_outdated",
                              self.refused(database, command=command))
                self.assertEqual(before, database.read_bytes())
        with closing(sqlite3.connect(database)) as connection:
            versions = connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        self.assertEqual(len(APPLICATION_MIGRATIONS) - 1, versions)

    def test_database_without_the_application_schema_is_refused_unchanged(self):
        empty = self.root / f"empty-{uuid4()}.sqlite3"
        with closing(sqlite3.connect(empty)) as connection:
            connection.execute("CREATE TABLE unrelated (value TEXT)")
        os.chmod(empty, 0o600)
        before = empty.read_bytes()
        self.assertIn("refused: database_schema_unsupported", self.refused(empty))
        self.assertEqual(before, empty.read_bytes())
        with closing(sqlite3.connect(empty)) as connection:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertEqual({"unrelated"}, tables)

    def test_newer_or_edited_schema_history_is_refused(self):
        database = existing_database(self.root)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("UPDATE schema_migrations SET checksum = 'edited' WHERE version = 1")
            connection.commit()
        self.assertIn("refused: database_schema_unsupported", self.refused(database))

    def test_existing_database_is_used(self):
        database = existing_database(self.root)
        status, stdout, stderr = run_cli("list", "--database", str(database))
        self.assertEqual(0, status, stderr)
        self.assertEqual("", stdout)


class ReplacingTerminal:
    """Types ``word`` after running ``action`` (the database swap) mid-confirmation."""

    def __init__(self, word, action):
        self.word, self.action = word, action

    def write(self, text):
        pass

    def read_line(self):
        self.action()
        return self.word

    def close(self):
        pass


class PinnedDatabaseTests(ListenerLifecycleHarness):
    """Codex PR #141: every ledger connection stays on the validated database file."""

    def replace(self, database):
        """Move the validated file away and put another valid database at its path."""
        moved = self.root / f"moved-{uuid4()}.sqlite3"
        os.rename(database, moved)
        replacement = existing_database(self.root)
        os.rename(replacement, database)
        return moved

    @staticmethod
    def audit_rows(path):
        with closing(sqlite3.connect(path)) as connection:
            return connection.execute("SELECT COUNT(*) FROM security_admin_audit_records").fetchone()[0]

    def test_revoke_refuses_when_the_database_is_replaced_during_confirmation(self):
        database = existing_database(self.root)
        moved = {}
        terminal = ReplacingTerminal("REVOKE", lambda: moved.setdefault("path", self.replace(database)))
        with patch.object(pairing_cli, "ControllingTerminal", lambda: terminal):
            status, stdout, stderr = run_cli("revoke", "--database", str(database),
                                             "--node", str(uuid4()))
        self.assertEqual(2, status)
        self.assertEqual("", stdout)
        self.assertIn("refused: database_rejected", stderr)
        self.assertEqual(0, self.audit_rows(database))
        self.assertEqual(0, self.audit_rows(moved["path"]))

    def test_revoke_never_recreates_a_database_removed_during_confirmation(self):
        database = existing_database(self.root)
        terminal = ReplacingTerminal("REVOKE", lambda: os.unlink(database))
        with patch.object(pairing_cli, "ControllingTerminal", lambda: terminal):
            status, _stdout, stderr = run_cli("revoke", "--database", str(database),
                                              "--node", str(uuid4()))
        self.assertEqual(2, status)
        self.assertIn("refused: database_rejected", stderr)
        self.assertFalse(database.exists())

    def test_every_connection_and_commit_rechecks_the_pinned_file(self):
        database = existing_database(self.root)
        with pairing_cli._ledger(database) as ledger:
            connection = ledger.database.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("INSERT INTO application_metadata VALUES ('probe', 'x')")
                self.replace(database)
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("COMMIT")
            finally:
                connection.close()
            with self.assertRaises(pairing_cli.PairingError):
                ledger.pairing_summaries()
            self.assertTrue(ledger.database.rejected)

    def test_a_connection_opened_on_a_substitute_file_is_refused(self):
        # Codex PR #141: the path names file B only while SQLite opens it and
        # is restored to the pinned file A before the post-open check. A
        # pathname check passes; the opened descriptor's inode must not.
        database = existing_database(self.root)
        substitute = existing_database(self.root)
        parked = self.root / f"parked-{uuid4()}.sqlite3"
        real_connect = sqlite3.connect

        def swapping_connect(*args, **kwargs):
            os.rename(database, parked)
            os.rename(substitute, database)
            try:
                return real_connect(*args, **kwargs)
            finally:
                os.rename(database, substitute)
                os.rename(parked, database)
        with pairing_cli._ledger(database) as ledger:
            owner = pairing_cli.LocalConsoleOwner()
            grant = object()
            owner._grants.append(grant)
            with patch.object(pairing_cli.sqlite3, "connect", swapping_connect):
                with self.assertRaises(pairing_cli.PairingError):
                    ledger.revoke(owner, grant, node_id=uuid4())
            self.assertTrue(ledger.database.rejected)
        self.assertEqual(0, self.audit_rows(substitute))
        self.assertEqual(0, self.audit_rows(database))

    def test_wal_mode_database_with_sidecars_is_accepted(self):
        database = existing_database(self.root)
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual("wal", connection.execute("PRAGMA journal_mode = WAL").fetchone()[0])
        holder = sqlite3.connect(database)  # keeps -wal/-shm present
        self.addCleanup(holder.close)
        holder.execute("SELECT count(*) FROM sqlite_master").fetchone()
        status, _stdout, stderr = run_cli("list", "--database", str(database))
        self.assertEqual(0, status, stderr)
        terminal = ReplacingTerminal("REVOKE", lambda: None)
        with patch.object(pairing_cli, "ControllingTerminal", lambda: terminal):
            status, stdout, stderr = run_cli("revoke", "--database", str(database),
                                             "--node", str(uuid4()))
        self.assertNotIn("database_rejected", stderr)

    def test_ledger_database_refuses_once_released(self):
        database = existing_database(self.root)
        with pairing_cli._ledger(database) as ledger:
            pass
        with self.assertRaises(sqlite3.DatabaseError):
            ledger.database.connect()


if __name__ == "__main__":
    unittest.main()
