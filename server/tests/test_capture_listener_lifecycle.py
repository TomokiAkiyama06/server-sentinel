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
import datetime
import errno
import io
import os
import pwd
from pathlib import Path
import socket
import ssl
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography import x509

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


SERVER_NAME = "capture-main.serversentinel.test"
DAY = datetime.timedelta(days=1)
LISTENER_FILES = ("main-server-certificate.pem", "main-server-key.pem")


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


if __name__ == "__main__":
    unittest.main()
