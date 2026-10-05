"""Issue #126 helper protocol, peer checks and client, on synthetic /proc trees.

No real sshd, systemd unit or privileged process is involved: the helper runs
in this test process against a temporary directory shaped like ``/proc`` and
answers over a temporary unix socket. Real-host behaviour (capabilities,
socket activation, the service account's group) is a MANUAL_TEST.md step.
"""

import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
from tempfile import TemporaryDirectory
import threading
import time
from unittest import TestCase

from app.auth.reservation import (
    CheckKind, HostnameReservationCheck, IsolationMode, Listener, ListenerException, ProcNetListeners,
    Reason, ReservationConfig, ReservationEnumerationError, ServeStatusRoutes, SocketOwner,
)
from app.auth.socket_owner import (
    MAX_REQUEST_BYTES, MAX_REQUEST_INODES, OP_OWNERS, OP_REQUESTER_ONLY, SocketOwnerHelper,
    SocketOwnerHelperClient, SocketOwnerProtocolError, decode_owners, decode_request,
    decode_requester_only, encode_error, encode_owners, encode_request, read_service_uid,
    systemd_listener,
)


HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
          "   uid  timeout inode")
UID = os.getuid()
SSHD = SocketOwner("/usr/sbin/sshd", "ssh.service")
PYTHON = "/usr/bin/python3.12"


def _hex(address):
    raw = ipaddress.ip_address(address).packed
    return b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4)).hex().upper()


def proc_net(*rows, ipv6=False):
    """(address, port, state, inode) rows as little-endian /proc/net text."""
    zero = "::" if ipv6 else "0.0.0.0"
    lines = [HEADER]
    for number, (address, port, state, inode) in enumerate(rows):
        lines.append(f"{number:4d}: {_hex(address)}:{port:04X} {_hex(zero)}:0000 {state} "
                     f"00000000:00000000 00:00000000 00000000  0        0 {inode} 1 0000000000000000 100 0 0 10 0")
    return "\n".join(lines) + "\n"


class SyntheticProc:
    """A /proc-shaped tree: the peer (this test process) and other processes."""

    def __init__(self, root: Path, *, tcp=(), tcp6=(), udp=(), udp6=(), peer_uid=UID):
        self.root = root
        self.peer = self.process(os.getpid(), PYTHON, [], cgroup="0::/system.slice/server-sentinel.service\n")
        (self.peer / "status").write_text(f"Name:\tpythoné\nUid:\t{peer_uid}\t{peer_uid}\t{peer_uid}\t{peer_uid}\n")
        net = self.peer / "net"
        net.mkdir()
        (net / "tcp").write_text(proc_net(*tcp))
        (net / "tcp6").write_text(proc_net(*tcp6, ipv6=True))
        (net / "udp").write_text(proc_net(*udp))
        (net / "udp6").write_text(proc_net(*udp6, ipv6=True))

    def process(self, pid, exe, fds, cgroup="0::/system.slice/ssh.service\n"):
        base = self.root / str(pid)
        (base / "fd").mkdir(parents=True, exist_ok=True)
        if not (base / "exe").is_symlink():
            (base / "exe").symlink_to(exe)
            (base / "cgroup").write_text(cgroup)
        for target in fds:
            number = len(os.listdir(base / "fd"))
            (base / "fd" / str(number + 3)).symlink_to(target)
        return base


class Audit:
    def __init__(self):
        self.events = []

    def __call__(self, event, **fields):
        self.events.append((event, fields))


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


class Fixture(TestCase):
    def setUp(self):
        if UID == 0:
            self.skipTest("the synthetic peer must be a non-root service account")
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        (self.base / "proc").mkdir()
        # tcp: the loopback upstream (1000, held by the peer), a wildcard sshd
        # (1001), a connected socket (1002, not listening); udp: tailscaled-like (1003).
        self.proc = SyntheticProc(self.base / "proc",
                                  tcp=(("127.0.0.1", 8080, "0A", 1000), ("0.0.0.0", 22, "0A", 1001),
                                       ("100.64.0.10", 40000, "01", 1002)),
                                  udp=(("0.0.0.0", 41641, "07", 1003),))
        self.proc.process(os.getpid(), PYTHON, ["socket:[1000]"])
        self.proc.process(4242, "/usr/sbin/sshd", ["socket:[1001]", "socket:[1002]"])
        self.proc.process(4343, "/usr/sbin/tailscaled", ["socket:[1003]"],
                          cgroup="0::/system.slice/tailscaled.service\n")
        self.audit = Audit()
        self.clock = Clock()

    def helper(self, **kwargs):
        kwargs.setdefault("audit", self.audit)
        kwargs.setdefault("monotonic", self.clock)
        return SocketOwnerHelper(kwargs.pop("service_uid", UID), proc=str(self.base / "proc"), **kwargs)


class ProtocolTests(TestCase):
    def test_request_round_trip_and_bounds(self):
        self.assertEqual(decode_request(encode_request(OP_OWNERS, {3, 1, 2})), (OP_OWNERS, frozenset({1, 2, 3})))
        for op, inodes in ((OP_OWNERS, set()), ("pids", {1}), (OP_OWNERS, {0}), (OP_OWNERS, {-1}),
                           (OP_OWNERS, {True}), (OP_OWNERS, set(range(1, MAX_REQUEST_INODES + 2)))):
            with self.subTest(op=op, inodes=len(inodes)), self.assertRaises(SocketOwnerProtocolError):
                encode_request(op, inodes)

    def test_malformed_requests_are_refused(self):
        cases = [b"", b"{", b"[]", b'{"version":1,"op":"owners"}', b'{"version":2,"op":"owners","inodes":[1]}',
                 b'{"version":true,"op":"owners","inodes":[1]}',
                 b'{"version":1,"op":"owners","inodes":[1],"pid":1}', b'{"version":1,"op":"owners","inodes":[1,1]}',
                 b'{"version":1,"op":"owners","inodes":["1"]}', b'{"version":1,"op":"owners","inodes":[1.0]}',
                 b'{"version":1,"version":1,"op":"owners","inodes":[1]}', b'{"version":1,"op":"owners","inodes":[]}',
                 b"\xff", b" " * (MAX_REQUEST_BYTES + 1)]
        for data in cases:
            with self.subTest(data=data[:40]), self.assertRaises(SocketOwnerProtocolError):
                decode_request(data)

    def test_owner_answer_round_trip_carries_no_process_detail(self):
        data = encode_owners({1001: frozenset({SSHD, SocketOwner(None, None)})})
        document = json.loads(data)
        self.assertEqual(set(document["sockets"][0]["holders"][0]), {"executable", "unit"})
        self.assertEqual(decode_owners(data, frozenset({1001})), {1001: frozenset({SSHD, SocketOwner(None, None)})})

    def test_malformed_answers_raise(self):
        requested = frozenset({1001})
        good = {"inode": 1001, "holders": [{"executable": "/usr/sbin/sshd", "unit": "ssh.service"}]}
        cases = [
            {"version": 1, "sockets": [{**good, "inode": 9}]},
            {"version": 1, "sockets": [good, good]},
            {"version": 1, "sockets": [{**good, "pid": 1}]},
            {"version": 1, "sockets": [{**good, "holders": []}]},
            {"version": 1, "sockets": [{**good, "holders": [{"executable": "sshd", "unit": None}]}]},
            {"version": 1, "sockets": [{**good, "holders": [{"executable": None, "unit": "../x.service"}]}]},
            {"version": 1, "sockets": [{**good, "holders": [{"executable": None, "unit": None, "uid": 0}]}]},
            {"version": 1, "sockets": "all"},
            {"version": 1, "error": "lower case"},
            {"version": 2, "sockets": []},
        ]
        for document in cases:
            with self.subTest(document=document), self.assertRaises(SocketOwnerProtocolError):
                decode_owners(json.dumps(document).encode(), requested)
        with self.assertRaises(SocketOwnerProtocolError):
            decode_requester_only(b'{"version":1,"sockets":[{"inode":1001,"requester_only":1}]}', requested)

    def test_error_answer_raises_the_code(self):
        with self.assertRaisesRegex(ReservationEnumerationError, "RATE_LIMITED"):
            decode_owners(encode_error("RATE_LIMITED"), frozenset({1}))


class HelperAnswerTests(Fixture):
    def test_owners_only_for_sockets_listening_in_the_peer_namespace(self):
        answer = decode_owners(self.helper().answer(encode_request(OP_OWNERS, {1001, 1002, 1003, 9999}),
                                                    os.getpid()), frozenset({1001, 1002, 1003, 9999}))
        # 1002 is sshd's connected socket: held, but not a listener, so not answered.
        self.assertEqual(answer, {1001: frozenset({SSHD}),
                                  1003: frozenset({SocketOwner("/usr/sbin/tailscaled", "tailscaled.service")})})
        self.assertEqual(self.audit.events[-1], ("answered", {"op": OP_OWNERS, "inodes": 4, "answered": 2}))

    def test_requester_only(self):
        helper = self.helper()
        request = encode_request(OP_REQUESTER_ONLY, {1000, 1001})
        self.assertEqual(decode_requester_only(helper.answer(request, os.getpid()), frozenset({1000, 1001})),
                         {1000: True, 1001: False})
        # A forked child (or SCM_RIGHTS receiver) shares the upstream socket.
        self.proc.process(5555, PYTHON, ["socket:[1000]"], cgroup="0::/system.slice/server-sentinel.service\n")
        self.assertEqual(decode_requester_only(helper.answer(request, os.getpid()), frozenset({1000, 1001})),
                         {1000: False, 1001: False})

    def test_peer_of_another_account_or_gone_is_unverified(self):
        for name, prepare in {
            "status uid differs": lambda: (self.proc.peer / "status").write_text("Uid:\t1\t1\t1\t1\n"),
            "status unreadable": lambda: (self.proc.peer / "status").unlink(),
            "netns tables missing": lambda: (self.proc.peer / "net" / "udp6").unlink(),
        }.items():
            with self.subTest(name):
                self.setUp()
                prepare()
                data = self.helper().answer(encode_request(OP_OWNERS, {1001}), os.getpid())
                self.assertEqual(json.loads(data), {"version": 1, "error": "PEER_UNVERIFIED"})
        data = self.helper().answer(encode_request(OP_OWNERS, {1001}), 77777)
        self.assertEqual(json.loads(data)["error"], "PEER_UNVERIFIED")

    def test_incomplete_scan_fails_closed(self):
        hidden = self.proc.process(6000, "/usr/sbin/other", [])
        (hidden / "fd").chmod(0)
        self.addCleanup((hidden / "fd").chmod, 0o700)
        if os.access(hidden / "fd", os.R_OK):
            self.skipTest("running with privilege that bypasses directory permissions")
        data = self.helper().answer(encode_request(OP_REQUESTER_ONLY, {1000}), os.getpid())
        self.assertEqual(json.loads(data)["error"], "SOCKET_OWNERS_INCOMPLETE")
        self.assertEqual(self.audit.events[-1][0], "failed")

    def test_bad_request_is_refused(self):
        self.assertEqual(json.loads(self.helper().answer(b"{}", os.getpid()))["error"], "BAD_REQUEST")


class HelperConnectionTests(Fixture):
    def exchange(self, helper, payload, *, shutdown=True):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with client:
            client.sendall(payload)
            if shutdown:
                client.shutdown(socket.SHUT_WR)
            helper.handle(server)
            try:
                return client.recv(1 << 20)
            except ConnectionResetError:
                # Closed with the request still unread.
                return b""

    def test_service_peer_is_answered(self):
        data = self.exchange(self.helper(), encode_request(OP_OWNERS, {1001}) + b"\n")
        self.assertEqual(decode_owners(data, frozenset({1001})), {1001: frozenset({SSHD})})

    def test_other_uid_is_closed_unread_and_audited_coalesced(self):
        helper = self.helper(service_uid=UID + 1)
        for _ in range(3):
            self.assertEqual(self.exchange(helper, encode_request(OP_OWNERS, {1001}) + b"\n"), b"")
        refused = [fields for event, fields in self.audit.events if event == "refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual((refused[0]["reason"], refused[0]["peer_uid"]), ("peer_uid", UID))
        self.clock.value += 61
        self.exchange(helper, b"x\n")
        refused = [fields for event, fields in self.audit.events if event == "refused"]
        self.assertEqual(refused[-1]["count"], 3)

    def test_rate_limit(self):
        helper = self.helper(burst=2, rate=0.5)
        request = encode_request(OP_OWNERS, {1001}) + b"\n"
        for _ in range(2):
            self.assertIn(b"sockets", self.exchange(helper, request))
        self.assertEqual(json.loads(self.exchange(helper, request))["error"], "RATE_LIMITED")
        self.clock.value += 2
        self.assertIn(b"sockets", self.exchange(helper, request))

    def test_oversized_unterminated_or_slow_request(self):
        helper = self.helper(connection_timeout=0.2)
        for payload, shutdown in ((b"x" * (MAX_REQUEST_BYTES + 10) + b"\n", True),
                                  (encode_request(OP_OWNERS, {1001}), True),
                                  (encode_request(OP_OWNERS, {1001}) + b"\nextra", True)):
            with self.subTest(size=len(payload)):
                self.assertEqual(json.loads(self.exchange(helper, payload, shutdown=shutdown))["error"],
                                 "BAD_REQUEST")
        real = SocketOwnerHelper(UID, proc=str(self.base / "proc"), audit=self.audit, connection_timeout=0.2)
        started = time.monotonic()
        self.assertEqual(json.loads(self.exchange(real, b'{"version":1', shutdown=False))["error"], "BAD_REQUEST")
        self.assertLess(time.monotonic() - started, 2)


class ServedHelper:
    """The helper answering on a temporary unix socket in a background thread."""

    def __init__(self, helper, directory: Path):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        self.path = str(directory / "socket")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        os.chmod(self.path, 0o660)
        self.listener.listen(8)
        self.thread = threading.Thread(target=self._serve, args=(helper,), daemon=True)
        self.thread.start()

    def _serve(self, helper):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            helper.handle(connection)

    def close(self):
        self.listener.shutdown(socket.SHUT_RDWR)
        self.listener.close()


class ClientTests(Fixture):
    def served(self, **kwargs):
        served = ServedHelper(self.helper(**kwargs), self.base / "run")
        self.addCleanup(served.close)
        return served

    def client(self, path, **kwargs):
        kwargs.setdefault("trusted_uid", UID)
        return SocketOwnerHelperClient(path, **kwargs)

    def test_end_to_end_answers(self):
        client = self.client(self.served().path)
        self.assertEqual(client.owners(frozenset({1001})), {1001: frozenset({SSHD})})
        self.assertEqual(client.held_only_by_requester(frozenset({1000})), {1000: True})
        self.assertEqual(client.owners(frozenset()), {})

    def test_untrusted_or_missing_endpoint(self):
        served = self.served()
        with self.assertRaisesRegex(ReservationEnumerationError, "HELPER_UNTRUSTED"):
            self.client(served.path, trusted_uid=UID + 1).owners(frozenset({1001}))
        os.chmod(served.path, 0o666)
        with self.assertRaisesRegex(ReservationEnumerationError, "HELPER_UNTRUSTED"):
            self.client(served.path).owners(frozenset({1001}))
        os.chmod(served.path, 0o660)
        (self.base / "run").chmod(0o777)
        self.addCleanup((self.base / "run").chmod, 0o755)
        with self.assertRaisesRegex(ReservationEnumerationError, "HELPER_UNTRUSTED"):
            self.client(served.path).owners(frozenset({1001}))
        with self.assertRaisesRegex(ReservationEnumerationError, "HELPER_UNAVAILABLE"):
            self.client(str(self.base / "absent" / "socket")).owners(frozenset({1001}))

    def test_regular_file_in_place_of_the_socket_is_untrusted(self):
        (self.base / "run").mkdir(mode=0o755)
        (self.base / "run" / "socket").write_text("")
        with self.assertRaisesRegex(ReservationEnumerationError, "HELPER_UNTRUSTED"):
            self.client(str(self.base / "run" / "socket")).owners(frozenset({1001}))

    def test_silent_helper_times_out(self):
        (self.base / "run").mkdir(mode=0o755)
        path = str(self.base / "run" / "socket")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(path)
        os.chmod(path, 0o660)
        listener.listen(1)
        started = time.monotonic()
        with self.assertRaisesRegex(ReservationEnumerationError, "HELPER_TIMEOUT"):
            self.client(path, timeout=0.2).owners(frozenset({1001}))
        self.assertLess(time.monotonic() - started, 2)

    def test_refused_peer_sees_a_failure(self):
        served = self.served(service_uid=UID + 1)
        with self.assertRaisesRegex(ReservationEnumerationError, "HELPER_RESPONSE_INVALID|HELPER_UNAVAILABLE"):
            self.client(served.path).owners(frozenset({1001}))

    def test_invalid_client_configuration(self):
        for kwargs in (dict(path="relative"), dict(path="/run/../x"), dict(timeout=0), dict(timeout=True),
                       dict(trusted_uid=-1)):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SocketOwnerHelperClient(**kwargs)


class ReservationCompositionTests(Fixture):
    """The reservation check composed with the client and helper (still synthetic)."""

    def check(self, client, files):
        config = ReservationConfig(
            hostname="sentinel.example-tailnet.ts.net", port=443,
            reserved_addresses=frozenset({ipaddress.IPv4Address("100.64.0.10")}),
            human_listener=Listener(ipaddress.IPv4Address("127.0.0.1"), 8080),
            isolation=IsolationMode.SINGLE_PURPOSE_NODE)

        class Resolver:
            def resolve(self, hostname):
                return (ipaddress.IPv4Address("100.64.0.10"),)

        class Revoker:
            pending = False

            def record_exposure(self):
                self.pending = True

            def exposure_pending(self):
                return self.pending

            def revoke_all_human_sessions(self):
                self.pending = False

        status = json.dumps({"TCP": {"443": {"HTTPS": True}}, "Web": {
            "sentinel.example-tailnet.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}}}})

        class Sink:
            def emit(self, fault):
                pass

        check = HostnameReservationCheck(
            config, ProcNetListeners(lambda name: files[name], byteorder="little"), ServeStatusRoutes(lambda: status),
            Sink(), resolver=Resolver(), socket_owners=client, own_sockets=lambda: frozenset({1000}),
            session_revoker=Revoker())
        check._exceptions, check._exceptions_loaded = frozenset({ListenerException(22, executable="/usr/sbin/sshd")}), True
        return check

    def files(self):
        return {name: (self.proc.peer / "net" / name).read_text() for name in ("tcp", "tcp6", "udp", "udp6")}

    def test_helper_verified_sshd_exception_opens(self):
        files = self.files()
        files["udp"] = proc_net()
        served = ServedHelper(self.helper(), self.base / "run")
        self.addCleanup(served.close)
        check = self.check(SocketOwnerHelperClient(served.path, trusted_uid=UID), files)
        self.assertTrue(check._check(CheckKind.RETRY).open)

    def test_helper_down_fails_closed(self):
        files = self.files()
        files["udp"] = proc_net()
        check = self.check(SocketOwnerHelperClient(str(self.base / "run" / "socket"), trusted_uid=UID), files)
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.LISTENER_OWNER_UNVERIFIED,))

    def test_other_process_on_the_excepted_port(self):
        files = self.files()
        files["udp"] = proc_net()
        # sshd stopped; another program took tcp/22 (same inode number reused for clarity).
        (self.base / "proc" / "4242" / "exe").unlink()
        (self.base / "proc" / "4242" / "exe").symlink_to(PYTHON)
        served = ServedHelper(self.helper(), self.base / "run")
        self.addCleanup(served.close)
        check = self.check(SocketOwnerHelperClient(served.path, trusted_uid=UID), files)
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.UNEXPECTED_LISTENER,))

    def test_shared_upstream_socket(self):
        files = self.files()
        files["udp"] = proc_net()
        self.proc.process(5555, PYTHON, ["socket:[1000]"], cgroup="0::/system.slice/server-sentinel.service\n")
        served = ServedHelper(self.helper(), self.base / "run")
        self.addCleanup(served.close)
        check = self.check(SocketOwnerHelperClient(served.path, trusted_uid=UID), files)
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.UNEXPECTED_LISTENER,))


class ConfigurationTests(TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "etc"
        self.directory.mkdir(mode=0o750)
        self.path = self.directory / "deployment.json"

    def write(self, document, mode=0o640):
        self.path.write_text(document if isinstance(document, str) else json.dumps(document))
        self.path.chmod(mode)

    def read(self):
        return read_service_uid(str(self.path), administrator_uid=UID)

    def ancestors_controlled(self):
        current = Path("/")
        for part in self.directory.parts[1:]:
            current /= part
            info = current.lstat()
            if info.st_uid not in {0, UID} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                self.skipTest("temporary directory ancestors are not administrator-controlled here")

    def test_reads_the_service_uid(self):
        self.ancestors_controlled()
        self.write({"service_uid": 991, "human_port": 8000})
        self.assertEqual(self.read(), 991)

    def test_writable_or_invalid_configuration_is_refused(self):
        self.ancestors_controlled()
        for document, mode in (({"service_uid": 991}, 0o660), ({"service_uid": 991}, 0o646),
                               ({"service_uid": UID}, 0o640), ({"service_uid": True}, 0o640),
                               ({"service_uid": "991"}, 0o640), ({}, 0o640), ("[991]", 0o640), ("{", 0o640),
                               (" " * 20000, 0o640)):
            with self.subTest(document=str(document)[:30], mode=oct(mode)), self.assertRaises(ValueError):
                self.write(document, mode)
                self.read()

    def test_symlink_and_writable_directory_are_refused(self):
        self.ancestors_controlled()
        self.write({"service_uid": 991})
        link = self.directory / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            read_service_uid(str(link), administrator_uid=UID)
        self.directory.chmod(0o770)
        self.addCleanup(self.directory.chmod, 0o750)
        with self.assertRaises(ValueError):
            self.read()
        with self.assertRaises(ValueError):
            read_service_uid("relative.json")


class SocketActivationTests(TestCase):
    def test_only_a_single_passed_unix_stream_socket_is_accepted(self):
        pid = str(os.getpid())
        for environ in ({}, {"LISTEN_PID": "1", "LISTEN_FDS": "1"}, {"LISTEN_PID": pid, "LISTEN_FDS": "2"}):
            with self.subTest(environ=environ), self.assertRaises(ValueError):
                systemd_listener(environ)

    def test_passed_socket(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream, \
                socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as datagram:
            environ = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"}
            listener = systemd_listener(environ, fileno=stream.fileno())
            self.assertEqual(listener.fileno(), stream.fileno())
            listener.detach()
            with self.assertRaises(ValueError):
                systemd_listener(environ, fileno=datagram.fileno())
