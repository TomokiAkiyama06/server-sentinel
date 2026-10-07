"""Issue #126: unprivileged sock_diag creator lookup.

Synthetic netlink byte fixtures, temporary cgroup/proc trees and fake sockets
cover the parser and its boundaries; one integration test talks to this
host's kernel about this process's own listener (skipped when netlink
sock_diag or a cgroup v2 hierarchy is unavailable, for example in a sandbox).
"""

import errno
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from app.auth.reservation import ReservationEnumerationError, SocketCreator
from app.auth.sock_diag import (
    INET_DIAG_CGROUP_ID, INET_DIAG_MSG, NETLINK_SOCK_DIAG, NLM_F_DUMP, NLM_F_DUMP_INTR,
    NLM_F_MULTI, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_HEADER, NLMSG_NOOP, NLMSG_OVERRUN,
    SOCK_DIAG_BY_FAMILY, TABLES, TCP_CLOSE, TCP_LISTEN, DiagSocket, NetlinkSockDiag, SockDiagError,
    SockDiagOwners, build_request, cgroup_paths, own_cgroup, parse_messages,
)


SEQ, PORT_ID = 7, 4242
INET_DIAG_PAD = 14


def attribute(kind, payload):
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + bytes(-length % 4)


def diag_message(*, inode, uid=0, cgroup=None, family=socket.AF_INET, state=TCP_LISTEN, extra=b"",
                 seq=SEQ, pid=PORT_ID, flags=NLM_F_MULTI, kind=SOCK_DIAG_BY_FAMILY):
    body = INET_DIAG_MSG.pack(family, state, 0, 0, bytes(48), 0, 0, 0, uid, inode) + extra
    if cgroup is not None:
        body += attribute(INET_DIAG_CGROUP_ID, struct.pack("=Q", cgroup))
    return NLMSG_HEADER.pack(NLMSG_HEADER.size + len(body), kind, flags, seq, pid) + body


def done(error=0, seq=SEQ, pid=PORT_ID):
    return NLMSG_HEADER.pack(NLMSG_HEADER.size + 4, NLMSG_DONE, NLM_F_MULTI, seq, pid) + struct.pack("=i", error)


def control(kind, payload=b"", seq=SEQ, pid=PORT_ID):
    return NLMSG_HEADER.pack(NLMSG_HEADER.size + len(payload), kind, 0, seq, pid) + payload


def parse(data, **kwargs):
    values = dict(family=socket.AF_INET, protocol=socket.IPPROTO_TCP, state=TCP_LISTEN,
                  sequence=SEQ, port_id=PORT_ID)
    values.update(kwargs)
    return parse_messages(data, **values)


class RequestTests(TestCase):
    def test_dump_request_layout(self):
        request = build_request(socket.AF_INET6, socket.IPPROTO_UDP, TCP_CLOSE, 9)
        length, kind, flags, seq, pid = NLMSG_HEADER.unpack_from(request)
        self.assertEqual((length, kind, flags, seq, pid),
                         (len(request), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, 9, 0))
        family, protocol, ext, pad, states = struct.unpack_from("=BBBBI", request, 16)
        self.assertEqual((family, protocol, ext, pad, states),
                         (socket.AF_INET6, socket.IPPROTO_UDP, 0, 0, 1 << 7))
        # inet_diag_req_v2 is 56 bytes; the socket id is all zero (no filter).
        self.assertEqual(len(request), 16 + 56)
        self.assertEqual(request[24:], bytes(48))

    def test_constants_match_the_kernel_uapi(self):
        # linux/sock_diag.h, linux/netlink.h, linux/inet_diag.h; checked
        # against the installed headers when this was written.
        self.assertEqual((NETLINK_SOCK_DIAG, SOCK_DIAG_BY_FAMILY, INET_DIAG_CGROUP_ID), (4, 20, 21))
        self.assertEqual((NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN), (1, 2, 3, 4))
        self.assertEqual((NLM_F_DUMP, NLM_F_DUMP_INTR, TCP_LISTEN, TCP_CLOSE), (0x300, 0x10, 10, 7))
        self.assertEqual(INET_DIAG_MSG.size, 72)
        # The four /proc/net tables, with the state the reservation check enumerates.
        self.assertEqual(TABLES, ((socket.AF_INET, socket.IPPROTO_TCP, 10), (socket.AF_INET6, socket.IPPROTO_TCP, 10),
                                  (socket.AF_INET, socket.IPPROTO_UDP, 7), (socket.AF_INET6, socket.IPPROTO_UDP, 7)))


class ParserTests(TestCase):
    def test_sockets_attributes_and_end_of_dump(self):
        data = (diag_message(inode=11, uid=0, cgroup=5147,
                             extra=attribute(INET_DIAG_PAD, b"")) + control(NLMSG_NOOP)
                + diag_message(inode=12, uid=1000, cgroup=None, extra=attribute(1, b"\x01\x02\x03")))
        sockets, finished = parse(data)
        self.assertFalse(finished)
        self.assertEqual(sockets, [DiagSocket(socket.AF_INET, socket.IPPROTO_TCP, TCP_LISTEN, 11, 0, 5147),
                                   DiagSocket(socket.AF_INET, socket.IPPROTO_TCP, TCP_LISTEN, 12, 1000, None)])
        sockets, finished = parse(diag_message(inode=13, cgroup=1) + done() + b"ignored after done")
        self.assertTrue(finished)
        self.assertEqual([item.inode for item in sockets], [13])

    def test_nested_and_byte_order_flags_are_masked(self):
        flagged = struct.pack("=HH", 12, INET_DIAG_CGROUP_ID | 0x8000) + struct.pack("=Q", 99)
        body = INET_DIAG_MSG.pack(socket.AF_INET, TCP_LISTEN, 0, 0, bytes(48), 0, 0, 0, 0, 5) + flagged
        message = NLMSG_HEADER.pack(16 + len(body), SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, SEQ, PORT_ID) + body
        self.assertEqual(parse(message)[0][0].cgroup_id, 99)

    def test_errors_and_interrupted_dumps_raise(self):
        cases = {
            "netlink error (EPERM / ENOENT)": control(NLMSG_ERROR, struct.pack("=i", -errno.EPERM) + bytes(16)),
            "acknowledgement instead of a dump": control(NLMSG_ERROR, struct.pack("=i", 0) + bytes(16)),
            "done with an error": done(-errno.ENOENT),
            "overrun": control(NLMSG_OVERRUN),
            "interrupted dump": diag_message(inode=1, cgroup=1, flags=NLM_F_MULTI | NLM_F_DUMP_INTR),
            "unexpected type": diag_message(inode=1, cgroup=1, kind=21),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(SockDiagError):
                parse(data)

    def test_malformed_input_raises(self):
        good = diag_message(inode=1, cgroup=1)
        cases = {
            "short header": good[:10],
            "length below header": struct.pack("=IHHII", 8, SOCK_DIAG_BY_FAMILY, 0, SEQ, PORT_ID),
            "length beyond data": good[:-4],
            "body shorter than inet_diag_msg": NLMSG_HEADER.pack(16 + 20, SOCK_DIAG_BY_FAMILY, 0, SEQ, PORT_ID)
            + bytes(20),
            "other sequence": diag_message(inode=1, cgroup=1, seq=SEQ + 1),
            "other port id": diag_message(inode=1, cgroup=1, pid=1),
            "other family": diag_message(inode=1, cgroup=1, family=socket.AF_INET6),
            "other state": diag_message(inode=1, cgroup=1, state=1),
            "attribute shorter than its header": diag_message(inode=1, extra=struct.pack("=HH", 2, 1)),
            "attribute beyond the message": diag_message(inode=1, extra=struct.pack("=HH", 40, 1) + bytes(4)),
            "truncated attribute header": diag_message(inode=1, extra=b"\x08\x00"),
            "cgroup id of the wrong size": diag_message(
                inode=1, extra=attribute(INET_DIAG_CGROUP_ID, struct.pack("=I", 5))),
            "duplicate cgroup id": diag_message(inode=1, cgroup=1, extra=attribute(
                INET_DIAG_CGROUP_ID, struct.pack("=Q", 2))),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(SockDiagError):
                parse(data)


class FakeChannel:
    """A NETLINK_SOCK_DIAG socket that answers each dump request from a script."""

    def __init__(self, answers, *, sender=0, flags=0, fail_send=False):
        self.answers = list(answers)
        self.sender = sender
        self.flags = flags
        self.fail_send = fail_send
        self.requests = []
        self.pending = []
        self.timeouts = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def sendto(self, data, address):
        if self.fail_send:
            raise PermissionError(errno.EPERM, "synthetic")
        self.requests.append((data, address))
        seq = NLMSG_HEADER.unpack_from(data)[3]
        family, protocol, _, _, states = struct.unpack_from("=BBBBI", data, 16)
        answer = self.answers.pop(0)
        self.pending = list(answer(seq, family, protocol, states)) if callable(answer) else list(answer)

    def getsockname(self):
        return (PORT_ID, 0)

    def settimeout(self, value):
        self.timeouts.append(value)

    def recvmsg(self, size):
        item = self.pending.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item, [], self.flags, (self.sender, 0)


def table(*inodes, cgroup=1):
    """One dump answer: a socket per inode in the requested table, then DONE."""
    def answer(seq, family, protocol, states):
        state = states.bit_length() - 1
        messages = b"".join(diag_message(inode=inode, cgroup=cgroup, family=family, state=state, seq=seq)
                            for inode in inodes)
        return ([messages] if messages else []) + [done(seq=seq)]
    return answer


class Clock:
    def __init__(self, step=0.0):
        self.value, self.step = 100.0, step

    def __call__(self):
        self.value += self.step
        return self.value


class NetlinkDumpTests(TestCase):
    def diag(self, channel, **kwargs):
        def factory(family, kind, protocol):
            self.assertEqual((family, kind & ~socket.SOCK_CLOEXEC, protocol),
                             (socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG))
            if isinstance(channel, BaseException):
                raise channel
            return channel
        kwargs.setdefault("monotonic", Clock())
        return NetlinkSockDiag(socket_factory=factory, **kwargs)

    def test_dumps_all_four_tables_across_multipart_receives(self):
        channel = FakeChannel([table(1, 2), table(3), table(4), table()])
        sockets = self.diag(channel).dump()
        self.assertEqual([(item.inode, item.family, item.protocol, item.state) for item in sockets],
                         [(1, socket.AF_INET, socket.IPPROTO_TCP, TCP_LISTEN),
                          (2, socket.AF_INET, socket.IPPROTO_TCP, TCP_LISTEN),
                          (3, socket.AF_INET6, socket.IPPROTO_TCP, TCP_LISTEN),
                          (4, socket.AF_INET, socket.IPPROTO_UDP, TCP_CLOSE)])
        self.assertEqual(len(channel.requests), 4)
        self.assertTrue(all(address == (0, 0) for _, address in channel.requests))
        self.assertTrue(channel.closed)
        # A positive, shrinking timeout bounds every receive.
        self.assertTrue(all(0 < value <= 5.0 for value in channel.timeouts))

    def test_failures_raise(self):
        cases = {
            "address family denied": PermissionError(errno.EAFNOSUPPORT, "synthetic"),
            "send refused": FakeChannel([table(1)], fail_send=True),
            "truncated datagram": FakeChannel([table(1)], flags=socket.MSG_TRUNC),
            "not from the kernel": FakeChannel([table(1)], sender=999),
            "receive timeout": FakeChannel([lambda *args: [socket.timeout("synthetic")]]),
            "receive error": FakeChannel([lambda *args: [OSError(errno.ENOBUFS, "synthetic")]]),
            "empty datagram": FakeChannel([lambda *args: [b""]]),
            "module missing": FakeChannel([table(1), table(), lambda seq, *rest: [
                control(NLMSG_ERROR, struct.pack("=i", -errno.ENOENT) + bytes(16), seq=seq)]]),
        }
        for name, channel in cases.items():
            with self.subTest(name), self.assertRaises(SockDiagError):
                self.diag(channel).dump()

    def test_overall_deadline(self):
        # Every clock read advances 2 s against a 5 s budget: a dump that keeps
        # sending messages without DONE stops instead of reading forever.
        endless = FakeChannel([lambda seq, *rest: [diag_message(inode=1, cgroup=1, seq=seq)] * 100])
        with self.assertRaises(SockDiagError) as raised:
            self.diag(endless, monotonic=Clock(step=2.0)).dump()
        self.assertEqual(str(raised.exception), "SOCK_DIAG_TIMEOUT")

    def test_total_size_and_socket_count_are_bounded(self):
        def answer(seq, *rest):
            return [diag_message(inode=1, cgroup=1, seq=seq) * 8] * 50

        for name, limit in (("MAX_DUMP_BYTES", 4000), ("MAX_DUMP_SOCKETS", 30)):
            with self.subTest(name), patch(f"app.auth.sock_diag.{name}", limit), \
                    self.assertRaises(SockDiagError) as raised:
                self.diag(FakeChannel([answer])).dump()
            self.assertEqual(str(raised.exception), "SOCK_DIAG_TOO_LARGE")


class CgroupTreeTests(TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "cgroup"
        self.root.mkdir()
        (self.root / "cgroup.controllers").write_text("cpu memory\n")

    def mkdir(self, relative):
        path = self.root / relative
        path.mkdir(parents=True)
        return path.stat().st_ino

    def test_inodes_map_to_paths(self):
        ssh = self.mkdir("system.slice/ssh.socket")
        user = self.mkdir("user.slice/user-1000.slice/session-2.scope")
        (self.root / "system.slice" / "cgroup.procs").write_text("")
        paths = cgroup_paths(str(self.root))
        self.assertEqual(paths[ssh], "/system.slice/ssh.socket")
        self.assertEqual(paths[user], "/user.slice/user-1000.slice/session-2.scope")
        self.assertEqual(paths[self.root.stat().st_ino], "/")
        self.assertNotIn("cgroup.procs", "".join(paths.values()))

    def test_symbolic_links_are_not_followed(self):
        self.mkdir("system.slice")
        (self.root / "system.slice" / "loop").symlink_to(self.root)
        self.assertEqual(sorted(cgroup_paths(str(self.root)).values()), ["/", "/system.slice"])

    def test_not_a_cgroup_v2_hierarchy_or_too_large(self):
        (self.root / "cgroup.controllers").unlink()
        with self.assertRaises(SockDiagError):
            cgroup_paths(str(self.root))
        (self.root / "cgroup.controllers").write_text("")
        for number in range(5):
            self.mkdir(f"a{number}")
        with self.assertRaises(SockDiagError):
            cgroup_paths(str(self.root), max_entries=3)

    def test_unlistable_subtree_is_left_out(self):
        hidden = self.mkdir("system.slice/private.service")
        self.mkdir("system.slice/private.service/child")
        (self.root / "system.slice" / "private.service").chmod(0)
        self.addCleanup((self.root / "system.slice" / "private.service").chmod, 0o755)
        if os.access(self.root / "system.slice" / "private.service", os.R_OK):
            self.skipTest("running with privilege that bypasses directory permissions")
        paths = cgroup_paths(str(self.root))
        # The directory itself is known from its parent; what it hides is not.
        self.assertEqual(paths[hidden], "/system.slice/private.service")
        self.assertNotIn("/system.slice/private.service/child", paths.values())

    def test_own_cgroup(self):
        directory = Path(self.temporary.name) / "self"
        directory.mkdir()
        cases = {"0::/system.slice/server-sentinel.service\n": "/system.slice/server-sentinel.service",
                 "12:cpu:/x\n0::/user.slice/a.scope\n": "/user.slice/a.scope", "0::/\n": "/"}
        for text, expected in cases.items():
            (directory / "cgroup").write_text(text)
            self.assertEqual(own_cgroup(str(directory)), expected)
        for text in ("", "12:cpu:/x\n", "0::relative\n", "0::/a\n0::/b\n"):
            with self.subTest(text=text):
                (directory / "cgroup").write_text(text)
                with self.assertRaises(SockDiagError):
                    own_cgroup(str(directory))
        with self.assertRaises(SockDiagError):
            own_cgroup(str(directory / "missing"))


class FakeDiag:
    def __init__(self, sockets):
        self.sockets = sockets
        self.calls = 0

    def dump(self):
        self.calls += 1
        if isinstance(self.sockets, BaseException):
            raise self.sockets
        return tuple(self.sockets() if callable(self.sockets) else self.sockets)


class OwnersFixture(TestCase):
    UID = 991
    PID = 500

    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.cgroups = base / "cgroup"
        self.cgroups.mkdir()
        (self.cgroups / "cgroup.controllers").write_text("")
        self.proc = base / "proc"
        self.proc.mkdir()
        self.self_dir = base / "self"
        self.self_dir.mkdir()
        (self.self_dir / "cgroup").write_text("0::/system.slice/server-sentinel.service\n")
        self.own = self.cgroup("system.slice/server-sentinel.service", [self.PID])
        self.upstream = self.cgroup("system.slice/server-sentinel-upstream.socket", [])
        self.ssh = self.cgroup("system.slice/ssh.socket", [])

    def cgroup(self, relative, pids):
        path = self.cgroups / relative
        path.mkdir(parents=True, exist_ok=True)
        (path / "cgroup.procs").write_text("".join(f"{pid}\n" for pid in pids))
        return path.stat().st_ino

    def process(self, pid, fds):
        directory = self.proc / str(pid) / "fd"
        directory.mkdir(parents=True)
        for number, target in enumerate(fds):
            (directory / str(number)).symlink_to(target)
        return directory

    def owners(self, sockets, **kwargs):
        kwargs.setdefault("probe", None)
        return SockDiagOwners(diag=FakeDiag(sockets), cgroup_root=str(self.cgroups), proc=str(self.proc),
                              proc_self=str(self.self_dir), getpid=lambda: self.PID,
                              geteuid=lambda: self.UID, **kwargs)


def diag(inode, uid, cgroup, family=socket.AF_INET):
    return DiagSocket(family, socket.IPPROTO_TCP, TCP_LISTEN, inode, uid, cgroup)


class CreatorTests(OwnersFixture):
    def test_creators_by_inode(self):
        sockets = [diag(1, 0, self.ssh), diag(2, 0, self.upstream), diag(3, 0, 999_999),
                   diag(4, 1000, None), diag(0, 0, self.ssh)]
        creators = self.owners(sockets).creators(frozenset({1, 2, 3, 4, 5}))
        self.assertEqual(creators, {
            1: SocketCreator("/system.slice/ssh.socket", 0),
            2: SocketCreator("/system.slice/server-sentinel-upstream.socket", 0),
            # A deleted cgroup id and a missing attribute are unresolved.
            3: SocketCreator(None, 0),
            4: SocketCreator(None, 1000),
        })

    def test_conflicting_duplicate_inode_raises(self):
        with self.assertRaises(SockDiagError):
            self.owners([diag(1, 0, self.ssh), diag(1, 0, self.upstream)]).creators(frozenset({1}))
        # The same socket reported twice identically is accepted.
        self.assertEqual(self.owners([diag(1, 0, self.ssh)] * 2).creators(frozenset({1})),
                         {1: SocketCreator("/system.slice/ssh.socket", 0)})

    def test_dump_failure_propagates(self):
        with self.assertRaises(ReservationEnumerationError):
            self.owners(SockDiagError("SOCK_DIAG_UNAVAILABLE")).creators(frozenset({1}))

    def test_self_check_requires_the_probe_with_this_cgroup_and_uid(self):
        probe = socket.socket()
        self.addCleanup(probe.close)
        inode = os.fstat(probe.fileno()).st_ino
        probes = []

        def make_probe():
            probes.append(probe)
            return probe

        good = [diag(inode, self.UID, self.own), diag(1, 0, self.ssh)]
        self.assertEqual(self.owners(good, probe=make_probe).creators(frozenset({1})),
                         {1: SocketCreator("/system.slice/ssh.socket", 0)})
        self.assertEqual(probe.fileno(), -1)  # closed after the dump
        cases = {
            "probe missing from the dump": [diag(1, 0, self.ssh)],
            "no cgroup attribute": [diag(inode, self.UID, None)],
            "other cgroup (namespace or view mismatch)": [diag(inode, self.UID, self.ssh)],
            "other uid": [diag(inode, 0, self.own)],
        }
        for name, sockets in cases.items():
            with self.subTest(name):
                fresh = socket.socket()
                self.addCleanup(fresh.close)
                fresh_inode = os.fstat(fresh.fileno()).st_ino
                rewritten = [diag(fresh_inode if item.inode == inode else item.inode, item.uid, item.cgroup_id)
                             for item in sockets]
                with self.assertRaises(SockDiagError) as raised:
                    self.owners(rewritten, probe=lambda: fresh).creators(frozenset({1}))
                self.assertEqual(str(raised.exception), "SOCK_DIAG_SELF_CHECK_FAILED")
                self.assertEqual(fresh.fileno(), -1)

    def test_invalid_construction(self):
        for kwargs in (dict(cgroup_root="relative"), dict(proc="proc"), dict(extra_units=("../x.socket",)),
                       dict(extra_units=("x.target",))):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SockDiagOwners(**kwargs)


class SoleHolderTests(OwnersFixture):
    def test_only_this_process_holds_the_upstream(self):
        self.process(self.PID, ["socket:[77]"])  # this process: ignored
        self.process(501, ["socket:[88]", "/dev/null"])
        self.cgroup("system.slice/server-sentinel.service", [self.PID, 501])
        resolver = self.owners([], extra_units=("server-sentinel-upstream.socket",))
        self.assertEqual(resolver.held_only_by_requester(frozenset({77})), {77: True})

    def test_child_or_descriptor_receiver_in_the_unit_is_seen(self):
        self.process(501, ["socket:[77]"])
        # A sub-cgroup of the unit and the upstream socket unit's own cgroup count too.
        self.process(502, ["socket:[78]"])
        self.process(503, ["socket:[79]"])
        self.cgroup("system.slice/server-sentinel.service/worker", [501])
        self.cgroup("system.slice/server-sentinel-upstream.socket", [502])
        self.cgroup("system.slice/ssh.socket", [503])  # not scanned
        resolver = self.owners([], extra_units=("server-sentinel-upstream.socket",))
        self.assertEqual(resolver.held_only_by_requester(frozenset({77, 78, 79})),
                         {77: False, 78: False, 79: True})

    def test_exited_process_is_skipped(self):
        self.cgroup("system.slice/server-sentinel.service", [self.PID, 600])
        self.assertEqual(self.owners([]).held_only_by_requester(frozenset({77})), {77: True})

    def test_unreadable_process_or_listing_raises(self):
        directory = self.process(501, ["socket:[77]"])
        self.cgroup("system.slice/server-sentinel.service", [self.PID, 501])
        directory.chmod(0)
        self.addCleanup(directory.chmod, 0o755)
        if os.access(directory, os.R_OK):
            self.skipTest("running with privilege that bypasses directory permissions")
        with self.assertRaises(ReservationEnumerationError):
            self.owners([]).held_only_by_requester(frozenset({77}))

    def test_unusable_cgroup_state_raises(self):
        cases = {
            "malformed cgroup.procs": "500\nabc\n",
            "oversized cgroup.procs": "1\n" * 600_000,
        }
        for name, text in cases.items():
            with self.subTest(name):
                (self.cgroups / "system.slice/server-sentinel.service/cgroup.procs").write_text(text)
                with self.assertRaises(ReservationEnumerationError):
                    self.owners([]).held_only_by_requester(frozenset({77}))
        (self.self_dir / "cgroup").write_text("0::/system.slice/gone.service\n")
        with self.assertRaises(ReservationEnumerationError):
            self.owners([]).held_only_by_requester(frozenset({77}))
        (self.self_dir / "cgroup").write_text("0::/../../etc\n")
        with self.assertRaises(ReservationEnumerationError):
            self.owners([]).held_only_by_requester(frozenset({77}))

    def test_inactive_extra_unit_has_no_processes(self):
        self.assertEqual(self.owners([], extra_units=("absent.socket",)).held_only_by_requester(frozenset({77})),
                         {77: True})


def _sock_diag_available():
    try:
        SockDiagOwners().creators(frozenset())
    except (OSError, ReservationEnumerationError) as error:
        return str(error)
    return None


class HostIntegrationTests(TestCase):
    """Unprivileged sock_diag against this process's own sockets on this host's kernel."""

    def setUp(self):
        reason = _sock_diag_available()
        if reason is not None:
            self.skipTest(f"netlink sock_diag or cgroup v2 unavailable here: {reason}")

    def test_own_listeners_report_this_cgroup_and_uid(self):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(tcp.close)
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(1)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(udp.close)
        udp.bind(("127.0.0.1", 0))
        connected = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(connected.close)  # not listening: not reported
        inodes = {os.fstat(item.fileno()).st_ino for item in (tcp, udp, connected)}
        creators = SockDiagOwners().creators(frozenset(inodes))
        expected = SocketCreator(own_cgroup(), os.geteuid())
        self.assertEqual(creators, {os.fstat(tcp.fileno()).st_ino: expected,
                                    os.fstat(udp.fileno()).st_ino: expected})

    def test_inherited_descriptor_in_the_same_cgroup_is_seen(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        inode = os.fstat(listener.fileno()).st_ino
        resolver = SockDiagOwners()
        try:
            alone = resolver.held_only_by_requester(frozenset({inode}))
        except ReservationEnumerationError:
            self.skipTest("another process in this cgroup cannot be read here")
        if not alone[inode]:
            self.skipTest("another process in this cgroup already shares the socket")
        child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"],
                                 stdin=subprocess.PIPE, pass_fds=(listener.fileno(),))
        self.addCleanup(child.wait)
        self.addCleanup(child.stdin.close)
        try:
            self.assertEqual(resolver.held_only_by_requester(frozenset({inode})), {inode: False})
        except ReservationEnumerationError:
            self.skipTest("another process in this cgroup cannot be read here")
