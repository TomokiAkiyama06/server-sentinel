"""Synthetic /proc/net and Serve status fixtures only; no host sockets or tailscale."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import os
import ipaddress
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from unittest import TestCase
from unittest.mock import patch

from app.audit import (
    ActorCategory, AuditAction, AuditOutcome, AuditStore, OwnerAuditService,
    OwnerAuthorizationError, TargetKind,
)
from app.audit.integration import RESERVATION_LISTENER_EXCEPTIONS_ID, ReservationAdministration
from app.auth.reservation import (
    DAILY_SECONDS, AddressFamily, CheckKind, GetaddrinfoResolver, OwnSocketInodes, ProcSocketOwners, ProcessIdentity, SocketOwner, HostnameReservationCheck, IsolationMode, Listener, ListenerException,
    RETRY_WHILE_CLOSED_SECONDS, ProcNetListeners, ProxyRoute, Reason, ReservationConfig,
    ReservationEnumerationError,
    ReservationFault, RouteKind, ServeStatusRoutes, TransportProtocol, evaluate, parse_proc_net_tcp,
    parse_proc_net_udp, parse_serve_status,
)
from app.auth.model import AccessValidationError, Permission
from app.auth.reservation_store import (
    HUMAN_SESSIONS_ID, REVOCATION_PENDING_KEY, STORE_KEY, ListenerExceptionStore,
    ReservationSessionRevocation, decode, encode,
)
from app.auth.session_binding import SessionBindingKey
from app.auth.store import AccessStore
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
HOST = "sentinel.example-tailnet.ts.net"
V4 = ipaddress.IPv4Address("100.64.0.10")
V6 = ipaddress.IPv6Address("fd7a:115c:a1e0::10")
HUMAN = Listener(ipaddress.IPv4Address("127.0.0.1"), 8080)
HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
          "   uid  timeout inode")
# Header lines captured verbatim (``head -1``) from /proc/net/{tcp,tcp6,udp,udp6}
# on the Main host (Linux 7.0, Issue #154). IPv4 files name the peer column
# ``rem_address``; the IPv6 files name it ``remote_address``.
REAL_HEADERS = {
    "tcp": "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
           "   uid  timeout inode                                                     ",
    "tcp6": "  sl  local_address                         remote_address                        "
            "st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
    "udp": "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
           "   uid  timeout inode ref pointer drops            ",
    "udp6": "  sl  local_address                         remote_address                        "
            "st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops",
}
HEADER6 = REAL_HEADERS["tcp6"]


def _hex(address, byteorder="little"):
    raw = address.packed
    if byteorder == "little":
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
    return raw.hex().upper()


def proc(*sockets, ipv6=False, byteorder="little"):
    """Render (address, port, state) tuples as a synthetic /proc/net/tcp{,6} file."""
    zero = ipaddress.IPv6Address("::") if ipv6 else ipaddress.IPv4Address("0.0.0.0")
    lines = [HEADER6 if ipv6 else HEADER]
    for number, (address, port, state) in enumerate(sockets):
        lines.append(
            f"{number:4d}: {_hex(ipaddress.ip_address(address), byteorder)}:{port:04X} "
            f"{_hex(zero, byteorder)}:0000 {state} 00000000:00000000 00:00000000 00000000"
            f"  1000        0 {1000 + number} 1 0000000000000000 100 0 0 10 0")
    return "\n".join(lines) + "\n"


def serve(port=443, host=HOST, target="http://127.0.0.1:8080", **extra):
    document = {"TCP": {str(port): {"HTTPS": True}},
                "Web": {f"{host}:{port}": {"Handlers": {"/": {"Proxy": target}}}}}
    document.update(extra)
    return json.dumps(document)


def config(isolation=IsolationMode.SINGLE_PURPOSE_NODE, **overrides):
    values = dict(hostname=HOST, port=443, reserved_addresses=frozenset({V4, V6}),
                  human_listener=HUMAN, isolation=isolation)
    values.update(overrides)
    return ReservationConfig(**values)


class Files:
    def __init__(self, tcp=None, tcp6=None, udp=None, udp6=None):
        self.files = {"tcp": tcp if tcp is not None else proc(("127.0.0.1", 8080, "0A")),
                      "tcp6": tcp6 if tcp6 is not None else proc(ipv6=True),
                      "udp": udp if udp is not None else proc(),
                      "udp6": udp6 if udp6 is not None else proc(ipv6=True)}

    def __call__(self, name):
        value = self.files[name]
        if isinstance(value, BaseException):
            raise value
        return value


class Status:
    def __init__(self, text=None):
        self.text = serve() if text is None else text

    def __call__(self):
        if isinstance(self.text, BaseException):
            raise self.text
        return self.text


class Sink:
    def __init__(self, fail=False):
        self.events: list[ReservationFault] = []
        self.fail = fail

    def emit(self, fault):
        if self.fail:
            raise OSError("synthetic delivery failure")
        self.events.append(fault)


class FakeRevoker:
    def __init__(self, fail=False):
        self.fail = fail
        self.pending = False
        self.revocations = 0

    def record_exposure(self):
        self.pending = True

    def exposure_pending(self):
        return self.pending

    def revoke_all_human_sessions(self):
        if self.fail:
            raise OSError("synthetic revocation failure")
        self.pending = False
        self.revocations += 1


class Resolver:
    def __init__(self, answer=None):
        self.answer = (V4, V6) if answer is None else answer
        self.calls = 0

    def resolve(self, hostname):
        self.calls += 1
        if hostname != HOST:
            raise AssertionError(hostname)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


SSHD = "/usr/sbin/sshd"
SSHD_OWNER = SocketOwner(SSHD, "ssh.service")
TAILSCALED = ProcessIdentity(unit="tailscaled.service")
TAILSCALED_OWNER = SocketOwner("/usr/sbin/tailscaled", "tailscaled.service")


def exc(*args, **kwargs):
    """A listener exception owned by the synthetic sshd unless stated otherwise."""
    if "unit" not in kwargs:
        kwargs.setdefault("executable", SSHD)
    return ListenerException(*args, **kwargs)


class Owners:
    """Synthetic socket ownership: every inode is held by ``default`` unless overridden."""

    def __init__(self, default=SSHD_OWNER, overrides=None):
        self.default = default
        self.overrides = dict(overrides or {})
        self.calls = []

    def owners(self, inodes):
        self.calls.append(inodes)
        if isinstance(self.default, BaseException):
            raise self.default
        result = {}
        for inode in inodes:
            holders = self.overrides.get(inode, self.default)
            if holders is not None:
                result[inode] = holders if isinstance(holders, frozenset) else frozenset({holders})
        return result


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


def checker(files=None, status=None, sink=None, cfg=None, clock=None, **kwargs):
    files = files or Files()
    status = status or Status()
    sink = sink if sink is not None else Sink()
    kwargs.setdefault("resolver", Resolver())
    kwargs.setdefault("socket_owners", Owners())
    # Synthetic rows number their inodes from 1000; this process holds the upstream.
    kwargs.setdefault("own_sockets", lambda: frozenset(range(1000, 1100)))
    kwargs.setdefault("session_revoker", FakeRevoker())
    check = HostnameReservationCheck(
        cfg or config(), ProcNetListeners(files, byteorder="little"), ServeStatusRoutes(status), sink,
        monotonic=clock or Clock(), utcnow=lambda: NOW, **kwargs)
    return check, files, status, sink


class ProcNetParserTests(TestCase):
    def test_ipv4_listen_sockets_are_decoded_and_others_ignored(self):
        text = proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 22, "01"), ("0.0.0.0", 5355, "0A"))
        self.assertEqual(parse_proc_net_tcp(text, ipv6=False, byteorder="little"),
                         (HUMAN, Listener(ipaddress.IPv4Address("0.0.0.0"), 5355)))

    def test_known_kernel_encoding(self):
        # 127.0.0.1:8080 as printed by a little-endian kernel.
        text = HEADER + "\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1\n"
        self.assertEqual(parse_proc_net_tcp(text, ipv6=False, byteorder="little"), (HUMAN,))

    def test_ipv6_and_mapped_addresses(self):
        text = proc((str(V6), 443, "0A"), ("::", 8443, "0A"), ("::ffff:100.64.0.10", 9000, "0A"), ipv6=True)
        parsed = parse_proc_net_tcp(text, ipv6=True, byteorder="little")
        self.assertEqual([item.port for item in parsed], [443, 8443, 9000])
        self.assertEqual(parsed[0].address, V6)
        self.assertEqual(parsed[2].address.ipv4_mapped, V4)

    def test_big_endian_host_order(self):
        text = proc(("100.64.0.10", 443, "0A"), byteorder="big")
        self.assertEqual(parse_proc_net_tcp(text, ipv6=False, byteorder="big"), (Listener(V4, 443),))

    def test_malformed_input_raises_instead_of_skipping(self):
        for text in ("", "garbage\n", HEADER + "\n   0: 0100007F 00000000:0000 0A\n",
                     HEADER + "\n   0: 0100007F:1F90 00000000:0000 ZZ\n",
                     HEADER + "\n   0: 00007F:1F90 00000000:0000 0A\n",
                     HEADER + "\nbroken line\n"):
            with self.subTest(text=text), self.assertRaises(ReservationEnumerationError):
                parse_proc_net_tcp(text, ipv6=False, byteorder="little")
        with self.assertRaises(ReservationEnumerationError):
            parse_proc_net_tcp(proc(("127.0.0.1", 1, "0A")), ipv6=True, byteorder="little")

    def test_real_kernel_headers_are_accepted_per_family(self):
        # Issue #154: tcp6/udp6 print ``remote_address``; rejecting it made every
        # check report LISTENER_ENUMERATION_UNAVAILABLE on a real host.
        v4_row = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 1 1 0 0"
        v6_row = ("   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A"
                  " 00000000:00000000 00:00000000 00000000  0 0 2 1 0 0")
        v6_loopback = Listener(ipaddress.IPv6Address("::1"), 8080)
        cases = (("tcp", parse_proc_net_tcp, False, v4_row, HUMAN),
                 ("tcp6", parse_proc_net_tcp, True, v6_row, v6_loopback),
                 ("udp", parse_proc_net_udp, False, v4_row.replace(" 0A ", " 07 "),
                  Listener(HUMAN.address, 8080, TransportProtocol.UDP)),
                 ("udp6", parse_proc_net_udp, True, v6_row.replace(" 0A ", " 07 "),
                  Listener(v6_loopback.address, 8080, TransportProtocol.UDP)))
        for name, parse, ipv6, row, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(parse(REAL_HEADERS[name] + "\n", ipv6=ipv6, byteorder="little"), ())
                self.assertEqual(parse(REAL_HEADERS[name] + "\n" + row + "\n", ipv6=ipv6,
                                       byteorder="little"), (expected,))

    def test_header_of_the_other_family_or_unknown_header_fails_closed(self):
        unknown = ("  sl  local_address peer_address st tx_queue rx_queue tr tm->when retrnsmt"
                   "   uid  timeout inode")
        for name, parse, ipv6, header in (
                ("tcp", parse_proc_net_tcp, False, REAL_HEADERS["tcp6"]),
                ("tcp6", parse_proc_net_tcp, True, REAL_HEADERS["tcp"]),
                ("udp", parse_proc_net_udp, False, REAL_HEADERS["udp6"]),
                ("udp6", parse_proc_net_udp, True, REAL_HEADERS["udp"]),
                ("tcp unknown", parse_proc_net_tcp, False, unknown),
                ("tcp6 unknown", parse_proc_net_tcp, True, unknown)):
            with self.subTest(name=name), self.assertRaises(ReservationEnumerationError):
                parse(header + "\n", ipv6=ipv6, byteorder="little")

    def test_this_hosts_proc_net_files_parse(self):
        # Exercises the live kernel format when the files are readable; the
        # result depends on the host's sockets, so only success is asserted.
        parsers = {"tcp": (parse_proc_net_tcp, False), "tcp6": (parse_proc_net_tcp, True),
                   "udp": (parse_proc_net_udp, False), "udp6": (parse_proc_net_udp, True)}
        for name, (parse, ipv6) in parsers.items():
            with self.subTest(name=name):
                try:
                    with open(f"/proc/net/{name}", encoding="ascii") as stream:
                        text = stream.read()
                except OSError:
                    self.skipTest(f"/proc/net/{name} is not readable on this host")
                for listener in parse(text, ipv6=ipv6):
                    self.assertEqual(listener.address.version, 6 if ipv6 else 4)


class ServeStatusParserTests(TestCase):
    def test_single_mapping(self):
        self.assertEqual(parse_serve_status(serve()),
                         (ProxyRoute(RouteKind.PROXY, "https", 443, HOST, "/", "http://127.0.0.1:8080"),))

    def test_every_answering_route_is_reported(self):
        document = {
            "TCP": {"443": {"HTTPS": True}, "8443": {"HTTPS": True}, "80": {"HTTP": True},
                    "2222": {"TCPForward": "127.0.0.1:22"}},
            "Web": {f"{HOST}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"},
                                                 "/static": {"Path": "/srv/www"}}},
                    f"{HOST}:8443": {"Handlers": {"/": {"Text": "hello"}}}},
            "AllowFunnel": {f"{HOST}:443": True},
        }
        kinds = sorted((route.kind.value, route.scheme, route.port) for route in parse_serve_status(json.dumps(document)))
        self.assertEqual(kinds, [("empty_web_listener", "http", 80), ("funnel", "https", 443),
                                 ("path", "https", 443), ("proxy", "https", 443),
                                 ("tcp_forward", "tcp", 2222), ("text", "https", 8443)])

    def test_unrecognized_or_malformed_status_raises(self):
        for text in ("", "not json", "[]", '{"TCP": {"443": {"HTTPS": true}}, "TCP": {}}',
                     json.dumps({"Foreground": {"session": {"TCP": {"8443": {"HTTPS": True}}}}}),
                     json.dumps({"TCP": {"443": {"Mystery": True}}}),
                     json.dumps({"TCP": {"443": {}}}),
                     json.dumps({"TCP": {"0": {"HTTPS": True}}}),
                     json.dumps({"TCP": {"443": {"HTTPS": True}},
                                 "Web": {f"{HOST}:443": {"Handlers": {"/": {"Redirect": "x"}}}}}),
                     json.dumps({"TCP": {"443": {"HTTPS": True}},
                                 "Web": {f"{HOST}:443": {"Handlers": {"/": {"Proxy": "a", "Text": "b"}}}}}),
                     json.dumps({"AllowFunnel": {f"{HOST}:443": "yes"}})):
            with self.subTest(text=text), self.assertRaises(ReservationEnumerationError):
                parse_serve_status(text)

    def test_empty_config_has_no_routes(self):
        self.assertEqual(parse_serve_status("{}"), ())


class ConfigTests(TestCase):
    def test_rejects_non_loopback_upstream_and_bad_addresses(self):
        bad = (dict(human_listener=Listener(V4, 8080)),
               dict(human_listener=Listener(ipaddress.IPv4Address("0.0.0.0"), 8080)),
               dict(reserved_addresses=frozenset()),
               dict(reserved_addresses=frozenset({ipaddress.IPv4Address("127.0.0.1")})),
               dict(reserved_addresses=frozenset({ipaddress.IPv6Address("::ffff:100.64.0.10")})),
               dict(hostname="Not A Host"), dict(port=0),
               dict(proxy_listeners=frozenset({Listener(ipaddress.IPv4Address("100.64.0.99"), 443)})),
               # A proxy socket is exempt only at the configured origin port.
               dict(proxy_listeners=frozenset({Listener(V4, 8443)})),
               dict(proxy_listeners=frozenset({Listener(V6, 80)})),
               dict(proxy_listeners=frozenset({Listener(V4, 443, TransportProtocol.UDP)})),
               dict(human_listener=Listener(ipaddress.IPv4Address("127.0.0.1"), 8080, TransportProtocol.UDP)))
        for overrides in bad:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                config(**overrides)

    def test_proxy_listener_must_be_at_the_configured_port(self):
        cfg = config(port=8443, proxy_listeners=frozenset({Listener(V4, 8443)}), proxy_owner=TAILSCALED)
        self.assertEqual(cfg.proxy_listeners, frozenset({Listener(V4, 8443)}))
        with self.assertRaises(ValueError):
            config(proxy_listeners=frozenset({Listener(V4, 443), Listener(V4, 8443)}))

    def test_ipv6_upstream_url(self):
        cfg = config(human_listener=Listener(ipaddress.IPv6Address("::1"), 8080))
        self.assertEqual(cfg.upstream, "http://[::1]:8080")


class ProcNetUdpTests(TestCase):
    def test_only_unconnected_udp_sockets_are_listeners(self):
        text = proc(("0.0.0.0", 41641, "07"), ("100.64.0.10", 53000, "01"), ("100.64.0.10", 443, "07"))
        self.assertEqual(parse_proc_net_udp(text, ipv6=False, byteorder="little"),
                         (Listener(ipaddress.IPv4Address("0.0.0.0"), 41641, TransportProtocol.UDP),
                          Listener(V4, 443, TransportProtocol.UDP)))
        self.assertEqual(parse_proc_net_udp(proc((str(V6), 443, "07"), ipv6=True), ipv6=True,
                                            byteorder="little"),
                         (Listener(V6, 443, TransportProtocol.UDP),))
        with self.assertRaises(ReservationEnumerationError):
            parse_proc_net_udp("garbage", ipv6=False)


class ReservationCheckTests(TestCase):
    def assertClosed(self, check, reason):
        self.assertFalse(check.access_open)
        self.assertIn(reason, check.verdict.reasons)

    def test_closed_before_any_check(self):
        check, *_ = checker()
        self.assertFalse(check.access_open)

    def test_exact_single_mapping_passes(self):
        for isolation in IsolationMode:
            with self.subTest(isolation=isolation):
                check, _, _, sink = checker(cfg=config(isolation=isolation))
                verdict = check.startup()
                self.assertTrue(verdict.open)
                self.assertTrue(check.access_open)
                self.assertEqual(verdict.reasons, ())
                self.assertEqual(verdict.check, CheckKind.STARTUP)
                self.assertEqual(sink.events, [])

    def test_expected_proxy_socket_on_reserved_address_passes(self):
        files = Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 443, "0A")),
                      tcp6=proc((str(V6), 443, "0A"), ipv6=True))
        cfg = config(proxy_listeners=frozenset({Listener(V4, 443), Listener(V6, 443)}), proxy_owner=TAILSCALED)
        check, *_ = checker(files=files, cfg=cfg, socket_owners=Owners(TAILSCALED_OWNER))
        self.assertTrue(check.startup().open)

    def test_duplicate_expected_listener_sockets_close(self):
        # Independent SO_REUSEPORT sockets show as identical /proc/net rows; a
        # second process sharing the upstream or proxy endpoint receives
        # requests and cookies, so only one socket per expected endpoint passes.
        cfg = config(proxy_listeners=frozenset({Listener(V4, 443), Listener(V6, 443)}), proxy_owner=TAILSCALED)
        cases = {
            "human upstream twice": Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("127.0.0.1", 8080, "0A"))),
            "human upstream via v4-mapped v6": Files(
                tcp6=proc(("::ffff:127.0.0.1", 8080, "0A"), ipv6=True)),
            "proxy v4 twice": Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 443, "0A"),
                                             ("100.64.0.10", 443, "0A")),
                                    tcp6=proc((str(V6), 443, "0A"), ipv6=True)),
            "proxy v6 twice": Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 443, "0A")),
                                    tcp6=proc((str(V6), 443, "0A"), (str(V6), 443, "0A"), ipv6=True)),
        }
        for name, files in cases.items():
            with self.subTest(name):
                check, _, _, sink = checker(files=files, cfg=cfg, socket_owners=Owners(TAILSCALED_OWNER))
                self.assertFalse(check.startup().open)
                self.assertEqual(check.verdict.reasons[0], Reason.UNEXPECTED_LISTENER)
                self.assertEqual(sink.events[-1].unexpected_listeners, 1)

    def test_unrelated_listeners_elsewhere_do_not_answer_for_the_name(self):
        files = Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("127.0.0.1", 5432, "0A"),
                               ("192.168.1.20", 9000, "0A")),
                      tcp6=proc(("::1", 631, "0A"), ipv6=True))
        check, *_ = checker(files=files)
        self.assertTrue(check.startup().open)

    def test_extra_listener_on_any_port_ipv4_and_ipv6_closes(self):
        cases = {
            "reserved v4 other port": Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 8443, "0A"))),
            "reserved v4 same port": Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 443, "0A"))),
            "reserved v4 plain http": Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 80, "0A"))),
            "wildcard v4": Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("0.0.0.0", 22, "0A"))),
            "reserved v6": Files(tcp6=proc((str(V6), 8443, "0A"), ipv6=True)),
            "wildcard v6": Files(tcp6=proc(("::", 3000, "0A"), ipv6=True)),
            "v4-mapped v6": Files(tcp6=proc(("::ffff:100.64.0.10", 3000, "0A"), ipv6=True)),
        }
        for name, files in cases.items():
            with self.subTest(name):
                check, _, _, sink = checker(files=files)
                check.startup()
                self.assertClosed(check, Reason.UNEXPECTED_LISTENER)
                self.assertEqual(sink.events[-1].reasons, check.verdict.reasons)
                self.assertEqual(sink.events[-1].unexpected_listeners, 1)

    def test_extra_route_on_any_port_or_scheme_closes(self):
        extra = {
            "same origin other path": json.dumps({
                "TCP": {"443": {"HTTPS": True}},
                "Web": {f"{HOST}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"},
                                                     "/other": {"Proxy": "http://127.0.0.1:9000"}}}}}),
            "other https port": json.dumps({
                "TCP": {"443": {"HTTPS": True}, "8443": {"HTTPS": True}},
                "Web": {f"{HOST}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}},
                        f"{HOST}:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9000"}}}}}),
            "plain http": json.dumps({
                "TCP": {"443": {"HTTPS": True}, "80": {"HTTP": True}},
                "Web": {f"{HOST}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}},
                        f"{HOST}:80": {"Handlers": {"/": {"Path": "/srv/www"}}}}}),
            "raw tcp forward": serve(TCP={"443": {"HTTPS": True}, "2222": {"TCPForward": "127.0.0.1:22"}}),
            "funnel": serve(AllowFunnel={f"{HOST}:443": True}),
        }
        for name, text in extra.items():
            with self.subTest(name):
                check, _, _, sink = checker(status=Status(text))
                check.startup()
                self.assertClosed(check, Reason.UNEXPECTED_ROUTE)
                self.assertNotIn(Reason.MAPPING_MISSING, check.verdict.reasons)
                self.assertEqual(len(sink.events), 1)

    def test_missing_or_different_mapping_closes(self):
        cases = {
            "empty": "{}",
            "wrong target": serve(target="http://127.0.0.1:9000"),
            "wrong host": serve(host="other.example-tailnet.ts.net"),
            "wrong port": serve(port=8443),
        }
        for name, text in cases.items():
            with self.subTest(name):
                check, *_ = checker(status=Status(text))
                check.startup()
                self.assertClosed(check, Reason.MAPPING_MISSING)

    def test_duplicate_expected_mapping_is_not_single(self):
        route = config().expected_route
        reasons, _, extra = evaluate(config(), (HUMAN,), (route, route))
        self.assertEqual(reasons, (Reason.UNEXPECTED_ROUTE,))
        self.assertEqual(extra, 1)

    def test_udp_listener_on_reserved_name_closes(self):
        cases = {
            "quic on reserved v4": Files(udp=proc(("100.64.0.10", 443, "07"))),
            "quic on reserved v6": Files(udp6=proc((str(V6), 443, "07"), ipv6=True)),
            "wildcard v4": Files(udp=proc(("0.0.0.0", 41641, "07"))),
            "wildcard v6": Files(udp6=proc(("::", 41641, "07"), ipv6=True)),
            "v4-mapped v6": Files(udp6=proc(("::ffff:100.64.0.10", 443, "07"), ipv6=True)),
        }
        for name, files in cases.items():
            with self.subTest(name):
                check, _, _, sink = checker(files=files)
                check.startup()
                self.assertClosed(check, Reason.UNEXPECTED_LISTENER)
                self.assertEqual(sink.events[-1].unexpected_listeners, 1)
        # Loopback/LAN UDP and connected client sockets do not answer for the name.
        check, *_ = checker(files=Files(udp=proc(("127.0.0.53", 53, "07"), ("192.168.1.20", 5353, "07"),
                                                 ("100.64.0.10", 53000, "01"))))
        self.assertTrue(check.startup().open)

    def test_human_listener_absent_closes(self):
        check, *_ = checker(files=Files(tcp=proc()))
        check.startup()
        self.assertClosed(check, Reason.HUMAN_LISTENER_MISSING)

    def test_unstated_isolation_closes(self):
        for isolation in (None, "single_purpose_node", True):
            with self.subTest(isolation=isolation):
                check, _, _, sink = checker(cfg=config(isolation=isolation))
                check.startup()
                self.assertEqual(check.verdict.reasons, (Reason.ISOLATION_UNSTATED,))
                self.assertFalse(check.access_open)
                self.assertEqual(sink.events[0].reasons, (Reason.ISOLATION_UNSTATED,))

    def test_enumeration_errors_close(self):
        cases = {
            Reason.LISTENER_ENUMERATION_UNAVAILABLE: dict(files=Files(tcp=PermissionError("denied"))),
            Reason.ROUTE_ENUMERATION_UNAVAILABLE: dict(status=Status(OSError("not running"))),
        }
        for reason, kwargs in cases.items():
            with self.subTest(reason):
                check, _, _, sink = checker(**kwargs)
                check.startup()
                self.assertClosed(check, reason)
                self.assertEqual(len(sink.events), 1)
        for text in ("", "No serve config", "{"):
            with self.subTest(status=text):
                check, *_ = checker(status=Status(text))
                check.startup()
                self.assertClosed(check, Reason.ROUTE_ENUMERATION_UNAVAILABLE)
        check, *_ = checker(files=Files(tcp6="garbage"))
        check.startup()
        self.assertClosed(check, Reason.LISTENER_ENUMERATION_UNAVAILABLE)

    def test_enumerator_returning_wrong_types_closes(self):
        class Bad:
            def listeners(self):
                return [("100.64.0.10", 443)]

            def routes(self):
                return None

        check = HostnameReservationCheck(config(), Bad(), Bad(), Sink(), utcnow=lambda: NOW)
        verdict = check.startup()
        self.assertIn(Reason.LISTENER_ENUMERATION_UNAVAILABLE, verdict.reasons)
        self.assertIn(Reason.ROUTE_ENUMERATION_UNAVAILABLE, verdict.reasons)

    def test_enumeration_timeout_closes_and_is_not_stacked(self):
        release = threading.Event()
        calls = []

        def hung():
            calls.append(1)
            release.wait(5)
            return serve()

        try:
            check, _, _, sink = checker(status=Status(), timeout=0.05)
            check._routes = ServeStatusRoutes(hung)
            check.startup()
            self.assertClosed(check, Reason.ROUTE_ENUMERATION_TIMEOUT)
            # The hung enumeration is still running: a second check neither
            # waits on it nor starts another one.
            check.startup()
            self.assertClosed(check, Reason.ROUTE_ENUMERATION_TIMEOUT)
            self.assertEqual(len(calls), 1)
            self.assertEqual([event.reasons for event in sink.events],
                             [(Reason.ROUTE_ENUMERATION_TIMEOUT,)] * 2)
        finally:
            release.set()

    def test_later_violation_closes_and_notifies(self):
        clock = Clock()
        check, files, status, sink = checker(clock=clock)
        self.assertTrue(check.startup().open)
        clock.value += 3600
        self.assertIsNone(check.tick())
        self.assertTrue(check.access_open)
        # A process binds another HTTPS port on the reserved IPv6 address and
        # a second Serve mapping appears; only the next daily check sees them.
        files.files["tcp6"] = proc((str(V6), 8443, "0A"), ipv6=True)
        status.text = serve(TCP={"443": {"HTTPS": True}, "8443": {"HTTPS": True}})
        self.assertTrue(check.access_open)
        clock.value += 86400
        verdict = check.tick()
        self.assertFalse(verdict.open)
        self.assertFalse(check.access_open)
        self.assertEqual(verdict.check, CheckKind.DAILY)
        self.assertEqual(set(verdict.reasons), {Reason.UNEXPECTED_LISTENER, Reason.UNEXPECTED_ROUTE})
        self.assertEqual(len(sink.events), 1)
        fault = sink.events[0]
        self.assertEqual((fault.check, fault.observed_at), (CheckKind.DAILY, NOW))
        self.assertEqual((fault.unexpected_listeners, fault.unexpected_routes), (1, 1))
        # The Owner event carries no addresses, ports or proxy targets.
        self.assertNotIn("fd7a", repr(fault))
        self.assertNotIn("127.0.0.1", repr(fault))

    def test_closed_retry_renotifies_only_on_change_and_reopens_on_pass(self):
        clock = Clock()
        revoker = FakeRevoker()
        check, files, status, sink = checker(clock=clock, status=Status(OSError("down")),
                                             session_revoker=revoker)
        check.startup()
        self.assertEqual(len(sink.events), 1)
        clock.value += 300
        check.tick()
        self.assertEqual(check.verdict.check, CheckKind.RETRY)
        self.assertEqual(len(sink.events), 1)
        status.text = "{}"
        clock.value += 300
        check.tick()
        self.assertEqual([event.reasons for event in sink.events][-1], (Reason.MAPPING_MISSING,))
        status.text = serve()
        clock.value += 300
        self.assertTrue(check.tick().open)
        self.assertTrue(check.access_open)
        # The earlier enumeration failure could not rule out an exposure.
        self.assertEqual(revoker.revocations, 1)

    def test_backward_monotonic_clock_forces_a_check(self):
        clock = Clock()
        check, files, *_ = checker(clock=clock)
        check.startup()
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 8443, "0A"))
        clock.value -= 10
        self.assertFalse(check.tick().open)

    def test_sink_failure_keeps_access_closed_and_retries_delivery(self):
        clock = Clock()
        sink = Sink(fail=True)
        check, *_ = checker(clock=clock, sink=sink, status=Status("{}"))
        check.startup()
        self.assertFalse(check.access_open)
        self.assertEqual(check.undelivered_faults, 1)
        sink.fail = False
        clock.value += 1
        check.tick()
        self.assertEqual([event.reasons for event in sink.events], [(Reason.MAPPING_MISSING,)])
        self.assertFalse(check.access_open)

    def test_invalid_timing_is_rejected(self):
        for value in (0, -1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker(timeout=value)


class SyntheticOwnerAuthorizer:
    def require_owner(self, actor_context):
        if actor_context != "synthetic-owner-session":
            raise OwnerAuthorizationError(ActorCategory.INVITED_USER)


SSH = exc(22)
WILDCARD_SSH = Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("0.0.0.0", 22, "0A")),
                     tcp6=proc(("::", 22, "0A"), ipv6=True))


class ExceptionFixture(TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Database(Path(self.temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.store = AuditStore(self.database, clock=lambda: NOW)
        self.service = OwnerAuditService(self.store, SyntheticOwnerAuthorizer())

        self.exception_store = ListenerExceptionStore(self.database)
        self.access = AccessStore(self.database, clock=lambda: NOW, audit=self.store,
                                  unaudited_writes=True, session_binding=SessionBindingKey.generate())
        self.revoker = ReservationSessionRevocation(self.access)

    def admin(self, files, **kwargs):
        kwargs.setdefault("session_revoker", self.revoker)
        check, _, _, sink = checker(files=Files(**files.files),
                                    exception_store=self.exception_store, **kwargs)
        return ReservationAdministration(self.service, check), check, sink

    def owner_records(self):
        return [record for record in self.store.list_records()
                if record.action is not AuditAction.INVALIDATE_HUMAN_SESSIONS]

    def stored(self):
        with closing(self.database.connect()) as connection:
            row = connection.execute(
                "SELECT value FROM application_metadata WHERE key=?", (STORE_KEY,)).fetchone()
        return None if row is None else row[0]

    def store_raw(self, value):
        with closing(self.database.connect()) as connection:
            connection.execute("INSERT OR REPLACE INTO application_metadata VALUES (?, ?)", (STORE_KEY, value))
            connection.commit()


class ListenerExceptionTests(ExceptionFixture):
    def test_default_is_empty_and_wildcard_system_listener_closes(self):
        _, check, _ = self.admin(WILDCARD_SSH)
        self.assertEqual(check.listener_exceptions, frozenset())
        check.startup()
        self.assertEqual(check.verdict.reasons, (Reason.UNEXPECTED_LISTENER,))

    def test_allowed_wildcard_port_passes_after_audited_owner_change(self):
        admin, check, sink = self.admin(WILDCARD_SSH)
        check.startup()
        verdict = admin.set_listener_exceptions("synthetic-owner-session", {SSH})
        self.assertTrue(verdict.open)
        self.assertEqual(verdict.check, CheckKind.CONFIGURATION)
        self.assertEqual(check.listener_exceptions, frozenset({SSH}))
        record, = self.owner_records()
        self.assertEqual((record.actor_category, record.action, record.target_kind,
                          record.target_logical_id, record.outcome),
                         (ActorCategory.OWNER, AuditAction.CHANGE_SECURITY_SETTING,
                          TargetKind.SECURITY_SETTINGS, RESERVATION_LISTENER_EXCEPTIONS_ID,
                          AuditOutcome.SUCCEEDED))
        # The fault from the earlier closed check carries reasons/counts only.
        self.assertNotIn("22", repr(sink.events[0].reasons))

    def test_family_restricted_exception(self):
        admin, check, _ = self.admin(WILDCARD_SSH)
        verdict = admin.set_listener_exceptions(
            "synthetic-owner-session", {exc(22, family=AddressFamily.IPV4)})
        self.assertFalse(verdict.open)
        self.assertEqual(verdict.reasons, (Reason.UNEXPECTED_LISTENER,))

    def test_ipv6_wildcard_needs_an_unrestricted_exception(self):
        # ``::`` may accept IPv4 too (bindv6only=0), so an IPv4-only exception never covers it.
        admin, check, _ = self.admin(Files(tcp6=proc(("::", 22, "0A"), ipv6=True)))
        self.assertFalse(admin.set_listener_exceptions(
            "synthetic-owner-session", {exc(22, family=AddressFamily.IPV4)}).open)
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {SSH}).open)
        self.assertFalse(exc(22, family=AddressFamily.IPV4).matches(
            Listener(ipaddress.IPv6Address("::"), 22)))
        self.assertTrue(exc(22, family=AddressFamily.IPV4).matches(
            Listener(ipaddress.IPv4Address("0.0.0.0"), 22)))

    def test_udp_exception_is_protocol_specific(self):
        tailscaled = Files(udp=proc(("0.0.0.0", 41641, "07")), udp6=proc(("::", 41641, "07"), ipv6=True))
        admin, check, _ = self.admin(tailscaled)
        self.assertFalse(admin.set_listener_exceptions(
            "synthetic-owner-session", {exc(41641)}).open)
        udp = exc(41641, TransportProtocol.UDP)
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {udp}).open)
        # A UDP exception never covers the dashboard port (HTTP/3 on the origin).
        with self.assertRaises(ValueError):
            admin.set_listener_exceptions("synthetic-owner-session", {exc(443, TransportProtocol.UDP)})
        # Nor a bind to a reserved address, nor TCP on the same port.
        admin, check, _ = self.admin(Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("0.0.0.0", 41641, "0A")),
                                           udp=proc(("100.64.0.10", 41641, "07"))))
        verdict = admin.set_listener_exceptions("synthetic-owner-session", {udp})
        self.assertFalse(verdict.open)
        self.assertEqual(check.verdict.reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual(decode(self.stored()), frozenset({udp}))

    def test_concurrent_changes_apply_in_commit_order(self):
        admin, check, _ = self.admin(WILDCARD_SSH)
        wide, narrow = {SSH}, set()
        committed, release = threading.Event(), threading.Event()
        original = check.apply_audited_listener_exceptions
        calls = []

        def paused_apply(change):
            calls.append(change.exceptions)
            if len(calls) == 1:
                # The wider change has committed; pause it before it applies.
                committed.set()
                release.wait(5)
            return original(change)

        errors = []

        def run(exceptions):
            try:
                admin.set_listener_exceptions("synthetic-owner-session", exceptions)
            except BaseException as error:  # pragma: no cover - surfaced below
                errors.append(error)

        with patch.object(check, "apply_audited_listener_exceptions", side_effect=paused_apply):
            first = threading.Thread(target=run, args=(wide,))
            first.start()
            self.assertTrue(committed.wait(5))
            second = threading.Thread(target=run, args=(narrow,))
            second.start()
            second.join(0.5)
            release.set()
            first.join(5)
            second.join(5)
        self.assertEqual(errors, [])
        # The durable latest change and the live set agree: the narrowing is not undone.
        self.assertEqual(decode(self.stored()), frozenset())
        self.assertEqual(check.listener_exceptions, frozenset())
        self.assertFalse(check.access_open)

    def test_check_in_progress_is_serialized_with_exception_change(self):
        # A daily/retry check evaluating the old, wider set must not publish its
        # verdict after a narrower set has durably committed.
        clock = Clock()
        admin, check, _ = self.admin(WILDCARD_SSH, clock=clock)
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {SSH}).open)
        entered, release = threading.Event(), threading.Event()
        original = check._listeners.listeners
        calls = []

        def paused_listeners():
            calls.append(None)
            if len(calls) == 1:
                entered.set()
                release.wait(5)
            return original()

        published = []
        errors = []

        def run(call):
            try:
                published.append(call())
            except BaseException as error:  # pragma: no cover - surfaced below
                errors.append(error)

        clock.value += DAILY_SECONDS
        with patch.object(check._listeners, "listeners", side_effect=paused_listeners):
            daily = threading.Thread(target=run, args=(check.tick,))
            daily.start()
            self.assertTrue(entered.wait(5))
            change = threading.Thread(target=run, args=(
                lambda: admin.set_listener_exceptions("synthetic-owner-session", ()),))
            change.start()
            change.join(0.3)
            # The narrowing has not committed while the stale check is still running.
            self.assertEqual(decode(self.stored()), frozenset({SSH}))
            release.set()
            daily.join(5)
            change.join(5)
        self.assertEqual(errors, [])
        self.assertEqual(decode(self.stored()), frozenset())
        self.assertEqual(check.listener_exceptions, frozenset())
        self.assertFalse(check.access_open)
        self.assertEqual(check.verdict.check, CheckKind.CONFIGURATION)
        self.assertEqual(check.verdict.reasons, (Reason.UNEXPECTED_LISTENER,))

    def test_duplicate_sockets_on_an_excepted_endpoint_close(self):
        # An exception allows one socket per wildcard endpoint it covers; an
        # identical SO_REUSEPORT copy is another process sharing that port.
        udp = exc(41641, TransportProtocol.UDP)
        cases = {
            "v4 wildcard twice": (Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("0.0.0.0", 22, "0A"),
                                                 ("0.0.0.0", 22, "0A"))), {SSH}),
            "v6 wildcard twice": (Files(tcp6=proc(("::", 22, "0A"), ("::", 22, "0A"), ipv6=True)), {SSH}),
            "both families, v6 doubled": (Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("0.0.0.0", 22, "0A")),
                                                tcp6=proc(("::", 22, "0A"), ("::", 22, "0A"), ipv6=True)),
                                          {SSH}),
            "udp wildcard twice": (Files(udp=proc(("0.0.0.0", 41641, "07"), ("0.0.0.0", 41641, "07"))), {udp}),
        }
        for name, (files, exceptions) in cases.items():
            with self.subTest(name):
                admin, check, sink = self.admin(files)
                verdict = admin.set_listener_exceptions("synthetic-owner-session", exceptions)
                self.assertFalse(verdict.open)
                self.assertEqual(verdict.reasons, (Reason.UNEXPECTED_LISTENER,))
                self.assertEqual(sink.events[-1].unexpected_listeners, 1)
        # Distinct IPv4 and IPv6 wildcard endpoints covered by one exception still pass.
        admin, check, _ = self.admin(WILDCARD_SSH)
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {SSH}).open)

    def test_same_port_on_reserved_address_still_closes(self):
        for files in (Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 22, "0A"))),
                      Files(tcp6=proc((str(V6), 22, "0A"), ipv6=True)),
                      Files(tcp6=proc(("::ffff:100.64.0.10", 22, "0A"), ipv6=True))):
            with self.subTest(files=files.files):
                admin, check, _ = self.admin(files)
                verdict = admin.set_listener_exceptions("synthetic-owner-session", {SSH})
                self.assertFalse(verdict.open)
                self.assertEqual(verdict.reasons, (Reason.UNEXPECTED_LISTENER,))

    def test_non_allowed_port_still_closes(self):
        files = Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("0.0.0.0", 22, "0A"), ("0.0.0.0", 8443, "0A")))
        admin, check, sink = self.admin(files)
        verdict = admin.set_listener_exceptions("synthetic-owner-session", {SSH})
        self.assertFalse(verdict.open)
        self.assertEqual(sink.events[-1].unexpected_listeners, 1)
        self.assertEqual(sink.events[-1].check, CheckKind.CONFIGURATION)

    def test_narrowing_closes_immediately(self):
        admin, check, _ = self.admin(WILDCARD_SSH)
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {SSH}).open)
        self.assertFalse(admin.set_listener_exceptions("synthetic-owner-session", ()).open)
        self.assertFalse(check.access_open)

    def test_non_owner_is_denied_audited_and_changes_nothing(self):
        admin, check, _ = self.admin(WILDCARD_SSH)
        check.startup()
        for actor in ({"invited": True}, None, "shared-tailnet-login"):
            with self.subTest(actor=actor), self.assertRaises(OwnerAuthorizationError):
                admin.set_listener_exceptions(actor, {SSH})
        self.assertEqual(check.listener_exceptions, frozenset())
        self.assertFalse(check.access_open)
        records = self.store.list_records()
        self.assertEqual(len(records), 3)
        self.assertTrue(all(record.outcome is AuditOutcome.DENIED
                            and record.action is AuditAction.CHANGE_SECURITY_SETTING
                            for record in records))

    def test_exception_never_covers_dashboard_or_human_listener(self):
        admin, check, _ = self.admin(WILDCARD_SSH)
        for exceptions in ({exc(443)}, {exc(8080)}, {22},
                           {exc(port) for port in range(1000, 1017)}):
            with self.subTest(exceptions=exceptions), self.assertRaises(ValueError):
                admin.set_listener_exceptions("synthetic-owner-session", exceptions)
        self.assertEqual(check.listener_exceptions, frozenset())
        self.assertTrue(all(record.outcome is AuditOutcome.FAILED for record in self.store.list_records()))
        with self.assertRaises(ValueError):
            evaluate(config(), (HUMAN,), (config().expected_route,), {exc(443)})

    def test_exception_type_is_validated(self):
        for kwargs in (dict(port=0), dict(port=70000), dict(port="22"), dict(port=22, family="ipv4"),
                       dict(port=22, protocol="udp"), dict(port=True),
                       # A ``::`` bind may be dual-stack; an IPv6-only exception is unverifiable.
                       dict(port=22, family=AddressFamily.IPV6)):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ListenerException(**kwargs)

    def test_direct_apply_waits_for_the_change_lock(self):
        _, check, _ = self.admin(WILDCARD_SSH)
        change = check.stage_listener_exceptions({SSH})
        done = threading.Event()
        with check.exception_change_lock:
            worker = threading.Thread(target=lambda: (check.apply_audited_listener_exceptions(change), done.set()))
            worker.start()
            self.assertFalse(done.wait(0.1))
        worker.join(5)
        self.assertTrue(done.is_set())
        self.assertEqual(check.listener_exceptions, frozenset({SSH}))

    def test_unaudited_change_object_from_another_check_is_refused(self):
        _, check, _ = self.admin(WILDCARD_SSH)
        other, *_ = checker()
        with self.assertRaises(ValueError):
            check.apply_audited_listener_exceptions(other.stage_listener_exceptions({SSH}))
        self.assertEqual(check.listener_exceptions, frozenset())


class ListenerExceptionPersistenceTests(ExceptionFixture):
    """Durable exceptions in the existing application_metadata table."""

    def test_exceptions_survive_restart(self):
        admin, _, _ = self.admin(WILDCARD_SSH)
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {SSH}).open)
        self.assertEqual(decode(self.stored()), frozenset({SSH}))
        # A new process: fresh check, same database, loaded before the first check.
        _, restarted, sink = self.admin(WILDCARD_SSH)
        self.assertEqual(restarted.listener_exceptions, frozenset())
        verdict = restarted.startup()
        self.assertTrue(verdict.open)
        self.assertEqual(restarted.listener_exceptions, frozenset({SSH}))
        self.assertEqual(sink.events, [])

    def test_missing_row_is_the_empty_default(self):
        _, check, sink = self.admin(Files())
        self.assertTrue(check.startup().open)
        self.assertEqual(sink.events, [])

    def test_corrupt_or_invalid_stored_value_fails_closed(self):
        corrupt = ("", "not json", "[]", "null", '{"version": 2}',
                   '{"version": 3, "exceptions": []}',
                   # Both owner identities, neither, or a relative/unnormalized path.
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 22, "family": null, "scope": "wildcard",'
                   ' "executable": "/usr/sbin/sshd", "unit": "ssh.service"}]}',
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 22, "family": null, "scope": "wildcard",'
                   ' "executable": null, "unit": null}]}',
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 22, "family": null, "scope": "wildcard",'
                   ' "executable": "sshd", "unit": null}]}',
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 22, "family": null, "scope": "wildcard",'
                   ' "executable": "/usr/sbin/../bin/sh", "unit": null}]}',
                   '{"version": 2, "exceptions": "*"}',
                   '{"version": 2, "exceptions": [{"port": 22}]}',
                   '{"version": 2, "exceptions": [{"protocol": "sctp", "port": 22, "family": null, "scope": "wildcard"}]}',
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 22, "family": "ipv6", "scope": "wildcard"}]}',
                   # Duplicate members must not silently keep the last value.
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 443, "port": 22,'
                   ' "family": null, "scope": "wildcard"}]}',
                   '{"version": 2, "version": 2, "exceptions": []}',
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 0, "family": null, "scope": "wildcard"}]}',
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 22, "family": null, "scope": "any"}]}',
                   '{"version": 2, "exceptions": [{"protocol": "tcp", "port": 22, "family": null, "scope": "wildcard"},'
                   ' {"protocol": "tcp", "port": 22, "family": null, "scope": "wildcard"}]}',
                   # Well-formed but covering the dashboard port: invalid for this config.
                   encode({exc(443), SSH}),
                   "x" * 5000)
        for value in corrupt:
            with self.subTest(value=value[:60]):
                self.store_raw(value)
                _, check, sink = self.admin(WILDCARD_SSH)
                verdict = check.startup()
                self.assertEqual(check.listener_exceptions, frozenset())
                self.assertFalse(verdict.open)
                self.assertEqual([event.reasons for event in sink.events],
                                 [(Reason.LISTENER_EXCEPTIONS_UNREADABLE, Reason.UNEXPECTED_LISTENER)])
                self.assertNotIn("22", repr(sink.events[0]))

    def test_unreadable_store_fails_closed(self):
        class Unreadable:
            def load(self):
                raise OSError("synthetic unreadable store")

        check, _, _, sink = checker(files=WILDCARD_SSH, exception_store=Unreadable())
        self.assertFalse(check.startup().open)
        self.assertEqual(check.listener_exceptions, frozenset())
        self.assertEqual(sink.events[0].reasons[0], Reason.LISTENER_EXCEPTIONS_UNREADABLE)

    def test_unreadable_store_keeps_startup_closed_without_an_unexpected_listener(self):
        # The fail-closed verdict must not depend on a wildcard listener being present.
        for value in ("not json", '{"version": 2, "exceptions": "*"}'):
            with self.subTest(value=value):
                self.store_raw(value)
                _, check, sink = self.admin(Files())
                verdict = check.startup()
                self.assertFalse(verdict.open)
                self.assertEqual(verdict.reasons, (Reason.LISTENER_EXCEPTIONS_UNREADABLE,))
                self.assertEqual([event.reasons for event in sink.events],
                                 [(Reason.LISTENER_EXCEPTIONS_UNREADABLE,)])

        class Unreadable:
            def load(self):
                raise OSError("synthetic unreadable store")

        clock = Clock()
        check, _, _, sink = checker(exception_store=Unreadable(), clock=clock)
        self.assertEqual(check.startup().reasons, (Reason.LISTENER_EXCEPTIONS_UNREADABLE,))
        # Retries and the daily check stay closed while the store is still unreadable.
        clock.value += RETRY_WHILE_CLOSED_SECONDS
        self.assertEqual(check.tick().reasons, (Reason.LISTENER_EXCEPTIONS_UNREADABLE,))
        clock.value += DAILY_SECONDS
        self.assertFalse(check.tick().open)

    def test_repaired_store_reopens_on_the_next_check(self):
        self.store_raw("not json")
        clock = Clock()
        _, check, _ = self.admin(Files(), clock=clock)
        self.assertFalse(check.startup().open)
        self.store_raw(encode(frozenset()))
        clock.value += RETRY_WHILE_CLOSED_SECONDS
        self.assertTrue(check.tick().open)

    def test_audited_owner_change_repairs_an_unreadable_store(self):
        self.store_raw("not json")
        admin, check, _ = self.admin(WILDCARD_SSH)
        self.assertFalse(check.startup().open)
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {SSH}).open)

    def test_persist_failure_rolls_back_with_audit(self):
        admin, check, _ = self.admin(WILDCARD_SSH)
        admin.set_listener_exceptions("synthetic-owner-session", {SSH})
        wider = {SSH, exc(8443)}
        with patch.object(ListenerExceptionStore, "write_on", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                admin.set_listener_exceptions("synthetic-owner-session", wider)
        self.assertEqual(decode(self.stored()), frozenset({SSH}))
        self.assertEqual(check.listener_exceptions, frozenset({SSH}))
        self.assertEqual(sorted(record.outcome.value for record in self.store.list_records()),
                         ["failed", "succeeded"])

    def test_audit_failure_rolls_back_persisted_value(self):
        admin, check, _ = self.admin(WILDCARD_SSH)
        with patch.object(AuditStore, "append_on", side_effect=OSError("synthetic audit failure")):
            with self.assertRaises(OSError):
                admin.set_listener_exceptions("synthetic-owner-session", {SSH})
        self.assertIsNone(self.stored())
        self.assertEqual(check.listener_exceptions, frozenset())

    def test_denied_change_persists_nothing(self):
        admin, _, _ = self.admin(WILDCARD_SSH)
        with self.assertRaises(OwnerAuthorizationError):
            admin.set_listener_exceptions({"invited": True}, {SSH})
        self.assertIsNone(self.stored())

    def test_facade_requires_a_store_sharing_the_audit_database(self):
        check, *_ = checker()
        with self.assertRaises(ValueError):
            ReservationAdministration(self.service, check)
        other = Database(Path(self.temporary.name) / "other.sqlite3")
        check, *_ = checker(exception_store=ListenerExceptionStore(other))
        with self.assertRaises(ValueError):
            ReservationAdministration(self.service, check)

    def test_write_requires_a_transaction(self):
        with closing(self.database.connect()) as connection, self.assertRaises(Exception):
            self.exception_store.write_on(connection, {SSH})


class SessionRevocationTests(ExceptionFixture):
    """Owner decision 2026-09-30: revoke every human session before reopening after an exposure."""

    EXTRA = proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 8443, "0A"))

    def session(self, identity, token, *, owner=False):
        if owner:
            principal = self.access.bootstrap_owner("Synthetic owner")
        else:
            principal = self.access.invite("Synthetic viewer", (Permission.LIVE_VIEW,))
        secret = hashlib.sha256(token).digest()
        self.access.issue_enrollment(principal.id, secret, NOW + timedelta(minutes=5))
        credential = self.access.enroll_credential(secret, identity, b"credential-" + token, b"synthetic-key", -7, 0)
        self.access.establish_session(principal.id, credential.credential_id, token, proxy_identity=identity)
        return principal, credential

    def marker(self):
        with closing(self.database.connect()) as connection:
            row = connection.execute("SELECT value FROM application_metadata WHERE key=?",
                                     (REVOCATION_PENDING_KEY,)).fetchone()
        return None if row is None else row[0]

    def revocation_records(self):
        return [record for record in self.store.list_records()
                if record.action is AuditAction.INVALIDATE_HUMAN_SESSIONS]

    def breached(self, **kwargs):
        clock = Clock()
        kwargs.setdefault("session_revoker", self.revoker)
        check, files, status, sink = checker(clock=clock, exception_store=self.exception_store, **kwargs)
        self.assertTrue(check.startup().open)
        files.files["tcp"] = self.EXTRA
        clock.value += DAILY_SECONDS
        self.assertFalse(check.tick().open)
        self.assertEqual(check.verdict.reasons, (Reason.UNEXPECTED_LISTENER,))
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        clock.value += 300
        return check, clock, sink

    def test_reopen_after_violation_revokes_every_session_with_audit_first(self):
        owner, owner_credential = self.session("owner@example.invalid", b"o" * 32, owner=True)
        self.session("viewer@example.invalid", b"v" * 32)
        pending = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
        self.access.issue_enrollment(pending.id, b"p" * 32, NOW + timedelta(minutes=5))
        check, clock, sink = self.breached()
        self.assertEqual(self.marker(), "1")
        observed = []
        original = self.revoker.revoke_all_human_sessions

        def revoke():
            original()
            # Committed before the verdict opens.
            observed.append((check.access_open, len(self.revocation_records())))

        with patch.object(self.revoker, "revoke_all_human_sessions", side_effect=revoke):
            self.assertTrue(check.tick().open)
        self.assertEqual(observed, [(False, 1)])
        record, = self.revocation_records()
        self.assertEqual((record.actor_category, record.target_kind, record.target_logical_id, record.outcome),
                         (ActorCategory.SYSTEM, TargetKind.SECURITY_SETTINGS, HUMAN_SESSIONS_ID,
                          AuditOutcome.SUCCEEDED))
        self.assertIsNone(self.marker())
        # Every earlier session is denied, the Owner's included.
        for token, identity in ((b"o" * 32, "owner@example.invalid"), (b"v" * 32, "viewer@example.invalid")):
            with self.subTest(identity=identity), self.assertRaises(AccessValidationError):
                self.access.authorize(token, identity, Permission.LIVE_VIEW)
        # An invitation issued under the previous generation must be issued again.
        with self.assertRaises(AccessValidationError):
            self.access.enroll_credential(b"p" * 32, "pending@example.invalid", b"pending", b"k", -7, 0)
        # Signing in again with the same credential works.
        self.access.establish_session(owner.id, owner_credential.credential_id, b"n" * 32,
                                      proxy_identity="owner@example.invalid")
        self.assertEqual(self.access.authorize(b"n" * 32, "owner@example.invalid", Permission.LIVE_VIEW).id,
                         owner.id)
        # A later pass with nothing pending does not revoke again.
        clock.value += DAILY_SECONDS
        self.assertTrue(check.tick().open)
        self.assertEqual(len(self.revocation_records()), 1)

    def test_revocation_failure_keeps_access_closed_and_notifies(self):
        self.session("viewer@example.invalid", b"v" * 32)
        check, clock, sink = self.breached()
        for target, method in ((AccessStore, "invalidate_all_sessions_on"), (AuditStore, "append_on")):
            with self.subTest(method=method):
                with patch.object(target, method, side_effect=OSError("synthetic failure")):
                    self.assertFalse(check.tick().open)
                clock.value += 300
                self.assertEqual(check.verdict.reasons, (Reason.SESSION_REVOCATION_FAILED,))
                # Rolled back: the old session is still valid in the store, the marker remains.
                self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)
                self.assertEqual(self.marker(), "1")
        self.assertIn((Reason.SESSION_REVOCATION_FAILED,), [event.reasons for event in sink.events])
        self.assertTrue(all(record.outcome is AuditOutcome.FAILED for record in self.revocation_records()))
        self.assertTrue(check.tick().open)
        with self.assertRaises(AccessValidationError):
            self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_missing_revoker_never_opens(self):
        # Nothing durable could carry a revocation requirement across a restart.
        check, _, _, sink = checker(exception_store=self.exception_store, session_revoker=None)
        self.assertEqual(check.startup().reasons, (Reason.SESSION_REVOCATION_UNAVAILABLE,))
        self.assertEqual(sink.events[-1].reasons, (Reason.SESSION_REVOCATION_UNAVAILABLE,))
        self.assertFalse(check._check(CheckKind.RETRY).open)

    def test_restart_without_revoker_after_exposure_keeps_old_sessions_out(self):
        self.session("viewer@example.invalid", b"v" * 32)
        files = Files(tcp=self.EXTRA)
        check, _, _, _ = checker(files=files, exception_store=self.exception_store, session_revoker=None)
        self.assertEqual(check.startup().reasons,
                         (Reason.UNEXPECTED_LISTENER, Reason.SESSION_REVOCATION_UNAVAILABLE))
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        restarted, _, _, _ = checker(files=files, exception_store=self.exception_store, session_revoker=None)
        self.assertFalse(restarted.startup().open)
        self.assertFalse(restarted.access_open)

    def test_restart_with_pending_revocation_revokes_before_opening(self):
        self.session("viewer@example.invalid", b"v" * 32)
        self.breached()
        self.assertEqual(self.marker(), "1")
        # A new process before the revocation happened.
        restarted, *_ = checker(exception_store=self.exception_store, session_revoker=self.revoker)
        self.assertTrue(restarted.startup().open)
        self.assertIsNone(self.marker())
        with self.assertRaises(AccessValidationError):
            self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_unreadable_pending_marker_revokes(self):
        with closing(self.database.connect()) as connection:
            connection.execute("INSERT INTO application_metadata VALUES (?, 'corrupt')", (REVOCATION_PENDING_KEY,))
            connection.commit()
        check, *_ = checker(exception_store=self.exception_store, session_revoker=self.revoker)
        self.assertTrue(check.startup().open)
        self.assertEqual(len(self.revocation_records()), 1)
        self.assertIsNone(self.marker())

    def test_non_exposure_close_reopens_without_revocation(self):
        self.session("viewer@example.invalid", b"v" * 32)
        check, _, status, _ = checker(exception_store=self.exception_store, session_revoker=self.revoker,
                                      status=Status("{}"))
        self.assertEqual(check.startup().reasons, (Reason.MAPPING_MISSING,))
        status.text = serve()
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(self.revocation_records(), [])
        self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_exposure_marker_failure_revokes_immediately(self):
        revoker = FakeRevoker()
        revoker.record_exposure = lambda: (_ for _ in ()).throw(OSError("synthetic marker failure"))
        check, files, _, sink = checker(session_revoker=revoker, files=Files(tcp=self.EXTRA))
        check.startup()
        # Access is closed and the revocation has committed, so a restart that
        # finds no marker cannot reopen with a session issued before exposure.
        self.assertEqual(check.verdict.reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual(revoker.revocations, 1)
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(revoker.revocations, 2)

    def test_restart_after_marker_failure_does_not_reopen_with_old_sessions(self):
        self.session("viewer@example.invalid", b"v" * 32)
        revoker = ReservationSessionRevocation(self.access)
        files = Files(tcp=self.EXTRA)
        with patch.object(revoker, "record_exposure", side_effect=OSError("synthetic marker failure")):
            check, _, _, _ = checker(exception_store=self.exception_store, session_revoker=revoker, files=files)
            self.assertFalse(check.startup().open)
        self.assertIsNone(self.marker())
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        restarted, _, _, _ = checker(exception_store=self.exception_store, session_revoker=revoker, files=files)
        self.assertTrue(restarted.startup().open)
        with self.assertRaises(AccessValidationError):
            self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_undurable_requirement_is_retried_on_every_check(self):
        revoker = FakeRevoker(fail=True)
        marker = {"fail": True}

        def record():
            if marker["fail"]:
                raise OSError("synthetic marker failure")
            revoker.pending = True

        revoker.record_exposure = record
        check, files, _, sink = checker(session_revoker=revoker, files=Files(tcp=self.EXTRA))
        self.assertEqual(check.startup().reasons,
                         (Reason.UNEXPECTED_LISTENER, Reason.SESSION_REVOCATION_FAILED))
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        # The listener is gone, but the requirement is still only in memory.
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.SESSION_REVOCATION_FAILED,))
        self.assertFalse(revoker.pending)
        marker["fail"] = False
        # The marker now commits; reopening still waits for the revocation.
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.SESSION_REVOCATION_FAILED,))
        self.assertTrue(revoker.pending)
        revoker.fail = False
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(revoker.revocations, 1)

    def test_committed_fallback_revocation_is_not_repeated_while_closed(self):
        # Issue #120: the marker keeps failing and the exposure persists, but the
        # immediate revocation already committed; retries must not repeat it,
        # but keep retrying the marker (PR #134).
        revoker = FakeRevoker()
        markers = []

        def record():
            markers.append(True)
            raise OSError("synthetic marker failure")

        revoker.record_exposure = record
        clock = Clock()
        check, files, _, _ = checker(session_revoker=revoker, files=Files(tcp=self.EXTRA), clock=clock)
        self.assertEqual(check.startup().reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual((revoker.revocations, len(markers)), (1, 1))
        for _ in range(5):
            clock.value += RETRY_WHILE_CLOSED_SECONDS
            self.assertEqual(check.tick().reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual((revoker.revocations, len(markers)), (1, 6))
        # The revocation before reopening still runs.
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        clock.value += RETRY_WHILE_CLOSED_SECONDS
        self.assertTrue(check.tick().open)
        self.assertEqual((revoker.revocations, len(markers)), (2, 7))
        # A new exposure after reopening is a new closed period: it revokes again.
        files.files["tcp"] = self.EXTRA
        clock.value += DAILY_SECONDS
        self.assertFalse(check.tick().open)
        self.assertEqual((revoker.revocations, len(markers)), (3, 8))
        clock.value += RETRY_WHILE_CLOSED_SECONDS
        self.assertFalse(check.tick().open)
        self.assertEqual(revoker.revocations, 3)

    def test_session_committed_after_fallback_revocation_does_not_survive_restart(self):
        # PR #134: a session-establishing request saw access open before the
        # check closed it and commits after the immediate fallback revocation.
        # The marker must keep being retried so that a restart after the
        # exposure disappears (before the clean check) still revokes it.
        revoker = ReservationSessionRevocation(self.access)
        clock = Clock()
        files = Files(tcp=self.EXTRA)
        marker = {"fail": True}
        original = revoker.record_exposure

        def record():
            if marker["fail"]:
                raise OSError("synthetic marker failure")
            original()

        with patch.object(revoker, "record_exposure", side_effect=record):
            check, _, _, _ = checker(exception_store=self.exception_store, session_revoker=revoker,
                                     files=files, clock=clock)
            self.assertFalse(check.startup().open)
            self.assertEqual(len(self.revocation_records()), 1)
            self.assertIsNone(self.marker())
            # The racing request commits its session after the revocation.
            self.session("viewer@example.invalid", b"v" * 32)
            marker["fail"] = False
            clock.value += RETRY_WHILE_CLOSED_SECONDS
            self.assertFalse(check.tick().open)
            # No repeated revocation, but the marker is now stored.
            self.assertEqual(len(self.revocation_records()), 1)
            self.assertEqual(self.marker(), "1")
        self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)
        # The exposure disappears and the process restarts before a clean check.
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        restarted, _, _, _ = checker(exception_store=self.exception_store, session_revoker=revoker, files=files)
        self.assertTrue(restarted.startup().open)
        self.assertIsNone(self.marker())
        with self.assertRaises(AccessValidationError):
            self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_marker_is_retried_after_fallback_while_closed_for_other_reasons(self):
        # The exposure is gone but access stays closed for a non-exposure
        # reason; the marker is still retried without repeating the revocation.
        revoker = FakeRevoker()
        marker = {"fail": True, "attempts": 0}

        def record():
            marker["attempts"] += 1
            if marker["fail"]:
                raise OSError("synthetic marker failure")
            revoker.pending = True

        revoker.record_exposure = record
        resolver = Resolver()
        check, files, _, _ = checker(session_revoker=revoker, files=Files(tcp=self.EXTRA), resolver=resolver)
        self.assertEqual(check.startup().reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual((revoker.revocations, marker["attempts"]), (1, 1))
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        resolver.answer = OSError("synthetic resolver failure")
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.HOSTNAME_RESOLUTION_UNAVAILABLE,))
        self.assertEqual((revoker.revocations, marker["attempts"], revoker.pending), (1, 2, False))
        marker["fail"] = False
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.HOSTNAME_RESOLUTION_UNAVAILABLE,))
        self.assertEqual((revoker.revocations, marker["attempts"], revoker.pending), (1, 3, True))
        # Stored: later closed checks do not rewrite it.
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.HOSTNAME_RESOLUTION_UNAVAILABLE,))
        self.assertEqual(marker["attempts"], 3)
        resolver.answer = (V4, V6)
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual((revoker.revocations, revoker.pending), (2, False))

    def test_fallback_is_retried_only_while_both_fail(self):
        revoker = FakeRevoker(fail=True)
        attempts = {"marker": 0, "revoke": 0}

        def record():
            attempts["marker"] += 1
            raise OSError("synthetic marker failure")

        original = revoker.revoke_all_human_sessions

        def revoke():
            attempts["revoke"] += 1
            original()

        revoker.record_exposure = record
        revoker.revoke_all_human_sessions = revoke
        check, _, _, _ = checker(session_revoker=revoker, files=Files(tcp=self.EXTRA))
        self.assertEqual(check.startup().reasons,
                         (Reason.UNEXPECTED_LISTENER, Reason.SESSION_REVOCATION_FAILED))
        self.assertEqual(check._check(CheckKind.RETRY).reasons,
                         (Reason.UNEXPECTED_LISTENER, Reason.SESSION_REVOCATION_FAILED))
        self.assertEqual(attempts, {"marker": 2, "revoke": 2})
        revoker.fail = False
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual(attempts, {"marker": 3, "revoke": 3})
        for _ in range(3):
            self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.UNEXPECTED_LISTENER,))
        # Only the marker keeps being retried (PR #134).
        self.assertEqual(attempts, {"marker": 6, "revoke": 3})
        self.assertEqual(revoker.revocations, 1)

    def test_outage_enrollment_survives_retries_after_fallback_revocation(self):
        self.session("viewer@example.invalid", b"v" * 32)
        revoker = ReservationSessionRevocation(self.access)
        clock = Clock()
        with patch.object(revoker, "record_exposure", side_effect=OSError("synthetic marker failure")):
            check, files, _, _ = checker(exception_store=self.exception_store, session_revoker=revoker,
                                         files=Files(tcp=self.EXTRA), clock=clock)
            self.assertFalse(check.startup().open)
            self.assertEqual(len(self.revocation_records()), 1)
            pending = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
            secret = hashlib.sha256(b"p" * 32).digest()
            self.access.issue_enrollment(pending.id, secret, NOW + timedelta(minutes=5))
            for _ in range(3):
                clock.value += RETRY_WHILE_CLOSED_SECONDS
                self.assertFalse(check.tick().open)
            # No repeated generation advance or audit record during the outage.
            self.assertEqual(len(self.revocation_records()), 1)
            self.access.enroll_credential(secret, "pending@example.invalid", b"pending", b"k", -7, 0)
            files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
            clock.value += RETRY_WHILE_CLOSED_SECONDS
            self.assertTrue(check.tick().open)
        self.assertEqual(len(self.revocation_records()), 2)
        with self.assertRaises(AccessValidationError):
            self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_resolution_failure_keeps_sessions_and_generation(self):
        self.session("viewer@example.invalid", b"v" * 32)
        resolver = Resolver(OSError("synthetic resolver failure"))
        check, _, _, _ = checker(exception_store=self.exception_store, session_revoker=self.revoker,
                                 resolver=resolver)
        self.assertEqual(check.startup().reasons, (Reason.HOSTNAME_RESOLUTION_UNAVAILABLE,))
        self.assertIsNone(self.marker())
        resolver.answer = (V4, V6)
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(self.revocation_records(), [])
        self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_address_change_revokes_before_reopening(self):
        self.session("viewer@example.invalid", b"v" * 32)
        resolver = Resolver((V4,))
        check, _, _, _ = checker(exception_store=self.exception_store, session_revoker=self.revoker,
                                 resolver=resolver)
        self.assertEqual(check.startup().reasons, (Reason.RESERVED_ADDRESSES_CHANGED,))
        self.assertEqual(self.marker(), "1")
        resolver.answer = (V4, V6)
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(len(self.revocation_records()), 1)
        with self.assertRaises(AccessValidationError):
            self.access.authorize(b"v" * 32, "viewer@example.invalid", Permission.LIVE_VIEW)

    def test_revoker_requires_an_audited_access_store(self):
        for store in (None, AccessStore(self.database), object()):
            with self.subTest(store=store), self.assertRaises(ValueError):
                ReservationSessionRevocation(store)


class HostnameResolutionTests(TestCase):
    def test_matching_resolution_opens(self):
        resolver = Resolver()
        check, _, _, _ = checker(resolver=resolver)
        self.assertTrue(check.startup().open)
        check._check(CheckKind.RETRY)
        self.assertEqual(resolver.calls, 2)

    def test_mapped_answer_matches(self):
        mapped = ipaddress.IPv6Address("::ffff:100.64.0.10")
        check, _, _, _ = checker(resolver=Resolver((mapped, V6)))
        self.assertTrue(check.startup().open)

    def test_listener_on_unlisted_resolved_address_is_an_exposure(self):
        extra = ipaddress.IPv4Address("100.64.0.11")
        revoker = FakeRevoker()
        check, _, _, sink = checker(resolver=Resolver((V4, V6, extra)), session_revoker=revoker,
                                    files=Files(tcp=proc(("127.0.0.1", 8080, "0A"), (str(extra), 8443, "0A"))))
        verdict = check.startup()
        self.assertEqual(verdict.reasons, (Reason.RESERVED_ADDRESSES_CHANGED, Reason.UNEXPECTED_LISTENER))
        self.assertTrue(revoker.pending)
        self.assertEqual(sink.events[-1].unexpected_listeners, 1)
        self.assertNotIn("100.64.0.11", repr(sink.events[-1]))

    def test_changed_resolution_is_an_exposure(self):
        resolver = Resolver((V4,))
        revoker = FakeRevoker()
        check, _, _, _ = checker(resolver=resolver, session_revoker=revoker)
        self.assertEqual(check.startup().reasons, (Reason.RESERVED_ADDRESSES_CHANGED,))
        self.assertTrue(revoker.pending)
        resolver.answer = (V4, V6)
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(revoker.revocations, 1)

    def test_failed_or_missing_resolution_fails_closed_without_revocation(self):
        for resolver in (Resolver(OSError("synthetic resolver failure")), Resolver(()),
                         Resolver(("100.64.0.10",)), None):
            with self.subTest(resolver=resolver):
                revoker = FakeRevoker()
                check, _, _, _ = checker(resolver=resolver, session_revoker=revoker)
                self.assertEqual(check.startup().reasons, (Reason.HOSTNAME_RESOLUTION_UNAVAILABLE,))
                self.assertFalse(revoker.pending)
                if resolver is not None:
                    resolver.answer = (V4, V6)
                    self.assertTrue(check._check(CheckKind.RETRY).open)
                    self.assertEqual(revoker.revocations, 0)

    def test_exposure_during_resolution_failure_still_revokes(self):
        resolver = Resolver(OSError("synthetic resolver failure"))
        revoker = FakeRevoker()
        files = Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 8443, "0A")))
        check, _, _, _ = checker(resolver=resolver, session_revoker=revoker, files=files)
        self.assertEqual(check.startup().reasons,
                         (Reason.HOSTNAME_RESOLUTION_UNAVAILABLE, Reason.UNEXPECTED_LISTENER))
        files.files["tcp"] = proc(("127.0.0.1", 8080, "0A"))
        self.assertEqual(check._check(CheckKind.RETRY).reasons, (Reason.HOSTNAME_RESOLUTION_UNAVAILABLE,))
        self.assertEqual(revoker.revocations, 0)
        resolver.answer = (V4, V6)
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(revoker.revocations, 1)

    def test_hung_resolution_times_out(self):
        release = threading.Event()

        class Hung:
            def resolve(self, hostname):
                release.wait(5)
                return (V4, V6)

        try:
            check, _, _, _ = checker(resolver=Hung(), timeout=0.05)
            self.assertEqual(check.startup().reasons, (Reason.HOSTNAME_RESOLUTION_TIMEOUT,))
        finally:
            release.set()

    def test_getaddrinfo_resolver(self):
        answers = [(10, 1, 6, "", ("fd7a:115c:a1e0::10", 0, 0, 0)),
                   (2, 1, 6, "", ("100.64.0.10", 0)),
                   (10, 1, 6, "", ("::ffff:100.64.0.10", 0, 0, 0)),
                   (10, 1, 6, "", ("fe80::1%eth0", 0, 0, 2))]
        calls = []

        def lookup(*args):
            calls.append(args)
            return answers

        resolved = GetaddrinfoResolver(lookup).resolve(HOST)
        self.assertEqual(set(resolved), {V4, V6, ipaddress.IPv6Address("fe80::1")})
        self.assertEqual(calls[0][0], HOST)
        for failing in (lambda *args: [], lambda *args: (_ for _ in ()).throw(OSError("synthetic")),
                        lambda *args: [(2, 1, 6, "", ("not-an-address", 0))]):
            with self.subTest(failing=failing), self.assertRaises(ReservationEnumerationError):
                GetaddrinfoResolver(failing).resolve(HOST)
        with self.assertRaises(ValueError):
            GetaddrinfoResolver(None)

    def test_pure_evaluate_uses_union_of_resolved_and_configured(self):
        extra = ipaddress.IPv4Address("100.64.0.11")
        listeners = (HUMAN, Listener(extra, 22))
        reasons, count, _ = evaluate(config(), listeners, (config().expected_route,), resolved=(V4, V6, extra))
        self.assertEqual(reasons, (Reason.RESERVED_ADDRESSES_CHANGED, Reason.UNEXPECTED_LISTENER))
        self.assertEqual(count, 1)
        self.assertEqual(evaluate(config(), listeners, (config().expected_route,))[0], ())


class ListenerOwnershipTests(ExceptionFixture):
    """Owner decision 2026-10-01: an exception is a port plus its owning process."""

    def opened(self, owners, **kwargs):
        admin, check, sink = self.admin(WILDCARD_SSH, socket_owners=owners, **kwargs)
        return admin.set_listener_exceptions("synthetic-owner-session", {SSH}), check, sink

    def test_port_only_or_ambiguous_exception_is_refused(self):
        for kwargs in (dict(port=22), dict(port=22, executable=SSHD, unit="ssh.service"),
                       dict(port=22, executable="sshd"), dict(port=22, executable="/usr/sbin/../sbin/sshd"),
                       dict(port=22, executable="/usr/sbin/sshd (deleted)"), dict(port=22, executable=""),
                       dict(port=22, unit="ssh"), dict(port=22, unit="../ssh.service"), dict(port=22, unit=7)):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ListenerException(**kwargs)
        admin, check, _ = self.admin(WILDCARD_SSH)
        with self.assertRaises(ValueError):
            admin.set_listener_exceptions("synthetic-owner-session", {22})
        self.assertIsNone(self.stored())

    def test_matching_owner_opens(self):
        owners = Owners()
        verdict, _, _ = self.opened(owners)
        self.assertTrue(verdict.open)
        self.assertEqual(owners.calls[-1], frozenset({1001, 1000}))

    def test_other_process_on_excepted_port_is_an_exposure(self):
        intruder = SocketOwner("/usr/bin/python3.12", "user@1000.service")
        for holders in (intruder, frozenset({SSHD_OWNER, intruder})):
            with self.subTest(holders=holders):
                revoker = FakeRevoker()
                verdict, _, sink = self.opened(Owners(overrides={1000: holders}), session_revoker=revoker)
                self.assertEqual(verdict.reasons, (Reason.UNEXPECTED_LISTENER,))
                self.assertTrue(revoker.pending)
                self.assertNotIn("python", repr(sink.events[-1]))

    def test_unverifiable_owner_is_an_exposure(self):
        release = threading.Event()

        class Hung:
            def owners(self, inodes):
                release.wait(5)
                return {}

        self.addCleanup(release.set)
        cases = {"no owner found": dict(socket_owners=Owners(overrides={1000: None})),
                 "resolver fails": dict(socket_owners=Owners(default=OSError("synthetic /proc failure"))),
                 "no resolver": dict(socket_owners=None),
                 "hung resolver": dict(socket_owners=Hung(), timeout=0.05),
                 "unknown exe": dict(socket_owners=Owners(default=SocketOwner(None, None)))}
        for name, kwargs in cases.items():
            with self.subTest(name):
                revoker = FakeRevoker()
                admin, check, _ = self.admin(WILDCARD_SSH, session_revoker=revoker, **kwargs)
                verdict = admin.set_listener_exceptions("synthetic-owner-session", {SSH})
                self.assertFalse(verdict.open)
                self.assertTrue(set(verdict.reasons) & {Reason.LISTENER_OWNER_UNVERIFIED,
                                                         Reason.UNEXPECTED_LISTENER})
                self.assertTrue(revoker.pending)

    def test_unknown_inode_is_unverified(self):
        listeners = (HUMAN, Listener(ipaddress.IPv4Address("0.0.0.0"), 22, inode=0))
        reasons, count, _ = evaluate(config(), listeners, (config().expected_route,), {SSH},
                                     owners={0: frozenset({SSHD_OWNER})})
        self.assertEqual(reasons, (Reason.LISTENER_OWNER_UNVERIFIED,))
        self.assertEqual(count, 1)

    def test_unit_exception_matches_the_unit_only(self):
        by_unit = ListenerException(22, unit="ssh.service")
        self.assertTrue(by_unit.owned_by(SocketOwner("/usr/sbin/sshd", "ssh.service")))
        self.assertFalse(by_unit.owned_by(SocketOwner("/usr/sbin/sshd", "other.service")))
        self.assertFalse(SSH.owned_by(SocketOwner("/usr/bin/sshd", "ssh.service")))
        admin, check, _ = self.admin(WILDCARD_SSH, socket_owners=Owners(SocketOwner(None, "ssh.service")))
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {by_unit}).open)
        self.assertEqual(decode(self.stored()), frozenset({by_unit}))

    def test_port_only_stored_exceptions_fail_closed_as_outdated(self):
        self.store_raw('{"version":1,"exceptions":[{"protocol":"tcp","port":22,"family":null,"scope":"wildcard"}]}')
        admin, check, sink = self.admin(WILDCARD_SSH)
        verdict = check.startup()
        self.assertEqual(verdict.reasons[0], Reason.LISTENER_EXCEPTIONS_OUTDATED)
        self.assertFalse(verdict.open)
        self.assertEqual(check.listener_exceptions, frozenset())
        # The Owner re-enters the exception with its owner through the audited path.
        self.assertTrue(admin.set_listener_exceptions("synthetic-owner-session", {SSH}).open)
        self.assertEqual(decode(self.stored()), frozenset({SSH}))

    def test_round_trip_keeps_owner(self):
        values = {SSH, ListenerException(41641, TransportProtocol.UDP, unit="tailscaled.service")}
        self.assertEqual(decode(encode(values)), frozenset(values))
        with self.assertRaises(ValueError):
            encode({ListenerException(port, executable="/" + "x" * 1000) for port in range(1, 17)}
                   | {ListenerException(17, executable="/" + "y" * 1023)})


class ProcSocketOwnersTests(TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def process(self, pid, exe, fds, cgroup="0::/system.slice/ssh.service\n"):
        base = self.root / str(pid)
        (base / "fd").mkdir(parents=True)
        (base / "exe").symlink_to(exe)
        (base / "cgroup").write_text(cgroup)
        for number, target in enumerate(fds):
            (base / "fd" / str(number)).symlink_to(target)
        return base

    def test_maps_inodes_to_owning_processes(self):
        self.process(100, "/usr/sbin/sshd", ["socket:[1000]", "/dev/null", "pipe:[5]"])
        self.process(200, "/usr/bin/python3.12", ["socket:[1000]", "socket:[2000]"],
                     cgroup="0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n")
        self.process(300, "/usr/sbin/other", ["socket:[3000]"])
        (self.root / "self").mkdir()
        owners = ProcSocketOwners(str(self.root)).owners(frozenset({1000, 2000, 4000}))
        self.assertEqual(owners, {
            # A user-session scope is not a system unit, so it names none.
            1000: frozenset({SocketOwner("/usr/sbin/sshd", "ssh.service"),
                             SocketOwner("/usr/bin/python3.12", None)}),
            2000: frozenset({SocketOwner("/usr/bin/python3.12", None)}),
        })

    def unreadable(self, base):
        (base / "fd").chmod(0)
        self.addCleanup((base / "fd").chmod, 0o700)
        if os.access(base / "fd", os.R_OK):
            self.skipTest("running with privilege that bypasses directory permissions")

    def test_unreadable_process_makes_the_scan_incomplete(self):
        self.unreadable(self.process(100, "/usr/sbin/sshd", ["socket:[1000]"]))
        with self.assertRaises(ReservationEnumerationError):
            ProcSocketOwners(str(self.root)).owners(frozenset({1000}))

    def test_unreadable_holder_beside_a_matching_one_closes_access(self):
        # An unreadable fd table may hide another holder of the excepted socket.
        self.process(100, "/usr/sbin/sshd", ["socket:[1000]", "socket:[1001]"])
        self.unreadable(self.process(200, "/usr/bin/python3.12", ["socket:[1000]"]))
        with self.assertRaises(ReservationEnumerationError):
            ProcSocketOwners(str(self.root)).owners(frozenset({1000, 1001}))
        check, _, _, _ = checker(files=WILDCARD_SSH, socket_owners=ProcSocketOwners(str(self.root)))
        check._exceptions, check._exceptions_loaded = frozenset({SSH}), True
        verdict = check._check(CheckKind.RETRY)
        self.assertEqual(verdict.reasons, (Reason.LISTENER_OWNER_UNVERIFIED,))

    def test_process_that_exited_during_the_scan_is_skipped(self):
        self.process(100, "/usr/sbin/sshd", ["socket:[1000]"])
        (self.root / "200").mkdir()  # no fd directory: gone before it was read
        self.assertEqual(ProcSocketOwners(str(self.root)).owners(frozenset({1000})),
                         {1000: frozenset({SocketOwner("/usr/sbin/sshd", "ssh.service")})})

    def test_missing_exe_or_cgroup_unit(self):
        base = self.process(100, "/usr/sbin/sshd", ["socket:[1000]"], cgroup="0::/\n")
        (base / "exe").unlink()
        self.assertEqual(ProcSocketOwners(str(self.root)).owners(frozenset({1000})),
                         {1000: frozenset({SocketOwner(None, None)})})

    def test_root_must_be_absolute(self):
        with self.assertRaises(ValueError):
            ProcSocketOwners("proc")

    def test_only_a_direct_system_slice_unit_is_reported(self):
        cases = {
            # A non-root user can create ssh.service in their own user@ manager.
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/ssh.service\n": None,
            "0::/user.slice/user-1000.slice/user@1000.service\n": None,
            "0::/system.slice/ssh.service/child\n": None,
            "0::/machine.slice/ssh.service\n": None,
            "0::/init.scope\n": None,
            "0::/system.slice/ssh.service\n": "ssh.service",
            "0::/system.slice/getty@tty1.service\n": "getty@tty1.service",
        }
        for number, (cgroup, unit) in enumerate(cases.items()):
            with self.subTest(cgroup=cgroup):
                pid = 100 + number
                self.process(pid, "/usr/sbin/sshd", [f"socket:[{5000 + number}]"], cgroup=cgroup)
                owners = ProcSocketOwners(str(self.root)).owners(frozenset({5000 + number}))
                self.assertEqual(owners[5000 + number], frozenset({SocketOwner("/usr/sbin/sshd", unit)}))

    def test_user_manager_impersonating_a_unit_does_not_match(self):
        self.process(100, "/usr/bin/python3.12", ["socket:[1001]"],
                     cgroup="0::/user.slice/user-1000.slice/user@1000.service/app.slice/ssh.service\n")
        owners = ProcSocketOwners(str(self.root)).owners(frozenset({1001}))
        exception = ListenerException(22, unit="ssh.service")
        self.assertFalse(any(exception.owned_by(owner) for owner in owners[1001]))


class ProcNetInodeTests(TestCase):
    def test_inode_is_parsed_and_not_part_of_identity(self):
        parsed = parse_proc_net_tcp(proc(("0.0.0.0", 22, "0A")), ipv6=False, byteorder="little")
        self.assertEqual(parsed[0].inode, 1000)
        self.assertEqual(parsed[0], Listener(ipaddress.IPv4Address("0.0.0.0"), 22))

    def test_missing_or_malformed_inode_is_rejected(self):
        for line in ("   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0",
                     "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 x 1"):
            with self.subTest(line=line), self.assertRaises(ReservationEnumerationError):
                parse_proc_net_tcp(HEADER + "\n" + line + "\n", ipv6=False, byteorder="little")


class ProxyListenerOwnershipTests(TestCase):
    """Recorded proxy sockets must exist and be held by the recorded proxy alone."""

    CFG = dict(proxy_listeners=frozenset({Listener(V4, 443), Listener(V6, 443)}), proxy_owner=TAILSCALED)

    def files(self, v4=True, v6=True):
        return Files(tcp=proc(("127.0.0.1", 8080, "0A"), *([("100.64.0.10", 443, "0A")] if v4 else [])),
                     tcp6=proc(*([(str(V6), 443, "0A")] if v6 else []), ipv6=True))

    def test_proxy_owner_is_required_with_proxy_listeners(self):
        with self.assertRaises(ValueError):
            config(proxy_listeners=frozenset({Listener(V4, 443)}))
        with self.assertRaises(ValueError):
            config(proxy_owner=TAILSCALED)
        for kwargs in (dict(), dict(executable="/a", unit="b.service"), dict(executable="tailscaled")):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ProcessIdentity(**kwargs)

    def test_missing_proxy_listener_closes_without_revocation(self):
        files = self.files(v6=False)
        revoker = FakeRevoker()
        check, *_ = checker(files=files, cfg=config(**self.CFG), session_revoker=revoker,
                            socket_owners=Owners(TAILSCALED_OWNER))
        self.assertEqual(check.startup().reasons, (Reason.PROXY_LISTENER_MISSING,))
        self.assertFalse(revoker.pending)
        files.files.update(self.files().files)
        self.assertTrue(check._check(CheckKind.RETRY).open)
        self.assertEqual(revoker.revocations, 0)

    def test_replacement_process_on_proxy_socket_is_an_exposure(self):
        intruder = SocketOwner("/usr/bin/python3.12", "user@1000.service")
        for holders in (intruder, frozenset({TAILSCALED_OWNER, intruder})):
            with self.subTest(holders=holders):
                revoker = FakeRevoker()
                check, *_ = checker(files=self.files(), cfg=config(**self.CFG), session_revoker=revoker,
                                    socket_owners=Owners(TAILSCALED_OWNER, overrides={1001: holders}))
                self.assertEqual(check.startup().reasons, (Reason.UNEXPECTED_LISTENER,))
                self.assertTrue(revoker.pending)

    def test_unverifiable_proxy_owner_is_an_exposure(self):
        for owners in (None, Owners(OSError("synthetic /proc failure")), Owners(overrides={1001: None})):
            with self.subTest(owners=owners):
                revoker = FakeRevoker()
                check, *_ = checker(files=self.files(), cfg=config(**self.CFG), session_revoker=revoker,
                                    socket_owners=owners)
                self.assertIn(Reason.LISTENER_OWNER_UNVERIFIED, check.startup().reasons)
                self.assertTrue(revoker.pending)

    def test_executable_identity(self):
        cfg = config(proxy_listeners=frozenset({Listener(V4, 443)}),
                     proxy_owner=ProcessIdentity(executable="/usr/sbin/tailscaled"))
        check, *_ = checker(files=self.files(v6=False), cfg=cfg, socket_owners=Owners(TAILSCALED_OWNER))
        self.assertTrue(check.startup().open)


class HumanListenerOwnershipTests(TestCase):
    """The loopback upstream must be a socket this ServerSentinel process holds."""

    def test_own_socket_opens(self):
        check, *_ = checker(own_sockets=lambda: frozenset({1000}))
        self.assertTrue(check.startup().open)

    def test_single_replacement_is_an_exposure(self):
        # One row only (no SO_REUSEPORT duplicate), but not this process's socket.
        revoker = FakeRevoker()
        check, _, _, sink = checker(own_sockets=lambda: frozenset({4242}), session_revoker=revoker)
        self.assertEqual(check.startup().reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual(sink.events[-1].unexpected_listeners, 1)
        self.assertTrue(revoker.pending)

    def test_unverifiable_own_sockets_are_an_exposure(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def hung():
            release.wait(5)
            return frozenset({1000})

        def fails():
            raise OSError("synthetic /proc/self/fd failure")

        for name, kwargs in {"fails": dict(own_sockets=fails), "hangs": dict(own_sockets=hung, timeout=0.05),
                             "bad value": dict(own_sockets=lambda: {"1000"}),
                             "none": dict(own_sockets=None)}.items():
            with self.subTest(name):
                revoker = FakeRevoker()
                check, *_ = checker(session_revoker=revoker, **kwargs)
                self.assertEqual(check.startup().reasons, (Reason.LISTENER_OWNER_UNVERIFIED,))
                self.assertTrue(revoker.pending)

    def test_unknown_inode_is_unverified(self):
        reasons, count, _ = evaluate(config(), (Listener(HUMAN.address, HUMAN.port, inode=0),),
                                     (config().expected_route,), own_inodes=frozenset({0}))
        self.assertEqual(reasons, (Reason.LISTENER_OWNER_UNVERIFIED,))
        self.assertEqual(count, 1)

    def test_proc_self_fd_reader(self):
        with TemporaryDirectory() as directory:
            fd = Path(directory) / "fd"
            fd.mkdir()
            (fd / "3").symlink_to("socket:[1234]")
            (fd / "4").symlink_to("/dev/null")
            (fd / "5").symlink_to("socket:[99]")
            self.assertEqual(OwnSocketInodes(directory)(), frozenset({1234, 99}))
            with self.assertRaises(OSError):
                OwnSocketInodes(directory + "/missing")()
