"""Synthetic /proc/net and Serve status fixtures only; no host sockets or tailscale."""

from datetime import datetime, timezone
import ipaddress
import json
import threading
from unittest import TestCase

from app.auth.reservation import (
    CheckKind, HostnameReservationCheck, IsolationMode, Listener, ProcNetListeners, ProxyRoute,
    Reason, ReservationConfig, ReservationEnumerationError, ReservationFault, RouteKind,
    ServeStatusRoutes, evaluate, parse_proc_net_tcp, parse_serve_status,
)


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
HOST = "sentinel.example-tailnet.ts.net"
V4 = ipaddress.IPv4Address("100.64.0.10")
V6 = ipaddress.IPv6Address("fd7a:115c:a1e0::10")
HUMAN = Listener(ipaddress.IPv4Address("127.0.0.1"), 8080)
HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
          "   uid  timeout inode")


def _hex(address, byteorder="little"):
    raw = address.packed
    if byteorder == "little":
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
    return raw.hex().upper()


def proc(*sockets, ipv6=False, byteorder="little"):
    """Render (address, port, state) tuples as a synthetic /proc/net/tcp{,6} file."""
    zero = ipaddress.IPv6Address("::") if ipv6 else ipaddress.IPv4Address("0.0.0.0")
    lines = [HEADER]
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
    def __init__(self, tcp=None, tcp6=None):
        self.files = {"tcp": tcp if tcp is not None else proc(("127.0.0.1", 8080, "0A")),
                      "tcp6": tcp6 if tcp6 is not None else proc(ipv6=True)}

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


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


def checker(files=None, status=None, sink=None, cfg=None, clock=None, **kwargs):
    files = files or Files()
    status = status or Status()
    sink = sink if sink is not None else Sink()
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
               dict(proxy_listeners=frozenset({Listener(ipaddress.IPv4Address("100.64.0.99"), 443)})))
        for overrides in bad:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                config(**overrides)

    def test_ipv6_upstream_url(self):
        cfg = config(human_listener=Listener(ipaddress.IPv6Address("::1"), 8080))
        self.assertEqual(cfg.upstream, "http://[::1]:8080")


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
        cfg = config(proxy_listeners=frozenset({Listener(V4, 443), Listener(V6, 443)}))
        check, *_ = checker(files=files, cfg=cfg)
        self.assertTrue(check.startup().open)

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
        check, files, status, sink = checker(clock=clock, status=Status(OSError("down")))
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
