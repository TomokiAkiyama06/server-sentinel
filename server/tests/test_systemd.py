import os
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.systemd import (
    SocketActivationError, activated_listener, build_server, listen_fds, notify_ready,
)


class Client:
    def __init__(self):
        self.messages = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def sendto(self, message, address):
        self.messages.append((message, address))
        return len(message)


class SystemdNotificationTests(unittest.TestCase):
    def test_ready_uses_only_local_systemd_datagram(self):
        client = Client()
        calls = []

        def factory(family, kind):
            calls.append((family, kind))
            return client

        self.assertTrue(notify_ready({"NOTIFY_SOCKET": "@synthetic-notify"},
                                     socket_factory=factory))
        self.assertEqual(calls, [(socket.AF_UNIX, socket.SOCK_DGRAM)])
        self.assertEqual(client.messages, [(b"READY=1", "\0synthetic-notify")])
        self.assertFalse(notify_ready({}, socket_factory=factory))

    def test_invalid_or_incomplete_notification_fails(self):
        for address in ("relative", "", "@" + "x" * 108, "/tmp/x\0tail"):
            with self.subTest(address=address), self.assertRaises(OSError):
                notify_ready({"NOTIFY_SOCKET": address}, socket_factory=lambda *_: Client())

        client = Client()
        client.sendto = lambda *_: 0
        with self.assertRaisesRegex(OSError, "incomplete"):
            notify_ready({"NOTIFY_SOCKET": "@synthetic"}, socket_factory=lambda *_: client)


class Server:
    def __init__(self, config):
        self.config = config
        self.should_exit = False

    async def startup(self, sockets=None):
        self.config.events.append(("startup", sockets))


class SystemdStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_ready_follows_lifespan_and_listener_startup(self):
        events = []
        module = SimpleNamespace(
            Server=Server,
            Config=lambda application, **options: SimpleNamespace(
                application=application, options=options, events=events,
            ),
        )
        server = build_server(object(), uvicorn_module=module,
                              notifier=lambda: events.append(("ready", None)), host="127.0.0.1")
        await server.startup(sockets=["synthetic-listener"])
        self.assertEqual(events, [
            ("startup", ["synthetic-listener"]), ("ready", None),
        ])
        self.assertEqual(server.config.options["host"], "127.0.0.1")

    async def test_failed_startup_or_notification_never_reports_success(self):
        class FailedServer(Server):
            async def startup(self, sockets=None):
                raise OSError("synthetic bind failure")

        module = SimpleNamespace(
            Server=FailedServer,
            Config=lambda *_args, **_kwargs: SimpleNamespace(events=[]),
        )
        notifications = []
        server = build_server(object(), uvicorn_module=module,
                              notifier=lambda: notifications.append(True))
        with self.assertRaisesRegex(OSError, "bind failure"):
            await server.startup()
        self.assertEqual(notifications, [])

        module.Server = Server
        server = build_server(object(), uvicorn_module=module,
                              notifier=lambda: (_ for _ in ()).throw(OSError("notify failure")))
        with self.assertRaisesRegex(OSError, "notify failure"):
            await server.startup()


class SocketActivationTests(unittest.TestCase):
    """Issue #126: the human upstream is created by server-sentinel-upstream.socket."""

    def passed(self, sock):
        # Place the socket at a free descriptor number standing in for fd 3.
        number = os.dup(sock.fileno())
        sock.close()
        self.addCleanup(self.close_quietly, number)
        return number

    @staticmethod
    def close_quietly(number):
        try:
            os.close(number)
        except OSError:
            pass

    def environ(self, count="1", pid=None):
        return {"LISTEN_PID": str(os.getpid() if pid is None else pid), "LISTEN_FDS": count,
                "LISTEN_FDNAMES": "server-sentinel-upstream.socket", "OTHER": "kept"}

    def bound(self, kind=socket.SOCK_STREAM, listen=True):
        sock = socket.socket(socket.AF_INET, kind)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        if listen:
            sock.listen(1)
        return self.passed(sock), port

    def test_listen_fds_follows_sd_listen_fds(self):
        self.assertEqual(listen_fds({}), ())
        environ = self.environ(count="2")
        self.assertEqual(listen_fds(environ), (3, 4))
        # Consumed: a child never takes the variables as its own.
        self.assertEqual(environ, {"OTHER": "kept"})
        environ = self.environ(pid=os.getpid() + 1)
        self.assertEqual(listen_fds(environ), ())
        self.assertEqual(environ, {"OTHER": "kept"})
        for environ in ({"LISTEN_PID": "x", "LISTEN_FDS": "1"}, {"LISTEN_PID": str(os.getpid())},
                        {"LISTEN_FDS": "1"}, {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "-1"},
                        {"LISTEN_PID": "0", "LISTEN_FDS": "1"}):
            with self.subTest(environ=environ), self.assertRaises(SocketActivationError):
                listen_fds(dict(environ))

    def test_activated_listener_is_accepted_and_made_non_inheritable(self):
        number, port = self.bound()
        os.set_inheritable(number, True)  # as systemd passes it
        listener = activated_listener("127.0.0.1", port, self.environ(), first_fd=number)
        self.addCleanup(listener.detach)
        self.assertEqual(listener.fileno(), number)
        self.assertEqual(listener.getsockname(), ("127.0.0.1", port))
        self.assertFalse(os.get_inheritable(number))

    def test_without_activation_nothing_is_taken(self):
        self.assertIsNone(activated_listener("127.0.0.1", 8000, {}))
        self.assertIsNone(activated_listener("127.0.0.1", 8000, self.environ(pid=os.getpid() + 1)))

    def test_mismatched_or_unusable_descriptor_is_refused(self):
        def other_port(port):
            return port + 1 if port < 65535 else port - 1

        cases = {
            "other port": (dict(), lambda port: ("127.0.0.1", other_port(port))),
            "other address": (dict(), lambda port: ("127.0.0.2", port)),
            "udp": (dict(kind=socket.SOCK_DGRAM, listen=False), lambda port: ("127.0.0.1", port)),
            "not listening": (dict(listen=False), lambda port: ("127.0.0.1", port)),
        }
        for name, (made, expected) in cases.items():
            with self.subTest(name):
                number, port = self.bound(**made)
                with self.assertRaises(SocketActivationError):
                    activated_listener(*expected(port), self.environ(), first_fd=number)
                # The refused socket is closed rather than kept open unused.
                with self.assertRaises(OSError):
                    os.fstat(number)
        # A listening SOCK_STREAM socket of another protocol (for example
        # SCTP or MPTCP) is not the TCP upstream.
        number, port = self.bound()
        real = socket.socket

        class OtherProtocol(real):
            def getsockopt(self, level, option, *args):
                if (level, option) == (socket.SOL_SOCKET, socket.SO_PROTOCOL):
                    return 132  # IPPROTO_SCTP
                return super().getsockopt(level, option, *args)

        with patch("app.systemd.socket.socket", OtherProtocol), self.assertRaises(SocketActivationError):
            activated_listener("127.0.0.1", port, self.environ(), first_fd=number)
        with self.assertRaises(OSError):
            os.fstat(number)
        read, write = os.pipe()
        self.addCleanup(self.close_quietly, read)
        self.addCleanup(self.close_quietly, write)
        with self.assertRaises(SocketActivationError):
            activated_listener("127.0.0.1", 8000, self.environ(), first_fd=read)
        number, port = self.bound()
        with self.assertRaises(SocketActivationError):
            activated_listener("127.0.0.1", port, self.environ(count="2"), first_fd=number)


if __name__ == "__main__":
    unittest.main()
