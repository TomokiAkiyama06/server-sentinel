import socket
from types import SimpleNamespace
import unittest

from app.systemd import build_server, notify_ready


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


if __name__ == "__main__":
    unittest.main()
