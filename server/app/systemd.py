"""Minimal systemd readiness notification without an external dependency."""

import os
import socket
from typing import Mapping


def notify_ready(environ: Mapping[str, str] | None = None, *,
                 socket_factory=socket.socket) -> bool:
    values = os.environ if environ is None else environ
    address = values.get("NOTIFY_SOCKET")
    if address is None:
        return False
    if (not isinstance(address, str) or not address or "\0" in address
            or address[0] not in {"/", "@"} or len(address.encode()) > 107):
        raise OSError("invalid systemd notification socket")
    target = "\0" + address[1:] if address.startswith("@") else address
    with socket_factory(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        sent = client.sendto(b"READY=1", target)
    if sent != len(b"READY=1"):
        raise OSError("incomplete systemd readiness notification")
    return True


def build_server(application, *, uvicorn_module=None, notifier=notify_ready, **options):
    """Create a server that notifies only after lifespan and listener startup."""
    if uvicorn_module is None:
        import uvicorn as uvicorn_module

    class NotifyingServer(uvicorn_module.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            if not self.should_exit:
                notifier()

    return NotifyingServer(uvicorn_module.Config(application, **options))
