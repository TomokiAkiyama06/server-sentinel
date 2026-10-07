"""Minimal systemd readiness notification and socket activation, standard library only."""

import ipaddress
import os
import re
import socket
from typing import Callable, Mapping, MutableMapping


# sd_listen_fds(3): passed descriptors start at 3.
SD_LISTEN_FDS_START = 3
_ACTIVATION_VARIABLES = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")


class SocketActivationError(OSError):
    """The passed socket is not the single expected human upstream listener."""


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


def listen_fds(environ: MutableMapping[str, str] | None = None, *,
               getpid: Callable[[], int] = os.getpid,
               first_fd: int = SD_LISTEN_FDS_START) -> tuple[int, ...]:
    """The descriptors systemd passed to this process (``sd_listen_fds`` semantics).

    Returns ``()`` when nothing was passed to this process (``LISTEN_PID``
    absent or naming another process). The variables are removed once read so
    a child process never takes them as its own. Malformed values raise.
    """
    values = os.environ if environ is None else environ
    pid, count = values.get("LISTEN_PID"), values.get("LISTEN_FDS")
    for name in _ACTIVATION_VARIABLES:
        values.pop(name, None)
    if pid is None and count is None:
        return ()
    if (not isinstance(pid, str) or not re.fullmatch(r"[1-9][0-9]{0,9}", pid)
            or not isinstance(count, str) or not re.fullmatch(r"[0-9]{1,4}", count)):
        raise SocketActivationError("invalid socket activation environment")
    if int(pid) != getpid():
        return ()
    return tuple(range(first_fd, first_fd + int(count)))


def activated_listener(host: str, port: int, environ: MutableMapping[str, str] | None = None, *,
                       getpid: Callable[[], int] = os.getpid,
                       first_fd: int = SD_LISTEN_FDS_START) -> socket.socket | None:
    """The human upstream passed by ``server-sentinel-upstream.socket``, or None without activation.

    Exactly one descriptor must be passed, and it must be a listening TCP
    socket bound to exactly ``host``:``port``; anything else raises, so the
    backend never serves a socket it was not configured for. The descriptor is
    made non-inheritable: a child process never holds the upstream.
    """
    descriptors = listen_fds(environ, getpid=getpid, first_fd=first_fd)
    if not descriptors:
        return None
    if len(descriptors) != 1:
        raise SocketActivationError("exactly one activated socket is required")
    try:
        listener = socket.socket(fileno=descriptors[0])
    except OSError:
        raise SocketActivationError("activated descriptor is not a socket") from None
    try:
        os.set_inheritable(listener.fileno(), False)
        bound = listener.getsockname()
        accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        if (listener.family not in (socket.AF_INET, socket.AF_INET6)
                or listener.type != socket.SOCK_STREAM or accepting != 1
                or ipaddress.ip_address(bound[0]) != ipaddress.ip_address(host)
                or bound[1] != port):
            raise SocketActivationError("activated socket does not match the human listener")
    except (OSError, ValueError, IndexError):
        listener.close()
        raise SocketActivationError("activated socket does not match the human listener") from None
    return listener
