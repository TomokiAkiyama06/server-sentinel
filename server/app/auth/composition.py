"""Production human-access composition (Issue #10; ADR-0003, ADR-0004, Issue #232).

``build_human_access`` turns a validated ``human_access`` deployment section
(``app.auth.access_config``) into the one ``HumanAccess`` the launcher passes
to ``create_app``. Every opening input of the ``HostnameReservationCheck`` is
the production one:

- listeners: ``ProcNetListeners`` over this network namespace's
  ``/proc/net/{tcp,tcp6,udp,udp6}`` (bounded reads);
- proxy routes: ``ServeStatusRoutes`` over ``ServeStatusCommand``, a bounded,
  read-only ``<tailscale> serve status --json`` runner (absolute executable,
  empty environment, no stdin, output cap, timeout; any failure is a
  ``ReservationEnumerationError``, so the check fails closed);
- hostname resolution: ``GetaddrinfoResolver``;
- socket creators and holders: ``SockDiagOwners`` (Issue #126);
- stored Owner listener exceptions: ``ListenerExceptionStore`` on the
  application database, and session revocation after an exposure:
  ``ReservationSessionRevocation`` of the same ``AccessStore``.

The access store is audited, uses the deployment's invitation lifetime and
the deployment-local ``SessionBindingKey`` (``Settings.session_binding_key_path``),
and the passkey ceremonies use the reserved ``https`` relying party and the
deployment's ``require_device_bound`` policy. The one ``AccessFaultMonitor``
(``faults``) is both the check's ``sink`` and the ceremonies' ``findings``
(Issue #232 item 4); the caller also passes it as
``MonitoringDependencies(access_faults=...)``, and ``create_app`` refuses any
other combination.

Nothing here runs ``tailscale`` with any argument other than the fixed
read-only status query, changes Tailscale ACLs/Grants, or needs a Tailscale
administrative credential. Every failure raises ``HumanAccessUnavailable``,
which carries no value; the launcher then refuses to start.
"""

from __future__ import annotations

from contextlib import suppress
import ipaddress
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from typing import Callable

from app.auth.access_config import SERVE_STATUS_ARGUMENTS, HumanAccessDeployment
from app.auth.human_surface import (
    HumanAccess, HumanAccessConfiguration, HumanAccessUnavailable, reserved_origin,
)
from app.auth.passkeys import PasskeyCeremonies
from app.auth.reservation import (
    ENUMERATION_TIMEOUT_SECONDS, MAX_SERVE_STATUS_BYTES, GetaddrinfoResolver,
    HostnameReservationCheck, IsolationMode, Listener, ProcessIdentity, ProcNetListeners,
    ReservationConfig, ReservationEnumerationError, ServeStatusRoutes, TransportProtocol,
)
from app.auth.reservation_store import ListenerExceptionStore, ReservationSessionRevocation
from app.auth.session_binding import SessionBindingKey
from app.auth.sock_diag import SockDiagOwners
from app.auth.store import AccessStore
from app.auth.web_assets import WebAssets
from app.auth.webauthn import RelyingParty
from app.audit import AuditStore
from app.settings import Settings
from app.storage.database import Database


# Below the check's own enumeration timeout, so the runner (not the check)
# ends a hung CLI and the next check starts a fresh one.
SERVE_STATUS_TIMEOUT_SECONDS = 5.0
PROC_NET_ROOT = "/proc/net"
PROC_NET_TABLES = frozenset({"tcp", "tcp6", "udp", "udp6"})
# ``parse_proc_net_*`` refuses more than a million rows; a table larger than
# this is refused before it is decoded.
MAX_PROC_NET_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 65536


def read_proc_net(name: str, *, root: str = PROC_NET_ROOT,
                  limit: int = MAX_PROC_NET_BYTES) -> str:
    """One ``/proc/net`` socket table of this network namespace, bounded.

    A missing table (for example ``tcp6`` on a kernel booted without IPv6),
    a read error, a table over ``limit`` bytes or non-ASCII text raises
    ``ReservationEnumerationError``: the check then keeps access closed.
    """
    if name not in PROC_NET_TABLES:
        raise ReservationEnumerationError("INVALID_PROC_NET_TABLE")
    try:
        with open(os.path.join(root, name), "rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        raise ReservationEnumerationError("PROC_NET_UNREADABLE") from None
    if len(data) > limit:
        raise ReservationEnumerationError("PROC_NET_TOO_LARGE")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise ReservationEnumerationError("MALFORMED_PROC_NET") from None


class ServeStatusCommand:
    """Bounded, read-only ``<executable> serve status --json`` (the Serve status source).

    The executable is an absolute path validated by the deployment launcher
    (administrator-owned, executable by the service account); it is run with
    the fixed arguments ``SERVE_STATUS_ARGUMENTS`` only, an empty environment,
    ``/`` as working directory, no stdin, stderr discarded and every other
    descriptor closed, in its own session so a timeout kills its whole process
    group. Standard output is read up to ``max_bytes``; more output, a run
    longer than ``timeout`` seconds, a non-zero exit status, a failure to
    start or text that is not UTF-8 raises ``ReservationEnumerationError``.
    The output itself is returned to the parser and never logged.
    """

    def __init__(self, executable: Path, *, timeout: float = SERVE_STATUS_TIMEOUT_SECONDS,
                 max_bytes: int = MAX_SERVE_STATUS_BYTES,
                 popen: Callable = subprocess.Popen,
                 monotonic: Callable[[], float] = time.monotonic):
        if not isinstance(executable, Path) or not executable.is_absolute():
            raise ValueError("INVALID_SERVE_STATUS_COMMAND")
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout < ENUMERATION_TIMEOUT_SECONDS):
            raise ValueError("INVALID_SERVE_STATUS_COMMAND")
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_SERVE_STATUS_BYTES:
            raise ValueError("INVALID_SERVE_STATUS_COMMAND")
        self._argv = (str(executable), *SERVE_STATUS_ARGUMENTS)
        self._timeout = float(timeout)
        self._max_bytes = max_bytes
        self._popen = popen
        self._monotonic = monotonic

    def __call__(self) -> str:
        deadline = self._monotonic() + self._timeout
        try:
            process = self._popen(
                list(self._argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env={}, cwd="/", close_fds=True,
                start_new_session=True,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            raise ReservationEnumerationError("SERVE_STATUS_UNAVAILABLE") from None
        try:
            output = self._read(process, deadline)
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise ReservationEnumerationError("SERVE_STATUS_TIMEOUT")
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ReservationEnumerationError("SERVE_STATUS_TIMEOUT") from None
        except ReservationEnumerationError:
            self._kill(process)
            raise
        except Exception:
            self._kill(process)
            raise ReservationEnumerationError("SERVE_STATUS_UNAVAILABLE") from None
        finally:
            with suppress(OSError, ValueError):
                process.stdout.close()
        if code != 0:
            raise ReservationEnumerationError("SERVE_STATUS_UNAVAILABLE")
        try:
            return output.decode("utf-8")
        except UnicodeDecodeError:
            raise ReservationEnumerationError("MALFORMED_SERVE_STATUS") from None

    def _read(self, process, deadline: float) -> bytes:
        descriptor = process.stdout.fileno()
        chunks: list[bytes] = []
        total = 0
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while True:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise ReservationEnumerationError("SERVE_STATUS_TIMEOUT")
                if not selector.select(remaining):
                    continue
                chunk = os.read(descriptor, _READ_CHUNK)
                if not chunk:
                    return b"".join(chunks)
                total += len(chunk)
                if total > self._max_bytes:
                    raise ReservationEnumerationError("SERVE_STATUS_TOO_LARGE")
                chunks.append(chunk)

    @staticmethod
    def _kill(process) -> None:
        # Only a child that has not been reaped yet: its pid (and process
        # group, from start_new_session) cannot have been reused.
        if process.poll() is None:
            with suppress(OSError):
                os.killpg(process.pid, signal.SIGKILL)
        with suppress(Exception):
            process.wait(timeout=1.0)


def reservation_config(configuration: HumanAccessDeployment, human_host: str,
                       human_port: int) -> ReservationConfig:
    """The ``ReservationConfig`` for the section and the deployment's loopback upstream."""
    owner = configuration.proxy_owner
    return ReservationConfig(
        hostname=configuration.hostname,
        port=configuration.port,
        reserved_addresses=frozenset(configuration.reserved_addresses),
        human_listener=Listener(ipaddress.ip_address(human_host), human_port,
                                TransportProtocol.TCP),
        proxy_listeners=frozenset(Listener(address, configuration.port, TransportProtocol.TCP)
                                  for address in configuration.proxy_listeners),
        isolation=(IsolationMode(configuration.isolation)
                   if configuration.isolation is not None else None),
        proxy_owner=ProcessIdentity(owner.unit, owner.uid) if owner is not None else None,
    )


def build_human_access(configuration: HumanAccessDeployment, settings: Settings,
                       database: Database, *, faults, monitoring=None, listeners=None, routes=None,
                       resolver=None, socket_owners=None,
                       session_binding: SessionBindingKey | None = None,
                       **check_options) -> HumanAccess:
    """Compose the production ``HumanAccess``; raise ``HumanAccessUnavailable`` otherwise.

    ``faults`` is the single ``AccessFaultMonitor`` of this process.
    ``monitoring`` is the deployment's storage-configured
    ``MonitoringConfiguration``: the session-binding key is read or created
    only after ``admit_state_file`` verified the declared recording
    filesystem identity and, for a creation, the hard reserve (Codex PR #282),
    exactly like the database file, because this runs before the monitoring
    runtime binds the storage admission. The keyword overrides
    (``listeners``, ``routes``, ``resolver``, ``socket_owners``,
    ``session_binding`` and further ``HostnameReservationCheck`` options)
    exist for synthetic tests; the launcher passes none of them. Reads the
    session-binding key (creating it once, mode 0600, under that check) and
    the Web build; opens no socket and writes no database row: the startup
    check runs in the application lifespan.
    """
    from app.monitoring.access import AccessFaultMonitor
    from app.monitoring.config import MonitoringConfiguration
    if (not isinstance(configuration, HumanAccessDeployment) or configuration.enabled is not True
            or not isinstance(settings, Settings) or not isinstance(database, Database)
            or not isinstance(faults, AccessFaultMonitor)
            or (session_binding is None and not (isinstance(monitoring, MonitoringConfiguration)
                                                 and monitoring.storage_configured))
            or settings.web_assets_dir is None
            or configuration.upstream_host not in (None, settings.human_host)
            or configuration.upstream_port not in (None, settings.human_port)
            or database != Database(settings.database_path)):
        raise HumanAccessUnavailable()
    try:
        config = reservation_config(configuration, settings.human_host, settings.human_port)
        assets = WebAssets.load(settings.web_assets_dir)
        if session_binding is None:
            from app.monitoring.runtime import admit_state_file
            # Never spend the hard reserve or place the key on a fallback
            # root filesystem under a missing or replaced mount.
            admit_state_file(monitoring, settings.session_binding_key_path)
            session_binding = SessionBindingKey.load_or_create(settings.session_binding_key_path)
        binding = session_binding
        audit = AuditStore(database)
        store = AccessStore(database, audit=audit, session_binding=binding,
                            invitation_lifetime=settings.invitation_lifetime)
        check = HostnameReservationCheck(
            config,
            listeners if listeners is not None else ProcNetListeners(read_proc_net),
            routes if routes is not None else ServeStatusRoutes(
                ServeStatusCommand(configuration.tailscale_executable)),
            faults,
            exception_store=ListenerExceptionStore(database),
            session_revoker=ReservationSessionRevocation(store),
            resolver=resolver if resolver is not None else GetaddrinfoResolver(),
            socket_owners=socket_owners if socket_owners is not None else SockDiagOwners(),
            **check_options,
        )
        origin, _host = reserved_origin(check)
        ceremonies = PasskeyCeremonies(
            store, RelyingParty(configuration.hostname, origin), session_gate=check,
            require_device_bound=configuration.require_device_bound, findings=faults)
        return HumanAccess(HumanAccessConfiguration(enabled=True), store=store,
                           ceremonies=ceremonies, reservation=check, assets=assets)
    except HumanAccessUnavailable:
        raise
    except Exception:
        # Value-free: no hostname, address, path or key material.
        raise HumanAccessUnavailable() from None
