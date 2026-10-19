"""The ``human_access`` deployment section (Issue #10; ADR-0003, ADR-0004).

Standard library only: the standalone installer bundles this module with
``app.deployment`` and validates the section without the application's
dependencies. ``app.auth.composition`` turns the parsed value into the
production ``HumanAccess`` composition; nothing here touches the host.

Every refusal is a ``HumanAccessRefused`` whose ``reason`` is one fixed word
(``setting`` here); no hostname, address, unit, path or other supplied value
is ever part of an error.

The section only *states* the Owner's reservation (ADR-0003): the reserved
``https://<hostname>[:<port>]`` origin, every address the name resolves to on
this node, how the reservation is isolated outside the application, and the
proxy socket the Owner observed. Opening access still needs every startup and
daily ``HostnameReservationCheck`` to pass, an invitation and the person's own
passkey; ``isolation: null`` keeps access closed (``ISOLATION_UNSTATED``).
"""

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path, PurePosixPath
import re

from app.settings import ConfigurationError


# ``app.auth.reservation.IsolationMode`` values; a test keeps them equal.
ISOLATION_MODES = ("dedicated_network_identity", "single_purpose_node")
# The read-only Serve status query; the executable is the only configured part.
SERVE_STATUS_ARGUMENTS = ("serve", "status", "--json")
MAX_RESERVED_ADDRESSES = 16
MAX_UID = 0xFFFFFFFE  # (uid_t)-1 is never a real account

_REQUIRED = frozenset({"enabled", "hostname", "reserved_addresses", "isolation",
                       "tailscale_executable"})
_OPTIONAL = frozenset({"port", "proxy_listeners", "proxy_owner", "require_device_bound"})
# The same grammar as ``app.auth.reservation`` (lower-case DNS name, no
# trailing dot); the relying-party id must equal it exactly (ADR-0004).
_HOSTNAME = re.compile(
    r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
# Owner decision 2026-10-07: a proxy owner names a systemd service or socket unit.
_UNIT = re.compile(r"[A-Za-z0-9:_.\\@-]{1,250}\.(service|socket)")

Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class HumanAccessRefused(ConfigurationError):
    """The ``human_access`` section was refused; ``reason`` is one value-free word.

    ``setting`` (the section's shape or a value), ``web_assets`` (enabled
    without ``web_assets_directory``) or ``executable`` (the Tailscale CLI is
    not an administrator-controlled executable the service account can run).
    """

    def __init__(self, reason: str) -> None:
        super().__init__("human access configuration refused")
        self.reason = reason


@dataclass(frozen=True)
class ProxyOwner:
    """The systemd unit and uid that create the recorded proxy sockets."""

    unit: str
    uid: int


@dataclass(frozen=True)
class HumanAccessDeployment:
    """A validated ``human_access`` section. Private values stay out of ``repr``."""

    enabled: bool
    hostname: str = field(repr=False)
    port: int = field(repr=False)
    reserved_addresses: frozenset = field(repr=False)
    isolation: str | None
    tailscale_executable: Path = field(repr=False)
    proxy_listeners: frozenset = field(default=frozenset(), repr=False)
    proxy_owner: ProxyOwner | None = field(default=None, repr=False)
    require_device_bound: bool = False
    # The deployment's loopback human upstream (``human_host`` /
    # ``human_port``), set by ``app.deployment.Deployment.load``; the proxy
    # mapping must target it.
    upstream_host: str | None = field(default=None, repr=False)
    upstream_port: int | None = field(default=None, repr=False)

    def reservation_config(self):
        """The ``app.auth.reservation.ReservationConfig`` this section states.

        A zero-argument call for host-local tools (the listener-exception
        CLI) that need the reservation without building the composition.
        Imports the application modules only when called, so this module
        stays standard-library only. Raises ``HumanAccessRefused("setting")``
        when the upstream is unset or the values are refused.
        """
        if self.upstream_host is None or self.upstream_port is None:
            raise HumanAccessRefused("setting")
        from app.auth.composition import reservation_config
        try:
            return reservation_config(self, self.upstream_host, self.upstream_port)
        except ValueError:
            raise HumanAccessRefused("setting") from None


def _refuse() -> HumanAccessRefused:
    return HumanAccessRefused("setting")


def _address(value: object) -> Address:
    # A zone id ("%eth0") or an IPv4-mapped spelling never names a reserved
    # address the check compares; loopback and unspecified are no origin.
    if not isinstance(value, str) or "%" in value or not value.isascii():
        raise _refuse()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise _refuse() from None
    if (address.is_loopback or address.is_unspecified or address.is_multicast
            or (address.version == 6 and address.ipv4_mapped is not None)):
        raise _refuse()
    return address


def _addresses(value: object, *, allow_empty: bool) -> frozenset:
    if not isinstance(value, list) or len(value) > MAX_RESERVED_ADDRESSES:
        raise _refuse()
    if not value and not allow_empty:
        raise _refuse()
    addresses = [_address(item) for item in value]
    if len(set(addresses)) != len(addresses):
        raise _refuse()
    return frozenset(addresses)


def _proxy_owner(value: object) -> ProxyOwner:
    if not isinstance(value, dict) or set(value) != {"unit", "uid"}:
        raise _refuse()
    unit, uid = value["unit"], value["uid"]
    if (not isinstance(unit, str) or not _UNIT.fullmatch(unit)
            or type(uid) is not int or not 0 <= uid <= MAX_UID):
        raise _refuse()
    return ProxyOwner(unit, uid)


def _executable(value: object) -> Path:
    # Absolute, normalized and without ``..``; ``app.deployment`` checks the
    # file itself (administrator-owned, executable by the service account).
    if not isinstance(value, str) or not value or "\0" in value or not value.isascii():
        raise _refuse()
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value or value == "/":
        raise _refuse()
    return Path(value)


def parse_human_access(value: object) -> HumanAccessDeployment:
    """Validate the ``human_access`` deployment section, or raise ``HumanAccessRefused``.

    Shape (values are examples)::

        {"enabled": true,
         "hostname": "sentinel.example-tailnet.ts.net",
         "port": 443,
         "reserved_addresses": ["100.64.0.10", "fd7a:115c:a1e0::10"],
         "isolation": "dedicated_network_identity",
         "tailscale_executable": "/usr/bin/tailscale",
         "proxy_listeners": [],
         "proxy_owner": null,
         "require_device_bound": false}

    ``port`` defaults to 443. ``isolation`` is required and is one of
    ``ISOLATION_MODES`` or ``null`` (closed until the Owner states it).
    ``proxy_listeners`` are reserved addresses on which the proxy holds a
    visible TCP socket at ``port`` (empty when Serve intercepts without one);
    ``proxy_owner`` (``{"unit", "uid"}``) is required exactly when they are
    listed. ``require_device_bound`` defaults to false. Unknown keys refuse.
    """
    if not isinstance(value, dict):
        raise _refuse()
    keys = set(value)
    if not _REQUIRED <= keys or not keys <= _REQUIRED | _OPTIONAL:
        raise _refuse()
    enabled = value["enabled"]
    hostname = value["hostname"]
    port = value.get("port", 443)
    isolation = value["isolation"]
    device_bound = value.get("require_device_bound", False)
    if type(enabled) is not bool or type(device_bound) is not bool:
        raise _refuse()
    if not isinstance(hostname, str) or not _HOSTNAME.fullmatch(hostname):
        raise _refuse()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        # A relying-party id is a domain, never an IP literal (ADR-0004).
        raise _refuse()
    if type(port) is not int or not 1 <= port <= 65535:
        raise _refuse()
    if isolation is not None and isolation not in ISOLATION_MODES:
        raise _refuse()
    reserved = _addresses(value["reserved_addresses"], allow_empty=False)
    proxies = _addresses(value.get("proxy_listeners", []), allow_empty=True)
    if not proxies <= reserved:
        raise _refuse()
    owner_value = value.get("proxy_owner")
    if bool(proxies) != (owner_value is not None):
        # A proxy socket is verified by its creator; an owner without a
        # socket would verify nothing.
        raise _refuse()
    owner = _proxy_owner(owner_value) if owner_value is not None else None
    return HumanAccessDeployment(
        enabled=enabled, hostname=hostname, port=port, reserved_addresses=reserved,
        isolation=isolation, tailscale_executable=_executable(value["tailscale_executable"]),
        proxy_listeners=proxies, proxy_owner=owner, require_device_bound=device_bound,
    )
