"""The optional ``capture_ingest`` deployment section (Issue #14).

Standard library only at import time: the installer validates deployment
configurations with a standard-library zipapp (``build_installer.py``). The
TLS material is loaded by ``load_capture_ingest_material``, which imports the
``cryptography``-based modules only when it runs.

Absent, no capture ingest listener exists. Present, it names the listener's
explicit private bind (``IngestListenerConfig``: no wildcard, no Tailscale
address, never the human listener's socket address) and the Main listener
directory that ``serversentinel-pairing init`` prepared (the Main ingest key
and certificate and the public CA copy, all owned by the service account;
never the capture-node CA directory)::

    "capture_ingest": {"bind_host": "<private IP>", "port": <port>,
                       "listener_directory": "<absolute path>",
                       "maximum_connections": <optional, 1-256>}

A section whose material cannot be loaded does not stop the service
(recording and the integrity and recording-health checks keep running); the
listener stays closed and the value-free reason is reported, like a human
access composition the launcher cannot build (Issue #283 item 1).
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
from pathlib import Path
from uuid import UUID

from app.settings import ConfigurationError

from .addresses import is_tailscale_address


DEFAULT_HANDSHAKE_TIMEOUT_SECONDS = 10.0
_REQUIRED = frozenset({"bind_host", "port", "listener_directory"})
_OPTIONAL = frozenset({"maximum_connections"})


class IngestTlsError(RuntimeError):
    """A fixed-reason refusal; it never contains peer, key or certificate bytes."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class IngestConfigurationError(IngestTlsError):
    pass


@dataclass(frozen=True)
class IngestListenerConfig:
    """Explicit ingest bind; there is no default address, port or wildcard.

    ``human_host``/``human_port`` are the dashboard listener's values so the
    two listeners can never share a socket address. Ingest is private-LAN only
    and needs no Tailscale, so a Tailscale address (IPv4 ``100.64.0.0/10``,
    IPv6 ``fd7a:115c:a1e0::/48``, or the IPv4-mapped spelling) is refused
    (Issue #150).
    """

    bind_host: str
    port: int
    human_host: str
    human_port: int
    handshake_timeout_seconds: float = DEFAULT_HANDSHAKE_TIMEOUT_SECONDS
    backlog: int = 8

    def __post_init__(self):
        try:
            bind = ipaddress.ip_address(self.bind_host)
            human = ipaddress.ip_address(self.human_host)
        except (TypeError, ValueError):
            raise IngestConfigurationError("ingest_bind_requires_ip_literal") from None
        if bind.is_unspecified or bind.is_multicast:
            raise IngestConfigurationError("ingest_bind_wildcard_refused")
        if is_tailscale_address(bind):
            raise IngestConfigurationError("ingest_bind_tailscale_address_refused")
        for port in (self.port, self.human_port):
            if type(port) is not int or not 1 <= port <= 65535:
                raise IngestConfigurationError("ingest_port_invalid")
        if self.port == self.human_port and (bind == human or human.is_unspecified):
            raise IngestConfigurationError("ingest_listener_must_differ_from_human_listener")
        if (not isinstance(self.handshake_timeout_seconds, (int, float))
                or not 0 < self.handshake_timeout_seconds <= 60):
            raise IngestConfigurationError("ingest_handshake_timeout_invalid")
        if type(self.backlog) is not int or not 1 <= self.backlog <= 128:
            raise IngestConfigurationError("ingest_backlog_invalid")


@dataclass(frozen=True)
class CaptureIngestLimits:
    """Bounds of the ingest listener (``ingest_server``); every value is positive."""

    maximum_connections: int = 16
    maximum_handshakes_per_address: int = 2
    maximum_frame_bytes: int = 16 * 1024
    # The heartbeat contract (Issue #14): at least three of the Agent's
    # longest heartbeat intervals (`MAXIMUM_HEARTBEAT_SECONDS`, 5 s) plus
    # 15 s for a slow tick; `tests.test_capture_ingest_contract` checks it.
    idle_timeout_seconds: float = 30.0
    frames_per_second: int = 10
    maximum_nodes: int = 64

    def __post_init__(self):
        for name in ("maximum_connections", "maximum_handshakes_per_address",
                     "maximum_frame_bytes", "frames_per_second", "maximum_nodes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError("invalid capture ingest limit")
        if not 1 <= self.maximum_connections <= 256 or self.maximum_frame_bytes > 1024 * 1024:
            raise ValueError("invalid capture ingest limit")
        if (type(self.idle_timeout_seconds) not in (int, float)
                or not math.isfinite(self.idle_timeout_seconds)
                or not 1 <= self.idle_timeout_seconds <= 300):
            raise ValueError("invalid capture ingest limit")


class CaptureIngestUnavailable(Exception):
    """The configured listener cannot be built; ``reason`` is one fixed word."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CaptureIngestDeployment:
    listener: IngestListenerConfig
    listener_directory: Path
    limits: CaptureIngestLimits

    def __repr__(self) -> str:
        return "CaptureIngestDeployment(<redacted>)"


@dataclass(frozen=True)
class CaptureIngestMaterial:
    """What ``create_app`` needs to open the listener; holds no private key bytes.

    ``context`` is the ``ssl.SSLContext`` from ``build_ingest_server_context``.
    """

    listener: IngestListenerConfig
    limits: CaptureIngestLimits
    context: object
    deployment_id: UUID

    def __repr__(self) -> str:
        return "CaptureIngestMaterial(<redacted>)"


def parse_capture_ingest(value: object, *, human_host: str, human_port: int,
                         forbidden_roots: tuple[Path, ...] = ()) -> CaptureIngestDeployment:
    if (not isinstance(value, dict) or not _REQUIRED <= set(value)
            or not set(value) <= _REQUIRED | _OPTIONAL):
        raise ConfigurationError("invalid capture ingest configuration")
    try:
        listener = IngestListenerConfig(bind_host=value["bind_host"], port=value["port"],
                                        human_host=human_host, human_port=human_port)
    except IngestConfigurationError as refused:
        # One fixed word (no address or port value).
        raise ConfigurationError(f"capture ingest refused: {refused.reason}") from None
    if listener.port < 1024:
        # The service account holds no capability, so a privileged port could
        # never be bound and would only be retried forever.
        raise ConfigurationError("capture ingest refused: ingest_port_privileged")
    directory = value["listener_directory"]
    if not isinstance(directory, str) or not directory or "\x00" in directory:
        raise ConfigurationError("invalid capture ingest listener directory")
    path = Path(directory)
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigurationError("capture ingest listener directory must be absolute")
    if any(path == root or path.is_relative_to(root) or root.is_relative_to(path)
           for root in forbidden_roots):
        raise ConfigurationError(
            "capture ingest listener directory must be outside runtime data, code and the CA")
    options = {}
    if "maximum_connections" in value:
        options["maximum_connections"] = value["maximum_connections"]
    try:
        limits = CaptureIngestLimits(**options)
    except (TypeError, ValueError):
        raise ConfigurationError("invalid capture ingest limit") from None
    return CaptureIngestDeployment(listener, path, limits)


def load_capture_ingest_material(section: CaptureIngestDeployment) -> CaptureIngestMaterial:
    """Load and check the listener material; refuse with one fixed word.

    Run as the service account: the listener directory must be its private
    directory (``PrivateDirectory``), the key must match the certificate
    (``listener_material``), and the certificate must be the deployment CA's
    leaf (``verify_listener_certificate``). Files are loaded from verified
    ``O_NOFOLLOW`` descriptors, as the pairing CLI does (review B1 of #109).
    An interrupted ``rotate-listener`` is not completed here (the service
    never renames listener files); it is refused until the Owner reruns it.
    """
    from .ingest_tls import build_ingest_server_context
    from .node_ca import (
        CaptureAuthorityError, DeploymentTrust, ListenerAuthorityMismatch, PrivateDirectory,
        listener_material,
    )
    try:
        directory = PrivateDirectory(section.listener_directory)
        if not directory.exists("main-server-key.pem"):
            raise CaptureIngestUnavailable("listener_credential_incomplete")
        listener_material(directory)
        trust = DeploymentTrust.load_public(directory)
        trust.verify_listener_certificate(directory)
        with directory.open_private("main-server-certificate.pem") as certificate, \
                directory.open_private("main-server-key.pem") as key:
            context = build_ingest_server_context(trust.ca_certificate_pem(),
                                                  Path(f"/proc/self/fd/{certificate}"),
                                                  Path(f"/proc/self/fd/{key}"))
    except CaptureIngestUnavailable:
        raise
    except ListenerAuthorityMismatch:
        raise CaptureIngestUnavailable("listener_authority_mismatch") from None
    except (CaptureAuthorityError, IngestConfigurationError, OSError, ValueError):
        raise CaptureIngestUnavailable("listener_material_unavailable") from None
    return CaptureIngestMaterial(section.listener, section.limits, context,
                                 trust.deployment_id)
