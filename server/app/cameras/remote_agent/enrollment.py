"""Bootstrap enrollment listener and wire protocol (ADR-0006, Issue #13).

This is the Main side of the one-time capture-node enrollment exchange. It is a
separate, explicitly configured private listener: it is not the human
dashboard listener and not the strict client-certificate ingest listener
(``ingest_tls.py``). It carries only one bounded request/response per
connection, performs no HTTP routing, and cannot receive media or reach a
human/API route.

Protocol (version 1), after a TLS 1.3 handshake in which the Main presents its
deployment-CA-issued server certificate and both sides agree on the ALPN
protocol ``serversentinel-capture-enroll/1``:

* The Agent sends one frame: a 4-byte big-endian length followed by a JSON
  object with exactly ``version`` (1), ``deployment_id``, ``code`` (the 26
  character Base32 pairing code) and ``csr`` (PEM). The Agent only sends it
  after it has verified the Main with the Owner-transferred trust bundle.
* The Main answers with one frame: ``{"status": "issued", "certificate": PEM}``
  or the generic ``{"status": "refused"}``. The refusal never says why, so an
  unauthenticated peer learns nothing about deployments, nodes or approvals.

The Main looks up the approval by the CSR's proven public key among the
approvals created by *this process* (the ledger's process epoch makes approvals
from any other process unusable anyway), redeems it through
``PairingLedger.redeem`` (HMAC digest, constant-time comparison, single use,
five-minute monotonic lifetime), then activates the certificate that the
CA-account issuer signed for that approval before the code was shown
(Issue #109) and returns it. This process never holds the CA private key and
cannot sign: it has only the public ``DeploymentTrust``. A pre-signed
certificate admits nothing until this activation (``ingest_tls`` requires the
ledger's active record), so an unredeemed one is inert.

Resource limits are mandatory and explicit: request/response sizes, concurrent
connections, one absolute per-connection deadline (handshake, request and
response together, so a slow peer cannot hold a slot), attempts per source
address per minute, and a cap on refused requests after which the listener
closes. The listener closes as soon as its approvals are completed, expire or
hit the cap. Logs carry fixed reason words only: no code, CSR, certificate,
peer address or exception text.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hmac
import ipaddress
import json
import logging
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from typing import Callable
from uuid import UUID

from .addresses import is_tailscale_address, socket_address
from .node_ca import (
    MAX_CSR_BYTES, CaptureAuthorityError, DeploymentTrust,
    IssuedNodeCredential,
)
from .pairing import EnrollmentApproval, PairingError, PairingLedger


LOGGER = logging.getLogger("serversentinel.capture_enrollment")
ENROLLMENT_ALPN = "serversentinel-capture-enroll/1"
PROTOCOL_VERSION = 1
FRAME_HEADER = struct.Struct(">I")
# A CSR is at most 16 KiB; the other fields are short and fixed.
MAX_REQUEST_BYTES = MAX_CSR_BYTES + 4 * 1024
MAX_RESPONSE_BYTES = 32 * 1024
_CODE_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_REQUEST_KEYS = frozenset({"version", "deployment_id", "code", "csr"})
_MAX_TRACKED_SOURCES = 256
_RATE_WINDOW_SECONDS = 60.0
REFUSED = b'{"status":"refused"}'


class EnrollmentError(RuntimeError):
    """A fixed-reason enrollment failure; never contains peer or secret bytes."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class EnrollmentConfigurationError(EnrollmentError):
    pass


@dataclass(frozen=True)
class EnrollmentLimits:
    """Explicit resource limits required before the listener may open."""

    max_concurrent_connections: int = 4
    connection_deadline_seconds: float = 10.0
    max_attempts_per_source_per_minute: int = 6
    max_refused_requests: int = 16
    backlog: int = 8

    def __post_init__(self):
        bounded = (
            (self.max_concurrent_connections, 1, 16),
            (self.max_attempts_per_source_per_minute, 1, 60),
            (self.max_refused_requests, 1, 256),
            (self.backlog, 1, 64),
        )
        for value, low, high in bounded:
            if type(value) is not int or not low <= value <= high:
                raise EnrollmentConfigurationError("enrollment_limit_invalid")
        deadline = self.connection_deadline_seconds
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not 0 < deadline <= 60:
            raise EnrollmentConfigurationError("enrollment_limit_invalid")


@dataclass(frozen=True)
class EnrollmentListenerConfig:
    """Explicit private bind; no default address, port, wildcard, public or Tailscale address.

    ``reserved`` lists the socket addresses of the other listeners (human
    dashboard, capture ingest) so this listener can never share one of them.
    IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are compared in their IPv4
    form, because Linux treats both spellings as the same socket; the bind
    itself is classified in that form too. Tailscale addresses (IPv4
    ``100.64.0.0/10`` and the IPv6 ULA ``fd7a:115c:a1e0::/48``, Issue #150) are
    refused like public ones: enrollment is private-LAN only.
    """

    bind_host: str
    port: int
    reserved: tuple[tuple[str, int], ...] = ()

    def __post_init__(self):
        try:
            bind = ipaddress.ip_address(self.bind_host)
        except (TypeError, ValueError):
            raise EnrollmentConfigurationError("enrollment_bind_requires_ip_literal") from None
        if bind.is_unspecified or bind.is_multicast:
            raise EnrollmentConfigurationError("enrollment_bind_wildcard_refused")
        identity = socket_address(bind)
        if not identity.is_private or identity.is_global or is_tailscale_address(identity):
            raise EnrollmentConfigurationError("enrollment_bind_requires_private_address")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise EnrollmentConfigurationError("enrollment_port_invalid")
        if not isinstance(self.reserved, tuple):
            raise EnrollmentConfigurationError("enrollment_reserved_listeners_invalid")
        for entry in self.reserved:
            try:
                host, port = entry
                other = ipaddress.ip_address(host)
            except (TypeError, ValueError):
                raise EnrollmentConfigurationError("enrollment_reserved_listeners_invalid") from None
            if type(port) is not int or not 1 <= port <= 65535:
                raise EnrollmentConfigurationError("enrollment_reserved_listeners_invalid")
            if port == self.port and (socket_address(other) == identity
                                      or other.is_unspecified):
                raise EnrollmentConfigurationError("enrollment_listener_must_differ_from_other_listeners")


def build_enrollment_server_context(certificate_path: Path, key_path: Path) -> ssl.SSLContext:
    """TLS 1.3 server context with the Main certificate and the enrollment ALPN.

    No client certificate is requested (the Agent has none yet); the Agent
    authenticates the Main. Built explicitly, so no system trust store or
    key-log file from the environment is involved, and session tickets are off.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_TICKET
    context.num_tickets = 0
    try:
        context.set_alpn_protocols([ENROLLMENT_ALPN])
        context.load_cert_chain(certfile=str(certificate_path), keyfile=str(key_path))
    except (ssl.SSLError, OSError, ValueError):
        raise EnrollmentConfigurationError("enrollment_tls_material_invalid") from None
    return context


def _valid_code(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 26
            and all(character in _CODE_ALPHABET for character in value))


@dataclass(frozen=True)
class PresignedEnrollment:
    """One Owner approval and the certificate the CA-account issuer signed for it.

    The certificate was verified against the public CA (fixed clientAuth
    profile, approved node and key) before the pairing code was shown.
    """

    approval: EnrollmentApproval
    credential: IssuedNodeCredential


class EnrollmentService:
    """Validates one request and, for a matching approval, activates exactly once.

    ``enrollments`` are the approvals created by this process, each with its
    pre-signed certificate. Every refusal is reported as the same generic
    response. Nothing here can sign: ``trust`` is public CA material only.
    """

    def __init__(self, ledger: PairingLedger, trust: DeploymentTrust,
                 enrollments: tuple[PresignedEnrollment, ...]):
        # Exactly the public trust: the signing subclass (which holds the CA
        # key) is refused, so this network-facing service can never sign.
        if (not isinstance(ledger, PairingLedger) or type(trust) is not DeploymentTrust
                or not isinstance(enrollments, tuple) or not enrollments
                or not all(isinstance(entry, PresignedEnrollment)
                           and isinstance(entry.approval, EnrollmentApproval)
                           and isinstance(entry.credential, IssuedNodeCredential)
                           and entry.credential.node_id == entry.approval.node_id
                           and hmac.compare_digest(entry.credential.public_key_digest,
                                                   entry.approval.public_key_digest)
                           for entry in enrollments)):
            raise EnrollmentConfigurationError("enrollment_service_dependency_invalid")
        self._ledger = ledger
        self._trust = trust
        self._enrollments = enrollments
        self._approvals = tuple(entry.approval for entry in enrollments)
        self._completed: set[UUID] = set()
        self._lock = threading.Lock()

    @property
    def outstanding(self) -> int:
        with self._lock:
            return len(self._approvals) - len(self._completed)

    def issued_nodes(self) -> tuple[UUID, ...]:
        with self._lock:
            return tuple(approval.node_id for approval in self._approvals
                         if approval.enrollment_id in self._completed)

    def _enrollment_for(self, key_digest: str) -> PresignedEnrollment | None:
        match = None
        for entry in self._enrollments:
            # Compare every entry so timing does not depend on the position.
            if hmac.compare_digest(entry.approval.public_key_digest, key_digest):
                match = entry
        return match

    def handle(self, body: bytes) -> tuple[bytes, IssuedNodeCredential | None]:
        """Return the response frame body and the issued credential, if any."""
        try:
            request = json.loads(body.decode("ascii"))
            if (not isinstance(request, dict) or set(request) != _REQUEST_KEYS
                    or request["version"] != PROTOCOL_VERSION
                    or type(request["version"]) is not int
                    or not isinstance(request["deployment_id"], str)
                    or not isinstance(request["csr"], str)
                    or not _valid_code(request["code"])):
                raise EnrollmentError("request_malformed")
            deployment = UUID(request["deployment_id"])
            if deployment != self._trust.deployment_id:
                raise EnrollmentError("deployment_mismatch")
            csr = request["csr"].encode("ascii")
            # Proof of possession of the approved key; the CSR is used for
            # nothing else (the certificate was signed before the code).
            key_digest = DeploymentTrust.enrollment_key_digest(csr)
            entry = self._enrollment_for(key_digest)
            if entry is None:
                raise EnrollmentError("approval_unavailable")
            approval, issued = entry.approval, entry.credential
            # Serialize redemption and activation: the ledger already
            # guarantees single use, this also keeps one activation per approval.
            with self._lock:
                claim = self._ledger.redeem(enrollment_id=approval.enrollment_id,
                                            public_key_digest=key_digest,
                                            code=request["code"])
                if not hmac.compare_digest(claim.public_key_digest, issued.public_key_digest):
                    raise EnrollmentError("approval_unavailable")
                self._ledger.activate(claim, credential_serial_digest=issued.credential_digest,
                                      not_after=issued.not_after.timestamp())
                self._completed.add(approval.enrollment_id)
        except EnrollmentError as error:
            LOGGER.info("capture enrollment refused: reason=%s", error.reason)
            return REFUSED, None
        except (PairingError, CaptureAuthorityError):
            LOGGER.info("capture enrollment refused: reason=approval_unavailable")
            return REFUSED, None
        except (ValueError, TypeError, UnicodeError, RecursionError):
            LOGGER.info("capture enrollment refused: reason=request_malformed")
            return REFUSED, None
        except Exception:
            LOGGER.info("capture enrollment refused: reason=internal_failure")
            return REFUSED, None
        response = json.dumps({"status": "issued",
                               "certificate": issued.certificate_pem.decode("ascii")},
                              sort_keys=True, separators=(",", ":")).encode("ascii")
        LOGGER.info("capture enrollment completed")
        return response, issued


@dataclass(frozen=True)
class EnrollmentOutcome:
    """Why the listener closed: ``completed``, ``expired``, ``attempt_limit`` or ``stopped``."""

    reason: str
    issued_nodes: tuple[UUID, ...]


def _recv_exact(connection, size: int, deadline: float, clock: Callable[[], float]) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        left = deadline - clock()
        if left <= 0:
            raise EnrollmentError("connection_deadline")
        connection.settimeout(left)
        try:
            chunk = connection.recv(min(remaining, 4096))
        except (socket.timeout, TimeoutError):
            raise EnrollmentError("connection_deadline") from None
        if not chunk:
            raise EnrollmentError("connection_closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_frame(connection, body: bytes, deadline: float, clock: Callable[[], float]) -> None:
    left = deadline - clock()
    if left <= 0 or len(body) > MAX_RESPONSE_BYTES:
        raise EnrollmentError("connection_deadline")
    connection.settimeout(left)
    connection.sendall(FRAME_HEADER.pack(len(body)) + body)


def _close(connection) -> None:
    try:
        connection.close()
    except OSError:
        pass


class EnrollmentListener:
    """Bounded bootstrap listener; bind with ``open()`` then run ``serve()``."""

    def __init__(self, config: EnrollmentListenerConfig, context: ssl.SSLContext, *,
                 limits: EnrollmentLimits, clock: Callable[[], float] = time.monotonic):
        if (not isinstance(config, EnrollmentListenerConfig)
                or not isinstance(context, ssl.SSLContext)
                or context.minimum_version < ssl.TLSVersion.TLSv1_3
                or not isinstance(limits, EnrollmentLimits) or not callable(clock)):
            raise EnrollmentConfigurationError("enrollment_listener_dependency_invalid")
        self._config = config
        self._context = context
        self._service: EnrollmentService | None = None
        self._limits = limits
        self._clock = clock
        self._socket: socket.socket | None = None
        self._slots = threading.BoundedSemaphore(limits.max_concurrent_connections)
        self._sources: dict[str, deque] = {}
        self._refused = 0
        self._state = threading.Lock()
        self._workers: list[threading.Thread] = []

    @property
    def address(self) -> tuple[str, int]:
        if self._socket is None:
            raise EnrollmentConfigurationError("enrollment_listener_not_open")
        return self._socket.getsockname()[:2]

    def open(self) -> None:
        family = (socket.AF_INET6 if ipaddress.ip_address(self._config.bind_host).version == 6
                  else socket.AF_INET)
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            # SO_REUSEADDR lets a re-run of ``approve`` bind while the previous
            # run's connections sit in TIME_WAIT (Issue #125). On Linux it never
            # lets a second socket bind a port that is already listening, so it
            # does not enable port hijacking; SO_REUSEPORT, which would, is
            # deliberately not set.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self._config.bind_host, self._config.port))
            listener.listen(self._limits.backlog)
        except OSError:
            listener.close()
            raise EnrollmentConfigurationError("enrollment_listener_bind_failed") from None
        self._socket = listener

    def close(self) -> None:
        if self._socket is not None:
            _close(self._socket)
            self._socket = None

    def _admit_source(self, host: str, now: float) -> bool:
        window = self._sources.get(host)
        if window is None:
            if len(self._sources) >= _MAX_TRACKED_SOURCES:
                for key in [key for key, value in self._sources.items()
                            if not value or now - value[-1] >= _RATE_WINDOW_SECONDS]:
                    del self._sources[key]
                if len(self._sources) >= _MAX_TRACKED_SOURCES:
                    return False
            window = self._sources[host] = deque()
        while window and now - window[0] >= _RATE_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= self._limits.max_attempts_per_source_per_minute:
            return False
        window.append(now)
        return True

    def _refusal(self) -> None:
        with self._state:
            self._refused += 1

    def _handle(self, raw: socket.socket) -> None:
        deadline = self._clock() + self._limits.connection_deadline_seconds
        connection = raw
        try:
            raw.settimeout(max(deadline - self._clock(), 0.001))
            try:
                connection = self._context.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                raise EnrollmentError("tls_handshake_failed") from None
            if (connection.version() != "TLSv1.3"
                    or connection.selected_alpn_protocol() != ENROLLMENT_ALPN):
                raise EnrollmentError("protocol_refused")
            (length,) = FRAME_HEADER.unpack(_recv_exact(connection, FRAME_HEADER.size,
                                                        deadline, self._clock))
            if not 0 < length <= MAX_REQUEST_BYTES:
                self._refusal()
                _send_frame(connection, REFUSED, deadline, self._clock)
                raise EnrollmentError("request_size_refused")
            body = _recv_exact(connection, length, deadline, self._clock)
            response, issued = self._service.handle(body)
            if issued is None:
                self._refusal()
            _send_frame(connection, response, deadline, self._clock)
        except EnrollmentError as error:
            LOGGER.info("capture enrollment connection closed: reason=%s", error.reason)
        except (ssl.SSLError, OSError):
            LOGGER.info("capture enrollment connection closed: reason=connection_failed")
        except Exception:
            LOGGER.info("capture enrollment connection closed: reason=internal_failure")
        finally:
            _close(connection)
            self._slots.release()

    def serve(self, service: EnrollmentService, *, expires_at_monotonic: float,
              stop: threading.Event | None = None) -> EnrollmentOutcome:
        """Accept until all approvals complete, expire, hit the cap, or ``stop``.

        The socket is bound by ``open()`` before the Owner approves, so a bind
        failure never leaves an approval without a listener.
        """
        if self._socket is None or not isinstance(service, EnrollmentService):
            raise EnrollmentConfigurationError("enrollment_listener_not_open")
        if (isinstance(expires_at_monotonic, bool)
                or not isinstance(expires_at_monotonic, (int, float))):
            raise EnrollmentConfigurationError("enrollment_listener_expiry_invalid")
        self._service = service
        listener = self._socket
        listener.settimeout(0.2)
        reason = "stopped"
        try:
            while True:
                now = self._clock()
                if self._service.outstanding == 0:
                    reason = "completed"
                    break
                if now >= expires_at_monotonic:
                    reason = "expired"
                    break
                with self._state:
                    if self._refused >= self._limits.max_refused_requests:
                        reason = "attempt_limit"
                        break
                if stop is not None and stop.is_set():
                    break
                try:
                    raw, peer = listener.accept()
                except (socket.timeout, TimeoutError):
                    continue
                except OSError:
                    reason = "stopped"
                    break
                if not self._admit_source(peer[0], now):
                    LOGGER.info("capture enrollment connection closed: reason=source_rate_limited")
                    _close(raw)
                    continue
                if not self._slots.acquire(blocking=False):
                    LOGGER.info("capture enrollment connection closed: reason=connection_limit")
                    _close(raw)
                    continue
                worker = threading.Thread(target=self._handle, args=(raw,), daemon=True,
                                          name="capture-enrollment")
                self._workers = [thread for thread in self._workers if thread.is_alive()]
                self._workers.append(worker)
                worker.start()
        finally:
            self.close()
            for worker in self._workers:
                worker.join(self._limits.connection_deadline_seconds + 1)
        if self._service.outstanding == 0:
            reason = "completed"
        LOGGER.info("capture enrollment listener closed: reason=%s", reason)
        return EnrollmentOutcome(reason=reason, issued_nodes=self._service.issued_nodes())
