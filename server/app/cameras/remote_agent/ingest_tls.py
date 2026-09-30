"""mTLS adapter for the dedicated capture-ingest listener (ADR-0006, Issue #13).

This adapter is deliberately separate from the human dashboard listener and
from ``ingest.py``: it only turns an accepted TCP connection into an
``AuthenticatedCaptureSession`` whose identity is a capture node, never a human
principal. It performs no HTTP routing and cannot reach dashboard routes. The
transport-neutral ingest core (Issue #14/#15) can consume the session's
``identity`` and ``still_admitted()`` result without importing ``ssl``.

Nothing here is started by the application: the ingest listener stays
disabled until a deployment explicitly configures a non-wildcard bind address
and port that differ from the human listener.

Admission requires all of:

* a TLS 1.3 handshake with a client certificate chaining only to the
  deployment CA (validity is enforced by OpenSSL during the handshake, and
  expiry again by the server clock on every admission check, because OpenSSL
  does not re-check a certificate on an already-open connection);
* a capture-only leaf (CA=false, clientAuth EKU, exactly one node URI and the
  expected deployment URI);
* the pairing ledger's *current* active record for that node, public key and
  exact certificate digest. Revocation therefore takes effect on the next
  admission or ``still_admitted()`` check even though the certificate itself
  is still cryptographically valid. Ledger failures deny.

TLS session tickets are disabled so a resumed session cannot skip admission,
and admission is repeated on every connection regardless.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime
import hashlib
import ipaddress
import logging
import socket
import ssl
from pathlib import Path
from typing import Callable
from uuid import UUID

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from .node_ca import (
    DEPLOYMENT_URI_PREFIX, NODE_URI_PREFIX, deployment_uri, public_key_digest,
)
from .pairing import PairingError, PairingLedger


LOGGER = logging.getLogger("serversentinel.capture_ingest.tls")
MAX_PEER_CERTIFICATE_BYTES = 16 * 1024
DEFAULT_HANDSHAKE_TIMEOUT_SECONDS = 10.0


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


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
    two listeners can never share a socket address.
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


def build_ingest_server_context(ca_certificate_pem: bytes, certificate_path: Path,
                                key_path: Path) -> ssl.SSLContext:
    """Server context: TLS 1.3 only, client certificate required, deployment CA only.

    Built explicitly rather than with ``ssl.create_default_context`` so no system
    trust store is loaded and no key-log file can be enabled from the environment.
    """
    if not isinstance(ca_certificate_pem, bytes) or not ca_certificate_pem:
        raise IngestConfigurationError("ingest_trust_anchor_missing")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.options |= ssl.OP_NO_TICKET
    context.num_tickets = 0
    try:
        context.load_verify_locations(cadata=ca_certificate_pem.decode("ascii"))
        context.load_cert_chain(certfile=str(certificate_path), keyfile=str(key_path))
    except (ssl.SSLError, OSError, UnicodeError, ValueError):
        raise IngestConfigurationError("ingest_tls_material_invalid") from None
    return context


@dataclass(frozen=True)
class CaptureNodeIdentity:
    """A capture node's protocol identity. It carries no human role or permission."""

    node_id: UUID
    public_key_digest: str
    credential_digest: str
    not_valid_after: datetime.datetime

    def __repr__(self) -> str:
        return "CaptureNodeIdentity(<redacted>)"


class CaptureNodeAdmission:
    """Maps a verified peer certificate to the ledger's current node authorization."""

    def __init__(self, ledger: PairingLedger, deployment_id: UUID, *,
                 clock: Callable[[], datetime.datetime] = _utc_now):
        if (not isinstance(ledger, PairingLedger) or not isinstance(deployment_id, UUID)
                or not callable(clock)):
            raise IngestConfigurationError("ingest_admission_dependency_invalid")
        self._ledger = ledger
        self._deployment = deployment_uri(deployment_id)
        self._clock = clock

    def identify(self, peer_der: bytes) -> CaptureNodeIdentity:
        if not isinstance(peer_der, bytes) or not 0 < len(peer_der) <= MAX_PEER_CERTIFICATE_BYTES:
            raise IngestTlsError("capture_node_certificate_invalid")
        try:
            certificate = x509.load_der_x509_certificate(peer_der)
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            uris = names.get_values_for_type(x509.UniformResourceIdentifier)
            nodes = [uri for uri in uris if uri.startswith(NODE_URI_PREFIX)]
            deployments = [uri for uri in uris if uri.startswith(DEPLOYMENT_URI_PREFIX)]
            if (constraints.ca or ExtendedKeyUsageOID.CLIENT_AUTH not in usages
                    or ExtendedKeyUsageOID.SERVER_AUTH in usages
                    or len(nodes) != 1 or deployments != [self._deployment]
                    or len(uris) != 2 or names.get_values_for_type(x509.DNSName)):
                raise ValueError
            node = UUID(nodes[0][len(NODE_URI_PREFIX):])
            if str(node) != nodes[0][len(NODE_URI_PREFIX):]:
                raise ValueError
            key_digest = public_key_digest(certificate.public_key())
            expiry = certificate.not_valid_after_utc
        except (ValueError, TypeError, x509.ExtensionNotFound):
            raise IngestTlsError("capture_node_certificate_invalid") from None
        return CaptureNodeIdentity(node_id=node, public_key_digest=key_digest,
                                   credential_digest=hashlib.sha256(peer_der).hexdigest(),
                                   not_valid_after=expiry)

    def is_admitted(self, identity: CaptureNodeIdentity) -> bool:
        """Check expiry and consult the durable ledger now; any failure denies."""
        if not isinstance(identity, CaptureNodeIdentity):
            return False
        try:
            if not identity.not_valid_after > self._clock():
                return False
            return self._ledger.admits(node_id=identity.node_id,
                                       public_key_digest=identity.public_key_digest,
                                       credential_serial_digest=identity.credential_digest)
        except (PairingError, ValueError, TypeError):
            return False

    def authorize(self, peer_der: bytes) -> CaptureNodeIdentity:
        identity = self.identify(peer_der)
        if not self.is_admitted(identity):
            raise IngestTlsError("capture_node_not_admitted")
        return identity


class AuthenticatedCaptureSession:
    """An admitted TLS connection. Re-check ``still_admitted`` before committing work."""

    def __init__(self, connection: ssl.SSLSocket, identity: CaptureNodeIdentity,
                 admission: CaptureNodeAdmission):
        self.connection = connection
        self.identity = identity
        self._admission = admission

    def __repr__(self) -> str:
        return "AuthenticatedCaptureSession(<redacted>)"

    def still_admitted(self) -> bool:
        if self._admission.is_admitted(self.identity):
            return True
        self.close()
        return False

    def close(self) -> None:
        try:
            self.connection.close()
        except OSError:
            pass


class CaptureIngestAcceptor:
    """Performs the server-side handshake and ledger admission for one connection."""

    def __init__(self, context: ssl.SSLContext, admission: CaptureNodeAdmission, *,
                 handshake_timeout_seconds: float = DEFAULT_HANDSHAKE_TIMEOUT_SECONDS):
        if (not isinstance(context, ssl.SSLContext) or context.verify_mode != ssl.CERT_REQUIRED
                or context.minimum_version < ssl.TLSVersion.TLSv1_3
                or not isinstance(admission, CaptureNodeAdmission)):
            raise IngestConfigurationError("ingest_acceptor_requires_mutual_tls13")
        if (not isinstance(handshake_timeout_seconds, (int, float))
                or not 0 < handshake_timeout_seconds <= 60):
            raise IngestConfigurationError("ingest_handshake_timeout_invalid")
        self._context = context
        self._admission = admission
        self._timeout = float(handshake_timeout_seconds)

    def accept(self, connection: socket.socket) -> AuthenticatedCaptureSession:
        connection.settimeout(self._timeout)
        try:
            tls = self._context.wrap_socket(connection, server_side=True)
        except (ssl.SSLError, OSError):
            _close(connection)
            LOGGER.info("capture ingest refused: reason=tls_handshake_failed")
            raise IngestTlsError("tls_handshake_failed") from None
        try:
            if tls.version() != "TLSv1.3":
                raise IngestTlsError("tls_version_refused")
            peer = tls.getpeercert(binary_form=True)
            if not peer:
                raise IngestTlsError("capture_node_certificate_missing")
            identity = self._admission.authorize(peer)
            # The timeout bounds only the handshake and admission. An admitted
            # session may legitimately pause (camera offline, backpressure);
            # session liveness is the ingest protocol's concern, not this bound.
            tls.settimeout(None)
        except IngestTlsError as error:
            _close(tls)
            LOGGER.info("capture ingest refused: reason=%s", error.reason)
            raise
        except (ssl.SSLError, OSError):
            _close(tls)
            LOGGER.info("capture ingest refused: reason=tls_session_failed")
            raise IngestTlsError("tls_session_failed") from None
        return AuthenticatedCaptureSession(tls, identity, self._admission)


def open_ingest_listener(config: IngestListenerConfig) -> socket.socket:
    """Bind the explicitly configured ingest socket; the caller owns its lifetime."""
    if not isinstance(config, IngestListenerConfig):
        raise IngestConfigurationError("ingest_listener_config_invalid")
    family = socket.AF_INET6 if ipaddress.ip_address(config.bind_host).version == 6 else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.bind((config.bind_host, config.port))
        listener.listen(config.backlog)
    except OSError:
        listener.close()
        raise IngestConfigurationError("ingest_listener_bind_failed") from None
    return listener


def _close(connection) -> None:
    try:
        connection.close()
    except OSError:
        pass
