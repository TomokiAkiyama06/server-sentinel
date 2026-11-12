"""Stdlib-only connection to the Main: pinned TLS 1.3 client and installed credential paths.

Split out of ``node_tls`` (Issue #14) so the long-running service, whose
runtime and CLI stay stdlib-only, can open its ingest session without
importing ``cryptography``; ``node_tls`` re-exports every name here, so the
pairing CLI and existing callers are unchanged. Nothing here parses or signs
certificates: ``ssl`` loads the installed chain by path, and the trust anchor
is the deployment CA copy committed with the credential.

* Trust is pinned to the deployment CA: no system trust store, TLS 1.3 only,
  hostname verification against the bundle's server name, and no key-log file
  (``ssl.create_default_context`` is deliberately not used because it honours
  ``SSLKEYLOGFILE``).
* A Main endpoint in a Tailscale range is refused (Issue #150): enrollment and
  ingest are private-LAN only.

Errors use fixed ``PairingRefused`` reasons and never include key, certificate
or endpoint bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
from uuid import UUID

from .addresses import is_tailscale_host
from .addresses import valid_endpoint_host as _valid_endpoint_host
from .addresses import valid_server_name as _valid_server_name
from .pairing import NodeCredentialStore, PairingRefused
from .storage import StorageRefused, open_directory


MAX_TRUST_BUNDLE_BYTES = 32 * 1024
# Fixed refusal for a Main endpoint (literal, override or connected peer) in a
# Tailscale range: enrollment and ingest are private-LAN only (Issue #150).
TAILSCALE_ENDPOINT_REFUSED = "main_endpoint_tailscale_address_refused"


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class InstalledCredential:
    """Validated paths of the committed credential generation (no key bytes)."""

    deployment_id: UUID
    node_id: UUID
    server_name: str
    ca_certificate_pem: bytes = field(repr=False)
    certificate_path: Path
    key_path: Path


def installed_credential(store: NodeCredentialStore) -> InstalledCredential:
    """Return the committed generation after the store's full integrity check.

    ``ssl`` loads certificate chains by path only; the files are write-once,
    0600 and inside a validated 0700 directory owned by the service account.
    """
    if not isinstance(store, NodeCredentialStore) or not store.installed():
        raise PairingRefused("node_identity_unavailable")
    root_fd = directory_fd = None
    try:
        root_fd = open_directory(store.runtime_root)
        directory_fd = os.open("node-credentials",
                               os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=root_fd)
        store._validate_directory(directory_fd, "credential_directory_rejected")
        manifest = json.loads(store._read_file(directory_fd, "current.json", maximum=16 * 1024,
                                               expected_links=2).decode("utf-8"))
        files = manifest["files"]
        ca_pem = store._read_file(directory_fd, files["ca_certificate"]["name"],
                                  maximum=MAX_TRUST_BUNDLE_BYTES)
        base = store.runtime_root / "node-credentials"
        return InstalledCredential(
            deployment_id=UUID(manifest["deployment_id"]), node_id=UUID(manifest["node_id"]),
            server_name=manifest["server_name"], ca_certificate_pem=ca_pem,
            certificate_path=base / files["client_certificate"]["name"],
            key_path=base / files["private_key"]["name"])
    except PairingRefused:
        raise
    except (OSError, StorageRefused, ValueError, KeyError, TypeError, UnicodeError):
        raise PairingRefused("node_identity_unavailable") from None
    finally:
        for descriptor in (directory_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)


def build_capture_client_context(ca_certificate_pem: bytes, *,
                                 certificate_path: Path | None = None,
                                 key_path: Path | None = None) -> ssl.SSLContext:
    """TLS 1.3 client pinned to the deployment CA; client cert optional for bootstrap."""
    if not isinstance(ca_certificate_pem, bytes) or not ca_certificate_pem:
        raise PairingRefused("trust_anchor_missing")
    if (certificate_path is None) != (key_path is None):
        raise PairingRefused("client_credential_incomplete")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    try:
        context.load_verify_locations(cadata=ca_certificate_pem.decode("ascii"))
        if certificate_path is not None:
            context.load_cert_chain(certfile=str(certificate_path), keyfile=str(key_path))
    except (ssl.SSLError, OSError, UnicodeError, ValueError):
        raise PairingRefused("client_tls_material_rejected") from None
    return context


def connect_to_main(context: ssl.SSLContext, *, server_name: str, host: str, port: int,
                    timeout_seconds: float = 10.0) -> ssl.SSLSocket:
    """Open an outbound TLS 1.3 connection that verifies ``server_name``.

    ``server_name`` comes from the trust bundle or the installed credential, never
    from the network. Verification failures and downgrades raise
    ``PairingRefused`` before any application byte is sent. ``timeout_seconds``
    bounds only the TCP connect and TLS handshake; the returned socket is
    blocking with no timeout, like the Main acceptor's admitted session, so a
    long backpressure or response wait does not tear the session down. Any
    session-level timeout belongs to the protocol layer above.

    A Main endpoint in a Tailscale range (IPv4 ``100.64.0.0/10``, IPv6
    ``fd7a:115c:a1e0::/48``) is refused with ``main_endpoint_tailscale_address_refused``:
    an IP literal before connecting, and a DNS name by its connected peer
    address before the TLS handshake (Issue #150).
    """
    if not isinstance(context, ssl.SSLContext) or not context.check_hostname:
        raise PairingRefused("client_tls_context_rejected")
    if (not _valid_server_name(server_name) or not _valid_endpoint_host(host)
            or type(port) is not int or not 1 <= port <= 65535):
        raise PairingRefused("main_endpoint_rejected")
    if is_tailscale_host(host):
        raise PairingRefused(TAILSCALE_ENDPOINT_REFUSED)
    try:
        raw = socket.create_connection((host, port), timeout=timeout_seconds)
    except OSError:
        raise PairingRefused("main_unreachable") from None
    # A DNS name (or the bundle/--endpoint literal) must not have led to a
    # Tailscale peer: checked on the connected address before any TLS byte.
    # Fail closed: a peer address that cannot be read or classified is refused.
    try:
        peer = raw.getpeername()[0]
    except (OSError, IndexError, TypeError):
        raw.close()
        raise PairingRefused("main_unreachable") from None
    if not isinstance(peer, str) or not _is_ip_literal(peer):
        raw.close()
        raise PairingRefused("main_endpoint_rejected")
    if is_tailscale_host(peer):
        raw.close()
        raise PairingRefused(TAILSCALE_ENDPOINT_REFUSED)
    try:
        connection = context.wrap_socket(raw, server_hostname=server_name)
    except ssl.SSLCertVerificationError:
        raw.close()
        raise PairingRefused("main_identity_rejected") from None
    except (ssl.SSLError, OSError):
        raw.close()
        raise PairingRefused("main_handshake_failed") from None
    if connection.version() != "TLSv1.3":
        connection.close()
        raise PairingRefused("main_handshake_failed")
    connection.settimeout(None)
    return connection
