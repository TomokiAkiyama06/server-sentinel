"""Agent-side node key, enrollment request and pinned TLS client (ADR-0006, #13).

This is the only Agent module that imports ``cryptography``; the stdlib-only
runtime, CLI and ring buffer never import it. It opens no listener and sends no
traffic by itself: callers connect outbound to the Main with the returned
``ssl.SSLContext``.

* The node key is an EC P-256 key generated locally by the non-root service
  account and written once (0600, ``O_EXCL | O_NOFOLLOW``) in an owner-only
  directory below the runtime root. It never leaves the capture host.
* The enrollment request is a CSR used only as proof of possession; the Main
  ignores its subject and extensions.
* Trust is pinned to the deployment CA from the Owner-transferred public trust
  bundle: no system trust store, TLS 1.3 only, hostname verification against the
  bundle's server name, and no key-log file (``ssl.create_default_context`` is
  deliberately not used because it honours ``SSLKEYLOGFILE``). That TLS
  client, ``connect_to_main`` and ``installed_credential`` live in the
  stdlib-only ``main_link`` (Issue #14), so the service's ingest session does
  not import ``cryptography``; they are re-exported here unchanged.

Errors use fixed ``PairingRefused`` reasons and never include key, CSR,
certificate or bundle bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from .addresses import is_tailscale_host
# Stdlib-only connection helpers (Issue #14), re-exported for existing callers.
from .main_link import (
    MAX_TRUST_BUNDLE_BYTES, TAILSCALE_ENDPOINT_REFUSED, InstalledCredential,
    _valid_endpoint_host, _valid_server_name, build_capture_client_context, connect_to_main,
    installed_credential,
)
from .pairing import EnrollmentLock, NodeCredentialMaterial, NodeCredentialStore, PairingRefused
from .storage import StorageRefused, open_directory


# Names kept importable from here (pairing CLI, e2e harness, transport PoC).
_REEXPORTED = (InstalledCredential, build_capture_client_context, connect_to_main)


NODE_URI_PREFIX = "urn:serversentinel:capture-node:"
DEPLOYMENT_URI_PREFIX = "urn:serversentinel:deployment:"
TRUST_BUNDLE_FORMAT = 1
MAX_CERTIFICATE_BYTES = 16 * 1024
_PENDING_DIRECTORY = "pending-enrollment"
_RENEWAL_DIRECTORY = "pending-renewal"
_REPAIR_DIRECTORY = "pending-repair"
# Owner decision 2026-09-30: automatic renewal. Start 30 days before expiry,
# retry with exponential backoff from 1 hour up to 24 hours; the Main warns the
# Owner if a credential is within 14 days of expiry and still not renewed.
RENEWAL_WINDOW = datetime.timedelta(days=30)
RENEWAL_OVERDUE = datetime.timedelta(days=14)
RENEWAL_FIRST_RETRY = datetime.timedelta(hours=1)
RENEWAL_MAX_RETRY = datetime.timedelta(hours=24)
_PENDING_KEY = "node-key.pem"


def public_key_digest(public_key) -> str:
    """Lowercase SHA-256 hex of the DER SubjectPublicKeyInfo (Main ledger digest)."""
    spki = public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _san_uris(certificate: x509.Certificate) -> list[str]:
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return names.get_values_for_type(x509.UniformResourceIdentifier)


@dataclass(frozen=True)
class TrustBundle:
    """Parsed public trust bundle; ``sha256`` is the digest of the exact bytes."""

    deployment_id: UUID
    ca_certificate_pem: bytes = field(repr=False)
    server_name: str
    endpoint_host: str
    endpoint_port: int
    sha256: str

    @classmethod
    def parse(cls, content: bytes, *, expected_sha256: str | None = None) -> "TrustBundle":
        if not isinstance(content, bytes) or not 0 < len(content) <= MAX_TRUST_BUNDLE_BYTES:
            raise PairingRefused("trust_bundle_rejected")
        digest = hashlib.sha256(content).hexdigest()
        if expected_sha256 is not None and not (
                isinstance(expected_sha256, str)
                and hmac.compare_digest(digest, expected_sha256.strip().lower())):
            raise PairingRefused("trust_bundle_digest_mismatch")
        try:
            value = json.loads(content.decode("ascii"))
            if (not isinstance(value, dict)
                    or set(value) != {"format_version", "deployment_id", "ca_certificate",
                                      "server_name", "endpoint"}
                    or value["format_version"] != TRUST_BUNDLE_FORMAT
                    or not isinstance(value["endpoint"], dict)
                    or set(value["endpoint"]) != {"host", "port"}):
                raise ValueError
            deployment = UUID(value["deployment_id"])
            if str(deployment) != value["deployment_id"]:
                raise ValueError
            ca_pem = value["ca_certificate"].encode("ascii")
            certificate = x509.load_pem_x509_certificate(ca_pem)
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not constraints.ca or DEPLOYMENT_URI_PREFIX + str(deployment) not in _san_uris(certificate):
                raise ValueError
            host, port = value["endpoint"]["host"], value["endpoint"]["port"]
            if (not _valid_server_name(value["server_name"]) or not _valid_endpoint_host(host)
                    or type(port) is not int or not 1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, x509.ExtensionNotFound):
            raise PairingRefused("trust_bundle_rejected") from None
        if is_tailscale_host(host):
            # Enrollment and ingest are private-LAN only (Issue #150).
            raise PairingRefused(TAILSCALE_ENDPOINT_REFUSED)
        return cls(deployment_id=deployment, ca_certificate_pem=ca_pem,
                   server_name=value["server_name"], endpoint_host=host,
                   endpoint_port=port, sha256=digest)


@dataclass(frozen=True)
class EnrollmentRequest:
    """Public enrollment request: CSR (proof of possession) plus key digest."""

    csr_pem: bytes = field(repr=False)
    public_key_digest: str


def generate_node_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def build_enrollment_request(private_key: ec.EllipticCurvePrivateKey) -> EnrollmentRequest:
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise PairingRefused("invalid_node_key")
    # The subject is intentionally empty: the Main assigns every identity field.
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([]))
           .sign(private_key, hashes.SHA256()))
    return EnrollmentRequest(csr_pem=csr.public_bytes(serialization.Encoding.PEM),
                             public_key_digest=public_key_digest(private_key.public_key()))


def _private_pem(private_key) -> bytes:
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())


class PendingNodeKeyStore:
    """Write-once node key awaiting enrollment, renewal or re-pairing.

    The default (enrollment) refuses once an identity is installed.
    ``renewal=True`` and ``repair=True`` require an installed identity and keep
    their key in a separate ``pending-renewal`` / ``pending-repair`` directory
    so retries reuse one fresh key. ``repair`` is the new node key for
    re-pairing after the Owner revoked the installed node (#116).
    """

    def __init__(self, runtime_root: Path, *, owner_uid: int | None = None,
                 renewal: bool = False, repair: bool = False):
        if renewal and repair:
            raise PairingRefused("pending_node_key_unavailable")
        self._files = NodeCredentialStore(runtime_root, owner_uid=owner_uid)
        self.runtime_root = Path(runtime_root)
        self._requires_identity = renewal or repair
        self._name = (_RENEWAL_DIRECTORY if renewal else
                      _REPAIR_DIRECTORY if repair else _PENDING_DIRECTORY)

    def _directory(self, *, create: bool) -> tuple[int, int]:
        root_fd = open_directory(self.runtime_root)
        try:
            self._files._validate_directory(root_fd, "runtime_root_rejected")
            if create:
                try:
                    os.mkdir(self._name, mode=0o700, dir_fd=root_fd)
                    os.fsync(root_fd)
                except FileExistsError:
                    pass
            directory_fd = os.open(self._name,
                                   os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=root_fd)
        except Exception:
            os.close(root_fd)
            raise
        try:
            self._files._validate_directory(directory_fd, "credential_directory_rejected")
        except Exception:
            os.close(directory_fd)
            os.close(root_fd)
            raise
        return root_fd, directory_fd

    def create(self) -> ec.EllipticCurvePrivateKey:
        """Generate and persist a new key; an existing pending key is never replaced."""
        if self._files.installed() != self._requires_identity:
            raise PairingRefused("node_identity_unavailable" if self._requires_identity
                                 else "node_identity_already_exists")
        key = generate_node_key()
        root_fd = directory_fd = None
        try:
            root_fd, directory_fd = self._directory(create=True)
            try:
                self._files._write_file(directory_fd, _PENDING_KEY, _private_pem(key))
            except FileExistsError:
                raise PairingRefused("pending_node_key_exists") from None
            os.fsync(directory_fd)
        except PairingRefused:
            raise
        except (OSError, StorageRefused, ValueError):
            raise PairingRefused("credential_storage_unavailable") from None
        finally:
            for descriptor in (directory_fd, root_fd):
                if descriptor is not None:
                    os.close(descriptor)
        return key

    def load(self) -> ec.EllipticCurvePrivateKey:
        root_fd = directory_fd = None
        try:
            root_fd, directory_fd = self._directory(create=False)
            content = self._files._read_file(directory_fd, _PENDING_KEY, maximum=16 * 1024)
            key = serialization.load_pem_private_key(content, password=None)
        except PairingRefused:
            raise
        except (OSError, StorageRefused, ValueError, TypeError):
            raise PairingRefused("pending_node_key_unavailable") from None
        finally:
            for descriptor in (directory_fd, root_fd):
                if descriptor is not None:
                    os.close(descriptor)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise PairingRefused("pending_node_key_unavailable")
        return key

    def discard(self) -> None:
        """Remove the pending key after its credential generation is installed."""
        root_fd = directory_fd = None
        try:
            root_fd, directory_fd = self._directory(create=False)
            os.unlink(_PENDING_KEY, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileNotFoundError:
            pass
        except (OSError, StorageRefused):
            raise PairingRefused("credential_storage_unavailable") from None
        finally:
            for descriptor in (directory_fd, root_fd):
                if descriptor is not None:
                    os.close(descriptor)


def validate_issued_credential(bundle: TrustBundle, private_key: ec.EllipticCurvePrivateKey,
                               certificate_pem: bytes) -> NodeCredentialMaterial:
    """Accept the Main's response only if it is our key, our deployment, capture-only."""
    if not isinstance(bundle, TrustBundle):
        raise PairingRefused("issued_credential_rejected")
    try:
        node, _ = _validate_leaf(bundle.ca_certificate_pem, bundle.deployment_id,
                                 private_key, certificate_pem)
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
        raise PairingRefused("issued_credential_rejected") from None
    return NodeCredentialMaterial(
        deployment_id=bundle.deployment_id, node_id=node, server_name=bundle.server_name,
        private_key=_private_pem(private_key), client_certificate=certificate_pem,
        ca_certificate=bundle.ca_certificate_pem)


def _validate_leaf(ca_certificate_pem: bytes, deployment_id: UUID,
                   private_key: ec.EllipticCurvePrivateKey, certificate_pem: bytes):
    if (not isinstance(private_key, ec.EllipticCurvePrivateKey)
            or not isinstance(certificate_pem, bytes)
            or not 0 < len(certificate_pem) <= MAX_CERTIFICATE_BYTES):
        raise ValueError
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    authority = x509.load_pem_x509_certificate(ca_certificate_pem)
    certificate.verify_directly_issued_by(authority)
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    uris = _san_uris(certificate)
    nodes = [uri for uri in uris if uri.startswith(NODE_URI_PREFIX)]
    if (constraints.ca or ExtendedKeyUsageOID.CLIENT_AUTH not in usages
            or ExtendedKeyUsageOID.SERVER_AUTH in usages or len(nodes) != 1
            or DEPLOYMENT_URI_PREFIX + str(deployment_id) not in uris
            or public_key_digest(certificate.public_key())
            != public_key_digest(private_key.public_key())):
        raise ValueError
    return UUID(nodes[0][len(NODE_URI_PREFIX):]), certificate


class RenewalSchedule:
    """When the Agent renews: 30 days before expiry, backoff 1 h doubling to 24 h.

    ``prepare_renewal`` and ``complete_renewal`` hold the runtime-wide
    ``EnrollmentLock`` and raise ``PairingRefused("enrollment_in_progress")``
    while a pairing CLI (or another renewal step) holds it. A future renewal
    loop must treat that refusal as transient -- back off by this schedule and
    retry -- never as a failed or rejected renewal, and must not alert on it.
    """

    @staticmethod
    def status(now: datetime.datetime, not_after: datetime.datetime) -> str:
        if not_after <= now:
            return "expired"
        if not_after - now <= RENEWAL_OVERDUE:
            return "renewal_overdue"
        if not_after - now <= RENEWAL_WINDOW:
            return "renewal_due"
        return "valid"

    @staticmethod
    def next_attempt(now: datetime.datetime, not_after: datetime.datetime,
                     consecutive_failures: int) -> datetime.datetime | None:
        """``None`` means the credential expired: renewal is impossible, re-pair."""
        if not_after <= now:
            return None
        start = not_after - RENEWAL_WINDOW
        if now < start:
            return start
        if consecutive_failures <= 0:
            return now
        delay = min(RENEWAL_FIRST_RETRY * (2 ** min(consecutive_failures - 1, 16)),
                    RENEWAL_MAX_RETRY)
        return min(now + delay, not_after)


def _installed_certificate(store: NodeCredentialStore) -> x509.Certificate:
    credential = installed_credential(store)
    try:
        content = credential.certificate_path.read_bytes()
        return x509.load_pem_x509_certificate(content)
    except (OSError, ValueError):
        raise PairingRefused("node_identity_unavailable") from None


def installed_certificate_expiry(store: NodeCredentialStore) -> datetime.datetime:
    return _installed_certificate(store).not_valid_after_utc


def installed_private_key(store: NodeCredentialStore) -> ec.EllipticCurvePrivateKey:
    """Load the committed generation's node key after the store's integrity check.

    Used only to re-pair an expired (not revoked) node with its same key; the
    key stays in this process and is never written anywhere else.
    """
    credential = installed_credential(store)
    root_fd = directory_fd = None
    try:
        root_fd = open_directory(store.runtime_root)
        directory_fd = os.open("node-credentials",
                               os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=root_fd)
        store._validate_directory(directory_fd, "credential_directory_rejected")
        content = store._read_file(directory_fd, credential.key_path.name, maximum=16 * 1024)
        key = serialization.load_pem_private_key(content, password=None)
    except PairingRefused:
        raise
    except (OSError, StorageRefused, ValueError, TypeError):
        raise PairingRefused("node_identity_unavailable") from None
    finally:
        for descriptor in (directory_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)
    if (not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1)
            or public_key_digest(key.public_key())
            != public_key_digest(_installed_certificate(store).public_key())):
        raise PairingRefused("node_identity_unavailable")
    return key


def prepare_renewal(store: NodeCredentialStore) -> EnrollmentRequest:
    """Return a CSR for a fresh renewal key, reusing it across retries.

    A pending key that already is the installed key is stale: the Agent
    stopped after ``store.rotate()`` committed but before ``pending.discard()``.
    The Main refuses current-key reuse, so it is discarded and replaced.
    Runs under the runtime-wide ``EnrollmentLock``, so it never races a
    concurrent pairing CLI (which refuses or is refused with
    ``enrollment_in_progress``; the renewal schedule simply retries).
    """
    with EnrollmentLock(store.runtime_root, owner_uid=store.owner_uid):
        pending = PendingNodeKeyStore(store.runtime_root, owner_uid=store.owner_uid, renewal=True)
        try:
            key = pending.load()
        except PairingRefused:
            key = pending.create()
        else:
            installed = public_key_digest(_installed_certificate(store).public_key())
            if hmac.compare_digest(public_key_digest(key.public_key()), installed):
                pending.discard()
                key = pending.create()
        return build_enrollment_request(key)


def complete_renewal(store: NodeCredentialStore, certificate_pem: bytes) -> NodeCredentialMaterial:
    """Validate the renewed certificate and atomically rotate to it.

    It must chain to the installed deployment CA, name the same node and
    deployment, carry the pending renewal key, and outlive the current
    certificate. The previous generation is replaced; the Main keeps admitting
    the old certificate until this new one is first presented. Runs under the
    runtime-wide ``EnrollmentLock`` like ``prepare_renewal``.
    """
    with EnrollmentLock(store.runtime_root, owner_uid=store.owner_uid):
        return _complete_renewal_locked(store, certificate_pem)


def _complete_renewal_locked(store: NodeCredentialStore,
                             certificate_pem: bytes) -> NodeCredentialMaterial:
    credential = installed_credential(store)
    pending = PendingNodeKeyStore(store.runtime_root, owner_uid=store.owner_uid, renewal=True)
    key = pending.load()
    current_expiry = installed_certificate_expiry(store)
    try:
        node, certificate = _validate_leaf(credential.ca_certificate_pem, credential.deployment_id,
                                           key, certificate_pem)
        if node != credential.node_id or certificate.not_valid_after_utc <= current_expiry:
            raise ValueError
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
        raise PairingRefused("renewed_credential_rejected") from None
    material = NodeCredentialMaterial(
        deployment_id=credential.deployment_id, node_id=node,
        server_name=credential.server_name, private_key=_private_pem(key),
        client_certificate=certificate_pem, ca_certificate=credential.ca_certificate_pem)
    store.rotate(material)
    pending.discard()
    return material
