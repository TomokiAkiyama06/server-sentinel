"""Deployment-local capture-node certificate authority (ADR-0006, Issue #13).

This module creates and loads the deployment CA, issues the Main ingest server
certificate and capture-node client certificates, and exports the public trust
bundle an Owner copies to an Agent through a trusted channel. It opens no
listener, runs no CLI and performs no network I/O.

A node certificate is issued only for an ``EnrollmentClaim`` produced by the
pairing ledger after single-use redemption. The CSR is used solely as proof of
possession of the approved public key: its subject, extensions and attributes
are ignored, so a node cannot choose its identity, SANs, key usages or scope.
Certificates are never the authority for admission; the ledger activation
record is (see ``ingest_tls.CaptureNodeAdmission``).

Private keys are written once, with ``O_EXCL | O_NOFOLLOW`` and mode 0600, into
owner-only (0700) directories that are validated before every access. Errors
carry fixed messages and never include key, CSR or certificate bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import datetime
import errno
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .pairing import EnrollmentClaim, PairingLedger


NODE_URI_PREFIX = "urn:serversentinel:capture-node:"
DEPLOYMENT_URI_PREFIX = "urn:serversentinel:deployment:"
TRUST_BUNDLE_FORMAT = 1
MAX_CSR_BYTES = 16 * 1024
MAX_PEM_BYTES = 64 * 1024
MAX_CA_VALIDITY = datetime.timedelta(days=3650)
MAX_LEAF_VALIDITY = datetime.timedelta(days=397)
# Owner decision 2026-09-30: node leaves default to the 397-day maximum and are
# renewed automatically (see renewal.py).
DEFAULT_NODE_VALIDITY = MAX_LEAF_VALIDITY
_CLOCK_SKEW_ALLOWANCE = datetime.timedelta(minutes=5)
_CA_KEY = "ca-key.pem"
_CA_CERTIFICATE = "ca-certificate.pem"
_SERVER_KEY = "main-server-key.pem"
_SERVER_CERTIFICATE = "main-server-certificate.pem"
_DNS_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")


class CaptureAuthorityError(RuntimeError):
    """A fixed CA/issuance failure that never embeds secret or peer bytes."""


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def public_key_digest(public_key) -> str:
    """Lowercase SHA-256 hex of the DER SubjectPublicKeyInfo (ledger key digest)."""
    spki = public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def certificate_digest(certificate: x509.Certificate) -> str:
    """Lowercase SHA-256 hex of the DER certificate.

    The ledger's ``credential_serial_digest`` binds this exact certificate
    (serial, validity, key and issuer signature), not only its serial number.
    """
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


def node_uri(node_id: UUID) -> str:
    return NODE_URI_PREFIX + str(node_id)


def deployment_uri(deployment_id: UUID) -> str:
    return DEPLOYMENT_URI_PREFIX + str(deployment_id)


def valid_server_name(value: object) -> bool:
    """Accept a lowercase DNS name only; IP literals and wildcards are refused."""
    if not isinstance(value, str) or not value.isascii() or not 0 < len(value) <= 253:
        return False
    if value != value.lower() or value.endswith("."):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.split(".")
    return len(labels) >= 2 and all(_DNS_LABEL.fullmatch(label) for label in labels)


def _valid_endpoint_host(value: object) -> bool:
    if not isinstance(value, str) or not value.isascii():
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return valid_server_name(value)
    return not (address.is_unspecified or address.is_multicast)


class PrivateDirectory:
    """An existing or newly created owner-only directory for issuer material.

    The directory must be a real directory (not a symlink) owned by
    ``owner_uid`` with no group/other permission bits. Files are created
    exclusively with mode 0600 and never replaced.
    """

    def __init__(self, path: Path, *, owner_uid: int | None = None):
        self.path = Path(path)
        if not self.path.is_absolute() or os.path.realpath(self.path) != str(self.path):
            # Refuse relative paths, ``..`` and symlinked ancestors up front.
            raise CaptureAuthorityError("private directory must be a canonical absolute path")
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid

    def ensure(self) -> "PrivateDirectory":
        try:
            os.mkdir(self.path, 0o700)
        except FileExistsError:
            pass
        except OSError:
            raise CaptureAuthorityError("private directory is unavailable") from None
        self._validate()
        return self

    def _validate(self) -> None:
        try:
            info = os.lstat(self.path)
        except OSError:
            raise CaptureAuthorityError("private directory is unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid
                or info.st_mode & 0o077):
            raise CaptureAuthorityError("private directory is not owner-only")

    def _open_directory(self) -> int:
        self._validate()
        try:
            return os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise CaptureAuthorityError("private directory is unavailable") from None

    def exists(self, name: str) -> bool:
        directory = self._open_directory()
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        finally:
            os.close(directory)

    def write_new(self, name: str, value: bytes) -> Path:
        directory = self._open_directory()
        try:
            try:
                descriptor = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=directory)
            except FileExistsError:
                raise CaptureAuthorityError("issuer material already exists") from None
            try:
                remaining = memoryview(value)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError(errno.EIO, "short write")
                    remaining = remaining[written:]
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            except OSError:
                os.close(descriptor)
                descriptor = None
                try:
                    os.unlink(name, dir_fd=directory)
                except OSError:
                    pass
                raise CaptureAuthorityError("issuer material could not be written") from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            os.fsync(directory)
            return self.path / name
        finally:
            os.close(directory)

    def read(self, name: str, *, maximum: int = MAX_PEM_BYTES) -> bytes:
        directory = self._open_directory()
        try:
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                     dir_fd=directory)
            except OSError:
                raise CaptureAuthorityError("issuer material is unavailable") from None
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                        or info.st_mode & 0o077 or info.st_nlink != 1
                        or not 0 < info.st_size <= maximum):
                    raise CaptureAuthorityError("issuer material is not a private file")
                content = os.read(descriptor, maximum + 1)
                if len(content) != info.st_size:
                    raise CaptureAuthorityError("issuer material changed while reading")
                return content
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)

    def private_file(self, name: str) -> Path:
        """Validate a private file and return its path for ``ssl`` path-only loaders."""
        self.read(name)
        return self.path / name


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _private_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _certificate_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _validity(value: object, maximum: datetime.timedelta) -> datetime.timedelta:
    if (not isinstance(value, datetime.timedelta) or value <= datetime.timedelta(0)
            or value > maximum):
        raise CaptureAuthorityError("certificate validity is outside the allowed range")
    return value


def _checked_now(clock: Callable[[], datetime.datetime]) -> datetime.datetime:
    now = clock()
    if not isinstance(now, datetime.datetime) or now.tzinfo is None:
        raise CaptureAuthorityError("issuer clock is invalid")
    return now.astimezone(datetime.timezone.utc)


@dataclass(frozen=True)
class IssuedNodeCredential:
    """Public issuance result; contains no private key."""

    node_id: UUID
    certificate_pem: bytes = field(repr=False)
    public_key_digest: str
    credential_digest: str
    not_after: datetime.datetime


@dataclass(frozen=True)
class MainServerCredential:
    certificate_path: Path
    key_path: Path


@dataclass(frozen=True)
class TrustBundleExport:
    """Public bundle bytes plus the full SHA-256 digest the Owner verifies."""

    content: bytes = field(repr=False)
    sha256: str


class DeploymentAuthority:
    """Issuer bound to one deployment UUID and one owner-only key directory."""

    def __init__(self, deployment_id: UUID, certificate: x509.Certificate,
                 private_key: ec.EllipticCurvePrivateKey, *,
                 clock: Callable[[], datetime.datetime] = _utc_now):
        self.deployment_id = deployment_id
        self.certificate = certificate
        self._private_key = private_key
        self._clock = clock

    def __repr__(self) -> str:
        return "DeploymentAuthority(<redacted>)"

    @classmethod
    def create(cls, directory: PrivateDirectory, deployment_id: UUID, *,
               validity: datetime.timedelta,
               clock: Callable[[], datetime.datetime] = _utc_now) -> "DeploymentAuthority":
        if not isinstance(deployment_id, UUID):
            raise CaptureAuthorityError("invalid deployment identity")
        lifetime = _validity(validity, MAX_CA_VALIDITY)
        directory.ensure()
        if directory.exists(_CA_KEY) or directory.exists(_CA_CERTIFICATE):
            raise CaptureAuthorityError("issuer material already exists")
        now = _checked_now(clock)
        key = _new_key()
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ServerSentinel deployment"),
            x509.NameAttribute(NameOID.COMMON_NAME, "capture-node CA " + str(deployment_id)),
        ])
        public = key.public_key()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _CLOCK_SKEW_ALLOWANCE)
            .not_valid_after(now + lifetime)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public), critical=False)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(deployment_uri(deployment_id))]), critical=False)
            .sign(key, hashes.SHA256())
        )
        directory.write_new(_CA_KEY, _private_pem(key))
        directory.write_new(_CA_CERTIFICATE, _certificate_pem(certificate))
        return cls(deployment_id, certificate, key, clock=clock)

    @classmethod
    def load(cls, directory: PrivateDirectory, deployment_id: UUID, *,
             clock: Callable[[], datetime.datetime] = _utc_now) -> "DeploymentAuthority":
        if not isinstance(deployment_id, UUID):
            raise CaptureAuthorityError("invalid deployment identity")
        try:
            key = serialization.load_pem_private_key(directory.read(_CA_KEY), password=None)
            certificate = x509.load_pem_x509_certificate(directory.read(_CA_CERTIFICATE))
        except CaptureAuthorityError:
            raise
        except (ValueError, TypeError):
            raise CaptureAuthorityError("issuer material is invalid") from None
        if (not isinstance(key, ec.EllipticCurvePrivateKey)
                or public_key_digest(key.public_key()) != public_key_digest(certificate.public_key())
                or deployment_uri(deployment_id) not in _uris(certificate)
                or not _is_ca(certificate)):
            raise CaptureAuthorityError("issuer material is invalid")
        return cls(deployment_id, certificate, key, clock=clock)

    def ca_certificate_pem(self) -> bytes:
        return _certificate_pem(self.certificate)

    def _leaf_window(self, validity: datetime.timedelta) -> tuple[datetime.datetime, datetime.datetime]:
        lifetime = _validity(validity, MAX_LEAF_VALIDITY)
        now = _checked_now(self._clock)
        not_after = now + lifetime
        if (now < self.certificate.not_valid_before_utc
                or not_after > self.certificate.not_valid_after_utc):
            raise CaptureAuthorityError("certificate validity exceeds the deployment CA")
        return now - _CLOCK_SKEW_ALLOWANCE, not_after

    def _leaf_builder(self, subject: str, public_key, window) -> x509.CertificateBuilder:
        not_before, not_after = window
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.certificate.public_key()), critical=False)
        )

    def issue_main_server_credential(self, target: PrivateDirectory, *, server_name: str,
                                     validity: datetime.timedelta) -> MainServerCredential:
        """Write a serverAuth-only Main ingest certificate and key into ``target``.

        ``target`` must be a different directory from the CA key directory so
        the ingest listener never needs read access to the CA private key.
        """
        if not valid_server_name(server_name):
            raise CaptureAuthorityError("invalid Main server name")
        window = self._leaf_window(validity)
        target.ensure()
        if target.exists(_CA_KEY):
            raise CaptureAuthorityError("listener material must not share the CA directory")
        key = _new_key()
        certificate = (
            self._leaf_builder("ServerSentinel capture ingest", key.public_key(), window)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(server_name),
                x509.UniformResourceIdentifier(deployment_uri(self.deployment_id)),
            ]), critical=False)
            .sign(self._private_key, hashes.SHA256())
        )
        key_path = target.write_new(_SERVER_KEY, _private_pem(key))
        certificate_path = target.write_new(_SERVER_CERTIFICATE, _certificate_pem(certificate))
        return MainServerCredential(certificate_path=certificate_path, key_path=key_path)

    def issue_node_certificate(self, claim: EnrollmentClaim, csr_pem: bytes, *,
                               validity: datetime.timedelta = DEFAULT_NODE_VALIDITY
                               ) -> IssuedNodeCredential:
        """Sign a capture-only client certificate for a redeemed enrollment claim."""
        if not isinstance(claim, EnrollmentClaim):
            raise CaptureAuthorityError("invalid enrollment claim")
        public, key_digest = self._proof_of_possession(csr_pem)
        if not hmac.compare_digest(key_digest, claim.public_key_digest):
            raise CaptureAuthorityError("enrollment request does not match the approved key")
        return self._sign_node(claim.node_id, public, key_digest, validity)

    @staticmethod
    def _proof_of_possession(csr_pem: bytes, *, strict: bool = False):
        """Return the CSR's EC P-256 public key and digest after verifying its signature.

        ``strict`` (renewal) additionally refuses any requested subject or
        extension, so a renewal request cannot even ask for another identity.
        """
        if not isinstance(csr_pem, bytes) or not 0 < len(csr_pem) <= MAX_CSR_BYTES:
            raise CaptureAuthorityError("invalid enrollment request")
        try:
            request = x509.load_pem_x509_csr(csr_pem)
            proof = request.is_signature_valid
            public = request.public_key()
        except (ValueError, TypeError, InvalidSignature):
            raise CaptureAuthorityError("invalid enrollment request") from None
        if (not proof or not isinstance(public, ec.EllipticCurvePublicKey)
                or not isinstance(public.curve, ec.SECP256R1)):
            raise CaptureAuthorityError("invalid enrollment request")
        if strict and (len(request.subject) or len(request.extensions)):
            raise CaptureAuthorityError("renewal request may not choose an identity")
        return public, public_key_digest(public)

    def _sign_node(self, node_id: UUID, public, key_digest: str,
                   validity: datetime.timedelta) -> IssuedNodeCredential:
        window = self._leaf_window(validity)
        certificate = (
            self._leaf_builder("capture-node " + str(node_id), public, window)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(node_uri(node_id)),
                x509.UniformResourceIdentifier(deployment_uri(self.deployment_id)),
            ]), critical=False)
            .sign(self._private_key, hashes.SHA256())
        )
        return IssuedNodeCredential(node_id=node_id,
                                    certificate_pem=_certificate_pem(certificate),
                                    public_key_digest=key_digest,
                                    credential_digest=certificate_digest(certificate),
                                    not_after=certificate.not_valid_after_utc)

    def issue_renewal_certificate(self, node_id: UUID, csr_pem: bytes, *,
                                  validity: datetime.timedelta = DEFAULT_NODE_VALIDITY
                                  ) -> IssuedNodeCredential:
        """Sign a renewal leaf for ``node_id``; use ``renewal.renew_node_credential``.

        This primitive checks only the CSR. Eligibility (current, admitted,
        unexpired identity) and ledger staging are enforced by the caller.
        """
        if not isinstance(node_id, UUID):
            raise CaptureAuthorityError("invalid node identity")
        public, key_digest = self._proof_of_possession(csr_pem, strict=True)
        return self._sign_node(node_id, public, key_digest, validity)

    def issue_and_activate(self, ledger: PairingLedger, claim: EnrollmentClaim, csr_pem: bytes, *,
                           validity: datetime.timedelta = DEFAULT_NODE_VALIDITY
                           ) -> IssuedNodeCredential:
        """Sign for a consumed claim, then activate that exact certificate in the ledger.

        Consumption was committed by ``PairingLedger.redeem`` before signing. If
        activation fails, the returned certificate never reaches the caller and
        stays unusable because ingest admission requires the activation record;
        a retry needs a fresh Owner approval.
        """
        issued = self.issue_node_certificate(claim, csr_pem, validity=validity)
        ledger.activate(claim, credential_serial_digest=issued.credential_digest,
                        not_after=issued.not_after.timestamp())
        return issued

    def export_trust_bundle(self, *, server_name: str, endpoint_host: str,
                            endpoint_port: int) -> TrustBundleExport:
        """Serialize the public bundle: no private key, code or credential."""
        if not valid_server_name(server_name) or not _valid_endpoint_host(endpoint_host):
            raise CaptureAuthorityError("invalid trust bundle endpoint")
        if type(endpoint_port) is not int or not 1 <= endpoint_port <= 65535:
            raise CaptureAuthorityError("invalid trust bundle endpoint")
        content = json.dumps({
            "format_version": TRUST_BUNDLE_FORMAT,
            "deployment_id": str(self.deployment_id),
            "ca_certificate": self.ca_certificate_pem().decode("ascii"),
            "server_name": server_name,
            "endpoint": {"host": endpoint_host, "port": endpoint_port},
        }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        return TrustBundleExport(content=content, sha256=hashlib.sha256(content).hexdigest())


def _uris(certificate: x509.Certificate) -> list[str]:
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return names.get_values_for_type(x509.UniformResourceIdentifier)


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def listener_material(directory: PrivateDirectory) -> MainServerCredential:
    """Validate and return the Main ingest server certificate/key paths."""
    return MainServerCredential(certificate_path=directory.private_file(_SERVER_CERTIFICATE),
                                key_path=directory.private_file(_SERVER_KEY))
