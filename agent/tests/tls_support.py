"""Throwaway deployment CA and Main TLS peer for Agent-only tests.

This stands in for the Main issuer so Agent tests do not import server code.
All material is generated per test in temporary directories.
"""
import datetime
import json
import os
from pathlib import Path
import socket
import ssl
import threading
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


SERVER_NAME = "capture-main.serversentinel.test"
DAY = datetime.timedelta(days=1)


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def write_private(path: Path, content: bytes) -> Path:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
    return path


class SyntheticAuthority:
    def __init__(self, deployment: UUID | None = None, *, start=None):
        self.deployment = deployment or uuid4()
        self.key = ec.generate_private_key(ec.SECP256R1())
        start = start or now() - DAY
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic capture CA")])
        public = self.key.public_key()
        self.certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(start + 3650 * DAY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                           critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(
                "urn:serversentinel:deployment:" + str(self.deployment))]), critical=False)
            .sign(self.key, hashes.SHA256()))

    def leaf(self, public_key, *, usage, names, start=None, lifetime=30 * DAY):
        start = start or now() - datetime.timedelta(minutes=5)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic leaf")]))
            .issuer_name(self.certificate.subject).public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(start + lifetime)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(self.key, hashes.SHA256()))

    def node_certificate(self, csr_pem: bytes, node: UUID, **kwargs):
        request = x509.load_pem_x509_csr(csr_pem)
        assert request.is_signature_valid
        return self.leaf(request.public_key(), usage=ExtendedKeyUsageOID.CLIENT_AUTH, names=[
            x509.UniformResourceIdentifier("urn:serversentinel:capture-node:" + str(node)),
            x509.UniformResourceIdentifier("urn:serversentinel:deployment:" + str(self.deployment)),
        ], **kwargs)

    def server_files(self, directory: Path, *, server_name=SERVER_NAME, **kwargs):
        directory.mkdir(mode=0o700)
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = self.leaf(key.public_key(), usage=ExtendedKeyUsageOID.SERVER_AUTH,
                                names=[x509.DNSName(server_name)], **kwargs)
        return (write_private(directory / "cert.pem", pem(certificate)),
                write_private(directory / "key.pem", key_pem(key)))

    def bundle(self, *, server_name=SERVER_NAME, host="127.0.0.1", port=7443) -> bytes:
        return json.dumps({
            "format_version": 1, "deployment_id": str(self.deployment),
            "ca_certificate": pem(self.certificate).decode("ascii"),
            "server_name": server_name, "endpoint": {"host": host, "port": port},
        }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


class MainPeer:
    """One-connection TLS server thread requiring a client certificate."""

    def __init__(self, certificate: Path, key: Path, client_ca_pem: bytes, *,
                 tls12_only=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if tls12_only:
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_OPTIONAL
        context.load_verify_locations(cadata=client_ca_pem.decode("ascii"))
        context.load_cert_chain(str(certificate), str(key))
        self.context = context
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.peer_certificate = None
        self.received = b""
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            connection, _ = self.listener.accept()
        except OSError:
            return
        try:
            connection.settimeout(10)
            with self.context.wrap_socket(connection, server_side=True) as tls:
                self.peer_certificate = tls.getpeercert(binary_form=True)
                self.received = tls.recv(4)
                tls.sendall(b"pong")
        except (ssl.SSLError, OSError):
            pass
        finally:
            self.listener.close()

    def join(self):
        self.thread.join(10)
