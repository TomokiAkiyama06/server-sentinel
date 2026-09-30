"""Agent pairing CLI and bootstrap enrollment client (ADR-0006, Issue #13).

Run as the dedicated non-root ``media-capture-agent`` account::

    python -m media_capture_agent.enroll request --runtime-root DIR --output FILE
    python -m media_capture_agent.enroll pair --runtime-root DIR \\
        --trust-bundle FILE --bundle-sha256 HEX [--endpoint HOST:PORT]

``request`` generates the node key locally (0600 in a 0700 directory below the
runtime root) and writes the *public* enrollment request (CSR plus key digest)
that the Owner carries to the Main approval CLI. It prints the key digest so
the Owner can compare it with the one the Main shows.

``pair`` accepts only public selectors: the trust-bundle file, its full SHA-256
as verified by the Owner, and optionally an endpoint override. Order of work:

1. parse the bundle and refuse unless its digest matches (no network yet);
2. connect with TLS 1.3 pinned to the bundle's deployment CA only, verify the
   bundle's server name, the enrollment ALPN protocol and that the Main
   certificate names the bundle's deployment -- then close;
3. only then read the code from a non-echoing controlling-terminal prompt
   (never argv, environment, URL or stdin; no echo fallback);
4. reconnect with the same full verification, send the code and CSR in one
   bounded frame, read one bounded response;
5. accept the certificate only for this key, deployment CA and capture-only
   scope, and install it atomically with owner-only permissions.

Any verification failure aborts before the prompt, so no code byte is ever
sent to an unverified peer. There is no plaintext, insecure, proxy or redirect
path; the TLS context never enables key logging. Output is fixed words only.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
import stat
import struct
import sys
from typing import Callable
from uuid import UUID

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from .node_tls import (
    DEPLOYMENT_URI_PREFIX, MAX_TRUST_BUNDLE_BYTES, PendingNodeKeyStore, TrustBundle,
    build_capture_client_context, build_enrollment_request, connect_to_main,
    validate_issued_credential,
)
from .pairing import NodeCredentialStore, PairingCode, PairingRefused, prompt_pairing_code


# Must match app.cameras.remote_agent.enrollment on the Main.
ENROLLMENT_ALPN = "serversentinel-capture-enroll/1"
PROTOCOL_VERSION = 1
REQUEST_FORMAT = 1
FRAME_HEADER = struct.Struct(">I")
MAX_REQUEST_BYTES = 20 * 1024
MAX_RESPONSE_BYTES = 32 * 1024
RESPONSE_TIMEOUT_SECONDS = 30.0


def _write_public_file(path: Path, content: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o644)
    except OSError:
        raise PairingRefused("output_file_unavailable") from None
    try:
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    except OSError:
        raise PairingRefused("output_file_unavailable") from None
    finally:
        os.close(descriptor)


def _read_public_file(path: Path, maximum: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise PairingRefused("trust_bundle_unavailable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise PairingRefused("trust_bundle_rejected")
        content = os.read(descriptor, maximum + 1)
        if len(content) != info.st_size:
            raise PairingRefused("trust_bundle_rejected")
        return content
    finally:
        os.close(descriptor)


def create_enrollment_request(runtime_root: Path, output: Path) -> str:
    """Create the write-once node key and the public request file; return its key digest."""
    request = build_enrollment_request(PendingNodeKeyStore(runtime_root).create())
    content = json.dumps({
        "format_version": REQUEST_FORMAT,
        "csr": request.csr_pem.decode("ascii"),
        "public_key_digest": request.public_key_digest,
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    _write_public_file(output, content)
    return request.public_key_digest


def enrollment_context(bundle: TrustBundle) -> ssl.SSLContext:
    context = build_capture_client_context(bundle.ca_certificate_pem)
    context.set_alpn_protocols([ENROLLMENT_ALPN])
    return context


def verify_main_session(connection: ssl.SSLSocket, bundle: TrustBundle) -> None:
    """Beyond chain/name/TLS 1.3 checks: enrollment protocol and deployment identity."""
    try:
        if (connection.version() != "TLSv1.3"
                or connection.selected_alpn_protocol() != ENROLLMENT_ALPN):
            raise ValueError
        peer = connection.getpeercert(binary_form=True)
        certificate = x509.load_der_x509_certificate(peer)
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        deployments = [uri for uri in names.get_values_for_type(x509.UniformResourceIdentifier)
                       if uri.startswith(DEPLOYMENT_URI_PREFIX)]
        if (constraints.ca or ExtendedKeyUsageOID.SERVER_AUTH not in usages
                or deployments != [DEPLOYMENT_URI_PREFIX + str(bundle.deployment_id)]):
            raise ValueError
    except (ValueError, TypeError, AttributeError, x509.ExtensionNotFound):
        raise PairingRefused("main_identity_rejected") from None


def open_verified_session(bundle: TrustBundle, host: str, port: int, *,
                          connector: Callable[..., ssl.SSLSocket] = connect_to_main
                          ) -> ssl.SSLSocket:
    connection = connector(enrollment_context(bundle), server_name=bundle.server_name,
                           host=host, port=port)
    try:
        verify_main_session(connection, bundle)
    except BaseException:
        connection.close()
        raise
    return connection


def _recv_exact(connection, size: int) -> bytes:
    chunks = []
    while size:
        chunk = connection.recv(min(size, 4096))
        if not chunk:
            raise PairingRefused("enrollment_refused")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def exchange(connection: ssl.SSLSocket, bundle: TrustBundle, code: PairingCode,
             csr_pem: bytes) -> bytes:
    """Send one enrollment frame and return the issued certificate PEM."""
    body = json.dumps({
        "version": PROTOCOL_VERSION,
        "deployment_id": str(bundle.deployment_id),
        "code": code.value,
        "csr": csr_pem.decode("ascii"),
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(body) > MAX_REQUEST_BYTES:
        raise PairingRefused("enrollment_request_too_large")
    try:
        connection.settimeout(RESPONSE_TIMEOUT_SECONDS)
        connection.sendall(FRAME_HEADER.pack(len(body)) + body)
        (length,) = FRAME_HEADER.unpack(_recv_exact(connection, FRAME_HEADER.size))
        if not 0 < length <= MAX_RESPONSE_BYTES:
            raise PairingRefused("enrollment_refused")
        response = json.loads(_recv_exact(connection, length).decode("ascii"))
        if (not isinstance(response, dict) or set(response) != {"status", "certificate"}
                or response["status"] != "issued" or not isinstance(response["certificate"], str)):
            raise PairingRefused("enrollment_refused")
        return response["certificate"].encode("ascii")
    except PairingRefused:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError, struct.error):
        raise PairingRefused("enrollment_refused") from None


def pair(runtime_root: Path, bundle: TrustBundle, *, host: str | None = None,
         port: int | None = None,
         prompt: Callable[[], PairingCode] = prompt_pairing_code,
         connector: Callable[..., ssl.SSLSocket] = connect_to_main) -> UUID:
    """Run the enrollment exchange; return the installed node UUID."""
    host = bundle.endpoint_host if host is None else host
    port = bundle.endpoint_port if port is None else port
    store = NodeCredentialStore(runtime_root)
    if store.installed():
        raise PairingRefused("node_identity_already_exists")
    pending = PendingNodeKeyStore(runtime_root)
    key = pending.load()
    request = build_enrollment_request(key)
    # 1. Authenticate the intended Main before the code exists in this process.
    open_verified_session(bundle, host, port, connector=connector).close()
    # 2. Only now read the code, from the non-echoing controlling terminal.
    code = prompt()
    # 3. Reconnect: full server authentication again before any code byte.
    connection = open_verified_session(bundle, host, port, connector=connector)
    try:
        certificate = exchange(connection, bundle, code, request.csr_pem)
    finally:
        connection.close()
    del code
    material = validate_issued_credential(bundle, key, certificate)
    store.install(material)
    pending.discard()
    return material.node_id


def _endpoint(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not separator or not host or not port.isascii() or not port.isdecimal():
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    return host, int(port)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="media-capture-agent-pair",
                                     description="Capture-node pairing (ADR-0006).")
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request", help="create the node key and public request")
    request.add_argument("--runtime-root", type=Path, required=True)
    request.add_argument("--output", type=Path, required=True)
    enroll = commands.add_parser("pair", help="enroll with the Main over verified TLS")
    enroll.add_argument("--runtime-root", type=Path, required=True)
    enroll.add_argument("--trust-bundle", type=Path, required=True)
    enroll.add_argument("--bundle-sha256", required=True,
                        help="full SHA-256 of the bundle, as shown on the Main console")
    enroll.add_argument("--endpoint", type=_endpoint, default=None,
                        help="override the bundle's bootstrap endpoint HOST:PORT")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise PairingRefused("root_refused")
        if args.command == "request":
            digest = create_enrollment_request(args.runtime_root, args.output)
            print(f"public_key_sha256={digest}")
            return 0
        bundle = TrustBundle.parse(_read_public_file(args.trust_bundle, MAX_TRUST_BUNDLE_BYTES),
                                   expected_sha256=args.bundle_sha256)
        host, port = args.endpoint if args.endpoint is not None else (None, None)
        node = pair(args.runtime_root, bundle, host=host, port=port)
    except PairingRefused as error:
        print(f"media-capture-agent pairing: refused: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("media-capture-agent pairing: refused: pairing_failed", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("media-capture-agent pairing: stopped", file=sys.stderr)
        return 1
    print(f"paired: node_id={node}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
