"""WebAuthn relying-party verification over ``cryptography`` (Issue #10, ADR-0004).

This module is pure verification: it holds no state, opens no database and
registers no route. It checks exactly the transient data a registration or
assertion carries — the server challenge, ``clientDataJSON`` (type, challenge,
origin, cross-origin markers), authenticator data (relying-party id hash, the
user-present and user-verified flags, the signature counter and the
backup-eligibility/backup-state flags), the COSE credential public key, the
attestation statement where one is present, and the assertion signature — and
returns only the values that are allowed to persist.

Every failure raises ``WebAuthnVerificationError`` with one fixed message. The
exception never carries the submitted value, which part failed, or any
deployment detail, so a caller can map all of them to the same generic denial.

Only the ``none`` attestation format and ``packed`` self attestation are
accepted. The registration options request ``attestation: "none"``; a
statement in any other format, or a ``packed`` statement with a certificate
chain, is refused rather than accepted unverified.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
from typing import Any, Mapping
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


class WebAuthnVerificationError(ValueError):
    """A ceremony failed verification; the message never names the reason."""

    def __init__(self) -> None:
        super().__init__("access is unavailable")


def _fail() -> WebAuthnVerificationError:
    return WebAuthnVerificationError()


# COSE algorithm identifiers (IANA COSE Algorithms registry).
ES256 = -7
EDDSA = -8
RS256 = -257
SUPPORTED_ALGORITHMS = (EDDSA, ES256, RS256)

# Authenticator data flags (WebAuthn Level 3 §6.1).
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80

CHALLENGE_BYTES = 32
MAX_CREDENTIAL_ID = 1023
MAX_CLIENT_DATA = 4096
MAX_ATTESTATION_OBJECT = 16384
MAX_AUTHENTICATOR_DATA = 4096
MAX_SIGNATURE = 1024
MAX_USER_HANDLE = 64
MIN_RSA_BITS = 2048


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: object, *, limit: int) -> bytes:
    """Strict unpadded base64url; anything else is a verification failure."""
    if not isinstance(value, str) or not value or len(value) > (limit * 4 + 2) // 3 + 1:
        raise _fail()
    if not value.isascii() or any(char not in _B64URL for char in value) or len(value) % 4 == 1:
        raise _fail()
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise _fail() from None
    # Reject non-canonical trailing bits so one value has one encoding.
    if b64url_encode(decoded) != value or not 1 <= len(decoded) <= limit:
        raise _fail()
    return decoded


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


# --- Minimal strict CBOR (RFC 8949) decoder for attestation/COSE structures ---

_MAX_DEPTH = 8
_MAX_ITEMS = 256


def _cbor_item(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > _MAX_DEPTH or offset >= len(data):
        raise _fail()
    initial = data[offset]
    offset += 1
    major, info = initial >> 5, initial & 0x1F
    if info < 24:
        argument = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if offset + size > len(data):
            raise _fail()
        argument = int.from_bytes(data[offset:offset + size], "big")
        offset += size
    else:
        # Reserved values and indefinite lengths are not used by WebAuthn.
        raise _fail()
    if major == 0:
        return argument, offset
    if major == 1:
        return -1 - argument, offset
    if major in (2, 3):
        end = offset + argument
        if end > len(data):
            raise _fail()
        raw = data[offset:end]
        if major == 2:
            return bytes(raw), end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError:
            raise _fail() from None
    if major == 4:
        if argument > _MAX_ITEMS:
            raise _fail()
        items = []
        for _ in range(argument):
            item, offset = _cbor_item(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:
        if argument > _MAX_ITEMS:
            raise _fail()
        result: dict = {}
        for _ in range(argument):
            key, offset = _cbor_item(data, offset, depth + 1)
            if not isinstance(key, (int, str)) or isinstance(key, bool) or key in result:
                raise _fail()
            value, offset = _cbor_item(data, offset, depth + 1)
            result[key] = value
        return result, offset
    if major == 7 and info < 24:
        simple = {20: False, 21: True, 22: None}
        if argument in simple:
            return simple[argument], offset
    # Tags, floats and other simple values are refused.
    raise _fail()


def cbor_decode_prefix(data: bytes, offset: int = 0) -> tuple[Any, int]:
    """Decode one CBOR item starting at ``offset`` and return the next offset."""
    if not isinstance(data, (bytes, bytearray)):
        raise _fail()
    return _cbor_item(bytes(data), offset, 0)


def cbor_decode(data: bytes) -> Any:
    value, end = cbor_decode_prefix(data)
    if end != len(data):
        raise _fail()
    return value


# --- Relying party configuration ---


@dataclass(frozen=True)
class RelyingParty:
    """The reserved dashboard origin and its relying-party id.

    ``origin`` must be a secure context: ``https://<host>[:port]``, or
    ``http://localhost[:port]`` for a strictly local browser, because browsers
    expose WebAuthn only there. The relying-party id must equal the origin's
    host: ServerSentinel reserves the whole hostname (ADR-0003), so a
    registrable parent domain is never used as the id.
    """

    rp_id: str
    origin: str

    def __post_init__(self) -> None:
        if not isinstance(self.rp_id, str) or not isinstance(self.origin, str):
            raise ValueError("relying party configuration is invalid")
        parts = urlsplit(self.origin)
        try:
            port = parts.port
        except ValueError:
            raise ValueError("relying party configuration is invalid") from None
        host = parts.hostname
        canonical = f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")
        secure = parts.scheme == "https" or (parts.scheme == "http" and host == "localhost")
        if (not secure or host is None or host != self.rp_id or canonical != self.origin
                or parts.username is not None or parts.password is not None
                or parts.path or parts.query or parts.fragment
                or not self.rp_id.isascii() or self.rp_id != self.rp_id.lower()
                or len(self.rp_id) > 253 or self.rp_id.endswith(".") or _is_ip(self.rp_id)):
            raise ValueError("relying party configuration is invalid")

    @property
    def rp_id_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode("ascii")).digest()


def _is_ip(host: str) -> bool:
    # WebAuthn relying-party ids are domains; an IP-literal origin cannot be one.
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


# --- COSE public keys ---


@dataclass(frozen=True)
class CosePublicKey:
    algorithm: int
    key: Any
    encoded: bytes


def parse_cose_key(encoded: bytes, *, allowed: tuple[int, ...] = SUPPORTED_ALGORITHMS) -> CosePublicKey:
    """Parse an EC2/P-256, OKP/Ed25519 or RSA COSE key into a verifier key."""
    value = cbor_decode(encoded)
    if not isinstance(value, dict):
        raise _fail()

    def exactly(label, expected):
        # CBOR ``true`` decodes to a bool, which Python would compare equal to 1.
        item = value.get(label)
        return type(item) is int and item == expected

    alg = value.get(3)
    if type(alg) is not int or alg not in allowed:
        raise _fail()
    try:
        if alg == ES256:
            x, y = value.get(-2), value.get(-3)
            if (not exactly(1, 2) or not exactly(-1, 1) or not isinstance(x, bytes) or not isinstance(y, bytes)
                    or len(x) != 32 or len(y) != 32):
                raise _fail()
            key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        elif alg == EDDSA:
            x = value.get(-2)
            if not exactly(1, 1) or not exactly(-1, 6) or not isinstance(x, bytes) or len(x) != 32:
                raise _fail()
            key = ed25519.Ed25519PublicKey.from_public_bytes(x)
        else:
            n, e = value.get(-1), value.get(-2)
            if not exactly(1, 3) or not isinstance(n, bytes) or not isinstance(e, bytes) or not n or not e:
                raise _fail()
            modulus, exponent = int.from_bytes(n, "big"), int.from_bytes(e, "big")
            if modulus.bit_length() < MIN_RSA_BITS or exponent < 3 or exponent % 2 == 0:
                raise _fail()
            key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except (ValueError, UnsupportedAlgorithm):
        raise _fail() from None
    return CosePublicKey(alg, key, bytes(encoded))


def verify_signature(public_key: CosePublicKey, signature: bytes, message: bytes) -> None:
    try:
        if public_key.algorithm == ES256:
            public_key.key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif public_key.algorithm == EDDSA:
            public_key.key.verify(signature, message)
        elif public_key.algorithm == RS256:
            public_key.key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise _fail()
    except (InvalidSignature, ValueError, TypeError):
        raise _fail() from None


# --- Authenticator data ---


@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None
    credential_public_key: bytes | None

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)

    @property
    def backup_eligible(self) -> bool:
        return bool(self.flags & FLAG_BE)

    @property
    def backup_state(self) -> bool:
        return bool(self.flags & FLAG_BS)


def parse_authenticator_data(data: bytes) -> AuthenticatorData:
    if not isinstance(data, bytes) or not 37 <= len(data) <= MAX_AUTHENTICATOR_DATA:
        raise _fail()
    rp_hash, flags, count = data[:32], data[32], int.from_bytes(data[33:37], "big")
    offset = 37
    credential_id = public_key = None
    if flags & FLAG_AT:
        if offset + 18 > len(data):
            raise _fail()
        length = int.from_bytes(data[offset + 16:offset + 18], "big")
        offset += 18
        if not 1 <= length <= MAX_CREDENTIAL_ID or offset + length > len(data):
            raise _fail()
        credential_id = data[offset:offset + length]
        offset += length
        _, end = cbor_decode_prefix(data, offset)
        public_key = data[offset:end]
        offset = end
    if flags & FLAG_ED:
        extensions, offset = cbor_decode_prefix(data, offset)
        if not isinstance(extensions, dict):
            raise _fail()
    if offset != len(data):
        raise _fail()
    # A credential cannot be backed up without being backup eligible.
    if flags & FLAG_BS and not flags & FLAG_BE:
        raise _fail()
    return AuthenticatorData(rp_hash, flags, count, credential_id, public_key)


# --- Client data ---


def _verify_client_data(raw: bytes, expected_type: str, rp: RelyingParty) -> bytes:
    """Check type/origin/cross-origin and return the decoded challenge bytes."""
    try:
        client = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _fail() from None
    if not isinstance(client, dict) or client.get("type") != expected_type:
        raise _fail()
    origin = client.get("origin")
    if not isinstance(origin, str) or not hmac.compare_digest(origin.encode("utf-8"), rp.origin.encode("ascii")):
        raise _fail()
    if client.get("crossOrigin", False) is not False or "topOrigin" in client:
        raise _fail()
    token_binding = client.get("tokenBinding")
    if token_binding is not None and (not isinstance(token_binding, dict)
                                      or token_binding.get("status") == "present"):
        raise _fail()
    return b64url_decode(client.get("challenge"), limit=CHALLENGE_BYTES)


def _field(mapping: Mapping, name: str) -> Any:
    if not isinstance(mapping, Mapping) or name not in mapping:
        raise _fail()
    return mapping[name]


def _credential_envelope(credential: Mapping) -> tuple[bytes, Mapping]:
    if _field(credential, "type") != "public-key":
        raise _fail()
    raw_id = b64url_decode(_field(credential, "rawId"), limit=MAX_CREDENTIAL_ID)
    if _field(credential, "id") != b64url_encode(raw_id):
        raise _fail()
    response = _field(credential, "response")
    if not isinstance(response, Mapping):
        raise _fail()
    return raw_id, response


# --- Ceremonies ---


@dataclass(frozen=True)
class VerifiedRegistration:
    credential_id: bytes
    public_key: bytes
    algorithm: int
    sign_count: int
    backup_eligible: bool
    backup_state: bool


def registration_challenge(credential: Mapping, rp: RelyingParty) -> bytes:
    """Return the challenge a registration response claims, after type/origin checks.

    The caller consumes that challenge server-side (single use) before calling
    ``verify_registration``; this function only exists so the lookup key is
    taken from verified client data rather than a separate client field.
    """
    _, response = _credential_envelope(credential)
    raw = b64url_decode(_field(response, "clientDataJSON"), limit=MAX_CLIENT_DATA)
    return _verify_client_data(raw, "webauthn.create", rp)


def verify_registration(credential: Mapping, rp: RelyingParty, expected_challenge: bytes,
                        *, allowed_algorithms: tuple[int, ...] = SUPPORTED_ALGORITHMS) -> VerifiedRegistration:
    """Verify a ``navigator.credentials.create`` response for this relying party."""
    raw_id, response = _credential_envelope(credential)
    client_raw = b64url_decode(_field(response, "clientDataJSON"), limit=MAX_CLIENT_DATA)
    challenge = _verify_client_data(client_raw, "webauthn.create", rp)
    if not isinstance(expected_challenge, bytes) or not hmac.compare_digest(challenge, expected_challenge):
        raise _fail()
    attestation = cbor_decode(b64url_decode(_field(response, "attestationObject"), limit=MAX_ATTESTATION_OBJECT))
    if not isinstance(attestation, dict) or set(attestation) != {"fmt", "attStmt", "authData"}:
        raise _fail()
    auth_raw, fmt, statement = attestation["authData"], attestation["fmt"], attestation["attStmt"]
    if not isinstance(auth_raw, bytes) or not isinstance(fmt, str) or not isinstance(statement, dict):
        raise _fail()
    data = parse_authenticator_data(auth_raw)
    if not hmac.compare_digest(data.rp_id_hash, rp.rp_id_hash):
        raise _fail()
    if not data.user_present or not data.user_verified:
        raise _fail()
    if data.credential_id is None or data.credential_public_key is None:
        raise _fail()
    if not hmac.compare_digest(data.credential_id, raw_id):
        raise _fail()
    key = parse_cose_key(data.credential_public_key, allowed=allowed_algorithms)
    client_hash = hashlib.sha256(client_raw).digest()
    if fmt == "none":
        if statement:
            raise _fail()
    elif fmt == "packed":
        # Self attestation only: the credential key signs authData||hash(clientData).
        if set(statement) != {"alg", "sig"} or statement["alg"] != key.algorithm:
            raise _fail()
        signature = statement["sig"]
        if not isinstance(signature, bytes) or not 1 <= len(signature) <= MAX_SIGNATURE:
            raise _fail()
        verify_signature(key, signature, auth_raw + client_hash)
    else:
        raise _fail()
    return VerifiedRegistration(data.credential_id, key.encoded, key.algorithm, data.sign_count,
                                data.backup_eligible, data.backup_state)


@dataclass(frozen=True)
class AssertionClaims:
    """Unverified identifiers read from an assertion to locate its records."""

    credential_id: bytes
    challenge: bytes
    user_handle: bytes | None


def assertion_claims(credential: Mapping, rp: RelyingParty) -> AssertionClaims:
    raw_id, response = _credential_envelope(credential)
    client_raw = b64url_decode(_field(response, "clientDataJSON"), limit=MAX_CLIENT_DATA)
    challenge = _verify_client_data(client_raw, "webauthn.get", rp)
    handle = response.get("userHandle")
    user_handle = None if handle is None else b64url_decode(handle, limit=MAX_USER_HANDLE)
    return AssertionClaims(raw_id, challenge, user_handle)


@dataclass(frozen=True)
class VerifiedAssertion:
    credential_id: bytes
    sign_count: int
    backup_eligible: bool
    backup_state: bool


def verify_assertion(credential: Mapping, rp: RelyingParty, expected_challenge: bytes,
                     stored_public_key: bytes, stored_algorithm: int) -> VerifiedAssertion:
    """Verify a ``navigator.credentials.get`` response against a stored credential.

    The caller compares the returned counter and backup-eligibility flag with
    its stored values; this function has no state to compare against.
    """
    raw_id, response = _credential_envelope(credential)
    client_raw = b64url_decode(_field(response, "clientDataJSON"), limit=MAX_CLIENT_DATA)
    challenge = _verify_client_data(client_raw, "webauthn.get", rp)
    if not isinstance(expected_challenge, bytes) or not hmac.compare_digest(challenge, expected_challenge):
        raise _fail()
    auth_raw = b64url_decode(_field(response, "authenticatorData"), limit=MAX_AUTHENTICATOR_DATA)
    signature = b64url_decode(_field(response, "signature"), limit=MAX_SIGNATURE)
    data = parse_authenticator_data(auth_raw)
    if data.credential_id is not None:
        # Assertions never carry attested credential data.
        raise _fail()
    if not hmac.compare_digest(data.rp_id_hash, rp.rp_id_hash):
        raise _fail()
    if not data.user_present or not data.user_verified:
        raise _fail()
    key = parse_cose_key(stored_public_key)
    if key.algorithm != stored_algorithm:
        raise _fail()
    verify_signature(key, signature, auth_raw + hashlib.sha256(client_raw).digest())
    return VerifiedAssertion(raw_id, data.sign_count, data.backup_eligible, data.backup_state)


def sign_count_advances(stored: int, received: int) -> bool:
    """Apply the §11.4 counter rule.

    Only an authenticator that keeps no counter (stored and received both 0)
    is exempt. Whenever either value is non-zero the received value must be
    strictly greater; a received 0 after a stored non-zero is a regression.
    """
    if stored == 0 and received == 0:
        return True
    return received > stored
