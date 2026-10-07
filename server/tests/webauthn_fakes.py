"""Synthetic WebAuthn authenticator for tests.

Keys are generated fresh in each test process. No real credential, attestation
certificate, authenticator identifier or biometric data is used or committed.
"""

import base64
from contextlib import contextmanager
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.auth.webauthn import EDDSA, ES256, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV, RS256


ORIGIN = "https://sentinel.example.invalid"
RP_ID = "sentinel.example.invalid"
# Pass as a client-data field value to omit that field entirely.
_DROP = object()


class OpenGate:
    """Synthetic always-open session gate (Issue #144) for ceremony tests
    that do not exercise the hostname reservation check; counts admissions."""

    def __init__(self):
        self.admitted = 0

    def epoch(self):
        return 0

    @contextmanager
    def admit(self, epoch):
        assert epoch == 0
        self.admitted += 1
        yield


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([major << 5 | argument])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 1 << (8 * size):
            return bytes([major << 5 | info]) + argument.to_bytes(size, "big")
    raise ValueError("argument too large")


def cbor(value) -> bytes:
    """Minimal CBOR encoder for synthetic attestation objects and COSE keys."""
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError("unsupported synthetic CBOR value")


class SyntheticAuthenticator:
    """A software authenticator holding one synthetic credential."""

    def __init__(self, algorithm=ES256, *, backup_eligible=False, backup_state=False,
                 credential_id=None, sign_count=0):
        self.algorithm = algorithm
        self.backup_eligible = backup_eligible
        self.backup_state = backup_state
        self.sign_count = sign_count
        # Random per instance: synthetic, never a real authenticator's identifier.
        self.credential_id = credential_id or os.urandom(16)
        if algorithm == ES256:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        elif algorithm == EDDSA:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        elif algorithm == RS256:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise ValueError("unsupported synthetic algorithm")
        self.user_handle = None

    def cose_key(self) -> bytes:
        public = self.private_key.public_key()
        if self.algorithm == ES256:
            numbers = public.public_numbers()
            return cbor({1: 2, 3: ES256, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
        if self.algorithm == EDDSA:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            return cbor({1: 1, 3: EDDSA, -1: 6, -2: public.public_bytes(Encoding.Raw, PublicFormat.Raw)})
        numbers = public.public_numbers()
        return cbor({1: 3, 3: RS256, -1: numbers.n.to_bytes(256, "big"), -2: numbers.e.to_bytes(3, "big")})

    def sign(self, message: bytes) -> bytes:
        if self.algorithm == ES256:
            return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        if self.algorithm == EDDSA:
            return self.private_key.sign(message)
        return self.private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def _flags(self, *, up=True, uv=True, attested=False, be=None, bs=None) -> int:
        be = self.backup_eligible if be is None else be
        bs = self.backup_state if bs is None else bs
        return ((FLAG_UP if up else 0) | (FLAG_UV if uv else 0) | (FLAG_AT if attested else 0)
                | (FLAG_BE if be else 0) | (FLAG_BS if bs else 0))

    @staticmethod
    def client_data(kind, challenge, origin, **extra) -> bytes:
        body = {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}
        body.update(extra)
        for key in [key for key, value in body.items() if value is _DROP]:
            del body[key]
        return json.dumps(body).encode()

    def register(self, options, *, origin=ORIGIN, rp_id=RP_ID, up=True, uv=True, kind="webauthn.create",
                 challenge=None, fmt="none", statement=None, raw_id=None, client_extra=None) -> dict:
        challenge = options["challenge"] if challenge is None else challenge
        client = self.client_data(kind, challenge, origin, **(client_extra or {}))
        auth_data = (hashlib.sha256(rp_id.encode()).digest()
                     + bytes([self._flags(up=up, uv=uv, attested=True)])
                     + struct.pack(">I", self.sign_count) + b"\x00" * 16
                     + struct.pack(">H", len(self.credential_id)) + self.credential_id + self.cose_key())
        if statement is None:
            statement = {}
            if fmt == "packed":
                statement = {"alg": self.algorithm,
                             "sig": self.sign(auth_data + hashlib.sha256(client).digest())}
        self.user_handle = unb64(options["user"]["id"])
        raw = self.credential_id if raw_id is None else raw_id
        return {"id": b64(raw), "rawId": b64(raw), "type": "public-key",
                "response": {"clientDataJSON": b64(client),
                             "attestationObject": b64(cbor({"fmt": fmt, "attStmt": statement, "authData": auth_data}))}}

    def assertion(self, options, *, origin=ORIGIN, rp_id=RP_ID, up=True, uv=True, kind="webauthn.get",
                  challenge=None, count=None, be=None, bs=None, user_handle=None,
                  omit_user_handle=False, tamper=False, advance=True) -> dict:
        if count is None:
            if advance and self.sign_count:
                self.sign_count += 1
            count = self.sign_count
        challenge = options["challenge"] if challenge is None else challenge
        client = self.client_data(kind, challenge, origin)
        auth_data = (hashlib.sha256(rp_id.encode()).digest()
                     + bytes([self._flags(up=up, uv=uv, be=be, bs=bs)]) + struct.pack(">I", count))
        signature = self.sign(auth_data + hashlib.sha256(client).digest())
        if tamper:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        response = {"clientDataJSON": b64(client), "authenticatorData": b64(auth_data),
                    "signature": b64(signature)}
        handle = self.user_handle if user_handle is None else user_handle
        if not omit_user_handle and handle is not None:
            response["userHandle"] = b64(handle)
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id), "type": "public-key",
                "response": response}
