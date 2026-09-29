"""GitHub App JWT -> installation token exchange for the review gate (#4).

This adapter runs only inside the Owner-controlled publisher deployment.  It
builds a short-lived App JWT, exchanges it for an installation token limited to
the one configured repository and the publisher's fixed permissions, validates
GitHub's answer, and refreshes the token before it expires.

Secret handling rules enforced here:

* the App key, the App JWT and the installation token live only in process
  memory.  They are never written to a file, ``os.environ``, a subprocess
  argument vector, a log record, ``repr()``, or an exception message;
* every failure raises ``TokenFailure`` with a fixed message and a suppressed
  exception chain, and drops any cached token (fail closed);
* no retry loop runs here.  The caller keeps the required check absent and
  tries again on its next reconciliation pass (bounded, no busy loop).

RS256 signing is deliberately *not* implemented.  The standard library has no
RSA signature primitive and no pinned dependency in this repository provides
one.  Adopting a crypto library, or any hand-written RSA, is an Owner /
license decision (AGENTS.md sections 13 and 18).  Until then the default
``UnconfiguredRs256Signer`` refuses to sign, so the exchange fails closed.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import logging
import re
import threading
import time
from typing import Any, Callable, Protocol

from pathlib import Path

from scripts.ci.review_gate_publisher import (GitHubTransport, PublisherFailure,
                                              RuntimeConfig, load_app_private_key)


LOG = logging.getLogger("server_sentinel.review_gate.app_token")
JWT_BACKDATE_SECONDS = 60
JWT_LIFETIME_SECONDS = 540  # iat is backdated, so exp - iat stays at 10 minutes.
REFRESH_MARGIN_SECONDS = 300
MAX_TOKEN_LIFETIME_SECONDS = 3600
CLOCK_SKEW_ALLOWANCE_SECONDS = 300
RSA_SIGNATURE_BYTES = frozenset({256, 384, 512})
# Exactly what the publisher and collector call; nothing that writes source.
REQUESTED_PERMISSIONS = {
    "checks": "write",
    "contents": "read",
    "metadata": "read",
    "pull_requests": "read",
}
_TOKEN = re.compile(r"ghs_[A-Za-z0-9_]{20,500}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class TokenFailure(RuntimeError):
    """Fail-closed token error; messages never include secret material."""


class Rs256Signer(Protocol):
    """RSASSA-PKCS1-v1_5 SHA-256 signer bound to the external App key."""

    def sign(self, signing_input: bytes) -> bytes:
        ...


class UnconfiguredRs256Signer:
    """Default signer until the Owner approves an RS256 implementation."""

    def __init__(self, private_key_pem: bytes | None = None) -> None:
        del private_key_pem  # Never retained.

    def __repr__(self) -> str:
        return "UnconfiguredRs256Signer()"

    def sign(self, signing_input: bytes) -> bytes:
        raise TokenFailure("RS256 signer is not configured (Owner decision pending)")


class _Secret:
    """Opaque holder whose text forms never reveal the value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<redacted>"

    __str__ = __repr__

    def __reduce__(self):  # type: ignore[no-untyped-def]
        raise TypeError("secret values are not serializable")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_segment(value: dict[str, Any]) -> str:
    return _b64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def build_app_jwt(app_id: int, signer: Rs256Signer, now: int) -> _Secret:
    """Return a signed App JWT (``iss`` = App ID) valid for at most 10 minutes."""
    if type(app_id) is not int or app_id <= 0 or type(now) is not int or now <= 0:
        raise TokenFailure("invalid App JWT input")
    signing_input = (_json_segment({"alg": "RS256", "typ": "JWT"}) + "."
                     + _json_segment({"iat": now - JWT_BACKDATE_SECONDS,
                                      "exp": now + JWT_LIFETIME_SECONDS,
                                      "iss": app_id}))
    try:
        signature = signer.sign(signing_input.encode("ascii"))
    except TokenFailure:
        raise
    except Exception:
        raise TokenFailure("App JWT signing failed") from None
    if not isinstance(signature, bytes) or len(signature) not in RSA_SIGNATURE_BYTES:
        raise TokenFailure("App JWT signing failed")
    return _Secret(signing_input + "." + _b64url(signature))


def _parse_expiry(value: Any) -> int:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise TokenFailure("invalid installation token response")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise TokenFailure("invalid installation token response") from None
    return int(parsed.replace(tzinfo=timezone.utc).timestamp())


class InstallationTokenSource:
    """Single-flight, in-memory installation token cache with early refresh."""

    def __init__(self, config: RuntimeConfig, signer: Rs256Signer,
                 transport: GitHubTransport,
                 clock: Callable[[], float] = time.time) -> None:
        if not isinstance(config, RuntimeConfig):
            raise TokenFailure("invalid review gate configuration")
        self._config = config
        self._signer = signer
        self._transport = transport
        self._clock = clock
        self._lock = threading.Lock()
        self._token: _Secret | None = None
        self._expires_at = 0

    def __repr__(self) -> str:
        return (f"InstallationTokenSource(installation_id="
                f"{self._config.installation_id}, cached={self._token is not None})")

    def _now(self) -> int:
        try:
            now = self._clock()
        except Exception:
            raise TokenFailure("clock is unavailable") from None
        if not isinstance(now, (int, float)) or now <= 0:
            raise TokenFailure("clock is unavailable")
        return int(now)

    def token(self) -> str:
        """Return a token valid for at least ``REFRESH_MARGIN_SECONDS``."""
        with self._lock:
            now = self._now()
            if self._token is not None and self._expires_at - now > REFRESH_MARGIN_SECONDS:
                return self._token.reveal()
            self._token, self._expires_at = None, 0
            try:
                token, expires_at = self._exchange(now)
            except TokenFailure as exc:
                # The message is one of this module's fixed strings.
                LOG.warning("installation token unavailable installation=%d reason=%s",
                            self._config.installation_id, exc)
                raise
            self._token, self._expires_at = token, expires_at
            LOG.info("installation token refreshed installation=%d expires_in=%ds",
                     self._config.installation_id, expires_at - now)
            return token.reveal()

    def invalidate(self) -> None:
        """Drop the cached token, e.g. after GitHub rejected it."""
        with self._lock:
            self._token, self._expires_at = None, 0

    def _exchange(self, now: int) -> tuple[_Secret, int]:
        config = self._config
        jwt = build_app_jwt(config.issuer.app_id, self._signer, now)
        payload = {"repository_ids": [config.repository_id],
                   "permissions": dict(REQUESTED_PERMISSIONS)}
        try:
            response = self._transport.post_json(
                f"/app/installations/{config.installation_id}/access_tokens",
                jwt.reveal(), payload)
        except Exception:  # PublisherFailure or an unexpected transport error.
            raise TokenFailure("installation token exchange failed") from None
        finally:
            del jwt
        return self._validated(response, now)

    def _validated(self, response: Any, now: int) -> tuple[_Secret, int]:
        config = self._config
        if not isinstance(response, dict):
            raise TokenFailure("invalid installation token response")
        token = response.get("token")
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise TokenFailure("invalid installation token response")
        expires_at = _parse_expiry(response.get("expires_at"))
        if not (now + REFRESH_MARGIN_SECONDS < expires_at
                <= now + MAX_TOKEN_LIFETIME_SECONDS + CLOCK_SKEW_ALLOWANCE_SECONDS):
            raise TokenFailure("installation token lifetime is out of bounds")
        # GitHub echoes the effective grant.  More permission than requested,
        # or less than the publisher needs, both fail closed.
        if response.get("permissions") != REQUESTED_PERMISSIONS:
            raise TokenFailure("installation token permissions differ from policy")
        repositories = response.get("repositories")
        if (response.get("repository_selection") != "selected"
                or not isinstance(repositories, list) or len(repositories) != 1
                or not isinstance(repositories[0], dict)
                or type(repositories[0].get("id")) is not int
                or repositories[0]["id"] != config.repository_id):
            raise TokenFailure("installation token is not limited to the repository")
        return _Secret(token), expires_at


def open_token_source(config: RuntimeConfig, checkout_root: Path,
                      transport: GitHubTransport,
                      signer_factory: Callable[[bytes], Rs256Signer] = UnconfiguredRs256Signer,
                      clock: Callable[[], float] = time.time) -> InstallationTokenSource:
    """Load the external private key and bind it to a signer, then discard it.

    The key is read with the publisher's descriptor-level checks (absolute,
    private, regular, outside the checkout).  Only the signer keeps it.
    """
    try:
        key = load_app_private_key(config, checkout_root)
    except PublisherFailure:
        raise TokenFailure("App private key is unavailable") from None
    try:
        signer = signer_factory(key)
    except Exception:
        raise TokenFailure("RS256 signer could not be initialised") from None
    finally:
        del key
    return InstallationTokenSource(config, signer, transport, clock)
