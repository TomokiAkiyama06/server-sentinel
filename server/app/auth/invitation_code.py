"""Invitation codes and bootstrap authorizations (Issue #10 phase 2 S2, Owner decision D5).

A code is a bearer authorization on a path every holder of the shared
Tailscale account can reach (REQUIREMENTS AUTH-013, ADR-0004 §4). It is
therefore:

- 20 bytes (160 bits) from ``secrets.token_bytes``: above the 128-bit floor,
  and the whole generated value is what the server checks (its SHA-256
  digest, ``AccessStore``), never a shortened display form;
- shown as 32 characters of the Crockford base32 alphabet
  (``0-9 A-Z`` without ``I``, ``L``, ``O`` and ``U``, so ``0``/``O`` and
  ``1``/``I``/``L`` cannot be confused), in eight groups of four joined by
  ``-``: ``XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX``;
- valid for 24 hours (``INVITATION_LIFETIME``, D5) and single use.

``parse_invitation_code`` is strict: only that exact canonical form is
accepted (upper case, the hyphens exactly at the group boundaries, nothing
around it). Lenient reading of hand-typed input (lower case, spaces, the
Crockford aliases) belongs to the Web page, which sends the canonical form;
the server never guesses. A refusal raises ``InvalidInvitationCode`` with a
fixed message and never carries the input.
"""

from __future__ import annotations

from datetime import timedelta
import re
import secrets
from typing import Callable


INVITATION_LIFETIME = timedelta(hours=24)
CODE_BYTES = 20
GROUP = 4
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_VALUES = {character: index for index, character in enumerate(ALPHABET)}
_CHARACTERS = CODE_BYTES * 8 // 5
_CLASS = "[" + re.escape(ALPHABET) + "]"
_CANONICAL = re.compile(
    rf"{_CLASS}{{{GROUP}}}(?:-{_CLASS}{{{GROUP}}}){{{_CHARACTERS // GROUP - 1}}}")
# The canonical display form's exact length (32 characters and 7 hyphens).
DISPLAY_LENGTH = _CHARACTERS + _CHARACTERS // GROUP - 1


class InvalidInvitationCode(ValueError):
    """Not a canonical invitation code; carries no part of the input."""

    def __init__(self) -> None:
        super().__init__("invitation code is invalid")


def _encode(secret: bytes) -> str:
    value = int.from_bytes(secret, "big")
    characters = [ALPHABET[(value >> (5 * index)) & 31] for index in range(_CHARACTERS)]
    plain = "".join(reversed(characters))
    return "-".join(plain[index:index + GROUP] for index in range(0, _CHARACTERS, GROUP))


def format_invitation_code(secret: bytes) -> str:
    """The grouped display form of a 20-byte secret."""
    if not isinstance(secret, bytes) or len(secret) != CODE_BYTES:
        raise InvalidInvitationCode()
    return _encode(secret)


def parse_invitation_code(value: object) -> bytes:
    """The 20-byte secret of a canonical display form, or ``InvalidInvitationCode``."""
    if not isinstance(value, str) or len(value) != DISPLAY_LENGTH or not _CANONICAL.fullmatch(value):
        raise InvalidInvitationCode()
    number = 0
    for character in value:
        if character != "-":
            number = (number << 5) | _VALUES[character]
    return number.to_bytes(CODE_BYTES, "big")


def new_invitation_code(random_bytes: Callable[[int], bytes] = secrets.token_bytes) -> tuple[bytes, str]:
    """``(secret, display form)`` of a fresh code from the CSPRNG."""
    secret = random_bytes(CODE_BYTES)
    if not isinstance(secret, bytes) or len(secret) != CODE_BYTES:
        raise InvalidInvitationCode()
    return secret, _encode(secret)
