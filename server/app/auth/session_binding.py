"""Deployment-local key for the supplementary proxy-identity session binding.

ADR-0003/ADR-0004 and SPECIFICATION §11.4: a session never stores the raw
trusted-proxy identity. It stores HMAC-SHA-256 over the canonical verified
identity under a deployment-local secret kept outside the database, and every
later request recomputes the binding and compares it in constant time.

The binding is a consistency signal only. In the shared-Tailnet-account
deployment every invited person arrives with the same Tailscale login, so the
binding never tells people apart and never grants anything: a matching binding
is necessary for an existing session to keep working, never sufficient for
access. The per-person key is the invitation and the passkey credential.

The key file is created once (``load_or_create``) with mode 0600 in a directory
owned by the service account, is refused when its ownership, mode, link count or
size is wrong, and is never logged, displayed, exported, put in diagnostics or
stored in the database. It is unrelated to Tailscale administrative
credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat


KEY_BYTES = 32
BINDING_BYTES = 32
_DOMAIN = b"serversentinel/session-proxy-identity-binding/v1\x00"


class SessionBindingKeyError(RuntimeError):
    """The binding key is unavailable; carries no path, key or identity."""

    def __init__(self) -> None:
        super().__init__("session binding key is unavailable")


def canonical_identity(value: object) -> str | None:
    """Return the canonical verified proxy identity, or ``None`` when unusable.

    The identity is compared exactly as the trusted proxy supplied it: 1–256
    printable ASCII characters without spaces. No case folding is applied, so a
    differently spelled value can only fail the comparison, never widen it.
    """
    if (not isinstance(value, str) or not 1 <= len(value) <= 256 or not value.isascii()
            or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        return None
    return value


class SessionBindingKey:
    """Holds the deployment-local HMAC key; never reveals it."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != KEY_BYTES:
            raise SessionBindingKeyError()
        self._key = key

    @classmethod
    def generate(cls) -> "SessionBindingKey":
        """An in-memory key (tests and fixtures; runtime uses ``load_or_create``)."""
        return cls(secrets.token_bytes(KEY_BYTES))

    def __repr__(self) -> str:
        return "SessionBindingKey(<redacted>)"

    __str__ = __repr__

    def __reduce__(self):
        # Never serialize the key through pickle/copy into another store.
        raise TypeError("session binding key cannot be serialized")

    def __eq__(self, other: object) -> bool:
        return self is other

    __hash__ = object.__hash__

    def bind(self, identity: object) -> bytes | None:
        """HMAC-SHA-256 over the canonical identity, or ``None`` when unusable."""
        canonical = canonical_identity(identity)
        if canonical is None:
            return None
        return hmac.new(self._key, _DOMAIN + canonical.encode("ascii"), hashlib.sha256).digest()

    def matches(self, stored: object, identity: object) -> bool:
        """Constant-time comparison of a stored binding with a fresh one."""
        fresh = self.bind(identity)
        if fresh is None or not isinstance(stored, (bytes, bytearray, memoryview)):
            return False
        stored = bytes(stored)
        if len(stored) != BINDING_BYTES:
            return False
        return hmac.compare_digest(stored, fresh)

    # --- durable deployment key ---

    @classmethod
    def load_or_create(cls, path: Path) -> "SessionBindingKey":
        """Load the deployment key, creating it once with mode 0600 if absent.

        The parent directory must be an existing directory owned by the
        service account and not writable by group or others. An existing key
        file must be a regular, singly linked, 0600 file of that account with
        exactly ``KEY_BYTES`` bytes; anything else fails closed instead of
        being repaired or replaced, because replacing the key silently would
        invalidate every session and hide tampering. Creation publishes the
        file atomically, so concurrent starts agree on one key. The one extra
        link that is tolerated is a creation staging name of the same file
        (a concurrent start that has not removed it yet, or one that died
        before it could); it is removed before the single-link check.
        """
        try:
            if not isinstance(path, Path) or not path.is_absolute() or not path.name or path.name in (".", ".."):
                raise ValueError
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except (OSError, ValueError):
            raise SessionBindingKeyError() from None
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise SessionBindingKeyError()
            try:
                return cls(_read_key(path.name, directory))
            except FileNotFoundError:
                pass
            return cls(_create_key(path.name, directory))
        except SessionBindingKeyError:
            raise
        except Exception:
            raise SessionBindingKeyError() from None
        finally:
            os.close(directory)


def _staging_pattern(name: str):
    return re.compile(re.escape(f".{name}.") + r"[0-9a-f]{16}\.tmp")


def _drop_staging_links(name: str, directory: int, info: os.stat_result) -> None:
    """Remove creation staging names that are hard links of the published key.

    ``_create_key`` publishes with ``link()`` and then unlinks its staging
    name, so between the two steps -- or forever, when that start died in
    between -- the key has a second link named ``.<name>.<16 hex>.tmp``. Only
    such a name that refers to the very same regular file is removed; any other
    extra link is left in place and the key is still refused.
    """
    pattern = _staging_pattern(name)
    for entry in os.listdir(directory):
        if not pattern.fullmatch(entry):
            continue
        try:
            other = os.stat(entry, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISREG(other.st_mode) and (other.st_dev, other.st_ino) == (info.st_dev, info.st_ino):
                os.unlink(entry, dir_fd=directory)
        except FileNotFoundError:
            # The creating start removed its own staging name meanwhile.
            pass


def _read_key(name: str, directory: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            _drop_staging_links(name, directory, info)
            info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != KEY_BYTES):
            raise SessionBindingKeyError()
        data = b""
        while len(data) <= KEY_BYTES:
            chunk = os.read(descriptor, KEY_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) != KEY_BYTES:
            raise SessionBindingKeyError()
        return data
    finally:
        os.close(descriptor)


def _create_key(name: str, directory: int) -> bytes:
    key = secrets.token_bytes(KEY_BYTES)
    staging = f".{name}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
    try:
        try:
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < KEY_BYTES:
                written += os.write(descriptor, key[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            # link() refuses an existing name, so a concurrent start that won
            # the race keeps its key and this one reads it back.
            os.link(staging, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            return _read_key(name, directory)
    finally:
        try:
            os.unlink(staging, dir_fd=directory)
        except FileNotFoundError:
            pass
    os.fsync(directory)
    return _read_key(name, directory)
