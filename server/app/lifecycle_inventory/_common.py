"""Shared primitives of the lifecycle inventory (Issue #47, split in #256).

The report format identity, the read-only state-database snapshot, value
digests (plain and keyed), the type checks the domain rules share, and the
``_fail_closed`` boundary: a comparison rule given a malformed stored value
returns its fail-closed default instead of aborting verification.

``_utcnow()`` is looked up on this module by every caller (``_common._utcnow()``),
so one replacement sets the verify time for the whole inventory.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote
from uuid import UUID


FORMAT = "server-sentinel-lifecycle-inventory"
FORMAT_VERSION = 1


class InventoryError(RuntimeError):
    """Refused or failed without echoing deployment paths or stored values."""


@dataclass(frozen=True)
class RuntimeTree:
    root: Path

    @property
    def database(self) -> Path:
        return self.root / "state" / "state.sqlite3"

    @property
    def recordings(self) -> Path:
        return self.root / "recordings"


def _json_value(value):
    """A stored value json cannot encode (a BLOB where text belongs) is
    digested by its type and bytes, so a malformed row is a change, never a
    crash."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"blob": bytes(value).hex()}
    return {"unencodable": type(value).__name__}


def _blob_hex(value):
    """Hex of a BLOB column; a wrong-typed value is kept as its type and
    repr (never through bytes(), which turns an int into zero bytes)."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return {"not_blob": type(value).__name__, "value": repr(value)}


def _fail_closed(default):
    """A comparison rule given a malformed stored value fails closed
    (``default``) instead of aborting verification; the current-state
    checks report the malformed value itself."""
    def wrap(function):
        @functools.wraps(function)
        def checked(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except (TypeError, ValueError, OverflowError, AttributeError, KeyError, IndexError):
                return default
        return checked
    return wrap


def _digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True,
                         default=_json_value)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _absolute(path: Path, what: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise InventoryError(f"{what} must be an absolute path without '..'")
    return path


def _connect_read_only(database: Path) -> sqlite3.Connection:
    try:
        info = os.lstat(database)
    except OSError:
        raise InventoryError("state database is unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise InventoryError("state database is unavailable")
    try:
        # mode=ro never creates a database or a fallback file; query_only also
        # refuses any statement that would write.
        connection = sqlite3.connect(
            "file:" + quote(str(database)) + "?mode=ro", uri=True,
            timeout=5, isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
    except sqlite3.Error:
        raise InventoryError("state database is unavailable") from None
    return connection


def _snapshot(database: Path) -> sqlite3.Connection:
    """A private in-memory copy of the state database, taken in one step.

    The SQLite online backup copies every page in a single step, so the
    shared lock on the state database is held only for that page copy (well
    under a second for 200 000 segments) and the copy is one consistent
    snapshot. Every query, validation and digest then runs on the copy: a
    service writer (DELETE journal mode, 5 s busy timeout) never waits for
    them. The copy needs memory of about the database size and is itself
    query-only.
    """
    source = _connect_read_only(database)
    try:
        snapshot = sqlite3.connect(":memory:", isolation_level=None)
        try:
            source.backup(snapshot)
        except sqlite3.Error:
            snapshot.close()
            raise
    except sqlite3.Error:
        raise InventoryError("state database could not be read") from None
    finally:
        source.close()
    snapshot.row_factory = sqlite3.Row
    snapshot.execute("PRAGMA query_only = ON")
    return snapshot


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _keyed(salt: str, value: object) -> str:
    """HMAC-SHA-256 under the per-inventory random salt.

    Used for stable but sensitive material (camera identity, credential
    public material, the Owner template) so the baseline never holds the raw
    value and the digest is no stable cross-file identifier. Whoever holds the
    baseline (and so its salt) can still test a guessed value, so the file
    stays deployment-local.
    """
    message = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True,
                         default=_json_value)
    return hmac.new(bytes.fromhex(salt), message.encode(), hashlib.sha256).hexdigest()


def _utc_instant(value):
    """A time as the integrity, Owner-template and monitoring stores write it
    (value.astimezone(utc).isoformat()), parsed; None for anything else."""
    try:
        moment = datetime.fromisoformat(value)
        if moment.tzinfo is None or moment.astimezone(timezone.utc).isoformat() != value:
            return None
        return moment
    except (TypeError, ValueError, AttributeError):
        return None


def _row_order(item) -> str:
    """A total order for rows of any stored types (a malformed value must
    never make sorting, and so the run, fail)."""
    return json.dumps(item, separators=(",", ":"), sort_keys=True, default=_json_value)


def _canonical_uuid(value) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _json(value) -> bool:
    try:
        json.loads(value)
        return isinstance(value, str)
    except (TypeError, ValueError):
        return False


def _int(value, low=0, high=2**63 - 1) -> bool:
    return type(value) is int and low <= value <= high


def _hex_digest(value) -> bool:
    """A lowercase SHA-256 hex digest (pairing ``_digest()``, segment sha256)."""
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _compare_keyed(baseline: dict | None, current: dict | None, *,
                   declared: frozenset[str] = frozenset(), rewrite_only=None) -> dict:
    if not baseline:
        return {"status": "empty", "preserved": [], "failed": [],
                "appended": sorted(current or {}), "declared_rewrites": []}
    current = current or {}
    preserved, failed, rewrites = [], [], []
    for key, value in sorted(baseline.items()):
        if key not in current:
            failed.append({"id": key, "reason": "missing"})
        elif current[key] == value:
            preserved.append(key)
        elif key in declared and rewrite_only is not None and rewrite_only(value, current[key]):
            rewrites.append(key)
        else:
            failed.append({"id": key, "reason": "changed"})
    return {"status": "failed" if failed else "preserved",
            "preserved": preserved, "failed": failed,
            "appended": sorted(set(current) - set(baseline)),
            "declared_rewrites": rewrites}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)
