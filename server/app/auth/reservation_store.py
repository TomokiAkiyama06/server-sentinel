"""Durable reservation state in the existing ``application_metadata`` table.

Holds the Owner listener exceptions and the pending session-revocation marker
set after a possible exposure of the reserved name.

The foundation migration's key/value table holds one row under a fixed key, so
no migration is added. ``write_on`` runs only inside the audited Owner
transaction (``app.audit.integration.ReservationAdministration``), committing
with its ``change_security_setting`` record. ``load`` is strict: a missing row
is the empty default, and any other unexpected value raises so the check fails
closed with an Owner fault instead of guessing.
"""

from contextlib import closing
import json
import sqlite3
from uuid import UUID

from app.audit.model import ActorCategory, AuditAction, AuditOutcome, TargetKind
from app.storage.database import Database, PinnedDatabase
from .store import AccessStore
from .reservation import (
    AddressFamily, BindScope, ListenerException, ListenerExceptionsOutdated, MAX_LISTENER_EXCEPTIONS,
    TransportProtocol,
)


STORE_KEY = "auth.reservation.listener_exceptions"
REVOCATION_PENDING_KEY = "auth.reservation.session_revocation_pending"
# Fixed logical ID for "every human session"; the audit record names no person.
HUMAN_SESSIONS_ID = UUID("0b6f3f64-54a9-4e0f-8f5e-7d2c9a4b1e37")
# Version 1 held port-only exceptions. They are not migrated: an owner cannot
# be inferred, so a stored version 1 set fails closed as outdated until the
# Owner enters the exceptions again with their owning process (2026-10-01).
FORMAT_VERSION = 2
OUTDATED_VERSIONS = frozenset({1})
MAX_STORED_BYTES = 32768


class ListenerExceptionStoreError(RuntimeError):
    """Stored exceptions are unreadable or corrupt; carries no stored value."""


class OutdatedListenerExceptions(ListenerExceptionStoreError, ListenerExceptionsOutdated):
    """Stored exceptions use the port-only format; the Owner must re-enter them."""


def encode(exceptions) -> str:
    values = frozenset(exceptions)
    if len(values) > MAX_LISTENER_EXCEPTIONS or any(not isinstance(item, ListenerException) for item in values):
        raise ValueError("INVALID_LISTENER_EXCEPTION")
    entries = sorted(
        ({"protocol": item.protocol.value, "port": item.port,
          "family": None if item.family is None else item.family.value, "scope": item.scope.value,
          "executable": item.executable, "unit": item.unit}
         for item in values),
        key=lambda entry: (entry["port"], entry["family"] or "", entry["protocol"], entry["scope"],
                           entry["executable"] or "", entry["unit"] or ""),
    )
    text = json.dumps({"version": FORMAT_VERSION, "exceptions": entries}, separators=(",", ":"))
    if len(text.encode()) > MAX_STORED_BYTES:
        raise ValueError("INVALID_LISTENER_EXCEPTION")
    return text


def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        # ``json.loads`` would otherwise keep the last member silently.
        raise ValueError("duplicate member")
    return dict(pairs)


def decode(text) -> frozenset:
    if not isinstance(text, str) or len(text.encode()) > MAX_STORED_BYTES:
        raise ListenerExceptionStoreError("LISTENER_EXCEPTIONS_UNREADABLE")
    try:
        document = json.loads(text, object_pairs_hook=_no_duplicates)
        if (isinstance(document, dict) and type(document.get("version")) is int
                and document["version"] in OUTDATED_VERSIONS):
            raise OutdatedListenerExceptions("LISTENER_EXCEPTIONS_OUTDATED")
        if (not isinstance(document, dict) or set(document) != {"version", "exceptions"}
                or type(document["version"]) is not int or document["version"] != FORMAT_VERSION
                or not isinstance(document["exceptions"], list)
                or len(document["exceptions"]) > MAX_LISTENER_EXCEPTIONS):
            raise ValueError
        result = []
        for entry in document["exceptions"]:
            if not isinstance(entry, dict) or set(entry) != {"protocol", "port", "family", "scope",
                                                              "executable", "unit"}:
                raise ValueError
            family = entry["family"]
            result.append(ListenerException(
                entry["port"], TransportProtocol(entry["protocol"]),
                None if family is None else AddressFamily(family), BindScope(entry["scope"]),
                executable=entry["executable"], unit=entry["unit"],
            ))
        values = frozenset(result)
        if len(values) != len(result):
            raise ValueError
        return values
    except (ValueError, TypeError, RecursionError):
        raise ListenerExceptionStoreError("LISTENER_EXCEPTIONS_UNREADABLE") from None


class ListenerExceptionStore:
    def __init__(self, database: Database | PinnedDatabase):
        if not isinstance(database, (Database, PinnedDatabase)):
            raise ValueError("database is required")
        self.database = database

    def load(self) -> frozenset:
        try:
            with closing(self.database.connect()) as connection:
                row = connection.execute(
                    "SELECT value FROM application_metadata WHERE key=?", (STORE_KEY,)
                ).fetchone()
        except sqlite3.Error:
            raise ListenerExceptionStoreError("LISTENER_EXCEPTIONS_UNREADABLE") from None
        return frozenset() if row is None else decode(row[0])

    def write_on(self, connection: sqlite3.Connection, exceptions) -> None:
        """Write inside the caller's (audited) transaction; never commits."""
        if not connection.in_transaction:
            raise ListenerExceptionStoreError("audited transaction is required")
        connection.execute(
            "INSERT INTO application_metadata(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (STORE_KEY, encode(exceptions)),
        )


class ReservationSessionRevocation:
    """Revoke every human session before access reopens after a possible exposure.

    Owner decision (2026-09-30, PR #91): a listener or route that answered for
    the reserved name may have received session cookies, so reopening first
    advances the authorization generation and invalidates every human session,
    committing that together with a ``system`` ``invalidate_human_sessions``
    audit record. ``record_exposure`` persists a marker so a restart before the
    revocation still revokes before opening.
    """

    def __init__(self, access_store: AccessStore):
        if not isinstance(access_store, AccessStore) or access_store.audit is None \
                or access_store.audit.database != access_store.database:
            raise ValueError("an audited access store is required")
        self.access_store = access_store
        self.audit = access_store.audit

    def record_exposure(self) -> None:
        with self.audit.transaction(write=True) as connection:
            connection.execute(
                "INSERT INTO application_metadata(key, value) VALUES (?, '1') "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (REVOCATION_PENDING_KEY,))

    def exposure_pending(self) -> bool:
        """Raise when unreadable; the caller then treats revocation as required."""
        try:
            with closing(self.access_store.database.connect()) as connection:
                row = connection.execute("SELECT value FROM application_metadata WHERE key=?",
                                         (REVOCATION_PENDING_KEY,)).fetchone()
        except sqlite3.Error:
            raise ListenerExceptionStoreError("REVOCATION_STATE_UNREADABLE") from None
        if row is None:
            return False
        if row[0] != "1":
            raise ListenerExceptionStoreError("REVOCATION_STATE_UNREADABLE")
        return True

    def revoke_all_human_sessions(self) -> None:
        """Commit the revocation, marker removal and audit record together, or raise."""
        at = self.access_store.now()
        try:
            with self.audit.transaction(write=True) as connection:
                self.access_store.invalidate_all_sessions_on(connection, at=at)
                connection.execute("DELETE FROM application_metadata WHERE key=?", (REVOCATION_PENDING_KEY,))
                self.audit.append_on(connection, actor_category=ActorCategory.SYSTEM,
                                     action=AuditAction.INVALIDATE_HUMAN_SESSIONS,
                                     target_kind=TargetKind.SECURITY_SETTINGS,
                                     target_logical_id=HUMAN_SESSIONS_ID, outcome=AuditOutcome.SUCCEEDED)
        except Exception:
            try:
                self.audit.append(actor_category=ActorCategory.SYSTEM,
                                  action=AuditAction.INVALIDATE_HUMAN_SESSIONS,
                                  target_kind=TargetKind.SECURITY_SETTINGS,
                                  target_logical_id=HUMAN_SESSIONS_ID, outcome=AuditOutcome.FAILED)
            except Exception:
                pass
            raise
