"""Durable Owner listener exceptions in the existing ``application_metadata`` table.

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

from app.storage.database import Database, PinnedDatabase
from .reservation import (
    AddressFamily, BindScope, ListenerException, MAX_LISTENER_EXCEPTIONS, TransportProtocol,
)


STORE_KEY = "auth.reservation.listener_exceptions"
FORMAT_VERSION = 1
MAX_STORED_BYTES = 4096


class ListenerExceptionStoreError(RuntimeError):
    """Stored exceptions are unreadable or corrupt; carries no stored value."""


def encode(exceptions) -> str:
    values = frozenset(exceptions)
    if len(values) > MAX_LISTENER_EXCEPTIONS or any(not isinstance(item, ListenerException) for item in values):
        raise ValueError("INVALID_LISTENER_EXCEPTION")
    entries = sorted(
        ({"protocol": item.protocol.value, "port": item.port,
          "family": None if item.family is None else item.family.value, "scope": item.scope.value}
         for item in values),
        key=lambda entry: (entry["port"], entry["family"] or "", entry["protocol"], entry["scope"]),
    )
    return json.dumps({"version": FORMAT_VERSION, "exceptions": entries}, separators=(",", ":"))


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
        if (not isinstance(document, dict) or set(document) != {"version", "exceptions"}
                or type(document["version"]) is not int or document["version"] != FORMAT_VERSION
                or not isinstance(document["exceptions"], list)
                or len(document["exceptions"]) > MAX_LISTENER_EXCEPTIONS):
            raise ValueError
        result = []
        for entry in document["exceptions"]:
            if not isinstance(entry, dict) or set(entry) != {"protocol", "port", "family", "scope"}:
                raise ValueError
            family = entry["family"]
            result.append(ListenerException(
                entry["port"], TransportProtocol(entry["protocol"]),
                None if family is None else AddressFamily(family), BindScope(entry["scope"]),
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
