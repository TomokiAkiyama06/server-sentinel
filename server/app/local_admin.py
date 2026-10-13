"""Local administrative command building blocks shared by the Main CLIs.

Used by the capture-node pairing CLI (``app.cameras.remote_agent.pairing_cli``)
and the Owner bootstrap/recovery command (``app.auth.bootstrap_cli``), so the
human-access package never imports the capture-node package:

- ``CliRefused``: a fixed refusal word, never a code, key or path;
- ``ControllingTerminal``: the process's controlling terminal opened directly
  (``/dev/tty``, never stdin/stdout); without one, ``controlling_terminal_required``;
- ``_existing_database``: the application's existing database file, pinned for
  every later connection (canonical path, regular file with one link owned by
  the running account, not group/other writable, opened ``mode=rw`` and
  re-verified after the open and before each commit; never created);
- ``_require_current_schema``: refuse unless the schema is exactly this
  release's (administrative commands never migrate).

Moved unchanged from ``pairing_cli`` (Issue #10 phase 2 S2); the issue
references in the docstrings below are the original ones.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import threading
from urllib.parse import quote

from app.storage.database import Database, held_descriptors, hold_database_file
from app.storage.schema import APPLICATION_MIGRATIONS


_MAX_TERMINAL_LINE = 128


class CliRefused(RuntimeError):
    """A fixed CLI refusal word; never contains a code, key or path."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ControllingTerminal:
    """The process's controlling terminal, opened directly (never stdin/stdout)."""

    def __init__(self, *, opener=os.open):
        try:
            descriptor = opener("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        except OSError:
            raise CliRefused("controlling_terminal_required") from None
        if not os.isatty(descriptor):
            os.close(descriptor)
            raise CliRefused("controlling_terminal_required")
        self._descriptor = descriptor

    def write(self, text: str) -> None:
        data = memoryview(text.encode("utf-8"))
        try:
            while data:
                written = os.write(self._descriptor, data)
                data = data[written:]
        except OSError:
            raise CliRefused("controlling_terminal_unavailable") from None

    def read_line(self) -> str:
        buffer = b""
        try:
            while not buffer.endswith(b"\n"):
                chunk = os.read(self._descriptor, _MAX_TERMINAL_LINE)
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > _MAX_TERMINAL_LINE:
                    raise CliRefused("owner_confirmation_declined")
        except OSError:
            raise CliRefused("controlling_terminal_unavailable") from None
        return buffer.decode("utf-8", "replace").strip()

    def close(self) -> None:
        try:
            os.close(self._descriptor)
        except OSError:
            pass


def _safe_database_file(info: os.stat_result) -> bool:
    """A regular file with one link, owned by this account, not group/other writable."""
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022 and info.st_nlink == 1)


class _LedgerDatabaseChanged(sqlite3.DatabaseError):
    """The pinned ledger database is no longer the file that was validated.

    A ``sqlite3.Error`` so the audit store rolls back and the ledger reports
    its ordinary bounded storage failure; the CLI then refuses with
    ``database_rejected`` instead of reporting success.
    """


class _VerifiedConnection(sqlite3.Connection):
    """A connection that re-validates the pinned database before committing."""

    verify_database = None

    def _verify_before_commit(self, sql) -> None:
        if (isinstance(sql, str) and sql.strip().upper() in ("COMMIT", "END")
                and self.verify_database is not None):
            self.verify_database()

    def execute(self, sql, *parameters):
        self._verify_before_commit(sql)
        return super().execute(sql, *parameters)

    def commit(self):
        if self.verify_database is not None and self.in_transaction:
            self.verify_database()
        return super().commit()


_CONNECT_LOCK = threading.Lock()


def _regular_descriptors() -> dict[int, tuple[int, int]]:
    """This process's open regular-file descriptors as (device, inode).

    Read from ``/proc/self/fd`` (the Main is Linux-only); when it cannot be
    read the ledger connection is refused rather than left unverified.
    """
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        raise _LedgerDatabaseChanged("open descriptors cannot be inspected") from None
    found = {}
    for name in names:
        try:
            info = os.stat(f"/proc/self/fd/{name}")
        except OSError:
            continue  # closed meanwhile (including the listing's own descriptor)
        if stat.S_ISREG(info.st_mode):
            found[int(name)] = (info.st_dev, info.st_ino)
    return found


class _PinnedLedgerDatabase(Database):
    """The application's existing database, pinned for every ledger operation.

    ``Database.connect()`` reopens by pathname and creates a missing file, so
    a database renamed, replaced or removed after validation -- for example
    while ``approve``/``revoke`` waits for the Owner's confirmation -- could
    be silently swapped for another inode or recreated empty (Issue #125).
    Instead this object holds a read-only descriptor to the validated file,
    so its inode cannot be freed and reused, and every connection:

    * requires the path to still be canonical and name that same pinned
      inode, and the pinned file to still be a private regular file;
    * opens it with SQLite ``mode=rw`` (never creates a file);
    * re-checks both right after the open and again before ``COMMIT``.

    A failed check marks the database rejected; nothing is committed.
    """

    def __init__(self, path: Path, descriptor: int, identity: tuple[int, int]):
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "_descriptor", descriptor)
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(self, "_state", {"rejected": False, "released": False})

    @property
    def rejected(self) -> bool:
        return self._state["rejected"]

    def _reject(self) -> None:
        self._state["rejected"] = True
        raise _LedgerDatabaseChanged("ledger database changed")

    def verify(self) -> None:
        if self._state["released"]:
            self._reject()
        try:
            held = os.fstat(self._descriptor)
            current = os.lstat(self.path)
            canonical = os.path.realpath(self.path) == str(self.path)
        except OSError:
            self._reject()
        if (not canonical or not _safe_database_file(held)
                or (held.st_dev, held.st_ino) != self._identity
                or (current.st_dev, current.st_ino) != self._identity):
            self._reject()

    def _check_backing_file(self, before: dict[int, tuple[int, int]]) -> None:
        """Require the file SQLite actually opened to be the pinned inode.

        A path check alone cannot prove which inode ``sqlite3.connect()``
        opened: the path could name another file during the open and be
        restored before the post-open check. So the regular files this
        process gained during the open are compared by (device, inode) and
        every one must be the pinned file or one of its SQLite sidecars
        (``-journal``/``-wal``/``-shm``) at the expected path; a descriptor
        to any other file rejects the connection. SQLite may reuse a
        descriptor it already holds for the same inode (while another
        connection in this process keeps a lock on it) instead of opening a
        new one, so it is enough that some SQLite descriptor refers to the
        pinned file. The pin and every other descriptor kept by the
        process-wide holder in ``app.storage.database`` (which is where the
        pin comes from, Issue #152) are never SQLite's and never count as
        that witness; otherwise an application-held descriptor on the pinned
        inode would satisfy the check whatever SQLite opened.
        """
        after = _regular_descriptors()
        gained = {identity for descriptor, identity in after.items()
                  if before.get(descriptor) != identity}
        sidecars = set()
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                info = os.lstat(str(self.path) + suffix)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                sidecars.add((info.st_dev, info.st_ino))
        not_sqlite = held_descriptors() | {self._descriptor}
        opened = any(identity == self._identity and descriptor not in not_sqlite
                     for descriptor, identity in after.items())
        if not opened or gained - sidecars - {self._identity}:
            self._reject()

    def connect(self) -> sqlite3.Connection:
        # One open at a time per process, so concurrent opens (the enrollment
        # listener's workers) never look like an unexpected descriptor.
        with _CONNECT_LOCK:
            self.verify()
            before = _regular_descriptors()
            connection = sqlite3.connect(
                "file:" + quote(str(self.path)) + "?mode=rw", uri=True, timeout=5,
                isolation_level=None, factory=_VerifiedConnection)
            try:
                # Force the open and the schema read (and any WAL sidecars),
                # then check what was actually opened and that the path still
                # names the pinned file.
                connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
                self._check_backing_file(before)
                self.verify()
                connection.verify_database = self.verify
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
            except BaseException:
                connection.close()
                raise
        return connection

    def connect_read_only(self) -> sqlite3.Connection:
        """A read through the pin (Issue #10 S4c ``list``), never by pathname.

        ``Database.connect_read_only`` reopens the path without the pin
        checks, so a read here uses the pinned ``connect()`` instead: the
        same inode checks, ``mode=rw`` (never creates a file). The caller
        only reads (``BEGIN``, never ``BEGIN IMMEDIATE``), so nothing is
        written.
        """
        return self.connect()

    def release(self) -> None:
        """End the ledger's use of the file; later connections and commits refuse.

        The pinned descriptor is not closed (Issue #152). It belongs to the
        process-wide holder in ``app.storage.database``: closing any
        descriptor on the file would drop every POSIX lock this process
        holds on it, including those of a connection still open in an
        enrollment worker that outlived ``EnrollmentListener.serve()``'s
        bounded join, and let another process write mid-transaction. Such a
        lingering worker's later commit is refused by ``verify()`` and rolls
        back.
        """
        self._state["released"] = True


def _existing_database(database_path: Path) -> _PinnedLedgerDatabase:
    """The application's existing database file, pinned, or a refusal.

    A mistyped ``--database`` must never silently create and migrate an empty
    database that the server does not use (Issue #125): the path must be
    canonical and absolute (no symlink, no ``..``) and name an existing
    regular file with one link, owned by the account running the CLI and not
    writable by group or others. The returned object keeps that exact file
    pinned for every later ledger connection.
    """
    if not database_path.is_absolute() or os.path.realpath(database_path) != str(database_path):
        raise CliRefused("database_path_rejected")
    # The pin is the process-wide held descriptor (Issue #152): it is never
    # closed, not even when the file is refused below, because closing a
    # descriptor on a database file drops this process's SQLite locks on it.
    try:
        descriptor, identity = hold_database_file(database_path)
    except FileNotFoundError:
        raise CliRefused("database_not_found") from None
    except ValueError:
        raise CliRefused("database_rejected") from None
    try:
        info = os.fstat(descriptor)
    except OSError:
        raise CliRefused("database_rejected") from None
    if not _safe_database_file(info) or (info.st_dev, info.st_ino) != identity:
        raise CliRefused("database_rejected")
    return _PinnedLedgerDatabase(database_path, descriptor, identity)


def _require_current_schema(connection: sqlite3.Connection) -> None:
    """Refuse unless the database already has exactly this application's schema.

    Administrative commands never migrate (Issue #125): migrations belong to
    application startup. Only ``schema_migrations`` is read.
    """
    try:
        history = [tuple(row) for row in connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version")]
    except sqlite3.Error:
        raise CliRefused("database_schema_unsupported") from None
    expected = [(migration.version, migration.name, migration.checksum)
                for migration in APPLICATION_MIGRATIONS]
    if history == expected:
        return
    if len(history) < len(expected) and history == expected[:len(history)]:
        raise CliRefused("database_schema_outdated")
    raise CliRefused("database_schema_unsupported")
