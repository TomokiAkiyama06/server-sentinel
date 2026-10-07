"""Local administrative capture-node pairing CLI on the Main host (ADR-0006, #13).

Accounts (Issue #109). Three local accounts take part:

* ``root`` only starts the commands that need the CA (``sudo``) and gives up
  its privileges before anything else happens;
* the static system account ``serversentinel-ca`` (``--ca-user``) owns the
  deployment CA directory (0700; key, certificate and the CA-only issuance
  log 0600). Only a short-lived child process of this CLI runs as it
  (``issuer_process``);
* the service account (``--service-user``, default ``server-sentinel``) owns
  the application database and the Main listener directory (0700; listener
  key, certificate and the public CA copy 0600). It never reads the CA
  directory, and the application refuses to start if it can.

Commands::

    sudo serversentinel-pairing init ...             # CA child + service account
    sudo serversentinel-pairing rotate-listener ...  # CA child + service account
    sudo serversentinel-pairing approve ...          # CA child + service account
    sudo serversentinel-pairing revoke ...           # service account (+ CA log)
    serversentinel-pairing export-bundle ...         # as the service account
    serversentinel-pairing list ...                  # as the service account

(``serversentinel-pairing`` is ``python -m app.cameras.remote_agent.pairing_cli``.)

``init``, ``rotate-listener``, ``approve`` and ``revoke`` must start as root.
Before any thread exists they fork the CA child, which drops to the CA
account and holds no terminal or database descriptor; the command itself
then drops to the service account and verifies that it has no capability
left and is not root, aborting otherwise -- before it opens the database or
the Agent's request file. Listener keys are generated on the service-account
side; the CA child only signs their CSR, so no file changes owner.

``approve`` validates the Agent's public enrollment request, asks the Owner on
the controlling terminal (opened as root before the fork) to confirm the
request's public-key digest, creates the approval (which *is* the pairing:
node UUID, key binding and one-time code are created together by
``PairingLedger.approve``), then sends ``{node_id, csr}`` to the CA child. The
child checks its own issuance log, signs exactly one fixed-profile clientAuth
leaf, logs it and exits. Only after the certificate verified against the
public CA certificate (direct issuer, node and deployment URIs, approved key,
clientAuth) and the child exited does the command write the code once to the
controlling terminal and serve the separate bootstrap enrollment listener --
with no process holding the CA key alive -- until the enrollment completes or
its five minutes expire. On redemption the listener activates that
pre-signed certificate; an unredeemed one is never activated and admits
nothing. Any issuer failure refuses ``issuer_unavailable`` without showing
the code. Approval and listener share one process because the ledger
rejects pending approvals from any other process epoch; the HMAC verifier
key is therefore generated in memory per run and never stored.

The code is never written to stdout, stderr, logs, files or the database (the
ledger keeps only its keyed digest). Without a controlling terminal the command
refuses before any state changes. No command accepts a code as input.

Owner authority: until the #6 human-access boundary exists, this CLI's Owner
gate is the local host itself -- the administrator who can start it as root
(and so reach the owner-only issuer material and database) -- plus an
explicit typed confirmation on the controlling terminal for each
approve/revoke. Each confirmation authorizes exactly one ledger call, which
records the audit row.

``revoke`` revokes in the ledger first (authoritative for admission), then
records the revocation in the CA issuance log so the CA side refuses that
node and its keys from then on. If the CA record cannot be written the
ledger revocation still stands; the command says ``ca_revocation_unrecorded``
and exits 1, and rerunning it records the revocation.

``rotate-listener`` (Issue #125) replaces the Main listener key and
certificate before the leaf expires. The deployment CA and the server name do
not change, so Agents keep their trust bundle; restart the listener processes
so they load the new pair.

``init``, ``rotate-listener``, ``export-bundle`` and ``approve`` print the
deployment CA expiry (``ca_not_after=``) and the same fixed
trust-warning words as the local ``capture_trust_warning`` on stderr (#127):
``deployment_ca_expiring`` from 30 days before the CA stops covering a
397-day node leaf, ``deployment_ca_validity_insufficient`` once it no longer
does, and ``listener_certificate_expiring`` from 30 days before the listener
certificate expires. A warning does not change the exit status.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
import datetime
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import sys
import threading
from typing import Iterator
from urllib.parse import quote
from uuid import UUID, uuid4

from app.audit.service import OwnerAuthorizationError
from app.audit.store import AuditStore
from app.storage.database import Database, held_descriptors, hold_database_file
from app.storage.schema import APPLICATION_MIGRATIONS

from .enrollment import (
    EnrollmentError, EnrollmentLimits, EnrollmentListener, EnrollmentListenerConfig,
    EnrollmentService, PresignedEnrollment, build_enrollment_server_context,
)
from .issuer_process import (
    DEFAULT_CA_ACCOUNT, DEFAULT_SERVICE_ACCOUNT, Account, ForkedIssuer, IssuerChannel,
    OsPrivileges, Privileges, checked_reply,
)
from .node_ca import (
    _CLOCK_SKEW_ALLOWANCE, DEFAULT_NODE_VALIDITY, MAX_CA_VALIDITY, MAX_CSR_BYTES,
    MAX_LEAF_VALIDITY, AuthorityValidityExceeded, CaptureAuthorityError, DeploymentTrust,
    PrivateDirectory, _certificate_pem, listener_material, main_server_name,
    main_server_not_after, new_listener_key, public_key_digest, publish_public_certificate,
    require_empty_listener_directory, rotate_listener_credential, valid_server_name,
    write_listener_credential,
)
from .pairing import HmacCodeVerifier, PairingError, PairingLedger
from .renewal import ca_expiry_reason, listener_expiry_reason


REQUEST_FORMAT = 1
MAX_REQUEST_FILE_BYTES = MAX_CSR_BYTES + 4 * 1024
_MAX_TERMINAL_LINE = 128
_DAY = datetime.timedelta(days=1)


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


class LocalConsoleOwner:
    """Owner gate for this local CLI: one typed confirmation, one ledger call."""

    def __init__(self):
        self._grants: list[object] = []

    def confirm(self, terminal: ControllingTerminal, prompt: str, word: str) -> object:
        terminal.write(prompt)
        if terminal.read_line() != word:
            raise CliRefused("owner_confirmation_declined")
        grant = object()
        self._grants.append(grant)
        return grant

    def require_owner(self, actor_context: object) -> None:
        for index, grant in enumerate(self._grants):
            if grant is actor_context:
                del self._grants[index]
                return
        raise OwnerAuthorizationError()


def _endpoint(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not separator or not host or not port.isascii() or not port.isdecimal():
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    number = int(port)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    return host, number


def _ip_endpoint(value: str) -> tuple[str, int]:
    host, port = _endpoint(value)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise argparse.ArgumentTypeError("expected an IP literal HOST:PORT") from None
    return host, port


def _directory(value: Path, *, owner_uid: int | None = None) -> PrivateDirectory:
    try:
        return PrivateDirectory(Path(value), owner_uid=owner_uid)
    except CaptureAuthorityError:
        raise CliRefused("private_directory_rejected") from None


# Seams for tests (Issue #109): the root start and account drops, and the CA
# child. Production always uses the real ones; no option or environment
# variable selects anything else.
_PRIVILEGES: Privileges = OsPrivileges()


def _start_issuer(authority_path: Path, ca: Account, privileges: Privileges) -> IssuerChannel:
    return ForkedIssuer.start(authority_path, ca, privileges)


class _Separation:
    """The forked CA child plus this not-yet-dropped command process."""

    def __init__(self, privileges: Privileges, issuer: IssuerChannel, authority_path: Path,
                 service: Account):
        self.privileges = privileges
        self.issuer = issuer
        self.authority_path = authority_path
        self.service = service

    def hello(self) -> DeploymentTrust:
        """The public CA certificate from the CA child; the key never leaves it.

        Any failure (wrong ownership or mode of the CA directory, a damaged
        issuance log, a child that did not start) is ``issuer_unavailable``
        with the issuer's fixed word as ``issuer_detail``.
        """
        try:
            reply = checked_reply(self.issuer, {"op": "hello"})
        except CaptureAuthorityError as error:
            raise _issuer_refusal(error) from None
        try:
            return DeploymentTrust.from_certificate_pem(
                reply["ca_certificate"].encode("ascii"),
                deployment_id=UUID(reply["deployment_id"]))
        except (KeyError, AttributeError, TypeError, ValueError, UnicodeError,
                CaptureAuthorityError):
            raise CliRefused("issuer_unavailable") from None

    def drop(self) -> None:
        """Become the service account for good; abort unless fully unprivileged."""
        self.privileges.drop(self.service)
        self.privileges.require_ca_directory_closed(self.authority_path)


@contextmanager
def _separated(args) -> Iterator[_Separation]:
    """Start as root, fork the CA child, and hand back the separation (Issue #109).

    Refuses before forking unless the process starts as root and both
    accounts resolve to distinct non-root accounts. The CA child is always
    ended (end of stream) and reaped when the block ends.
    """
    privileges = _PRIVILEGES
    privileges.require_start()
    authority = _directory(args.authority_dir)
    ca = privileges.account(args.ca_user)
    service = privileges.account(args.service_user)
    privileges.check_accounts(ca, service)
    issuer = _start_issuer(authority.path, ca, privileges)
    try:
        yield _Separation(privileges, issuer, authority.path, service)
    finally:
        issuer.close()


def _issuer_refusal(error: CaptureAuthorityError) -> CliRefused:
    """``issuer_unavailable``, with the issuer's fixed detail word on stderr."""
    detail = getattr(error, "detail", None) or error.reason
    print(f"serversentinel-pairing: issuer_detail={detail}", file=sys.stderr)
    return CliRefused("issuer_unavailable")


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


@contextmanager
def _ledger(database_path: Path) -> Iterator[PairingLedger]:
    database = _existing_database(database_path)
    try:
        try:
            with closing(database.connect()) as connection:
                _require_current_schema(connection)
        except CliRefused:
            raise
        except _LedgerDatabaseChanged:
            raise CliRefused("database_rejected") from None
        except Exception:
            raise CliRefused("database_unavailable") from None
        # Pending approvals are valid only in this process, so the verifier
        # key is per-process and never persisted.
        yield PairingLedger(database, HmacCodeVerifier(secrets.token_bytes(32)),
                            audit=AuditStore(database))
    finally:
        database.release()


def _ledger_refusal(ledger: PairingLedger, reason: str) -> CliRefused:
    """``database_rejected`` if the pinned database changed, else ``reason``."""
    if getattr(ledger.database, "rejected", False):
        return CliRefused("database_rejected")
    return CliRefused(reason)


def _confirm_database(ledger: PairingLedger) -> None:
    """Before reporting success, the pinned database must still be in place."""
    try:
        ledger.database.verify()
    except _LedgerDatabaseChanged:
        raise CliRefused("database_rejected") from None


def _read_public_file(path: Path, maximum: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise CliRefused("input_file_unavailable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise CliRefused("input_file_rejected")
        content = os.read(descriptor, maximum + 1)
        if len(content) != info.st_size:
            raise CliRefused("input_file_rejected")
        return content
    finally:
        os.close(descriptor)


def _write_public_file(path: Path, content: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o644)
    except OSError:
        raise CliRefused("output_file_unavailable") from None
    try:
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    except OSError:
        raise CliRefused("output_file_unavailable") from None
    finally:
        os.close(descriptor)


def parse_enrollment_request(content: bytes) -> tuple[bytes, str]:
    """Validate the Agent's public request file and return (CSR, key digest)."""
    try:
        value = json.loads(content.decode("ascii"))
        if (not isinstance(value, dict)
                or set(value) != {"format_version", "csr", "public_key_digest"}
                or value["format_version"] != REQUEST_FORMAT
                or type(value["format_version"]) is not int
                or not isinstance(value["csr"], str)
                or not isinstance(value["public_key_digest"], str)):
            raise ValueError
        csr = value["csr"].encode("ascii")
        digest = DeploymentTrust.enrollment_key_digest(csr)
    except (ValueError, TypeError, UnicodeError, RecursionError, CaptureAuthorityError):
        raise CliRefused("enrollment_request_rejected") from None
    if digest != value["public_key_digest"]:
        raise CliRefused("enrollment_request_rejected")
    return csr, digest


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _report_trust_expiry(authority: DeploymentTrust, *,
                         listener_not_after: datetime.datetime | None = None) -> None:
    """Print the CA expiry and any trust warning (Issue #127).

    Uses the same fixed words and 30-day lead as ``CaptureCredentialMonitor``'s
    ``capture_trust_warning``, so an Owner running the CLI sees an expiring
    CA (or listener certificate) before renewals and enrollments start to be
    refused. Public dates and fixed words only, on stderr, so each command's
    stdout stays exactly its documented result line(s).
    """
    now = _utc_now()
    ca_not_after = authority.not_valid_after.isoformat(timespec="seconds")
    print(f"serversentinel-pairing: ca_not_after={ca_not_after}", file=sys.stderr)
    reason = ca_expiry_reason(now, authority.not_valid_after)
    if reason is not None:
        print(f"serversentinel-pairing: warning: {reason} ca_not_after={ca_not_after} "
              "(replacing the CA needs a new init and re-pairing every Agent)",
              file=sys.stderr)
    reason = listener_expiry_reason(now, listener_not_after)
    if reason is not None:
        print(f"serversentinel-pairing: warning: {reason} "
              f"listener_not_after={listener_not_after.isoformat(timespec='seconds')} "
              "(run rotate-listener)", file=sys.stderr)


def _group(code: str) -> str:
    return "-".join(code[index:index + 5] for index in range(0, 20, 5)) + "-" + code[20:]


def _days(value: int, maximum: datetime.timedelta) -> datetime.timedelta:
    if not isinstance(value, int) or not 0 < value <= maximum.days:
        raise CliRefused("certificate_validity_rejected")
    return value * _DAY


def command_init(args) -> int:
    ca_validity = _days(args.ca_validity_days, MAX_CA_VALIDITY)
    server_validity = _days(args.server_validity_days, MAX_LEAF_VALIDITY)
    # Everything is validated before the write-once CA exists; a failed run
    # leaves no issuer material, so the corrected command can simply be rerun.
    if server_validity + _CLOCK_SKEW_ALLOWANCE > ca_validity:
        raise AuthorityValidityExceeded("certificate validity exceeds the deployment CA")
    if not valid_server_name(args.server_name):
        raise CaptureAuthorityError("invalid Main server name")
    if _directory(args.authority_dir).path == _directory(args.listener_dir).path:
        raise CliRefused("listener_directory_must_differ")
    deployment = uuid4()
    with _separated(args) as separation:
        separation.drop()
        listener = _directory(args.listener_dir).ensure()
        with listener.locked():
            require_empty_listener_directory(listener)
            # The listener key is generated here, as the service account; the
            # CA child only signs its CSR (Issue #109).
            key, csr = new_listener_key()
            try:
                reply = checked_reply(separation.issuer, {
                    "op": "initialize", "deployment_id": str(deployment),
                    "csr": csr.decode("ascii"), "server_name": args.server_name,
                    "ca_validity_days": args.ca_validity_days,
                    "server_validity_days": args.server_validity_days})
            except CaptureAuthorityError as error:
                if error.reason == "issuer_unavailable":
                    raise _issuer_refusal(error) from None
                raise
            try:
                trust = DeploymentTrust.from_certificate_pem(
                    reply["ca_certificate"].encode("ascii"), deployment_id=deployment)
                certificate = trust.verify_issued_listener_certificate(
                    reply["certificate"].encode("ascii"), server_name=args.server_name,
                    public_key_digest_value=public_key_digest(key.public_key()))
            except (KeyError, AttributeError, UnicodeError, CaptureAuthorityError):
                _abort_initialize(separation)
                raise CliRefused("issuer_unavailable") from None
            try:
                credential = write_listener_credential(listener, key,
                                                       _certificate_pem(certificate),
                                                       trust.ca_certificate_pem())
            except BaseException:
                _abort_initialize(separation)
                raise
            try:
                checked_reply(separation.issuer, {"op": "commit"})
            except CaptureAuthorityError as error:
                # The CA child removes its provisional CA when it is not
                # committed; remove the listener side too, so a rerun works.
                for name in (credential.key_path.name, credential.certificate_path.name,
                             "deployment-ca-certificate.pem"):
                    try:
                        listener.discard_created(name)
                    except CaptureAuthorityError:
                        pass
                raise _issuer_refusal(error) from None
    print(f"deployment_id={deployment}")
    _report_trust_expiry(trust, listener_not_after=certificate.not_valid_after_utc)
    return 0


def _abort_initialize(separation: _Separation) -> None:
    try:
        separation.issuer.request({"op": "abort"})
    except CaptureAuthorityError:
        pass


def command_rotate_listener(args) -> int:
    validity = _days(args.server_validity_days, MAX_LEAF_VALIDITY)
    if _directory(args.authority_dir).path == _directory(args.listener_dir).path:
        raise CliRefused("listener_directory_must_differ")
    with _separated(args) as separation:
        trust = separation.hello()
        separation.drop()
        listener = _directory(args.listener_dir)

        def sign(csr: bytes, server_name: str, lifetime: datetime.timedelta) -> bytes:
            try:
                reply = checked_reply(separation.issuer, {
                    "op": "sign_listener", "csr": csr.decode("ascii"),
                    "server_name": server_name, "validity_days": lifetime.days})
                return reply["certificate"].encode("ascii")
            except (KeyError, AttributeError, UnicodeError):
                raise CliRefused("issuer_unavailable") from None
            except CaptureAuthorityError as error:
                if error.reason == "issuer_unavailable":
                    raise _issuer_refusal(error) from None
                raise

        rotation = rotate_listener_credential(trust, listener, validity=validity, sign=sign)
    expiry = rotation.not_after.isoformat(timespec="seconds")
    if rotation.recovered:
        print(f"listener rotation completed (interrupted run): not_after={expiry}")
    else:
        print(f"listener rotated: not_after={expiry}")
    print("restart the capture ingest listener to load the new certificate")
    _report_trust_expiry(trust, listener_not_after=rotation.not_after)
    return 0


def command_export_bundle(args) -> int:
    # Public material only, as the service account (Issue #109): the CA
    # certificate copy and the listener certificate in the listener directory.
    listener_directory = _directory(args.listener_dir)
    trust = DeploymentTrust.load_public(listener_directory)
    # A bundle is only exported for a listener certificate this CA issued,
    # so mixed-up deployments fail here, not later at the Agent's TLS check.
    trust.verify_listener_certificate(listener_directory)
    server_name = main_server_name(listener_directory)
    host, port = args.endpoint
    bundle = trust.export_trust_bundle(server_name=server_name, endpoint_host=host,
                                       endpoint_port=port)
    _write_public_file(args.output, bundle.content)
    # Public: the Owner compares this full digest on the capture host.
    print(f"trust_bundle_sha256={bundle.sha256}")
    _report_trust_expiry(trust, listener_not_after=main_server_not_after(listener_directory))
    return 0


def _sign_approved(issuer: IssuerChannel, trust: DeploymentTrust, approval, csr: bytes,
                   digest: str):
    """Have the CA child sign the approved node, then verify it; or refuse.

    The child signs exactly one leaf and exits; this waits for that exit,
    so no process holding the CA key is alive afterwards. The certificate
    must verify against the public CA certificate for this node and key.
    """
    try:
        reply = checked_reply(issuer, {"op": "sign_node", "node_id": str(approval.node_id),
                                       "public_key_digest": digest,
                                       "csr": csr.decode("ascii")})
        issuer.finish()
        certificate = reply["certificate"].encode("ascii")
        return trust.verify_issued_node_certificate(
            certificate, node_id=approval.node_id, public_key_digest_value=digest)
    except (KeyError, AttributeError, UnicodeError):
        raise CliRefused("issuer_unavailable") from None
    except CaptureAuthorityError as error:
        raise _issuer_refusal(error) from None


def _approve_and_serve(ledger, trust, issuer, listener, terminal, csr, digest):
    """Confirm, approve, have it signed, then serve one enrollment on the pinned ledger."""
    # A key stays bound to its node for good, so a retry after an
    # interrupted, expired or unacknowledged enrollment -- or re-pairing a
    # node whose certificate expired without being revoked (#116) -- reuses
    # that node. A revoked node's keys are never accepted again: it re-pairs
    # as a new node with a new key, refused here before the Owner prompt or
    # the listener opens.
    try:
        revoked = ledger.key_revoked(digest)
        bound = None if revoked else ledger.bound_node(digest)
    except PairingError:
        raise _ledger_refusal(ledger, "approval_refused") from None
    if revoked:
        raise _ledger_refusal(ledger, "public_key_revoked")
    retry = (
        "  new capture node: camera sources are not carried over from any\n"
        "  earlier (revoked) node; approve its sources again after pairing\n"
        if bound is None else
        f"  existing capture node: {bound}\n"
        "  (retry or re-pairing with the same key: completing it replaces\n"
        "  that node's current certificate; its camera sources are unchanged)\n")
    listener.open()
    try:
        owner = LocalConsoleOwner()
        grant = owner.confirm(
            terminal,
            "Capture-node enrollment request\n"
            f"  public key SHA-256: {digest}\n"
            f"{retry}"
            "Compare it with the digest shown on the capture host.\n"
            "Type APPROVE to approve this capture node: ",
            "APPROVE")
        try:
            approval, code = ledger.approve(owner, grant, node_id=bound or uuid4(),
                                            public_key_digest=digest)
        except PairingError:
            raise _ledger_refusal(ledger, "approval_refused") from None
        # Signed after the Owner's approval and before any redemption
        # (ADR-0006 follow-up, Issue #109). Without a verified certificate
        # the code is never shown; the pending approval then expires unused.
        credential = _sign_approved(issuer, trust, approval, csr, digest)
        terminal.write(
            "\nOne-time pairing code (shown once, valid for 5 minutes):\n\n"
            f"    {_group(code.value)}\n\n"
            "Type it only into the media-capture-agent pairing prompt on the capture host.\n")
        del code
        print(f"enrollment listening: node_id={approval.node_id}", flush=True)
        service = EnrollmentService(ledger, trust, (PresignedEnrollment(approval, credential),))
        outcome = listener.serve(service, expires_at_monotonic=approval.expires_at_monotonic)
    finally:
        listener.close()
    # Never report an enrollment against a database that is no longer the
    # validated file.
    _confirm_database(ledger)
    return outcome, approval


def command_approve(args) -> int:
    # Refuse before any state change if the code cannot be shown privately.
    # The terminal is opened as root, before the CA child exists; the child
    # closes its copy and starts a new session without one.
    terminal = ControllingTerminal()
    try:
        try:
            human_host = ipaddress.ip_address(args.human_host)
        except ValueError:
            raise CliRefused("human_listener_must_be_loopback") from None
        if not human_host.is_loopback:
            raise CliRefused("human_listener_must_be_loopback")
        reserved = [(str(human_host), args.human_port)]
        if args.ingest_listen is not None:
            reserved.append(args.ingest_listen)
        host, port = args.listen
        config = EnrollmentListenerConfig(host, port, reserved=tuple(reserved))
        with _separated(args) as separation:
            trust = separation.hello()
            # Refuse before any approval when the CA can no longer cover a
            # node leaf; the code would otherwise be burned by a failed issuance.
            trust.check_leaf_validity(DEFAULT_NODE_VALIDITY)
            listener_directory = _directory(args.listener_dir,
                                            owner_uid=separation.service.uid)
            material = listener_material(listener_directory)
            listener_certificate = trust.verify_listener_certificate(listener_directory)
            listener = EnrollmentListener(
                config, build_enrollment_server_context(material.certificate_path,
                                                        material.key_path),
                limits=EnrollmentLimits())
            # From here on: the service account, no capability, before the
            # request file or the database is opened.
            separation.drop()
            publish_public_certificate(_directory(args.listener_dir), trust.ca_certificate_pem())
            _report_trust_expiry(trust,
                                 listener_not_after=listener_certificate.not_valid_after_utc)
            csr, digest = parse_enrollment_request(
                _read_public_file(args.request, MAX_REQUEST_FILE_BYTES))
            with _ledger(args.database) as ledger:
                outcome, approval = _approve_and_serve(ledger, trust, separation.issuer,
                                                       listener, terminal, csr, digest)
    finally:
        terminal.close()
    if outcome.reason == "completed":
        print(f"enrollment completed: node_id={approval.node_id}")
        return 0
    print(f"enrollment closed: reason={outcome.reason}")
    return 1


def command_list(args) -> int:
    with _ledger(args.database) as ledger:
        try:
            rows = ledger.pairing_summaries()
        except PairingError:
            raise _ledger_refusal(ledger, "pairing_ledger_refused") from None
        _confirm_database(ledger)
    for row in rows:
        expiry = ("-" if row.not_after is None else
                  datetime.datetime.fromtimestamp(row.not_after, datetime.timezone.utc)
                  .isoformat(timespec="seconds"))
        print(f"node_id={row.node_id} enrollment={row.enrollment_state or '-'} "
              f"credential={row.credential_state or '-'} not_after={expiry}")
    return 0


def _already_revoked(ledger: PairingLedger, node: UUID) -> bool:
    try:
        rows = ledger.pairing_summaries()
    except PairingError:
        return False
    # Revoked: its credential was revoked, or it never had one and its
    # enrollment was revoked. An active credential is never "already revoked".
    return any(row.node_id == node and (row.credential_state == "revoked" or (
        row.credential_state is None and row.enrollment_state == "revoked"))
        for row in rows)


def command_revoke(args) -> int:
    terminal = ControllingTerminal()
    recorded = False
    try:
        with _separated(args) as separation:
            # The revocation itself never depends on the CA side: a broken
            # CA directory only leaves the CA record missing (reported below).
            try:
                separation.hello()
                issuer_ready = True
            except (CliRefused, CaptureAuthorityError):
                issuer_ready = False
            separation.drop()
            with _ledger(args.database) as ledger:
                owner = LocalConsoleOwner()
                grant = owner.confirm(terminal,
                                      f"Type REVOKE to revoke capture node {args.node}: ",
                                      "REVOKE")
                if _already_revoked(ledger, args.node):
                    # A rerun after ``ca_revocation_unrecorded``: the ledger
                    # already revoked it; only the CA record is still owed.
                    owner.require_owner(grant)
                else:
                    try:
                        ledger.revoke(owner, grant, node_id=args.node)
                    except PairingError:
                        raise _ledger_refusal(ledger, "revocation_refused") from None
                _confirm_database(ledger)
            if issuer_ready:
                try:
                    checked_reply(separation.issuer, {"op": "revoke", "node_id": str(args.node)})
                    separation.issuer.finish()
                    recorded = True
                except CaptureAuthorityError as error:
                    detail = getattr(error, "detail", None) or error.reason
                    print(f"serversentinel-pairing: issuer_detail={detail}", file=sys.stderr)
    finally:
        terminal.close()
    print(f"revoked: node_id={args.node}")
    if not recorded:
        print("serversentinel-pairing: warning: ca_revocation_unrecorded "
              "(the ledger revocation stands; rerun revoke to record it at the CA)",
              file=sys.stderr)
        return 1
    return 0


def _separation_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--ca-user", default=DEFAULT_CA_ACCOUNT,
                         help="static system account owning --authority-dir "
                              f"(default {DEFAULT_CA_ACCOUNT})")
    command.add_argument("--service-user", default=DEFAULT_SERVICE_ACCOUNT,
                         help="service account owning the database and --listener-dir "
                              f"(default {DEFAULT_SERVICE_ACCOUNT})")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="serversentinel-pairing",
        description="Local Owner administration of capture-node pairing (ADR-0006). "
                    "init, rotate-listener, approve and revoke start as root (sudo) and "
                    "drop to --ca-user (CA child) and --service-user (Issue #109).")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create the deployment CA and Main listener certificate")
    init.add_argument("--authority-dir", type=Path, required=True)
    init.add_argument("--listener-dir", type=Path, required=True)
    init.add_argument("--server-name", required=True)
    init.add_argument("--ca-validity-days", type=int, default=3650)
    init.add_argument("--server-validity-days", type=int, default=MAX_LEAF_VALIDITY.days)
    _separation_arguments(init)
    init.set_defaults(handler=command_init)

    rotate = commands.add_parser(
        "rotate-listener",
        help="replace the Main listener key and certificate; the CA and Agent trust are kept")
    rotate.add_argument("--authority-dir", type=Path, required=True)
    rotate.add_argument("--listener-dir", type=Path, required=True)
    rotate.add_argument("--server-validity-days", type=int, default=MAX_LEAF_VALIDITY.days)
    _separation_arguments(rotate)
    rotate.set_defaults(handler=command_rotate_listener)

    export = commands.add_parser("export-bundle",
                                 help="write the public trust bundle (as the service account)")
    export.add_argument("--listener-dir", type=Path, required=True)
    export.add_argument("--endpoint", type=_endpoint, required=True,
                        help="bootstrap enrollment endpoint HOST:PORT the Agent connects to")
    export.add_argument("--output", type=Path, required=True)
    export.set_defaults(handler=command_export_bundle)

    approve = commands.add_parser("approve", help="approve one enrollment request and serve it")
    approve.add_argument("--database", type=Path, required=True)
    approve.add_argument("--authority-dir", type=Path, required=True)
    approve.add_argument("--listener-dir", type=Path, required=True)
    approve.add_argument("--request", type=Path, required=True)
    approve.add_argument("--listen", type=_ip_endpoint, required=True,
                         help="private IP literal HOST:PORT for the bootstrap listener "
                              "(bound as the service account)")
    approve.add_argument("--human-host", default="127.0.0.1",
                         help="loopback IP of the human dashboard listener (SERVERSENTINEL_HUMAN_HOST)")
    approve.add_argument("--human-port", type=int, default=8000,
                         help="port of the human dashboard listener (SERVERSENTINEL_HUMAN_PORT)")
    approve.add_argument("--ingest-listen", type=_ip_endpoint, default=None)
    _separation_arguments(approve)
    approve.set_defaults(handler=command_approve)

    listing = commands.add_parser("list", help="list capture-node pairing states")
    listing.add_argument("--database", type=Path, required=True)
    listing.set_defaults(handler=command_list)

    revoke = commands.add_parser("revoke", help="revoke a capture node (ledger and CA log)")
    revoke.add_argument("--database", type=Path, required=True)
    revoke.add_argument("--authority-dir", type=Path, required=True)
    revoke.add_argument("--node", type=UUID, required=True)
    _separation_arguments(revoke)
    revoke.set_defaults(handler=command_revoke)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
    try:
        return args.handler(args)
    except CliRefused as error:
        print(f"serversentinel-pairing: refused: {error.reason}", file=sys.stderr)
    except EnrollmentError as error:
        print(f"serversentinel-pairing: refused: {error.reason}", file=sys.stderr)
    except CaptureAuthorityError as error:
        # A fixed word per failure class; never a path, key or certificate.
        print(f"serversentinel-pairing: refused: {error.reason}", file=sys.stderr)
    except PairingError:
        print("serversentinel-pairing: refused: pairing_ledger_refused", file=sys.stderr)
    except KeyboardInterrupt:
        print("serversentinel-pairing: stopped", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
