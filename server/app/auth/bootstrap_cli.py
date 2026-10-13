"""Local Owner bootstrap, recovery and emergency administration on the Main Server.

ADR-0003; Issue #10 phase 2 S2 (``bootstrap`` / ``recover``) and S4c
(``list`` / ``revoke-principal`` / ``revoke-credential``, Owner decisions D6
and S4-6).

Commands (``python -m app.auth.bootstrap_cli``), run as the service account
that owns the application database, never as root and never with ``sudo``::

    python -m app.auth.bootstrap_cli bootstrap --config <deployment.json>
    python -m app.auth.bootstrap_cli recover --config <deployment.json>
    python -m app.auth.bootstrap_cli list --config <deployment.json>
    python -m app.auth.bootstrap_cli revoke-principal --config <deployment.json> <principal id>
    python -m app.auth.bootstrap_cli revoke-credential --config <deployment.json> <principal id> <handle>

Every command shares the checks described below (service account,
deployment configuration, controlling terminal, the pinned database of
exactly this release's schema). The emergency commands are described under
"Emergency administration (S4c)" at the end.

``--config`` is the deployment configuration the service itself runs with
(``app.deployment.Deployment.load``, the same validation as the launcher):
the command takes the application database (``<state directory>/state.sqlite3``)
and the deployment's invitation lifetime (``invitation_lifetime_hours``,
default 24 hours, at most 7 days; Owner decision 2026-10-11) from it, and
refuses unless it runs as the configuration's service account.

``bootstrap`` creates the single Owner principal (only when no Owner exists)
and issues exactly one enrollment authorization for it. ``recover`` advances
the deployment authorization generation (every human session ends, every
pending challenge is deleted and every outstanding invitation is void),
revokes every credential of the Owner principal and issues exactly one new
enrollment authorization for it (``AccessStore.recover_owner_on``). Either
way the Owner then redeems the code once, from a browser at the reserved
origin, through the ordinary redemption route (``POST
/api/auth/registration/options`` and ``POST /api/auth/registration``) and
signs in like everyone else. There is no bootstrap HTTP route.

Not through the server gate (Owner decision 2026-10-11, Issue #181 item 2).
The gate lives in the serving process's memory, so another process cannot
take it. What keeps the command safe instead is the generation binding: the
authorization records the deployment generation (and the Owner's revision) it
was issued under, and redemption, which is gated, refuses it once either has
advanced. An authorization committed before a reservation revocation is
voided by that revocation; one committed after it was shown only on this
console. The running server sees a recovery's new generation on its next
request.

Authority and inputs. The local administrative boundary is the host itself:
whoever can run this as the service account can already read and write the
application database. The command reads nothing secret from its arguments or
the environment (only ``--config``, a path); the Owner's display name and
the confirmation word are read from the controlling terminal, never inferred
from the local user name, an environment variable or a Tailscale login.

Output. The code is generated here from the CSPRNG (``invitation_code``,
160 bits, the deployment's lifetime, single use), stored only as its digest
(with its non-secret lookup key and the boot id plus ``CLOCK_BOOTTIME`` of
issuance, ``app.auth.boot_clock``), and written only to the controlling
terminal (``/dev/tty``), after the commit; never to stdout, stderr, a log, a
file, the database or the audit log. Without a controlling terminal the
command refuses before any change. Standard output gets only the Owner's
logical UUID and the expiry. If writing the code to the terminal fails after
the commit, the command exits ``2`` with ``committed_code_not_shown``: the
change is committed but the code is lost, so run ``recover`` (also after a
``bootstrap``; the Owner then exists) to issue a new one.

Database. The path must be canonical and name the existing database file, a
regular file with one link owned by this account and not group/other
writable; the file stays pinned for the whole command and is re-verified
before each commit, and the schema must be exactly this release's
(``app.local_admin._existing_database`` / ``_require_current_schema``: the
command never creates or migrates a database). The writes are a few bounded
rows and, like the pairing CLI's, are not admitted through the running
server's storage policy.

Audit (same transaction as the change; actor ``owner``, target the Owner's
logical UUID or the fixed human-sessions id, never a name, code or
identity): ``bootstrap`` records ``invite_principal`` and
``issue_principal_invitation``; ``recover`` records
``invalidate_human_sessions``, ``revoke_principal_credential`` (when a
credential was revoked) and ``issue_principal_invitation``. A refusal changes
nothing and records nothing, except ``committed_code_not_shown`` (above).

Exit status: ``0`` issued, ``2`` refused (a fixed word on stderr).

Emergency administration (S4c). For use over SSH while human access is
closed (D6); the commands work the same while it is open. Exactly three
(S4-6):

- ``list`` prints on stdout, per principal, its logical UUID, role, status,
  grants and display name and, per credential, its handle, status and label
  (``AccessStore.admin_inventory``: one read-only transaction; nothing is
  written or audited). Never the last observed proxy identity (Owner
  decision D14), a WebAuthn credential id, public key, signature counter,
  digest, session data or code. Names and labels are printed quoted, with
  every non-printable character escaped and the text bounded. The output is
  bounded (``MAX_LISTED_PRINCIPALS`` principals, ``MAX_LISTED_CREDENTIALS``
  credentials each): principals and credentials that are not revoked come
  first, and what does not fit is counted on a ``not shown`` line.
- ``revoke-principal <principal id>`` revokes that person: every credential
  (each on all the devices it synced to), every pending invitation code and
  every session (``AccessStore.revoke_principal_on``).
- ``revoke-credential <principal id> <handle>`` revokes one credential of
  that person, named by the handle ``list`` prints, on all the devices it
  synced to (revocation is credential-scoped, never device-scoped), and ends
  the sessions it established (``AccessStore.revoke_credential_on``).

Both revocations show the target and read the confirmation word ``REVOKE``
from the controlling terminal, then commit the effect and its audit record
(``revoke_principal`` / ``revoke_principal_credential``, actor ``owner``,
target the principal's logical UUID only) in one transaction, through the
same store methods as the Web routes. They refuse, changing and recording
nothing: the Owner principal (``owner_target_use_recover``; the Owner's
credentials change only through ``recover``, Owner decision S4-3), an
unknown principal (``principal_not_found``), a revoked one
(``principal_already_revoked``), a handle that is unknown or another
principal's (``credential_not_found``) or already revoked
(``credential_already_revoked``), a malformed argument
(``principal_id_rejected`` / ``credential_handle_rejected``) and a declined
confirmation (``owner_confirmation_declined``). The target is classified
again inside the write transaction, so a change made meanwhile is refused,
not overwritten.

Like ``recover`` they do not go through the server gate. That is safe
because they only reduce access, and the running server re-reads the
principal, credential and session inside each request's own transaction:
the revoked person's (or credential's) next request is denied. Standard
output gets only the principal's logical UUID (and the handle).
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import sys
from typing import Callable
from uuid import UUID, uuid4

from app.audit.model import ActorCategory, AuditAction, AuditOutcome, TargetKind
from app.audit.store import AuditStore
from app.deployment import Deployment, _runtime_roots
from app.local_admin import (
    CliRefused, ControllingTerminal, _existing_database, _LedgerDatabaseChanged,
    _require_current_schema,
)
from .invitation_code import new_invitation_code
from .model import AccessValidationError, CredentialStatus, PrincipalRole, PrincipalStatus, utc_time
from .reservation_store import HUMAN_SESSIONS_ID
from .store import AccessStore, InvitationClockUnavailable, OwnerAlreadyConfigured, OwnerNotConfigured


PROG = "python -m app.auth.bootstrap_cli"
BOOTSTRAP_WORD = "BOOTSTRAP"
RECOVER_WORD = "RECOVER"
REVOKE_WORD = "REVOKE"
REVOKE_COMMANDS = ("revoke-principal", "revoke-credential")
# Output bounds of ``list``. MAX_PRINCIPALS (64) bounds the principals that
# are not revoked; revoked ones accumulate.
MAX_LISTED_PRINCIPALS = 128
MAX_LISTED_CREDENTIALS = 32
_MAX_LISTED_TEXT = 128
# A fixed second line for a refusal that has a next step.
_HINTS = {
    "owner_target_use_recover": "the Owner's credentials change only through the 'recover' command",
}


def _append(audit: AuditStore, connection, action: AuditAction, kind: TargetKind, target: UUID) -> None:
    audit.append_on(connection, actor_category=ActorCategory.OWNER, action=action,
                    target_kind=kind, target_logical_id=target, outcome=AuditOutcome.SUCCEEDED)


def bootstrap_owner(store: AccessStore, display_name: str, secret: bytes, *,
                    at: datetime) -> tuple[UUID, datetime]:
    """Create the Owner and its one authorization with their audit records; one transaction."""
    audit = store.audit
    at = utc_time(at)
    expires_at = store.invitation_expiry(at)
    owner = uuid4()
    with audit.transaction(write=True) as connection:
        store.bootstrap_owner_on(connection, owner, display_name, secret, expires_at, at=at)
        _append(audit, connection, AuditAction.INVITE_PRINCIPAL, TargetKind.PRINCIPAL, owner)
        _append(audit, connection, AuditAction.ISSUE_PRINCIPAL_INVITATION, TargetKind.PRINCIPAL, owner)
    return owner, expires_at


def recover_owner(store: AccessStore, secret: bytes, *, at: datetime,
                  display_name: str | None = None) -> tuple[UUID, datetime]:
    """Recover the Owner (see ``AccessStore.recover_owner_on``) with its audit records."""
    audit = store.audit
    at = utc_time(at)
    expires_at = store.invitation_expiry(at)
    with audit.transaction(write=True) as connection:
        owner, _, revoked = store.recover_owner_on(connection, secret, expires_at, at=at,
                                                   display_name=display_name)
        _append(audit, connection, AuditAction.INVALIDATE_HUMAN_SESSIONS, TargetKind.SECURITY_SETTINGS,
                HUMAN_SESSIONS_ID)
        if revoked:
            _append(audit, connection, AuditAction.REVOKE_PRINCIPAL_CREDENTIAL, TargetKind.PRINCIPAL, owner)
        _append(audit, connection, AuditAction.ISSUE_PRINCIPAL_INVITATION, TargetKind.PRINCIPAL, owner)
    return owner, expires_at


def _uuid_argument(value: object, reason: str) -> UUID:
    """A UUID argument in its canonical hyphenated form (any case), else ``reason``."""
    try:
        if isinstance(value, str) and len(value) == 36:
            parsed = UUID(value)
            if str(parsed) == value.lower():
                return parsed
    except ValueError:
        pass
    raise CliRefused(reason)


def _revocation_target_on(connection, principal_id: UUID, handle: UUID | None) -> tuple[str, str | None]:
    """Classify a revocation target with a fixed refusal word; ``(display name, label)``.

    The store's ``*_on`` methods refuse the same targets with one generic
    error (the Web routes answer every refusal alike); locally, where the
    caller can read the database anyway, the word says which it was.
    """
    row = connection.execute("SELECT role, status, display_name FROM access_principals WHERE id=?",
                             (str(principal_id),)).fetchone()
    if row is None:
        raise CliRefused("principal_not_found")
    if row["role"] != PrincipalRole.INVITED_USER.value:
        # Owner decision S4-3: only ``recover`` changes the Owner's credentials.
        raise CliRefused("owner_target_use_recover")
    if row["status"] == PrincipalStatus.REVOKED.value:
        raise CliRefused("principal_already_revoked")
    label = None
    if handle is not None:
        credential = connection.execute(
            "SELECT label, revoked_at_us FROM access_credentials WHERE handle=? AND principal_id=?",
            (str(handle), str(principal_id))).fetchone()
        if credential is None:
            raise CliRefused("credential_not_found")
        if credential["revoked_at_us"] is not None:
            raise CliRefused("credential_already_revoked")
        label = credential["label"]
    return row["display_name"], label


def revoke_principal(store: AccessStore, principal_id: UUID) -> None:
    """Revoke a person (``AccessStore.revoke_principal_on``) with its audit record; one transaction.

    The target is classified again and the time read inside the write
    transaction, after ``BEGIN IMMEDIATE`` (PR #234 rule).
    """
    audit = store.audit
    with audit.transaction(write=True) as connection:
        _revocation_target_on(connection, principal_id, None)
        store.revoke_principal_on(connection, principal_id, at=store.now())
        _append(audit, connection, AuditAction.REVOKE_PRINCIPAL, TargetKind.PRINCIPAL, principal_id)


def revoke_credential(store: AccessStore, principal_id: UUID, handle: UUID) -> None:
    """Revoke one credential by handle (``AccessStore.revoke_credential_on``) with its audit record.

    Credential-scoped: a synced passkey is revoked on every device it exists
    on. The record names the principal's logical UUID only.
    """
    audit = store.audit
    with audit.transaction(write=True) as connection:
        _revocation_target_on(connection, principal_id, handle)
        store.revoke_credential_on(connection, principal_id, str(handle), at=store.now())
        _append(audit, connection, AuditAction.REVOKE_PRINCIPAL_CREDENTIAL, TargetKind.PRINCIPAL, principal_id)


def _quoted(value: object) -> str:
    """Stored text for a terminal: quoted, non-printable characters escaped, bounded."""
    if value is None:
        return "-"
    text = str(value)
    pieces = []
    for char in text[:_MAX_LISTED_TEXT]:
        if char in '"\\':
            pieces.append("\\" + char)
        elif char.isprintable():
            pieces.append(char)
        elif ord(char) <= 0xFFFF:
            pieces.append(f"\\u{ord(char):04x}")
        else:
            pieces.append(f"\\U{ord(char):08x}")
    return '"' + "".join(pieces) + ('..."' if len(text) > _MAX_LISTED_TEXT else '"')


def inventory_lines(inventory) -> list[str]:
    """The ``list`` output: only the fields named in the module docstring, bounded."""
    def revoked(item):
        return item["status"] == PrincipalStatus.REVOKED.value

    principals = sorted(inventory, key=revoked)  # stable: creation order within each group
    lines = []
    for principal in principals[:MAX_LISTED_PRINCIPALS]:
        grants = ",".join(principal["permissions"]) or "-"
        lines.append(f"principal {principal['id']} role={principal['role']} status={principal['status']} "
                     f"permissions={grants} name={_quoted(principal['display_name'])}")
        credentials = sorted(principal["credentials"],
                             key=lambda item: item["status"] == CredentialStatus.REVOKED.value)
        for credential in credentials[:MAX_LISTED_CREDENTIALS]:
            lines.append(f"  credential {credential['handle']} status={credential['status']} "
                         f"label={_quoted(credential['label'])}")
        if len(credentials) > MAX_LISTED_CREDENTIALS:
            lines.append(f"  credentials not shown: {len(credentials) - MAX_LISTED_CREDENTIALS}")
    if len(principals) > MAX_LISTED_PRINCIPALS:
        lines.append(f"principals not shown: {len(principals) - MAX_LISTED_PRINCIPALS}")
    if not principals:
        lines.append("no principals")
    return lines


def _owner_configured(store: AccessStore) -> bool:
    with closing(store.database.connect()) as connection:
        return AccessStore.owner_configured_on(connection)


def _display_name(terminal: ControllingTerminal, prompt: str, *, optional: bool) -> str | None:
    terminal.write(prompt)
    name = terminal.read_line()
    if optional and name == "":
        return None
    if not 1 <= len(name) <= 64 or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise CliRefused("display_name_rejected")
    return name


def _confirm(terminal: ControllingTerminal, prompt: str, word: str) -> None:
    terminal.write(prompt)
    if terminal.read_line() != word:
        raise CliRefused("owner_confirmation_declined")


def _show_code(terminal: ControllingTerminal, code: str, expires_at: datetime) -> None:
    try:
        terminal.write(
            "\nOwner enrollment code (single use, valid until "
            f"{expires_at.isoformat(timespec='seconds')}):\n\n    {code}\n\n"
            "Open the reserved ServerSentinel origin in the browser you will use, enter\n"
            "this code once and register your passkey with user verification. Do not\n"
            "store or send the code anywhere else.\n")
    except Exception:
        # Committed, but the code never reached the Owner: it is lost and only
        # ``recover`` issues a new one (PR #234 review).
        raise CliRefused("committed_code_not_shown") from None


def _load_deployment(path: Path):
    """The validated deployment configuration, exactly as the launcher loads it."""
    code_root, install_root = _runtime_roots()
    return Deployment.load(path, code_root=code_root, install_root=install_root)


def _storage_refusal(database) -> CliRefused:
    return CliRefused("database_rejected" if database.rejected else "database_unavailable")


def _verify_pinned(database) -> None:
    try:
        database.verify()
    except _LedgerDatabaseChanged:
        raise CliRefused("database_rejected") from None


def _issue(args, store: AccessStore, database, terminal: ControllingTerminal, *, lifetime,
           clock: Callable[[], datetime], random_bytes: Callable[[int], bytes]) -> tuple[UUID, datetime, str]:
    """``bootstrap`` / ``recover`` up to the commit; ``(owner, expiry, code)``."""
    try:
        configured = _owner_configured(store)
    except Exception:
        raise _storage_refusal(database) from None
    bootstrap = args.command == "bootstrap"
    if bootstrap and configured:
        raise CliRefused("owner_already_configured")
    if not bootstrap and not configured:
        raise CliRefused("owner_not_configured")
    if bootstrap:
        name = _display_name(terminal, "Owner display name (1-64 characters): ", optional=False)
        _confirm(terminal,
                 f"Create the Owner and issue one enrollment code valid for "
                 f"{int(lifetime.total_seconds() // 3600)} hours. "
                 f"Type {BOOTSTRAP_WORD} to confirm: ", BOOTSTRAP_WORD)
    else:
        name = _display_name(terminal, "New Owner display name (empty keeps the current one): ",
                             optional=True)
        _confirm(terminal,
                 "Recovery ends every human session, voids every pending invitation, "
                 "revokes every Owner credential and issues one new Owner enrollment "
                 f"code. Type {RECOVER_WORD} to confirm: ", RECOVER_WORD)
    secret, code = new_invitation_code(random_bytes)
    at = utc_time(clock())
    try:
        if bootstrap:
            owner, expires_at = bootstrap_owner(store, name, secret, at=at)
        else:
            owner, expires_at = recover_owner(store, secret, at=at, display_name=name)
    except OwnerAlreadyConfigured:
        raise CliRefused("owner_already_configured") from None
    except OwnerNotConfigured:
        raise CliRefused("owner_not_configured") from None
    except InvitationClockUnavailable:
        raise CliRefused("invitation_clock_unavailable") from None
    except AccessValidationError:
        raise CliRefused("display_name_rejected") from None
    except Exception:
        raise _storage_refusal(database) from None
    _verify_pinned(database)
    return owner, expires_at, code


def _list(store: AccessStore, database) -> list[str]:
    """``list``: one read transaction through the pinned database; nothing is written."""
    try:
        inventory = store.admin_inventory()
    except Exception:
        raise _storage_refusal(database) from None
    _verify_pinned(database)
    return inventory_lines(inventory)


def _revoke(command: str, principal_id: UUID, handle: UUID | None, store: AccessStore, database,
            terminal: ControllingTerminal) -> list[str]:
    """``revoke-principal`` / ``revoke-credential``: confirm on the terminal, then one transaction."""
    try:
        with closing(database.connect()) as connection:
            name, label = _revocation_target_on(connection, principal_id, handle)
    except CliRefused:
        raise
    except Exception:
        raise _storage_refusal(database) from None
    if handle is None:
        _confirm(terminal,
                 f"Revoke principal {principal_id} name={_quoted(name)}: every credential of this "
                 "person is revoked on all the devices it synced to, and every pending invitation "
                 f"code and every session of this person end. Type {REVOKE_WORD} to confirm: ",
                 REVOKE_WORD)
    else:
        _confirm(terminal,
                 f"Revoke credential {handle} label={_quoted(label)} of principal {principal_id} "
                 f"name={_quoted(name)}: this passkey is revoked on all the devices it synced to "
                 "(a synced passkey is one credential; this is not a per-device revocation), and the "
                 f"sessions it established end. Type {REVOKE_WORD} to confirm: ", REVOKE_WORD)
    try:
        if handle is None:
            revoke_principal(store, principal_id)
        else:
            revoke_credential(store, principal_id, handle)
    except CliRefused:
        raise
    except AccessValidationError:
        # Classified in the same transaction, so the store refusing it as well
        # is not expected; refused all the same, nothing committed.
        raise CliRefused("revocation_refused") from None
    except Exception:
        raise _storage_refusal(database) from None
    _verify_pinned(database)
    if handle is None:
        return [f"principal revoked: principal_id={principal_id}"]
    return [f"credential revoked on all synced devices: principal_id={principal_id} handle={handle}"]


def _run(args, *, terminal_factory: Callable[[], ControllingTerminal],
         clock: Callable[[], datetime], random_bytes: Callable[[int], bytes]) -> int:
    if os.geteuid() == 0:
        # The service account, never root: root could create a database file
        # the service cannot use, and needs no part of this.
        raise CliRefused("run_as_service_account")
    principal_id = handle = None
    if args.command in REVOKE_COMMANDS:
        principal_id = _uuid_argument(args.principal, "principal_id_rejected")
        if args.command == "revoke-credential":
            handle = _uuid_argument(args.handle, "credential_handle_rejected")
    try:
        deployment = _load_deployment(args.config)
        settings = deployment.settings
        service_uid = deployment.service_uid
        database_path = settings.database_path
        lifetime = settings.invitation_lifetime
    except Exception:
        raise CliRefused("deployment_configuration_rejected") from None
    if os.geteuid() != service_uid:
        raise CliRefused("run_as_service_account")
    terminal = terminal_factory()
    issued = None
    try:
        database = _existing_database(database_path)
        try:
            try:
                with closing(database.connect()) as connection:
                    _require_current_schema(connection)
            except CliRefused:
                raise
            except Exception:
                raise _storage_refusal(database) from None
            audit = AuditStore(database, clock=clock)
            try:
                store = AccessStore(database, clock=clock, audit=audit, invitation_lifetime=lifetime)
            except AccessValidationError:
                raise CliRefused("deployment_configuration_rejected") from None
            if args.command == "list":
                lines = _list(store, database)
            elif args.command in REVOKE_COMMANDS:
                lines = _revoke(args.command, principal_id, handle, store, database, terminal)
            else:
                issued = _issue(args, store, database, terminal, lifetime=lifetime, clock=clock,
                                random_bytes=random_bytes)
        finally:
            database.release()
        if issued is not None:
            owner, expires_at, code = issued
            _show_code(terminal, code, expires_at)
            action = "bootstrapped" if args.command == "bootstrap" else "recovered"
            lines = [f"owner {action}: principal_id={owner} "
                     f"code_expires_at={expires_at.isoformat(timespec='seconds')}"]
    finally:
        terminal.close()
    for line in lines:
        print(line)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Local Owner bootstrap, recovery and emergency revocation (ADR-0003). Run as the "
                    "service account; an enrollment code is shown only on the controlling terminal.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("bootstrap", "create the Owner and issue its enrollment code"),
                       ("recover", "revoke every Owner credential and issue a new enrollment code"),
                       ("list", "list principals, grants and credential handles"),
                       ("revoke-principal", "revoke a person: every credential, pending code and session"),
                       ("revoke-credential", "revoke one credential (on all synced devices) and its sessions")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True,
                             help="the deployment configuration the service runs with")
        if name in REVOKE_COMMANDS:
            command.add_argument("principal", help="the principal's logical UUID (as 'list' prints it)")
        if name == "revoke-credential":
            command.add_argument("handle", help="the credential handle (as 'list' prints it)")
    return parser


def main(argv: list[str] | None = None, *,
         terminal_factory: Callable[[], ControllingTerminal] = ControllingTerminal,
         clock: Callable[[], datetime] | None = None,
         random_bytes: Callable[[int], bytes] = secrets.token_bytes) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args, terminal_factory=terminal_factory,
                    clock=clock or (lambda: datetime.now(timezone.utc)), random_bytes=random_bytes)
    except CliRefused as error:
        print(f"{PROG}: refused: {error.reason}", file=sys.stderr)
        if error.reason in _HINTS:
            print(f"{PROG}: {_HINTS[error.reason]}", file=sys.stderr)
    except KeyboardInterrupt:
        print(f"{PROG}: stopped", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
