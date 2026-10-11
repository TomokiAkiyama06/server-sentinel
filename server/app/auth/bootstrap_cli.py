"""Local Owner bootstrap and recovery on the Main Server (ADR-0003, Issue #10 phase 2 S2).

Commands (``python -m app.auth.bootstrap_cli``), run as the service account
that owns the application database, never as root and never with ``sudo``::

    python -m app.auth.bootstrap_cli bootstrap --config <deployment.json>
    python -m app.auth.bootstrap_cli recover --config <deployment.json>

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
from .model import AccessValidationError, utc_time
from .reservation_store import HUMAN_SESSIONS_ID
from .store import AccessStore, InvitationClockUnavailable, OwnerAlreadyConfigured, OwnerNotConfigured


PROG = "python -m app.auth.bootstrap_cli"
BOOTSTRAP_WORD = "BOOTSTRAP"
RECOVER_WORD = "RECOVER"


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


def _run(args, *, terminal_factory: Callable[[], ControllingTerminal],
         clock: Callable[[], datetime], random_bytes: Callable[[int], bytes]) -> int:
    if os.geteuid() == 0:
        # The service account, never root: root could create a database file
        # the service cannot use, and needs no part of this.
        raise CliRefused("run_as_service_account")
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
    try:
        database = _existing_database(database_path)
        try:
            try:
                with closing(database.connect()) as connection:
                    _require_current_schema(connection)
            except CliRefused:
                raise
            except Exception:
                raise CliRefused("database_rejected" if database.rejected else "database_unavailable") from None
            audit = AuditStore(database, clock=clock)
            try:
                store = AccessStore(database, clock=clock, audit=audit, invitation_lifetime=lifetime)
            except AccessValidationError:
                raise CliRefused("deployment_configuration_rejected") from None
            try:
                configured = _owner_configured(store)
            except Exception:
                raise CliRefused("database_rejected" if database.rejected else "database_unavailable") from None
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
                raise CliRefused("database_rejected" if database.rejected else "database_unavailable") from None
            try:
                database.verify()
            except _LedgerDatabaseChanged:
                raise CliRefused("database_rejected") from None
        finally:
            database.release()
        _show_code(terminal, code, expires_at)
    finally:
        terminal.close()
    action = "bootstrapped" if args.command == "bootstrap" else "recovered"
    print(f"owner {action}: principal_id={owner} code_expires_at={expires_at.isoformat(timespec='seconds')}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Local Owner bootstrap and recovery (ADR-0003). Run as the service account; "
                    "the enrollment code is shown only on the controlling terminal.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("bootstrap", "create the Owner and issue its enrollment code"),
                       ("recover", "revoke every Owner credential and issue a new enrollment code")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True,
                             help="the deployment configuration the service runs with")
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
    except KeyboardInterrupt:
        print(f"{PROG}: stopped", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
