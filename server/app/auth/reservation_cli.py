"""Local Owner command for the hostname-reservation listener exceptions.

Issue #10, Owner decision D3 (2026-10-16): the Owner records the listener
exceptions (``ListenerException``, ADR-0003) on the Main Server host itself,
with the same trust model as ``app.auth.bootstrap_cli``: run as the service
account that owns the application database, never as root and never with
``sudo``, with a confirmation word read from the controlling terminal, and an
audit record (actor ``owner``) committed in the same transaction as the
change. There is no WebAuthn step-up: whoever can run this as the service
account can already write the application database.

Commands (``python -m app.auth.reservation_cli``)::

    python -m app.auth.reservation_cli show --config <deployment.json>
    python -m app.auth.reservation_cli set --config <deployment.json> <exception> [<exception> ...]
    python -m app.auth.reservation_cli set --config <deployment.json> --clear

``set`` replaces the whole stored set; ``--clear`` stores the empty set. Each
``<exception>`` is one argument of comma-separated ``key=value`` fields::

    protocol=tcp,port=22,unit=ssh.socket,uid=0
    protocol=udp,port=41641,unit=tailscaled.service,uid=0
    scope=reserved_address,protocol=tcp,port=43210,family=ipv4,unit=tailscaled.service,uid=0

``protocol`` (``tcp`` or ``udp``), ``port``, ``unit`` and ``uid`` are
required; ``family`` (``ipv4``, ``ipv6`` or ``any``, the default) and
``scope`` (``wildcard``, the default, or ``reserved_address``) are optional.
What a scope accepts is ``ListenerException``'s rule (a ``reserved_address``
exception only for ``tailscaled.service``, uid 0, TCP; Owner decision D1,
2026-10-16), and the whole set is checked with
``validate_listener_exceptions`` against this deployment's reservation (never
the dashboard, upstream or proxy port; at most ``MAX_LISTENER_EXCEPTIONS``).
A field that is unknown, repeated, empty or not canonical refuses the command
(``listener_exception_rejected``), as does a repeated exception.

Applied on restart only. The running service loads the stored set once, at
its startup check, and keeps using that set; it does not see this change
until ``server-sentinel.service`` restarts, and the first check after that
restart applies it (narrowing it can close human access then). Until then
``show`` prints the stored set, not the one in force.

Checks shared with ``bootstrap_cli``: refused as root or as any account other
than the deployment's service account (``run_as_service_account``); the
deployment configuration is loaded and validated as the launcher loads it
(``deployment_configuration_rejected``); the controlling terminal
(``/dev/tty``, never stdin/stdout) is required for both commands
(``controlling_terminal_required``); the application database is the existing
file pinned by ``app.local_admin._existing_database`` for the whole command,
re-verified before each commit, and its schema must be exactly this
release's (``_require_current_schema``). ``set`` also needs the reservation the
deployment's ``human_access`` section states, read through
``HumanAccessDeployment.reservation_config()``
(``human_access_not_configured`` without the section,
``human_access_configuration_rejected`` when it states no usable
reservation; neither prints a value).

``set`` shows the stored set and the new set on the terminal and reads the
word ``CHANGE``; anything else is ``owner_confirmation_declined``. The stored
value is compared again inside the write transaction: if it changed after it
was shown, the command refuses (``listener_exceptions_changed``) and writes
nothing. Otherwise ``ListenerExceptionStore.write_on`` and the
``change_security_setting`` audit record (actor ``owner``, target the fixed
listener-exceptions id; no port, unit or address) commit in one transaction.
A refusal changes nothing and records nothing. One refusal comes after the
commit: ``committed_verification_failed`` means the change and its audit
record were committed, but re-verifying the pinned database file afterwards
failed (it was renamed or replaced), so the change may sit only in the old
file; run ``show`` and repeat ``set`` if the stored set is not the new one.

Output. Nothing secret exists here, and nothing beyond what the Owner typed
is printed: ``show`` prints each stored exception in the argument form above
(canonical field order) on stdout, or ``no listener exceptions``; ``set``
prints only the number of stored exceptions and the restart reminder. The
values are never logged and never enter the audit record. A stored set that
cannot be read is refused (``stored_exceptions_unreadable`` /
``stored_exceptions_outdated``) without printing it; ``set`` replaces it.

Exit status: ``0`` done, ``2`` refused (a fixed word on stderr).
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sys
from typing import Callable

from app.audit.model import ActorCategory, AuditAction, AuditOutcome, TargetKind
from app.audit.store import AuditStore
from app.auth.access_config import HumanAccessDeployment, HumanAccessRefused
from app.deployment import Deployment, _runtime_roots
from app.local_admin import (
    CliRefused, ControllingTerminal, _existing_database, _LedgerDatabaseChanged,
    _require_current_schema,
)
from .reservation import (
    AddressFamily, BindScope, ListenerException, MAX_LISTENER_EXCEPTIONS, ReservationConfig,
    TransportProtocol, validate_listener_exceptions,
)
from .reservation_store import (
    RESERVATION_LISTENER_EXCEPTIONS_ID, STORE_KEY, ListenerExceptionStore, ListenerExceptionStoreError,
    OutdatedListenerExceptions,
)


PROG = "python -m app.auth.reservation_cli"
CHANGE_WORD = "CHANGE"
RESTART_NOTE = ("the running service applies this only after 'systemctl restart server-sentinel.service'; "
                "until then it keeps the set it loaded at startup")
MAX_ARGUMENT_LENGTH = 320
_FIELDS = ("scope", "protocol", "port", "family", "unit", "uid")
_REQUIRED = frozenset({"protocol", "port", "unit", "uid"})
_NUMBER = re.compile(r"0|[1-9][0-9]{0,9}")
_HINTS = {
    "committed_verification_failed": ("the change was committed, but maybe not to the database now at the path; "
                                      "run 'show' and repeat 'set' if the stored set is not the new one"),
    "stored_exceptions_unreadable": "the check keeps human access closed; replace the stored set with 'set'",
    "stored_exceptions_outdated": "the check keeps human access closed; enter the exceptions again with 'set'",
    "human_access_not_configured": "the deployment configuration has no human_access section",
    "human_access_configuration_rejected": ("the deployment's human_access section does not state a usable "
                                            "reservation"),
}


def parse_exception(text: object) -> ListenerException:
    """One ``key=value,...`` argument as a ``ListenerException``, else ``listener_exception_rejected``."""
    if not isinstance(text, str) or not 0 < len(text) <= MAX_ARGUMENT_LENGTH:
        raise CliRefused("listener_exception_rejected")
    fields: dict[str, str] = {}
    for part in text.split(","):
        key, separator, value = part.partition("=")
        if not separator or key not in _FIELDS or key in fields or not value:
            raise CliRefused("listener_exception_rejected")
        fields[key] = value
    if not _REQUIRED <= set(fields):
        raise CliRefused("listener_exception_rejected")
    try:
        if not _NUMBER.fullmatch(fields["port"]) or not _NUMBER.fullmatch(fields["uid"]):
            raise ValueError
        family = fields.get("family", "any")
        return ListenerException(
            int(fields["port"]), TransportProtocol(fields["protocol"]),
            None if family == "any" else AddressFamily(family),
            BindScope(fields.get("scope", BindScope.WILDCARD.value)),
            unit=fields["unit"], uid=int(fields["uid"]))
    except ValueError:
        raise CliRefused("listener_exception_rejected") from None


def format_exception(item: ListenerException) -> str:
    """The canonical argument form of an exception (what ``parse_exception`` reads back)."""
    family = "any" if item.family is None else item.family.value
    return (f"scope={item.scope.value},protocol={item.protocol.value},port={item.port},"
            f"family={family},unit={item.unit},uid={item.uid}")


def _sorted_lines(exceptions) -> list[str]:
    return sorted(format_exception(item) for item in exceptions)


def parse_exceptions(arguments, config: ReservationConfig) -> frozenset:
    """Every argument parsed, none repeated, the set valid for ``config``."""
    if len(arguments) > MAX_LISTENER_EXCEPTIONS:
        raise CliRefused("listener_exception_rejected")
    parsed = [parse_exception(argument) for argument in arguments]
    values = frozenset(parsed)
    if len(values) != len(parsed):
        raise CliRefused("listener_exception_rejected")
    try:
        return validate_listener_exceptions(config, values)
    except ValueError:
        raise CliRefused("listener_exception_rejected") from None


def deployment_reservation(deployment) -> ReservationConfig:
    """The deployment's ``ReservationConfig``, the one the service's check uses.

    Read from the deployment's ``human_access`` section through
    ``HumanAccessDeployment.reservation_config()`` (the section plus the
    deployment's loopback upstream, as ``app.auth.composition`` builds it). A
    deployment without the section is refused: no reservation exists to
    validate against. The section's ``enabled`` flag does not matter here; the
    stated reservation is the same either way. Every refusal is value-free.
    """
    human_access = getattr(deployment, "human_access", None)
    if human_access is None:
        raise CliRefused("human_access_not_configured")
    if not isinstance(human_access, HumanAccessDeployment):
        raise CliRefused("deployment_configuration_rejected")
    try:
        config = human_access.reservation_config()
    except (HumanAccessRefused, ValueError):
        raise CliRefused("human_access_configuration_rejected") from None
    if not isinstance(config, ReservationConfig):
        raise CliRefused("human_access_configuration_rejected")
    return config


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


def _stored_raw_on(connection):
    row = connection.execute("SELECT value FROM application_metadata WHERE key=?", (STORE_KEY,)).fetchone()
    return None if row is None else row[0]


def _stored(store: ListenerExceptionStore, database):
    """``(raw value, exceptions or a refusal word)`` of the stored set."""
    try:
        with closing(database.connect_read_only()) as connection:
            raw = _stored_raw_on(connection)
    except Exception:
        raise _storage_refusal(database) from None
    try:
        exceptions = store.load()
    except OutdatedListenerExceptions:
        return raw, "stored_exceptions_outdated"
    except ListenerExceptionStoreError:
        if database.rejected:
            raise _storage_refusal(database) from None
        return raw, "stored_exceptions_unreadable"
    return raw, exceptions


def _show(store, database) -> list[str]:
    _, exceptions = _stored(store, database)
    _verify_pinned(database)
    if isinstance(exceptions, str):
        raise CliRefused(exceptions)
    return _sorted_lines(exceptions) or ["no listener exceptions"]


class _StoredSetChanged(Exception):
    pass


def store_exceptions(audit: AuditStore, store: ListenerExceptionStore, exceptions: frozenset, expected_raw) -> None:
    """Write the set and its Owner audit record in one transaction.

    The stored value is read again after ``BEGIN IMMEDIATE``; when it is no
    longer the value shown to the Owner nothing is written.
    """
    with audit.transaction(write=True) as connection:
        if _stored_raw_on(connection) != expected_raw:
            raise _StoredSetChanged()
        store.write_on(connection, exceptions)
        audit.append_on(connection, actor_category=ActorCategory.OWNER, action=AuditAction.CHANGE_SECURITY_SETTING,
                        target_kind=TargetKind.SECURITY_SETTINGS,
                        target_logical_id=RESERVATION_LISTENER_EXCEPTIONS_ID, outcome=AuditOutcome.SUCCEEDED)


def _describe(exceptions) -> str:
    if isinstance(exceptions, str):
        return "  (the stored set cannot be read; it is replaced)\n"
    lines = _sorted_lines(exceptions)
    return "".join(f"  {line}\n" for line in lines) if lines else "  (none)\n"


def _set(exceptions: frozenset, store, audit, database, terminal: ControllingTerminal) -> list[str]:
    raw, current = _stored(store, database)
    terminal.write("Stored listener exceptions:\n" + _describe(current)
                   + "New listener exceptions (replacing the whole set):\n" + _describe(exceptions)
                   + f"Note: {RESTART_NOTE}.\nType {CHANGE_WORD} to confirm: ")
    if terminal.read_line() != CHANGE_WORD:
        raise CliRefused("owner_confirmation_declined")
    try:
        store_exceptions(audit, store, exceptions, raw)
    except _StoredSetChanged:
        raise CliRefused("listener_exceptions_changed") from None
    except Exception:
        raise _storage_refusal(database) from None
    try:
        _verify_pinned(database)
    except CliRefused:
        raise CliRefused("committed_verification_failed") from None
    return [f"listener exceptions stored: {len(exceptions)}", f"note: {RESTART_NOTE}"]


def _run(args, *, terminal_factory: Callable[[], ControllingTerminal],
         clock: Callable[[], datetime]) -> int:
    if os.geteuid() == 0:
        raise CliRefused("run_as_service_account")
    if args.command == "set" and bool(args.clear) == bool(args.exceptions):
        # Either the replacement exceptions or ``--clear``, never both or neither.
        raise CliRefused("listener_exception_rejected")
    try:
        deployment = _load_deployment(args.config)
        service_uid = deployment.service_uid
        database_path = deployment.settings.database_path
    except Exception:
        raise CliRefused("deployment_configuration_rejected") from None
    if os.geteuid() != service_uid:
        raise CliRefused("run_as_service_account")
    exceptions = None
    if args.command == "set":
        exceptions = parse_exceptions(args.exceptions, deployment_reservation(deployment))
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
                raise _storage_refusal(database) from None
            store = ListenerExceptionStore(database)
            if args.command == "show":
                lines = _show(store, database)
            else:
                lines = _set(exceptions, store, AuditStore(database, clock=clock), database, terminal)
        finally:
            database.release()
    finally:
        terminal.close()
    for line in lines:
        print(line)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Show or replace the hostname-reservation listener exceptions (ADR-0003). Run as the "
                    "service account; the running service applies a change only after it restarts.")
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show", help="print the stored listener exceptions")
    change = commands.add_parser("set", help="replace the stored listener exceptions (confirmed on the terminal)")
    for command in (show, change):
        command.add_argument("--config", type=Path, required=True,
                             help="the deployment configuration the service runs with")
    change.add_argument("--clear", action="store_true", help="store the empty set")
    change.add_argument("exceptions", nargs="*",
                        help="protocol=tcp|udp,port=N,unit=NAME,uid=N[,family=ipv4|ipv6|any]"
                             "[,scope=wildcard|reserved_address]")
    return parser


def main(argv: list[str] | None = None, *,
         terminal_factory: Callable[[], ControllingTerminal] = ControllingTerminal,
         clock: Callable[[], datetime] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args, terminal_factory=terminal_factory,
                    clock=clock or (lambda: datetime.now(timezone.utc)))
    except CliRefused as error:
        print(f"{PROG}: refused: {error.reason}", file=sys.stderr)
        if error.reason in _HINTS:
            print(f"{PROG}: {_HINTS[error.reason]}", file=sys.stderr)
    except KeyboardInterrupt:
        print(f"{PROG}: stopped", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
