"""Local Owner command for the Main Server hardware baseline (Issue #390; D3).

Commands (``python -m app.integrity.admin_cli``), run as the service account
that owns the application database, never as root: an administrator runs it
with ``sudo -u <service account>``, never plain ``sudo``::

    python -m app.integrity.admin_cli show --config <deployment.json>
    python -m app.integrity.admin_cli approve --config <deployment.json>

Owner decision 2026-11-05: the same shape and trust model as the camera
command (``app.cameras.uvc.admin_cli``, Owner decision D3). The local
administrative boundary is the host itself; whoever can run this as the
service account can already read and write the application database. There
is no WebAuthn step-up and no Web approval. ``approve`` instead needs the
typed word ``APPROVE`` read from the controlling terminal (``/dev/tty``, never
stdin) and has no flag that skips it; that one confirmation authorizes
exactly one audited Owner operation (``LocalConsoleOwner``) through
``OwnerAdministration.approve_integrity_baseline``: the new baseline, the
integrity store's ``integrity_audit`` row and the ``approve_hardware_baseline``
security audit record (actor ``owner``, target the fixed logical
``HARDWARE_BASELINE_ID``, never a hardware identifier) commit in one
transaction. A refused or failed operation inside that boundary records
``failed``; a refusal before it changes and records nothing. The baseline is
never approved automatically: the service only compares.

What is approved. ``approve`` collects the inventory with the same read-only
probe the service uses (``app.integrity.probes.LinuxProbe``, the
``MonitoringDependencies`` default), as the same account, shows it as counts
per kind and compared with the baseline it replaces, asks for the confirmation, collects it again and refuses
(``inventory_changed``) unless the second collection equals the one shown,
then approves exactly that inventory with the baseline revision read before
the prompt as ``expected_revision``: a baseline changed meanwhile is refused
(``baseline_revision_changed``, recorded ``failed``). A collection without
any component is refused (``inventory_empty``). A kind whose probe is
unavailable (for example ``MEMORY`` without ``dmidecode`` permission) can be
approved; it then stays ``UNVERIFIABLE`` / ``PROBE_UNAVAILABLE`` at every
check, which the preview states. Inside a VM/LXD guest the probe sees only
the guest's virtual hardware (Owner decision 2026-10-22): the baseline
covers that, never the physical host. The command does not run under the
service unit's ``NoNewPrivileges`` / ``RestrictSUIDSGID``: on a host where
``dmidecode`` is setuid or has file capabilities it may read memory
identifiers the service cannot, and the service then reports ``MEMORY``
``UNVERIFIABLE`` (a warning, never an immediate alert); ``show`` after the
next start states it.

Output. Only fixed words and numbers: per-kind component counts, unavailable
kinds, the baseline revision and the comparison findings grouped as
kind / state / reason with a count, plus whether that finding would raise the
immediate ``hardware_integrity_failure`` or a warning. Never a serial, UUID,
WWN/WWID, PCI address or id, model string, ``/dev`` or sysfs path, or any
other observed value: those stay local in the baseline row
(``app/integrity/README.md``). ``show`` also prints the preview an unchanged
host would report after approving the current inventory, and the service's
last recorded check.

Service. ``show`` is read-only and allowed while the service runs (like the
camera command's ``sources`` / ``candidates``). ``approve`` refuses while it
runs (``service_running``): the running service compares only at startup and
then every 24 hours, so a baseline approved under it would leave its
current, stale verdict and alerts in place until the next daily check; with
the service stopped, the next start compares against the new baseline at
once. Stop the upstream socket together with the service
(``server-sentinel-upstream.socket``): with socket activation an incoming
connection would start a service that was stopped alone. The running service is detected exactly as the camera command does
(``app.cameras.uvc.admin_cli._database_holders``: any other process of the
service account that holds the database file open, also another local admin
command), checked before the prompt and again inside the approval's
transaction. The same limits apply: run it inside the environment the
service runs in (the VM/LXD guest, Owner decision D2), never from its host
or from a container.

``--config`` is the deployment configuration the service runs with
(``app.deployment.Deployment.load``). The database is that deployment's,
pinned and of exactly this release's schema (``app.local_admin``): the
command never creates or migrates a database. Like the other local admin
commands it writes without the monitoring storage reservation (a few small
metadata rows).

Exit status: ``0`` done, ``2`` refused (a fixed word on stderr).
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import nullcontext
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sys
from typing import Callable
from uuid import UUID

from app.audit.integration import OwnerAdministration
from app.audit.service import OwnerAuditService
from app.audit.store import AuditStore
from app.cameras.registry import CameraRegistry
from app.cameras.uvc.admin_cli import LocalConsoleOwner, _database_holders
from app.deployment import Deployment, _runtime_roots
from app.local_admin import (
    CliRefused, ControllingTerminal, _existing_database, _LedgerDatabaseChanged,
    _require_current_schema,
)
from .model import Finding, Inventory, Kind, State, compare
from .probes import LinuxProbe
from .store import IntegrityStore


PROG = "python -m app.integrity.admin_cli"
APPROVE_WORD = "APPROVE"
# The ``integrity_audit.actor`` of an approval made on the local console. A
# fixed logical ID, not a principal: the console Owner (D3) has no
# application principal, and the security audit record carries only the
# ``owner`` actor category.
LOCAL_CONSOLE_OWNER_ID = UUID("0c7759d4-cd43-4788-a299-56d8cd4c6b6a")
# The store's pending-event limit is irrelevant here (this command never
# records a check); the service's default is used so construction validates.
_MAX_PENDING_EVENTS = 64
_REASON = re.compile(r"[A-Z][A-Z_]{0,63}")
_STATE_ORDER = {state: index for index, state in enumerate(State)}
_KIND_ORDER = {kind: index for index, kind in enumerate(Kind)}
_HINTS = {
    "service_running": ("stop the upstream socket and the service (sudo systemctl stop "
                        "server-sentinel-upstream.socket server-sentinel.service; with socket "
                        "activation a connection restarts a service stopped alone), run "
                        "'approve', then start both again; the next start compares against the "
                        "new baseline. Any other process of the service account holding the "
                        "database counts, also another local admin command (bootstrap_cli, "
                        "pairing_cli, reservation_cli, a camera or a second integrity "
                        "admin_cli): let it finish first"),
    "inventory_changed": ("the hardware inventory differed between the confirmation and the "
                          "approval; run 'show' again and retry"),
    "baseline_revision_changed": ("the baseline changed since it was read; run 'show' again and "
                                  "retry"),
    "committed_verification_failed": ("the baseline was committed, but maybe not to the database "
                                      "now at the path; run 'show': if it is missing, investigate "
                                      "the state directory and re-run the command"),
}


class _ConsoleOwner(LocalConsoleOwner):
    """The console grant gate, also arming exactly one baseline approval."""

    def __init__(self):
        super().__init__()
        self._armed = 0

    def require_owner(self, actor_context: object) -> None:
        super().require_owner(actor_context)
        self._armed += 1


class _ConsoleBaselineApproval:
    """``IntegrityStore``'s approval: only after the audit boundary consumed a grant."""

    def __init__(self, owner: _ConsoleOwner):
        self._owner = owner

    def require_owner(self) -> UUID:
        if self._owner._armed < 1:
            raise PermissionError("OWNER_APPROVAL_REQUIRED")
        self._owner._armed -= 1
        return LOCAL_CONSOLE_OWNER_ID


class _StoppedServiceIntegrityStore(IntegrityStore):
    """The store whose approval re-checks, inside its transaction, that the service is stopped."""

    def __init__(self, connection, approval, *, require_stopped: Callable[[], None]):
        super().__init__(connection, approval, reservation=nullcontext,
                         max_pending_events=_MAX_PENDING_EVENTS)
        self._require_stopped = require_stopped

    def approve_on(self, connection, inventory, *, expected_revision, at):
        self._require_stopped()
        return super().approve_on(connection, inventory, expected_revision=expected_revision, at=at)


# -- presentation (fixed words and numbers only) ---------------------------

def _reason(finding: Finding) -> str:
    return finding.reason if _REASON.fullmatch(finding.reason) else "?"


def _notify(finding: Finding) -> str:
    if finding.immediate:
        return "failure"
    return "none" if finding.state == State.OK else "warning"


def inventory_counts(inventory: Inventory | None) -> str:
    """``CPU=1 MEMORY=unavailable STORAGE=2 GPU=1``; never a component's values."""
    if inventory is None:
        return "none"
    counts = Counter(item.kind for item in inventory.components)
    parts = []
    for kind in Kind:
        if kind in inventory.unavailable:
            parts.append(f"{kind.value}=unavailable")
        else:
            parts.append(f"{kind.value}={counts[kind]}")
    return " ".join(parts)


def finding_lines(findings, prefix: str = "  ") -> list[str]:
    """Findings grouped as kind / state / reason with a count, in a fixed order."""
    grouped = Counter((item.kind, item.state, _reason(item), _notify(item)) for item in findings)
    lines = [f"{prefix}{kind.value} {state.value} reason={reason} count={count} notify={notify}"
             for (kind, state, reason, notify), count in sorted(
                 grouped.items(), key=lambda entry: (_KIND_ORDER[entry[0][0]],
                                                     _STATE_ORDER[entry[0][1]], entry[0][2]))]
    return lines or [f"{prefix}no findings"]


def _verdict(findings) -> str:
    if any(item.immediate for item in findings):
        return "hardware_integrity_failure"
    if any(item.state != State.OK for item in findings):
        return "hardware_integrity_warning"
    return "ok"


# -- helpers -------------------------------------------------------------

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


def _collect(probe) -> Inventory:
    try:
        inventory = probe.collect()
    except Exception:
        raise CliRefused("inventory_unavailable") from None
    if not isinstance(inventory, Inventory):
        raise CliRefused("inventory_unavailable")
    return inventory


def _same_inventory(first: Inventory, second: Inventory) -> bool:
    """The same components (in any order) and the same unavailable kinds."""
    return (first.unavailable == second.unavailable
            and Counter(first.components) == Counter(second.components))


class _Context:
    def __init__(self, database, store, admin, owner, terminal, probe, require_stopped):
        self.database = database
        self.store = store
        self.admin = admin
        self.owner = owner
        self.terminal = terminal
        self.probe = probe
        self.require_stopped = require_stopped


def _baseline(context: _Context):
    try:
        return context.store.baseline()
    except Exception:
        raise _storage_refusal(context.database) from None


def _show(context: _Context) -> list[str]:
    revision, baseline = _baseline(context)
    try:
        latest = context.store.latest()
    except Exception:
        raise _storage_refusal(context.database) from None
    _verify_pinned(context.database)
    current = _collect(context.probe)
    findings = compare(baseline, current)
    lines = [f"baseline: revision={revision} components: {inventory_counts(baseline)}",
             f"current: components: {inventory_counts(current)}",
             f"current vs baseline: {_verdict(findings)}",
             *finding_lines(findings)]
    preview = compare(current, current)
    lines += [f"if the current inventory were approved, an unchanged host would report: "
              f"{_verdict(preview)}", *finding_lines(preview)]
    if latest is None:
        lines.append("last recorded check: none")
    else:
        recorded, blocked = latest
        lines.append(f"last recorded check: {_verdict(recorded)}"
                     f"{' delivery_blocked=yes' if blocked else ''}")
        lines += finding_lines(recorded)
    return lines


def _approve(context: _Context) -> list[str]:
    context.require_stopped()
    revision, baseline = _baseline(context)
    _verify_pinned(context.database)
    current = _collect(context.probe)
    if not current.components:
        raise CliRefused("inventory_empty")
    preview = compare(current, current)
    # What changes: the current inventory compared with the baseline it
    # replaces, so a same-count replacement shows as CHANGED here.
    findings = compare(baseline, current)
    prompt = "\n".join([
        f"Approve the current hardware inventory as the Main Server baseline "
        f"(revision {revision} -> {revision + 1}).",
        f"  baseline now: {inventory_counts(baseline)}",
        f"  current:      {inventory_counts(current)}",
        f"  current vs baseline: {_verdict(findings)}",
        *finding_lines(findings, "    "),
        "  Only the hardware this host (or VM guest) itself exposes is covered.",
        f"  An unchanged host would then report: {_verdict(preview)}",
        *finding_lines(preview, "    "),
        f"Type {APPROVE_WORD} to confirm: ",
    ])
    grant = context.owner.confirm(context.terminal, prompt, APPROVE_WORD)
    # Approve exactly what was shown: a second collection must equal it.
    if not _same_inventory(_collect(context.probe), current):
        raise CliRefused("inventory_changed")
    try:
        approved = context.admin.approve_integrity_baseline(
            grant, context.store, current, expected_revision=revision,
            at=datetime.now(timezone.utc))
    except CliRefused:
        raise  # service_running inside the transaction (recorded failed)
    except ValueError as error:
        if str(error) == "BASELINE_REVISION_CHANGED":
            raise CliRefused("baseline_revision_changed") from None
        raise _storage_refusal(context.database) from None
    except Exception:
        raise _storage_refusal(context.database) from None
    try:
        _verify_pinned(context.database)
    except CliRefused:
        raise CliRefused("committed_verification_failed") from None
    return [f"baseline approved: revision={approved} components: {inventory_counts(current)}",
            "next: start the service; its startup check compares against this baseline"]


def _run(args, *, terminal_factory: Callable[[], ControllingTerminal],
         probe_factory: Callable[[], object], holders: Callable[..., int]) -> int:
    if os.geteuid() == 0:
        raise CliRefused("run_as_service_account")
    try:
        deployment = _load_deployment(args.config)
        database_path = deployment.settings.database_path
        service_uid = deployment.service_uid
    except Exception:
        raise CliRefused("deployment_configuration_rejected") from None
    if os.geteuid() != service_uid:
        raise CliRefused("run_as_service_account")
    terminal = terminal_factory() if args.command == "approve" else None
    try:
        database = _existing_database(database_path)
        try:
            connection = None
            try:
                try:
                    connection = database.connect()
                    _require_current_schema(connection)
                except CliRefused:
                    raise
                except Exception:
                    raise _storage_refusal(database) from None
                identity, name = database._identity, database.path.name

                def require_stopped() -> None:
                    if holders(identity, name):
                        raise CliRefused("service_running")

                owner = _ConsoleOwner()
                try:
                    store = _StoppedServiceIntegrityStore(
                        connection, _ConsoleBaselineApproval(owner),
                        require_stopped=require_stopped)
                except Exception:
                    raise _storage_refusal(database) from None
                admin = OwnerAdministration(OwnerAuditService(AuditStore(database), owner),
                                            CameraRegistry(database))
                context = _Context(database, store, admin, owner, terminal, probe_factory(),
                                   require_stopped)
                lines = _show(context) if args.command == "show" else _approve(context)
            finally:
                if connection is not None:
                    connection.close()
        finally:
            database.release()
    finally:
        if terminal is not None:
            terminal.close()
    for line in lines:
        print(line)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Show or approve the Main Server hardware baseline (Issue #390, Owner "
                    "decision D3). Run as the service account; 'approve' needs the service "
                    "stopped and a confirmation typed on the controlling terminal.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("show", "compare the current inventory with the baseline (kinds, "
                                "states and counts only)"),
                       ("approve", "approve the current inventory as the baseline")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True,
                             help="the deployment configuration the service runs with")
    return parser


def main(argv: list[str] | None = None, *,
         terminal_factory: Callable[[], ControllingTerminal] = ControllingTerminal,
         probe_factory: Callable[[], object] = LinuxProbe,
         holders: Callable[..., int] = _database_holders) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args, terminal_factory=terminal_factory, probe_factory=probe_factory,
                    holders=holders)
    except CliRefused as error:
        print(f"{PROG}: refused: {error.reason}", file=sys.stderr)
        if error.reason in _HINTS:
            print(f"{PROG}: {_HINTS[error.reason]}", file=sys.stderr)
    except KeyboardInterrupt:
        print(f"{PROG}: stopped", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
