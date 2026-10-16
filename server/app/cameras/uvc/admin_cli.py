"""Local camera administration on the Main Server (Issue #11; Owner decision D3, 2026-10-16).

Commands (``python -m app.cameras.uvc.admin_cli``), run as the service account
that owns the application database, never as root and never with ``sudo``::

    python -m app.cameras.uvc.admin_cli sources --config <deployment.json>
    python -m app.cameras.uvc.admin_cli candidates --config <deployment.json>
    python -m app.cameras.uvc.admin_cli create-source --config <deployment.json> \\
        --name <name> --profile 1920x1080@30/MJPG
    python -m app.cameras.uvc.admin_cli approve --config <deployment.json> <source id> <candidate label>

Same trust model as ``app.auth.bootstrap_cli`` (Owner decision D3): the local
administrative boundary is the host itself; whoever can run this as the
service account can already read and write the application database. There
is no WebAuthn step-up. Each mutation instead needs a typed confirmation word
read from the controlling terminal (``/dev/tty``, never stdin), and that one
confirmation authorizes exactly one audited Owner operation
(``LocalConsoleOwner``): ``create-source`` goes through
``OwnerAdministration.create_source`` and ``approve`` through
``OwnerAdministration.approve_uvc`` (``LinuxDiscovery`` + ``LocalUvcAdapter``),
so the change and its audit record (actor ``owner``; ``create_source`` /
``approve_camera``, target the source's logical UUID only) commit in one
transaction. A refused or failed operation inside that boundary records
``failed``; a refusal before it changes and records nothing.

``--config`` is the deployment configuration the service runs with
(``app.deployment.Deployment.load``, the same validation as the launcher). The
database is that deployment's, pinned and of exactly this release's schema
(``app.local_admin._existing_database`` / ``_require_current_schema``): the
command never creates or migrates a database.

Applied on restart. The service reads its ``local_uvc.source_ids`` and the
approvals at startup, so a mutation refuses while the service is running
(``service_running``): stop it, run the command, then start it again. The
running service is detected as any other process of the service account that
holds the database file open (``_database_holders``: ``/proc/<pid>/fd`` of
every process whose real, effective, saved or filesystem uid is this
account). That is robust because every Main process keeps a descriptor on its
database for its whole lifetime (``app.storage.database``), whatever its UVC
state: unlike the UVC active-session marker it is never left behind by a
crash and is present even when no source is approved, and unlike a
device-busy probe it touches no camera. A same-account process whose
descriptors cannot be read refuses the command (``service_state_unavailable``)
instead of being assumed stopped. Limits: a process in another PID namespace
(the service in a container while this runs on its host) or hidden by a
``hidepid`` ``/proc`` is not seen, so run this inside the service's own
environment (the VM/LXD guest); and a service started after the final check,
inside the command's last transaction, is not refused (the check runs before
the confirmation and again inside that transaction).

Output. ``candidates`` identifies each connected USB video-capture camera only
by a short hashed label (``cam-`` and 10 hex digits of a SHA-256 over the
device's live-instance evidence, so it stays the same between ``candidates``
and ``approve`` while the camera stays plugged in, changes when it is
re-plugged, and does not reveal the serial), its USB vendor:product ids,
whether it reports a serial (``present`` / ``absent`` / ``shared`` when another
connected camera reports the same one), its advertised pixel formats and the
source whose approval currently holds it. Never a serial, ``/dev`` path,
by-id name or USB port. Names are printed quoted, escaped and bounded.

Ambiguity (AGENTS.md section 7). ``approve`` refuses a camera without a serial
(``camera_without_serial``) and one whose serial is not unique
(``camera_serial_not_unique``: another connected camera reports it, or the
source's approval already latched that serial as ambiguous). Such a camera
cannot be told apart from an identical one by stored evidence, so after the
restart the service would put the source in ``manual_intervention_required``
anyway; it needs a live Owner approval on the running service instead. A
camera that does not advertise the source's pixel format is refused
(``camera_format_unsupported``) because the service could only report
``capture_profile_unavailable``. The adapter rescans in the audited
preparation and refuses a camera that changed or vanished since the selection
(``candidate_unavailable``, recorded ``failed``), and it refuses a camera already approved for another enabled source and a
disabled or non-``local_uvc`` source; the registry refuses an enabled source
beyond the active-source limit (1 to 4).

Exit status: ``0`` done, ``2`` refused (a fixed word on stderr).
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Callable
from uuid import UUID

from app.audit.integration import OwnerAdministration
from app.audit.service import OwnerAuditService, OwnerAuthorizationError
from app.audit.store import AuditStore
from app.cameras.registry import CameraRegistry, CaptureProfile, SourceType
from app.cameras.registry.models import ValidationError
from app.cameras.registry.repository import ActiveSourceLimitError, NotFoundError
from app.deployment import Deployment, _runtime_roots
from app.local_admin import (
    CliRefused, ControllingTerminal, _existing_database, _LedgerDatabaseChanged,
    _require_current_schema,
)
from .capture import VideoProfile
from .discovery import LinuxDiscovery
from .identity import DeviceEvidence, same_physical_camera
from .persistence import ApprovalConflictError, ApprovalStore
from .registry_adapter import LocalUvcAdapter


PROG = "python -m app.cameras.uvc.admin_cli"
CREATE_WORD = "CREATE"
APPROVE_WORD = "APPROVE"
MUTATIONS = ("create-source", "approve")
LABEL_PREFIX = "cam-"
_LABEL_DIGITS = 10
_LABEL = re.compile(r"cam-[0-9a-f]{10}")
_LABEL_DOMAIN = b"serversentinel-local-uvc-candidate-label-v1\0"
_PROFILE = re.compile(r"([0-9]{1,5})x([0-9]{1,5})@([0-9]{1,4})/([0-9A-Z]{4})")
_USB_ID = re.compile(r"[0-9a-f]{4}")
_MAX_TEXT = 128
_HINTS = {
    "service_running": ("stop the service (sudo systemctl stop server-sentinel.service), run the "
                        "command, then start it again; changes apply on start"),
    "camera_without_serial": ("a camera without a serial cannot be approved offline: stored evidence "
                              "cannot tell it from an identical one after the restart"),
    "camera_serial_not_unique": ("this serial is not unique to one camera, so stored evidence cannot "
                                 "tell the cameras apart after the restart"),
    "committed_verification_failed": ("the change was committed, but maybe not to the database now at "
                                      "the path; run 'sources': if it is missing, investigate the state "
                                      "directory and re-run the command"),
}


class LocalConsoleOwner:
    """Owner gate: one typed terminal confirmation authorizes one audited operation."""

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


# -- service detection ---------------------------------------------------

def _process_uids(status_path: Path) -> set[int] | None:
    """Real, effective, saved and filesystem uid of a process, or None if gone."""
    try:
        with status_path.open("rb") as stream:
            text = stream.read(16384).decode("ascii", "replace")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError:
        raise CliRefused("service_state_unavailable") from None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            try:
                return {int(value) for value in line[4:].split()}
            except ValueError:
                break
    raise CliRefused("service_state_unavailable")


def _database_holders(identity: tuple[int, int], *, proc_root: Path = Path("/proc"),
                      own_pid: int | None = None, account: int | None = None) -> int:
    """How many other processes of this account hold the database file open.

    Never assumes "stopped" for a same-account process it cannot inspect:
    that refuses with ``service_state_unavailable``.
    """
    own_pid = os.getpid() if own_pid is None else own_pid
    account = os.geteuid() if account is None else account
    try:
        entries = os.listdir(proc_root)
    except OSError:
        raise CliRefused("service_state_unavailable") from None
    holders = 0
    for entry in entries:
        if not entry.isdecimal() or int(entry) == own_pid:
            continue
        uids = _process_uids(proc_root / entry / "status")
        if uids is None or account not in uids:
            continue
        descriptors = proc_root / entry / "fd"
        try:
            names = os.listdir(descriptors)
        except (FileNotFoundError, ProcessLookupError):
            continue  # exited meanwhile
        except OSError:
            raise CliRefused("service_state_unavailable") from None
        for name in names:
            try:
                info = os.stat(descriptors / name)
            except (FileNotFoundError, ProcessLookupError):
                continue  # closed meanwhile, or the process exited
            except OSError:
                # Never counted as "not the database": fail closed.
                raise CliRefused("service_state_unavailable") from None
            if (info.st_dev, info.st_ino) == identity:
                holders += 1
                break
    return holders


class _ServiceCheck:
    def __init__(self, database, holders: Callable[[tuple[int, int]], int]):
        self._identity = database._identity
        self._holders = holders

    def require_stopped(self) -> None:
        if self._holders(self._identity):
            raise CliRefused("service_running")


class _StoppedServiceRegistry(CameraRegistry):
    """The registry whose audited writes re-check, inside their transaction, that the service is stopped."""

    def __init__(self, database, check: _ServiceCheck):
        super().__init__(database)
        self._check = check

    def create_source_on(self, connection, source_id, **configuration):
        self._check.require_stopped()
        return super().create_source_on(connection, source_id, **configuration)

    def update_source_on(self, connection, source_id, **changes):
        self._check.require_stopped()
        return super().update_source_on(connection, source_id, **changes)


# -- presentation --------------------------------------------------------

def candidate_label(device: DeviceEvidence) -> str:
    """A short label for one connected device instance; reveals no serial or path."""
    evidence = json.dumps(list(device.live_instance_key), separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(_LABEL_DOMAIN + evidence.encode("ascii")).hexdigest()
    return LABEL_PREFIX + digest[:_LABEL_DIGITS]


def _quoted(value: object) -> str:
    """Stored text for a terminal: quoted, non-printable characters escaped, bounded."""
    text = str(value)
    pieces = []
    for char in text[:_MAX_TEXT]:
        if char in '"\\':
            pieces.append("\\" + char)
        elif char.isprintable():
            pieces.append(char)
        elif ord(char) <= 0xFFFF:
            pieces.append(f"\\u{ord(char):04x}")
        else:
            pieces.append(f"\\U{ord(char):08x}")
    return '"' + "".join(pieces) + ('..."' if len(text) > _MAX_TEXT else '"')


def _usb_ids(device: DeviceEvidence) -> str:
    vendor, product = device.vendor.lower(), device.product.lower()
    if _USB_ID.fullmatch(vendor) and _USB_ID.fullmatch(product):
        return f"{vendor}:{product}"
    return "?"


def _serial_state(device: DeviceEvidence, devices) -> str:
    if device.strong_key is None:
        return "absent"
    if sum(other.strong_key == device.strong_key for other in devices) > 1:
        return "shared"
    return "present"


def _formats(device: DeviceEvidence) -> str:
    names = ["".join(c if c.isalnum() else "?" for c in name) for name in device.formats[:16]]
    return ",".join(names) + (",..." if len(device.formats) > 16 else "") if names else "-"


def _held_approvals(database):
    """(source id, approval state) of every enabled local UVC source's active approval."""
    with closing(database.connect()) as connection:
        rows = connection.execute(
            "SELECT a.source_id, a.evidence, a.serial_ambiguous FROM uvc_approvals AS a "
            "JOIN camera_sources AS s ON s.id = a.source_id "
            "WHERE a.requires_approval = 0 AND s.enabled = 1 AND s.source_type = 'local_uvc' "
            "ORDER BY a.source_id").fetchall()
    held = []
    for row in rows:
        state = ApprovalStore._state((row[1], 0, None, row[2], 0))
        held.append((UUID(row[0]), state))
    return held


def _holders_of(device: DeviceEvidence, held) -> list[UUID]:
    return [source_id for source_id, state in held
            if same_physical_camera(state.approved, device, serial_ambiguous=state.serial_ambiguous)]


def candidate_lines(devices, failures: int, held) -> list[str]:
    lines = []
    for device in devices:
        holders = _holders_of(device, held)
        lines.append(f"candidate {candidate_label(device)} usb={_usb_ids(device)} "
                     f"serial={_serial_state(device, devices)} formats={_formats(device)} "
                     f"approved_for={','.join(map(str, holders)) or '-'}")
    if not devices:
        lines.append("no candidates")
    if failures:
        lines.append(f"devices not inspected: {failures}")
    return lines


def source_lines(registry: CameraRegistry, store: ApprovalStore, configured) -> list[str]:
    lines = []
    for source in registry.list_sources():
        if source.source_type is not SourceType.LOCAL_UVC:
            continue
        approval = store.load(source.id)
        state = ("none" if approval is None
                 else "approval_required" if approval.requires_approval or approval.session_token
                 else "approved")
        profile = source.desired_capture_profile
        wanted = ("-" if profile is None else
                  f"{profile.width}x{profile.height}@{profile.fps:g}/{profile.pixel_format}"
                  if None not in (profile.width, profile.height, profile.fps, profile.pixel_format)
                  else "?")
        lines.append(f"source {source.id} enabled={'yes' if source.enabled else 'no'} "
                     f"approval={state} configured={'yes' if source.id in configured else 'no'} "
                     f"profile={wanted} name={_quoted(source.name)}")
    if not lines:
        lines.append("no local_uvc sources")
    return lines


# -- arguments -----------------------------------------------------------

def parse_profile(value: str) -> CaptureProfile:
    """``WIDTHxHEIGHT@FPS/FOURCC`` (e.g. ``1920x1080@30/MJPG``), else ``capture_profile_rejected``."""
    match = _PROFILE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise CliRefused("capture_profile_rejected")
    width, height, fps = (int(match.group(index)) for index in (1, 2, 3))
    try:
        VideoProfile(width, height, fps, match.group(4))
        return CaptureProfile(width, height, fps, match.group(4))
    except (ValueError, ValidationError):
        raise CliRefused("capture_profile_rejected") from None


def _uuid_argument(value: object, reason: str) -> UUID:
    try:
        if isinstance(value, str) and len(value) == 36:
            parsed = UUID(value)
            if str(parsed) == value.lower():
                return parsed
    except ValueError:
        pass
    raise CliRefused(reason)


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


def _committed(database) -> None:
    try:
        _verify_pinned(database)
    except CliRefused:
        raise CliRefused("committed_verification_failed") from None


# -- commands ------------------------------------------------------------

class _Context:
    def __init__(self, database, registry, admin, owner, terminal, discovery, check, configured):
        self.database = database
        self.registry = registry
        self.admin = admin
        self.owner = owner
        self.terminal = terminal
        self.discovery = discovery
        self.check = check
        self.configured = configured


def _scan(context: _Context):
    try:
        return context.discovery.scan()
    except Exception:
        raise CliRefused("camera_scan_failed") from None


def _sources(context: _Context) -> list[str]:
    try:
        lines = source_lines(context.registry, ApprovalStore(context.database), context.configured)
    except Exception:
        raise _storage_refusal(context.database) from None
    _verify_pinned(context.database)
    return lines


def _candidates(context: _Context) -> list[str]:
    scan = _scan(context)
    try:
        held = _held_approvals(context.database)
    except Exception:
        raise _storage_refusal(context.database) from None
    _verify_pinned(context.database)
    return candidate_lines(scan.devices, scan.failures, held)


def _create_source(context: _Context, name: str, profile: CaptureProfile) -> list[str]:
    context.check.require_stopped()
    grant = context.owner.confirm(
        context.terminal,
        f"Create an enabled local_uvc source name={_quoted(name)} profile={profile.width}x"
        f"{profile.height}@{profile.fps:g}/{profile.pixel_format}. Type {CREATE_WORD} to confirm: ",
        CREATE_WORD)
    try:
        source = context.admin.create_source(
            grant, source_type=SourceType.LOCAL_UVC, name=name, enabled=True,
            desired_capture_profile=profile)
    except CliRefused:
        raise
    except ActiveSourceLimitError:
        raise CliRefused("active_source_limit_reached") from None
    except ValidationError:
        raise CliRefused("source_configuration_rejected") from None
    except Exception:
        raise _storage_refusal(context.database) from None
    _committed(context.database)
    return [f"source created: source_id={source.id}",
            "next: add this UUID to local_uvc.source_ids in the deployment configuration, approve "
            "a camera for it with 'approve', then start the service"]


def _select_candidate(scan, label: str) -> DeviceEvidence:
    if scan.failures:
        # A device that could not be inspected might be the label's twin.
        raise CliRefused("camera_scan_incomplete")
    matches = [device for device in scan.devices if candidate_label(device) == label]
    if not matches:
        raise CliRefused("candidate_not_found")
    if len(matches) > 1:
        raise CliRefused("candidate_label_ambiguous")
    return matches[0]


def _approve(context: _Context, source_id: UUID, label: str) -> list[str]:
    context.check.require_stopped()
    try:
        source = context.registry.get_source(source_id)
    except NotFoundError:
        raise CliRefused("source_not_found") from None
    except Exception:
        raise _storage_refusal(context.database) from None
    if source.source_type is not SourceType.LOCAL_UVC:
        raise CliRefused("source_not_local_uvc")
    if not source.enabled:
        raise CliRefused("source_disabled")
    scan = _scan(context)
    candidate = _select_candidate(scan, label)
    if candidate.strong_key is None:
        raise CliRefused("camera_without_serial")
    if _serial_state(candidate, scan.devices) == "shared":
        raise CliRefused("camera_serial_not_unique")
    wanted = source.desired_capture_profile
    if (wanted is not None and wanted.pixel_format is not None
            and wanted.pixel_format not in candidate.formats):
        # Also when the camera advertises no format at all: the service
        # would only report capture_profile_unavailable.
        raise CliRefused("camera_format_unsupported")
    store = ApprovalStore(context.database)
    try:
        prior = store.load(source_id)
        held = _held_approvals(context.database)
    except Exception:
        raise _storage_refusal(context.database) from None
    if prior is not None and prior.serial_ambiguous and prior.approved.strong_key == candidate.strong_key:
        # The store keeps this latch for the same serial (ApprovalStore.approve_on).
        raise CliRefused("camera_serial_not_unique")
    if any(holder != source_id for holder in _holders_of(candidate, held)):
        raise CliRefused("camera_approved_for_another_source")
    grant = context.owner.confirm(
        context.terminal,
        f"Approve camera {label} usb={_usb_ids(candidate)} for source {source_id} "
        f"name={_quoted(source.name)}; the service uses it from its next start. "
        f"Type {APPROVE_WORD} to confirm: ", APPROVE_WORD)
    adapter = LocalUvcAdapter(context.registry, emit_audit=lambda event: None,
                              on_frame=lambda source_id, frame: None, discovery=context.discovery)
    try:
        context.admin.approve_uvc(grant, adapter, source_id, candidate)
    except CliRefused:
        raise
    except ApprovalConflictError:
        raise CliRefused("camera_approved_for_another_source") from None
    except ValueError:
        # Rescanned in the audited preparation: the camera changed, vanished
        # or became ambiguous since the selection.
        raise CliRefused("candidate_unavailable") from None
    except Exception:
        raise _storage_refusal(context.database) from None
    finally:
        adapter.close()
    _committed(context.database)
    lines = [f"camera approved: source_id={source_id} candidate={label}"]
    if source_id not in context.configured:
        lines.append("next: add this UUID to local_uvc.source_ids in the deployment configuration")
    lines.append("next: start the service; the approval applies on start")
    return lines


def _run(args, *, terminal_factory: Callable[[], ControllingTerminal],
         discovery_factory: Callable[[], object],
         holders: Callable[..., int]) -> int:
    if os.geteuid() == 0:
        raise CliRefused("run_as_service_account")
    source_id = profile = None
    if args.command == "approve":
        source_id = _uuid_argument(args.source, "source_id_rejected")
        if not isinstance(args.candidate, str) or not _LABEL.fullmatch(args.candidate):
            raise CliRefused("candidate_label_rejected")
    if args.command == "create-source":
        profile = parse_profile(args.profile)
    try:
        deployment = _load_deployment(args.config)
        database_path = deployment.settings.database_path
        service_uid = deployment.service_uid
        local_uvc = getattr(deployment, "local_uvc", None)
        configured = frozenset(local_uvc.source_ids) if local_uvc is not None else frozenset()
    except Exception:
        raise CliRefused("deployment_configuration_rejected") from None
    if os.geteuid() != service_uid:
        raise CliRefused("run_as_service_account")
    terminal = terminal_factory() if args.command in MUTATIONS else None
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
            check = _ServiceCheck(database, holders)
            registry = _StoppedServiceRegistry(database, check)
            owner = LocalConsoleOwner()
            admin = OwnerAdministration(OwnerAuditService(AuditStore(database), owner), registry)
            context = _Context(database, registry, admin, owner, terminal, discovery_factory(),
                               check, configured)
            if args.command == "sources":
                lines = _sources(context)
            elif args.command == "candidates":
                lines = _candidates(context)
            elif args.command == "create-source":
                lines = _create_source(context, args.name, profile)
            else:
                lines = _approve(context, source_id, args.candidate)
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
        description="Local camera administration (Owner decision D3). Run as the service account "
                    "with the service stopped; changes apply when it starts.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("sources", "list the local_uvc sources and their approval state"),
                       ("candidates", "list connected cameras by hashed label (no serial or path)"),
                       ("create-source", "create an enabled local_uvc source"),
                       ("approve", "approve a connected camera for a local_uvc source")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True,
                             help="the deployment configuration the service runs with")
        if name == "create-source":
            command.add_argument("--name", required=True, help="the source's display name")
            command.add_argument("--profile", required=True,
                                 help="capture profile WIDTHxHEIGHT@FPS/FOURCC, e.g. 1920x1080@30/MJPG")
        if name == "approve":
            command.add_argument("source", help="the source's UUID (as 'sources' prints it)")
            command.add_argument("candidate", help="the camera's label (as 'candidates' prints it)")
    return parser


def main(argv: list[str] | None = None, *,
         terminal_factory: Callable[[], ControllingTerminal] = ControllingTerminal,
         discovery_factory: Callable[[], object] = LinuxDiscovery,
         holders: Callable[..., int] = _database_holders) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args, terminal_factory=terminal_factory, discovery_factory=discovery_factory,
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
