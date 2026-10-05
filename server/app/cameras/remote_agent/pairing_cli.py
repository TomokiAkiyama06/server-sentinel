"""Local administrative capture-node pairing CLI on the Main host (ADR-0006, #13).

Run as the local account that owns the deployment CA directory, the Main
listener directory and the application database::

    python -m app.cameras.remote_agent.pairing_cli init ...
    python -m app.cameras.remote_agent.pairing_cli rotate-listener ...
    python -m app.cameras.remote_agent.pairing_cli export-bundle ...
    python -m app.cameras.remote_agent.pairing_cli approve ...
    python -m app.cameras.remote_agent.pairing_cli list ...
    python -m app.cameras.remote_agent.pairing_cli revoke ...

``approve`` validates the Agent's public enrollment request, asks the Owner on
the controlling terminal to confirm the request's public-key digest, creates
the approval (which *is* the pairing: node UUID, key binding and one-time code
are created together by ``PairingLedger.approve``), writes the code once to the
controlling terminal, and then serves the separate bootstrap enrollment
listener in this same process until the enrollment completes or its five
minutes expire. Approval and listener share one process because the ledger
rejects pending approvals from any other process epoch; the HMAC verifier key
is therefore generated in memory per run and never stored.

The code is never written to stdout, stderr, logs, files or the database (the
ledger keeps only its keyed digest). Without a controlling terminal the command
refuses before any state changes. No command accepts a code as input.

Owner authority: until the #6 human-access boundary exists, this CLI's Owner
gate is the local host itself -- the operating-system account that can open the
owner-only (0700/0600) issuer material and database -- plus an explicit typed
confirmation on the controlling terminal for each approve/revoke. Each
confirmation authorizes exactly one ledger call, which records the audit row.

Separate accounts (Issue #124): ``--listener-owner`` names the OS account that
owns the Main listener directory when it differs from the account running the
CLI (for example a dedicated ingest service account that must never read the
CA key). New listener files are then created owned by that account. Writing
there needs effective ``CAP_CHOWN`` and ``CAP_DAC_OVERRIDE`` (root has both),
and reading it needs ``CAP_DAC_OVERRIDE`` or ``CAP_DAC_READ_SEARCH``; without
them the command refuses with ``listener_owner_requires_privilege`` before
anything is written.

``rotate-listener`` (Issue #125) replaces the Main listener key and
certificate before the leaf expires. The deployment CA and the server name do
not change, so Agents keep their trust bundle; restart the listener processes
so they load the new pair.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import datetime
import ipaddress
import json
import logging
import os
from pathlib import Path
import pwd
import secrets
import stat
import sys
from uuid import UUID, uuid4

from app.audit.service import OwnerAuthorizationError
from app.audit.store import AuditStore
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from .enrollment import (
    EnrollmentError, EnrollmentLimits, EnrollmentListener, EnrollmentListenerConfig,
    EnrollmentService, build_enrollment_server_context,
)
from .node_ca import (
    DEFAULT_NODE_VALIDITY, MAX_CA_VALIDITY, MAX_CSR_BYTES, MAX_LEAF_VALIDITY,
    CaptureAuthorityError, DeploymentAuthority,
    PrivateDirectory, deployment_id_of, listener_material, main_server_name,
)
from .pairing import HmacCodeVerifier, PairingError, PairingLedger


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


def _account(value: str) -> int:
    """An OS account name or numeric UID for ``--listener-owner``."""
    if value.isascii() and value.isdecimal():
        uid = int(value)
        if uid >= 2 ** 32 - 1:
            raise argparse.ArgumentTypeError("expected an account name or UID")
        return uid
    try:
        return pwd.getpwnam(value).pw_uid
    except (KeyError, ValueError, OverflowError):
        raise argparse.ArgumentTypeError("unknown account") from None


def _directory(value: Path, *, owner_uid: int | None = None) -> PrivateDirectory:
    try:
        return PrivateDirectory(Path(value), owner_uid=owner_uid)
    except CaptureAuthorityError:
        raise CliRefused("private_directory_rejected") from None


def _listener_directory(args) -> PrivateDirectory:
    return _directory(args.listener_dir, owner_uid=args.listener_owner)


def _existing_database(database_path: Path) -> tuple[int, int]:
    """Identity of the application's existing database file, or a refusal.

    A mistyped ``--database`` must never silently create and migrate an empty
    database that the server does not use (Issue #125): the path must be
    canonical and absolute (no symlink, no ``..``) and name an existing
    regular file with one link, owned by the account running the CLI and not
    writable by group or others.
    """
    if not database_path.is_absolute() or os.path.realpath(database_path) != str(database_path):
        raise CliRefused("database_path_rejected")
    try:
        descriptor = os.open(database_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NOCTTY | os.O_NONBLOCK)
    except FileNotFoundError:
        raise CliRefused("database_not_found") from None
    except OSError:
        raise CliRefused("database_rejected") from None
    try:
        info = os.fstat(descriptor)
    except OSError:
        raise CliRefused("database_rejected") from None
    finally:
        os.close(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022 or info.st_nlink != 1):
        raise CliRefused("database_rejected")
    return info.st_dev, info.st_ino


def _ledger(database_path: Path) -> PairingLedger:
    identity = _existing_database(database_path)
    database = Database(database_path)
    try:
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        info = os.stat(database_path, follow_symlinks=False)
    except Exception:
        raise CliRefused("database_unavailable") from None
    if (info.st_dev, info.st_ino) != identity:
        # Replaced while opening: never keep using whatever is there now.
        raise CliRefused("database_rejected")
    # Pending approvals are valid only in this process, so the verifier key is
    # per-process and never persisted.
    return PairingLedger(database, HmacCodeVerifier(secrets.token_bytes(32)),
                         audit=AuditStore(database))


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
        digest = DeploymentAuthority.enrollment_key_digest(csr)
    except (ValueError, TypeError, UnicodeError, RecursionError, CaptureAuthorityError):
        raise CliRefused("enrollment_request_rejected") from None
    if digest != value["public_key_digest"]:
        raise CliRefused("enrollment_request_rejected")
    return csr, digest


def _group(code: str) -> str:
    return "-".join(code[index:index + 5] for index in range(0, 20, 5)) + "-" + code[20:]


def _days(value: int, maximum: datetime.timedelta) -> datetime.timedelta:
    if not isinstance(value, int) or not 0 < value <= maximum.days:
        raise CliRefused("certificate_validity_rejected")
    return value * _DAY


def command_init(args) -> int:
    authority_directory = _directory(args.authority_dir)
    listener_directory = _listener_directory(args)
    if authority_directory.path == listener_directory.path:
        raise CliRefused("listener_directory_must_differ")
    # Everything is validated before the write-once CA exists; a failed run
    # leaves no issuer material, so the corrected command can simply be rerun.
    authority = DeploymentAuthority.initialize(
        authority_directory, listener_directory, uuid4(),
        validity=_days(args.ca_validity_days, MAX_CA_VALIDITY),
        server_name=args.server_name,
        server_validity=_days(args.server_validity_days, MAX_LEAF_VALIDITY))
    print(f"deployment_id={authority.deployment_id}")
    return 0


def _authority(args) -> DeploymentAuthority:
    directory = _directory(args.authority_dir)
    return DeploymentAuthority.load(directory, deployment_id_of(directory))


def command_rotate_listener(args) -> int:
    listener_directory = _listener_directory(args)
    if _directory(args.authority_dir).path == listener_directory.path:
        raise CliRefused("listener_directory_must_differ")
    authority = _authority(args)
    rotation = authority.rotate_main_server_credential(
        listener_directory, validity=_days(args.server_validity_days, MAX_LEAF_VALIDITY))
    expiry = rotation.not_after.isoformat(timespec="seconds")
    if rotation.recovered:
        print(f"listener rotation completed (interrupted run): not_after={expiry}")
    else:
        print(f"listener rotated: not_after={expiry}")
    print("restart the capture ingest listener to load the new certificate")
    return 0


def command_export_bundle(args) -> int:
    authority = _authority(args)
    listener_directory = _listener_directory(args)
    # A bundle is only exported for a listener certificate this CA issued,
    # so mixed-up deployments fail here, not later at the Agent's TLS check.
    authority.verify_listener_certificate(listener_directory)
    server_name = main_server_name(listener_directory)
    host, port = args.endpoint
    bundle = authority.export_trust_bundle(server_name=server_name, endpoint_host=host,
                                           endpoint_port=port)
    _write_public_file(args.output, bundle.content)
    # Public: the Owner compares this full digest on the capture host.
    print(f"trust_bundle_sha256={bundle.sha256}")
    return 0


def command_approve(args) -> int:
    # Refuse before any state change if the code cannot be shown privately.
    terminal = ControllingTerminal()
    try:
        authority = _authority(args)
        # Refuse before any approval when the CA can no longer cover a node
        # leaf; the code would otherwise be burned by a failed issuance.
        authority.check_leaf_validity(DEFAULT_NODE_VALIDITY)
        listener_directory = _listener_directory(args)
        material = listener_material(listener_directory)
        authority.verify_listener_certificate(listener_directory)
        csr, digest = parse_enrollment_request(
            _read_public_file(args.request, MAX_REQUEST_FILE_BYTES))
        del csr  # the Agent resubmits its CSR over TLS; the ledger stores only the digest
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
        listener = EnrollmentListener(
            config, build_enrollment_server_context(material.certificate_path, material.key_path),
            limits=EnrollmentLimits())
        ledger = _ledger(args.database)
        # A key stays bound to its node for good, so a retry after an
        # interrupted, expired or unacknowledged enrollment reuses that node.
        try:
            bound = ledger.bound_node(digest)
        except PairingError:
            raise CliRefused("approval_refused") from None
        retry = "" if bound is None else (
            f"  existing capture node: {bound}\n"
            "  (retry: completing it replaces that node's current certificate)\n")
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
                raise CliRefused("approval_refused") from None
            terminal.write(
                "\nOne-time pairing code (shown once, valid for 5 minutes):\n\n"
                f"    {_group(code.value)}\n\n"
                "Type it only into the media-capture-agent pairing prompt on the capture host.\n")
            del code
            print(f"enrollment listening: node_id={approval.node_id}", flush=True)
            service = EnrollmentService(ledger, authority, (approval,))
            outcome = listener.serve(service, expires_at_monotonic=approval.expires_at_monotonic)
        finally:
            listener.close()
    finally:
        terminal.close()
    if outcome.reason == "completed":
        print(f"enrollment completed: node_id={approval.node_id}")
        return 0
    print(f"enrollment closed: reason={outcome.reason}")
    return 1


def command_list(args) -> int:
    ledger = _ledger(args.database)
    for row in ledger.pairing_summaries():
        expiry = ("-" if row.not_after is None else
                  datetime.datetime.fromtimestamp(row.not_after, datetime.timezone.utc)
                  .isoformat(timespec="seconds"))
        print(f"node_id={row.node_id} enrollment={row.enrollment_state or '-'} "
              f"credential={row.credential_state or '-'} not_after={expiry}")
    return 0


def command_revoke(args) -> int:
    terminal = ControllingTerminal()
    try:
        ledger = _ledger(args.database)
        owner = LocalConsoleOwner()
        grant = owner.confirm(terminal, f"Type REVOKE to revoke capture node {args.node}: ",
                              "REVOKE")
        try:
            ledger.revoke(owner, grant, node_id=args.node)
        except PairingError:
            raise CliRefused("revocation_refused") from None
    finally:
        terminal.close()
    print(f"revoked: node_id={args.node}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="serversentinel-pairing",
        description="Local Owner administration of capture-node pairing (ADR-0006).")
    commands = parser.add_subparsers(dest="command", required=True)
    listener_owner_help = ("account (name or UID) owning --listener-dir when it differs from "
                           "the account running this command; needs CAP_CHOWN and "
                           "CAP_DAC_OVERRIDE (for example root)")

    init = commands.add_parser("init", help="create the deployment CA and Main listener certificate")
    init.add_argument("--authority-dir", type=Path, required=True)
    init.add_argument("--listener-dir", type=Path, required=True)
    init.add_argument("--server-name", required=True)
    init.add_argument("--ca-validity-days", type=int, default=3650)
    init.add_argument("--server-validity-days", type=int, default=MAX_LEAF_VALIDITY.days)
    init.add_argument("--listener-owner", type=_account, default=None, help=listener_owner_help)
    init.set_defaults(handler=command_init)

    rotate = commands.add_parser(
        "rotate-listener",
        help="replace the Main listener key and certificate; the CA and Agent trust are kept")
    rotate.add_argument("--authority-dir", type=Path, required=True)
    rotate.add_argument("--listener-dir", type=Path, required=True)
    rotate.add_argument("--server-validity-days", type=int, default=MAX_LEAF_VALIDITY.days)
    rotate.add_argument("--listener-owner", type=_account, default=None, help=listener_owner_help)
    rotate.set_defaults(handler=command_rotate_listener)

    export = commands.add_parser("export-bundle", help="write the public trust bundle")
    export.add_argument("--authority-dir", type=Path, required=True)
    export.add_argument("--listener-dir", type=Path, required=True)
    export.add_argument("--endpoint", type=_endpoint, required=True,
                        help="bootstrap enrollment endpoint HOST:PORT the Agent connects to")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--listener-owner", type=_account, default=None, help=listener_owner_help)
    export.set_defaults(handler=command_export_bundle)

    approve = commands.add_parser("approve", help="approve one enrollment request and serve it")
    approve.add_argument("--database", type=Path, required=True)
    approve.add_argument("--authority-dir", type=Path, required=True)
    approve.add_argument("--listener-dir", type=Path, required=True)
    approve.add_argument("--request", type=Path, required=True)
    approve.add_argument("--listen", type=_ip_endpoint, required=True,
                         help="private IP literal HOST:PORT for the bootstrap listener")
    approve.add_argument("--human-host", default="127.0.0.1",
                         help="loopback IP of the human dashboard listener (SERVERSENTINEL_HUMAN_HOST)")
    approve.add_argument("--human-port", type=int, default=8000,
                         help="port of the human dashboard listener (SERVERSENTINEL_HUMAN_PORT)")
    approve.add_argument("--ingest-listen", type=_ip_endpoint, default=None)
    approve.add_argument("--listener-owner", type=_account, default=None, help=listener_owner_help)
    approve.set_defaults(handler=command_approve)

    listing = commands.add_parser("list", help="list capture-node pairing states")
    listing.add_argument("--database", type=Path, required=True)
    listing.set_defaults(handler=command_list)

    revoke = commands.add_parser("revoke", help="revoke a capture node")
    revoke.add_argument("--database", type=Path, required=True)
    revoke.add_argument("--node", type=UUID, required=True)
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
