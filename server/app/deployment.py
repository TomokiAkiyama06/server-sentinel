"""Validated stable-deployment configuration and launcher."""

from dataclasses import dataclass, field, replace
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

from app.auth.access_config import HumanAccessDeployment, HumanAccessRefused, parse_human_access
from app.cameras.uvc.config import LocalUvcConfiguration, parse_local_uvc
from app.detection.foundation.config import DetectionConfiguration, parse_detection
from app.monitoring.config import MonitoringConfiguration, parse_monitoring
from app.settings import INVITATION_LIFETIME, ConfigurationError, Settings, invitation_lifetime


MAX_CONFIGURATION_BYTES = 16 * 1024
RELEASE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?")
# Administrator identity that owns deployment configuration.  The runtime
# account is always a different, non-zero dedicated account.
ADMINISTRATOR_UID = 0
# Stable, reformat-sensitive filesystem identity published by udev.  A Linux
# major/minor pair is reused by a replaced or reformatted disk, so it can only
# corroborate this identity, never replace it.
FILESYSTEM_UUID_ROOT = Path("/dev/disk/by-uuid")
FILESYSTEM_UUID = re.compile(r"[0-9A-Za-z][0-9A-Za-z-]{2,63}")


def _operating_system_root_device() -> int:
    return Path("/").stat().st_dev


def _approved_filesystem_device(uuid: object) -> int:
    """Resolve the Owner-approved filesystem UUID to the device now carrying it.

    Reformatting or replacing the runtime disk changes its filesystem UUID even
    when the mount path, directory layout and Linux device number are reused, so
    the approved entry disappears or points at another device and the
    replacement is refused instead of being written to.
    """
    if not isinstance(uuid, str) or not FILESYSTEM_UUID.fullmatch(uuid):
        raise ConfigurationError("invalid runtime filesystem identity")
    try:
        node = (FILESYSTEM_UUID_ROOT / uuid).resolve(strict=True)
        info = node.stat()
    except (OSError, RuntimeError, ValueError):
        raise ConfigurationError("approved runtime filesystem is unavailable") from None
    if not stat.S_ISBLK(info.st_mode):
        raise ConfigurationError("approved runtime filesystem is unavailable")
    return info.st_rdev


def _administrator_file(path: Path, info: os.stat_result) -> None:
    """Require an administrator-managed, runtime-readable configuration file.

    The runtime account must be able to read the configuration and must never
    be able to rewrite it, so neither the file nor its directory may be owned or
    writable by anything other than the administrator.
    """
    if info.st_uid != ADMINISTRATOR_UID:
        raise ConfigurationError("deployment configuration must be administrator-owned")
    if info.st_mode & 0o027:
        raise ConfigurationError(
            "deployment configuration must not be runtime-writable or world-readable"
        )
    try:
        directory = path.parent.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise ConfigurationError("deployment configuration is unavailable") from None
    _administrator_directory(directory)


def _administrator_directory(directory: Path) -> None:
    """Require every component of the configuration directory to be controlled.

    Checking only the immediate parent would let an ancestor that another
    account can rename or replace substitute the directory holding the
    configuration.  Walk the resolved path with ``lstat`` so a component
    replaced by a symbolic link is caught too.  A component may be writable by
    others only when it is sticky, where non-owners cannot replace existing
    entries.
    """
    current = Path(directory.anchor)
    try:
        for part in directory.parts[1:]:
            current /= part
            info = current.lstat()
            shared_writable = info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
            if (stat.S_ISLNK(info.st_mode) or shared_writable
                    or info.st_uid not in {ADMINISTRATOR_UID, 0}):
                raise ConfigurationError(
                    "deployment configuration directory must be administrator-controlled"
                )
    except OSError:
        raise ConfigurationError("deployment configuration is unavailable") from None


class CaptureCaSettingMissing(ConfigurationError):
    """``capture_ca_directory`` is absent; it must be a path or an explicit ``null``."""

    REASON = ("capture_ca_directory is required: the capture-node CA directory path, "
              "or null when this host keeps no capture-node CA")


def _capture_ca_directory(value: object) -> Path:
    """The configured capture-node CA directory (Issue #109): an absolute path."""
    if not isinstance(value, str) or not value or "\0" in value:
        raise ConfigurationError("invalid capture CA directory")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigurationError("capture CA directory must be absolute")
    return path


_CA_FILES = ("ca-key.pem", "ca-certificate.pem", "issuance-log.jsonl")


def _effective_access(path: Path, mode: int) -> bool:
    """``access(2)`` with this process's effective ids, ACLs included.

    Fail closed: where effective-id checks are unsupported or the check
    errors, access is assumed.
    """
    if os.access not in os.supports_effective_ids:
        return True
    try:
        return os.access(path, mode, effective_ids=True, follow_symlinks=False)
    except (OSError, NotImplementedError, ValueError, TypeError):
        return True


def _controlled_by_this_account(path: Path, info: os.stat_result, uid: int, *,
                                allow_sticky: bool) -> bool:
    """Whether this process's account owns ``path`` or may write to it.

    Write access is the kernel's answer for the effective ids (owner, group,
    other bits and POSIX ACLs alike), not an interpretation of mode bits.
    """
    if info.st_uid == uid:
        return True
    writable = _effective_access(path, os.W_OK)
    if writable and allow_sticky and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX:
        # Like ``_administrator_directory``: in a sticky directory others
        # cannot rename or replace an entry they do not own.
        return False
    return writable


def capture_ca_path_exposed(path: Path, *, missing_is_exposed: bool = True) -> bool:
    """Whether this process's account can reach or control the CA directory.

    Run as the service account (launcher, and the pairing CLI after its
    drop), Issue #109. Exposed when any of these holds, regardless of a
    current permission refusal (an owner can always ``chmod`` it back):

    * the directory, one of its path components or one of its CA files
      (``ca-key.pem``, ``ca-certificate.pem``, ``issuance-log.jsonl``) is owned
      by this account;
    * this account can write the directory, a CA file, or a path component
      (an ancestor only counts when it is not sticky), so it could replace
      what lies below -- decided by ``access(2)`` with the effective ids, so
      POSIX ACLs count, and assumed where that is unsupported;
    * this account may read or search the directory, or read a CA file;
    * a component is a symbolic link or the path is not a directory;
    * the directory or its key file can be opened.

    A missing component is exposure unless ``missing_is_exposed`` is false
    (only ``revoke`` uses that, so a lost CA directory never blocks the
    ledger revocation). Components this account cannot even look at (a
    parent without search permission) are protected by that parent, which
    was itself checked first.
    """
    path = Path(path)
    if not path.is_absolute():
        return True
    uid = os.geteuid()
    current = Path(path.anchor)
    components = path.parts[1:]
    for index, part in enumerate(components):
        current = current / part
        last = index == len(components) - 1
        try:
            info = os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            return missing_is_exposed
        except PermissionError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return True
        if _controlled_by_this_account(current, info, uid, allow_sticky=not last):
            return True
        if last and (_effective_access(current, os.R_OK)
                     or _effective_access(current, os.X_OK)):
            # The CA directory is 0700 for its own account: this account may
            # neither list nor search it (ACLs included).
            return True
    for name in _CA_FILES:
        try:
            info = os.lstat(path / name)
        except (FileNotFoundError, PermissionError):
            continue
        except OSError:
            return True
        if (not stat.S_ISREG(info.st_mode)
                or _controlled_by_this_account(path / name, info, uid, allow_sticky=False)
                or _effective_access(path / name, os.R_OK)):
            return True
    for target, flags in ((path, os.O_RDONLY | os.O_DIRECTORY),
                          (path / "ca-key.pem", os.O_RDONLY | os.O_NONBLOCK)):
        try:
            descriptor = os.open(target, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
        except PermissionError:
            continue
        except (FileNotFoundError, NotADirectoryError):
            if missing_is_exposed:
                return True
            continue
        except OSError:
            return True
        os.close(descriptor)
        return True
    return False


def capture_ca_directory_accessible(path: Path) -> bool:
    """Launcher check (Issue #109): the service must not reach or control the CA.

    Fail closed: a missing directory counts as exposed too, since the check
    would otherwise prove nothing. See ``capture_ca_path_exposed``.
    """
    return capture_ca_path_exposed(Path(path), missing_is_exposed=True)


def _runtime_roots() -> tuple[Path, Path | None]:
    """The running release (code root) and, for an installed one, the installation root.

    A release is ``<installation>/releases/<version>``; while the installer
    stages it, it is ``<installation>/releases/.<version>.staging`` and runs
    its own ``--check`` there, which must resolve the same settings.
    """
    try:
        code_root = Path(__file__).resolve(strict=True).parents[1]
    except (OSError, RuntimeError, IndexError):
        raise ConfigurationError("deployment code location is unavailable") from None
    install_root = None
    name = code_root.name
    if name.startswith(".") and name.endswith(".staging"):
        name = name[1:-len(".staging")]
    if code_root.parent.name == "releases" and RELEASE_VERSION.fullmatch(name):
        install_root = code_root.parent.parent
    return code_root, install_root


class WebAssetsRefused(ConfigurationError):
    """The configured Web build failed the loader; ``reason`` is one value-free word."""

    def __init__(self, reason: str) -> None:
        super().__init__("web assets refused")
        self.reason = reason


def _web_assets_directory(value: object, code_root: Path, install_root: Path | None) -> Path:
    """The release's own Web build directory named by ``web_assets_directory`` (Issue #10 S5c).

    On an installed host the value is exactly ``<installation>/current/web``:
    the release a process runs from is the one ``current`` names once it has
    started, so the path is taken as that process's own ``<release>/web``
    (``code_root``), the directory the installer checks against the release
    manifest. The rollback and staging checks therefore validate the build
    of the release being switched to, not of the one still running. Without
    an installation root (a source tree) it is exactly ``<code_root>/web``.

    The installation part is compared after resolving both sides, so the
    installer (which knows ``--destination`` as typed) and the release
    (which knows its own resolved location) accept the same value even when
    the installation path contains a symbolic link. Any other value is
    refused with the value-free reason ``setting``. Existence and content
    are checked by ``main`` (``WebAssets.load``).
    """
    if not isinstance(value, str) or not value or "\0" in value:
        raise WebAssetsRefused("setting")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path.name != "web":
        raise WebAssetsRefused("setting")
    if install_root is not None:
        if path.parent.name != "current":
            raise WebAssetsRefused("setting")
        named, expected = path.parent.parent, install_root
    else:
        named, expected = path.parent, code_root
    try:
        same = named.resolve(strict=True) == expected.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        same = False
    if not same:
        raise WebAssetsRefused("setting")
    return code_root / "web"


def _load_web_assets(directory: Path, code_root: Path) -> None:
    """Load the configured build exactly as the human surface would, or refuse."""
    from app.auth.web_assets import WebAssets, WebAssetsUnavailable
    try:
        resolved = directory.resolve(strict=True)
        release = code_root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise WebAssetsRefused("path") from None
    if not resolved.is_relative_to(release) or resolved == release:
        # A symbolic link inside the release must not lead out of it.
        raise WebAssetsRefused("path")
    try:
        WebAssets.load(directory)
    except WebAssetsUnavailable as refused:
        raise WebAssetsRefused(refused.reason) from None


def _tailscale_executable(path: Path) -> Path:
    """The ``human_access.tailscale_executable`` the service may run, resolved, or refuse.

    The Serve status runner executes it with the service account's
    privileges on every check, so, like the configuration itself, it must be
    a regular file owned by the administrator (or root) that neither group nor
    others can write, in a directory whose every component is
    administrator-controlled, and the service account must be able to
    execute it. Symbolic links (``/usr/bin/tailscale`` on some packagings)
    are resolved and the target is checked. Value-free reason ``executable``.
    """
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except (OSError, RuntimeError, ValueError):
        raise HumanAccessRefused("executable") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {ADMINISTRATOR_UID, 0}
            or info.st_mode & 0o022):
        raise HumanAccessRefused("executable")
    try:
        _administrator_directory(resolved.parent)
    except ConfigurationError:
        raise HumanAccessRefused("executable") from None
    if not _effective_access(resolved, os.X_OK):
        raise HumanAccessRefused("executable")
    return resolved


def _read_configuration(path: Path) -> tuple[dict, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o027:
                raise ConfigurationError("deployment configuration must be a private regular file")
            content = stream.read(MAX_CONFIGURATION_BYTES + 1)
            after = os.fstat(stream.fileno())
            if len(content) > MAX_CONFIGURATION_BYTES or (
                    before.st_size, before.st_mtime_ns, before.st_ctime_ns
            ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ConfigurationError("deployment configuration changed during validation")
        value = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ConfigurationError("deployment configuration is unavailable") from None
    if not isinstance(value, dict):
        raise ConfigurationError("deployment configuration must be an object")
    return value, before


def _private_directory(path: Path, uid: int, forbidden_roots: tuple[Path, ...]) -> Path:
    if not path.is_absolute():
        raise ConfigurationError("runtime_root must be absolute")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        forbidden = tuple(root.resolve(strict=True) for root in forbidden_roots)
    except (OSError, RuntimeError, ValueError):
        raise ConfigurationError("runtime directory is unavailable") from None
    if (not resolved.is_dir() or info.st_uid != uid or info.st_mode & 0o077
            or any(resolved.is_relative_to(root) for root in forbidden)):
        raise ConfigurationError("runtime directory failed ownership or location checks")
    # Owner-only modes such as 0o000 or 0o500 also pass the group/other check
    # while making every later recording or audit write fail, so readiness
    # would be announced for a runtime tree the service cannot actually use.
    if info.st_mode & 0o700 != 0o700:
        raise ConfigurationError("runtime directory is not readable and writable by the service")
    return resolved


@dataclass(frozen=True)
class Deployment:
    runtime_root: Path
    service_uid: int
    settings: Settings
    recordings_directory: Path
    audit_directory: Path
    # Monitoring runtime configuration. `load()` parses it structurally; the
    # launcher (`main`, including `--check`) refuses to run without its
    # storage sections because the mandatory integrity/self-test checks need it.
    monitoring: MonitoringConfiguration | None = field(default=None, repr=False)
    # Logical registry source UUIDs the backend supervises for local UVC
    # capture. Absent means an explicit `unconfigured` local UVC state.
    local_uvc: LocalUvcConfiguration | None = field(default=None, repr=False)
    # Detector bindings. Absent means no inference runtime may start and every
    # source's detector observation stays unknown/model_unavailable; there is
    # no default model, cadence or limit (see detection/foundation/config.py).
    detection: DetectionConfiguration | None = field(default=None, repr=False)
    # The capture-node CA directory. When configured, the launcher refuses to
    # run if the service account can open it (Issue #109).
    capture_ca_directory: Path | None = field(default=None, repr=False)
    # Whether the configuration contains the ``capture_ca_directory`` key at
    # all (``null`` counts). The installer compares it with the release it
    # switches to (Issue #109, review of PR #177).
    capture_ca_configured: bool = field(default=True, repr=False)
    # The optional ``human_access`` section (Issue #10). Absent keeps every
    # human path closed (``ClosedHumanSurface``); enabled, the launcher builds
    # the production composition (``app.auth.composition``); one it cannot
    # build keeps every human path closed and notifies the Owner.
    human_access: HumanAccessDeployment | None = field(default=None, repr=False)

    @property
    def state_directory(self) -> Path:
        return self.settings.data_directory

    @classmethod
    def load(cls, path: Path, *, code_root: Path | None = None,
             install_root: Path | None = None,
             capture_ca_setting: str = "required") -> "Deployment":
        """Load and validate the configuration.

        ``capture_ca_setting`` is ``"required"`` for the service itself. The
        installer passes ``"optional"`` and then requires or forbids the key
        according to the release it switches to: a release from before
        Issue #109 refuses the key as unknown (``capture_ca_configured``).
        """
        if capture_ca_setting not in ("required", "optional"):
            raise ConfigurationError("invalid deployment configuration")
        value, info = _read_configuration(path)
        code_root = code_root or Path(__file__).resolve().parents[1]
        allowed = {
            "runtime_root", "runtime_mount_point", "runtime_device",
            "runtime_filesystem_uuid", "service_uid",
            "human_host", "human_port", "log_level",
        }
        if (not allowed <= set(value)
                or not set(value) <= allowed | {"monitoring", "local_uvc", "detection",
                                                "capture_ca_directory",
                                                "invitation_lifetime_hours",
                                                "web_assets_directory", "human_access"}
                or type(value.get("service_uid")) is not int):
            raise ConfigurationError("invalid deployment configuration")
        # Required (Owner decision 2026-10-07, Issue #109): every configuration
        # states where the capture-node CA lives, or ``null`` for none, so the
        # start-time check can never be skipped by omission.
        configured = "capture_ca_directory" in value
        if not configured and capture_ca_setting == "required":
            raise CaptureCaSettingMissing("capture_ca_directory is required")
        uid = value["service_uid"]
        if uid <= 0:
            raise ConfigurationError("deployment configuration must name a non-root account")
        _administrator_file(path, info)
        roots = tuple(root for root in (code_root, install_root) if root is not None)
        try:
            configuration_path = path.resolve(strict=True)
            if any(configuration_path.is_relative_to(root.resolve(strict=True)) for root in roots):
                raise ConfigurationError("deployment configuration must be outside code")
            runtime_path = Path(value["runtime_root"])
        except (OSError, RuntimeError, TypeError, ValueError):
            raise ConfigurationError("invalid deployment configuration") from None
        runtime_root = _private_directory(runtime_path, uid, roots)
        if configuration_path.is_relative_to(runtime_root):
            raise ConfigurationError(
                "deployment configuration must be outside runtime-writable data"
            )
        device = value["runtime_device"]
        if (not isinstance(device, list) or len(device) != 2
                or any(type(part) is not int or part < 0 for part in device)):
            raise ConfigurationError("invalid runtime filesystem identity")
        approved_device = _approved_filesystem_device(value["runtime_filesystem_uuid"])
        try:
            configured_mount = Path(value["runtime_mount_point"])
        except (TypeError, ValueError):
            raise ConfigurationError("invalid runtime filesystem identity") from None
        # resolve() would silently anchor a relative value to the caller's
        # current directory, which differs between the administrator running
        # the installer and the service resolving it from the release tree.
        if not configured_mount.is_absolute():
            raise ConfigurationError("runtime_mount_point must be absolute")
        try:
            mount_point = configured_mount.resolve(strict=True)
            mount_info = mount_point.stat()
            root_info = runtime_root.stat()
            operating_system_root_device = _operating_system_root_device()
        except (OSError, RuntimeError, TypeError, ValueError):
            raise ConfigurationError("runtime mount is unavailable") from None
        if mount_point == Path(mount_point.anchor):
            raise ConfigurationError("runtime mount must not be root filesystem")
        if root_info.st_dev == operating_system_root_device:
            raise ConfigurationError("runtime mount must not use root filesystem device")
        if (not mount_point.is_dir()
                or not os.path.ismount(mount_point)
                or not runtime_root.is_relative_to(mount_point)
                or root_info.st_dev != mount_info.st_dev
                or root_info.st_dev != approved_device
                or [os.major(root_info.st_dev), os.minor(root_info.st_dev)] != device
                or any(mount_point.is_relative_to(root) for root in roots)):
            raise ConfigurationError("runtime filesystem identity mismatch")
        directories = tuple(
            _private_directory(runtime_root / name, uid, roots)
            for name in ("state", "recordings", "audit")
        )
        for directory in directories:
            directory_device = directory.stat().st_dev
            if (not directory.is_relative_to(runtime_root)
                    or directory_device != root_info.st_dev
                    or [os.major(directory_device), os.minor(directory_device)] != device):
                raise ConfigurationError("runtime subdirectory escapes the approved filesystem")
        # Optional (Owner decision 2026-10-11): whole hours from 1 to 168
        # (7 days); absent means the 24-hour default.
        if "invitation_lifetime_hours" in value:
            try:
                lifetime = invitation_lifetime(value["invitation_lifetime_hours"])
            except ValueError:
                raise ConfigurationError(
                    "invitation_lifetime_hours must be an integer from 1 to 168") from None
        else:
            lifetime = INVITATION_LIFETIME
        # Optional (Issue #10 S5c): the release's Web build. Absent means no
        # human composition can be mounted (``create_app`` refuses one
        # without ``Settings.web_assets_dir``), so human access stays closed.
        web_assets = (_web_assets_directory(value["web_assets_directory"], code_root, install_root)
                      if "web_assets_directory" in value else None)
        # Optional (Issue #10): the Owner's reservation of the human origin.
        # Enabled, it needs the release's Web build: the composition serves
        # nothing else, and create_app refuses one without it.
        human_access = (parse_human_access(value["human_access"])
                        if "human_access" in value else None)
        if human_access is not None and human_access.enabled and web_assets is None:
            raise HumanAccessRefused("web_assets")
        if human_access is not None:
            # Validated as a loopback literal and a port by Settings below.
            human_access = replace(human_access, upstream_host=value["human_host"],
                                   upstream_port=value["human_port"])
        settings = Settings(
            directories[0], human_host=value["human_host"],
            human_port=value["human_port"], log_level=value["log_level"],
            invitation_lifetime=lifetime, web_assets_dir=web_assets, source_root=code_root,
        )
        monitoring = None
        if "monitoring" in value:
            # Module-level lookups stay patchable, and the same UUID resolver is
            # re-run by the runtime on every storage sample.
            monitoring = parse_monitoring(
                value["monitoring"], recordings_directory=directories[1],
                resolve_device=lambda uuid: _approved_filesystem_device(uuid),
                root_device=lambda: _operating_system_root_device(),
                is_mount=lambda path: os.path.ismount(path),
            )
        local_uvc = parse_local_uvc(value["local_uvc"]) if "local_uvc" in value else None
        detection = parse_detection(value["detection"]) if "detection" in value else None
        capture_ca = (None if value.get("capture_ca_directory") is None
                      else _capture_ca_directory(value["capture_ca_directory"]))
        if capture_ca is not None and (capture_ca.is_relative_to(runtime_root)
                                       or any(capture_ca.is_relative_to(root) for root in roots)):
            raise ConfigurationError("capture CA directory must be outside runtime data and code")
        return cls(runtime_root, uid, settings, directories[1], directories[2], monitoring,
                   local_uvc=local_uvc, detection=detection, capture_ca_directory=capture_ca,
                   capture_ca_configured=configured, human_access=human_access)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(arguments)
    try:
        code_root, install_root = _runtime_roots()
        deployment = Deployment.load(
            args.config, code_root=code_root, install_root=install_root
        )
        if os.geteuid() != deployment.service_uid:
            raise ConfigurationError("launcher must run as the dedicated account")
        # The service must run the mandatory startup/daily hardware integrity
        # check and daily recording self-test, which need the monitoring
        # storage sections. `--check` (the unit's ExecStartPre) and the
        # launcher refuse, so a deployment never runs with them silently absent.
        if deployment.monitoring is None or not deployment.monitoring.storage_configured:
            raise ConfigurationError("monitoring storage configuration is required")
        # The service must not be able to open the capture-node CA directory
        # (Issue #109); `--check` refuses too, so the unit never starts.
        if (deployment.capture_ca_directory is not None
                and capture_ca_directory_accessible(deployment.capture_ca_directory)):
            raise ConfigurationError("service account can open the capture CA directory")
        # Issue #10 S5c: the configured Web build must load as this account
        # with the release's own loader, before every start (ExecStartPre)
        # and in the installer's staging and rollback checks.
        if deployment.settings.web_assets_dir is not None:
            _load_web_assets(deployment.settings.web_assets_dir, code_root)
        # Issue #10: the Serve status runner executes the Tailscale CLI as
        # this account on every reservation check; check it as this account.
        # The section itself is valid here, so a CLI that fails the check is
        # a change on the host (removed, replaced, permissions changed), not
        # a configuration error: refusing to start would also stop recording
        # and the integrity and recording-health checks, and with them the
        # Owner notification (Issue #283 item 1). The service starts with
        # every human path closed instead, handled like a composition failure
        # (immediate human_access_fault, degraded health), and the check and
        # the launcher print the value-free reason for the operator.
        human_access = deployment.human_access
        human_access_unavailable = None
        if human_access is not None and human_access.enabled:
            try:
                human_access = replace(human_access, tailscale_executable=_tailscale_executable(
                    human_access.tailscale_executable))
            except HumanAccessRefused as refused:
                human_access_unavailable = refused.reason
    except CaptureCaSettingMissing:
        parser.exit(1, "ServerSentinel deployment validation failed: "
                       + CaptureCaSettingMissing.REASON + "\n")
    except WebAssetsRefused as refused:
        # One value-free word for the operator (no path, name or digest);
        # no client ever sees it.
        parser.exit(1, "ServerSentinel deployment validation failed: web assets refused "
                       f"(reason={refused.reason})\n")
    except HumanAccessRefused as refused:
        # One value-free word (setting, web_assets or executable).
        parser.exit(1, "ServerSentinel deployment validation failed: human access refused "
                       f"(reason={refused.reason})\n")
    except ConfigurationError:
        parser.exit(1, "ServerSentinel deployment validation failed\n")
    if human_access_unavailable is not None:
        # One value-free word, on stderr (the journal for ExecStartPre and
        # the service); the check still passes so the unit starts.
        sys.stderr.write("ServerSentinel deployment warning: human access stays closed "
                         f"(reason={human_access_unavailable}); recording and monitoring "
                         "start\n")
    if args.check:
        print("ServerSentinel deployment validation passed")
        return 0
    from app.__main__ import run
    return run(deployment.settings, deployment.monitoring, deployment.local_uvc,
               human_access=human_access,
               human_access_unavailable=human_access_unavailable is not None)


if __name__ == "__main__":
    raise SystemExit(main())
