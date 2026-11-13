"""Local camera approval on the capture node (Issue #14), stdlib only.

Commands, run as the Agent's service account (never root) with the service
stopped::

    python -m media_capture_agent.capture_admin candidates --config <agent config>
    python -m media_capture_agent.capture_admin approve --config <agent config> \\
        <source id> <candidate label>
    python -m media_capture_agent.capture_admin revoke --config <agent config> <source id>

The Agent opens a camera only for a source of its ``capture`` section whose
Owner approval names that exact device (``uvc_identity``). This is the
Owner's local approval boundary, the same model as the Main's
``app.cameras.uvc.admin_cli``: whoever can run this as the service account
already controls the Agent's runtime state, and each approval needs the
typed word ``APPROVE`` read from the controlling terminal (``/dev/tty``,
never stdin or argv).

``candidates`` lists the connected video devices as short labels
(``cam-`` and 10 hex digits of a SHA-256 over the device evidence), never a
serial, path or USB port, with the USB vendor:product, whether a serial is
present, the formats and the configured source each is approved for. A label
changes when the device is re-plugged or the host restarts (it hashes the
per-boot device instance too); ``approved_for`` compares the serial identity.
``candidates`` starts no session; it only reads the approval state, except that
it copies the recorded duplicated-serial latches into the runtime-wide set.
``approve`` refuses a camera without a serial, a serial shared with another
connected camera or ever latched as ambiguous (``camera_serial_not_unique``;
the latches are kept runtime-wide in ``uvc-latched-serials.json`` as digests,
so neither replacing nor revoking an approval clears them) and a
camera already approved for another source
(``camera_approved_for_another_source``), because the service could never
reconnect such an approval; it then starts only that source's session,
persists the approval through ``UvcCapture.approve`` (identity re-verified)
and closes cleanly, so the next service start reconnects by serial. A
hang-up or stop at the prompt still releases the session.

The service holds the approval store's runtime-wide lock, so both commands
refuse ``service_running`` while it runs. Refusals are one fixed word.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import zipimport
from typing import Callable
from uuid import UUID

from .config import ConfigurationError, Settings


PROG = "python -m media_capture_agent.capture_admin"
APPROVE_WORD = "APPROVE"
REVOKE_WORD = "REVOKE"
_LABEL = re.compile(r"cam-[0-9a-f]{10}")
_LABEL_DOMAIN = b"serversentinel-agent-uvc-candidate-label-v1\0"


class AdminRefused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _NoPipeline:
    """Approval never starts a pipeline (``UvcCapture.poll`` is not called)."""

    def launch(self, device_fd, profile):  # pragma: no cover - never called
        raise AdminRefused("pipeline_not_available_here")


def candidate_label(device) -> str:
    record = device.to_record()
    evidence = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "cam-" + hashlib.sha256(_LABEL_DOMAIN + evidence.encode("ascii")).hexdigest()[:10]


def read_confirmation(prompt: str, *, opener: Callable[..., int] = os.open) -> str:
    """One line from the controlling terminal; stdin is never read."""
    try:
        descriptor = opener("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError:
        raise AdminRefused("controlling_terminal_required") from None
    try:
        if not os.isatty(descriptor):
            raise AdminRefused("controlling_terminal_required")
        # Descriptor-level I/O: a terminal is not seekable, so a buffered
        # "r+" file object cannot be used (Codex P1 on PR #412).
        data = prompt.encode("utf-8")
        while data:
            data = data[os.write(descriptor, data):]
        line = b""
        while len(line) < 256 and not line.endswith(b"\n"):
            chunk = os.read(descriptor, 256 - len(line))
            if not chunk:
                break
            line += chunk
        text = line.decode("utf-8")
    except (OSError, UnicodeError):
        raise AdminRefused("controlling_terminal_required") from None
    finally:
        os.close(descriptor)
    return text.strip()


def _settings(path: Path) -> Settings:
    location = Path(__file__).absolute()
    code_root = (Path(__loader__.archive).resolve().parents[1]
                 if isinstance(__loader__, zipimport.zipimporter) else location.parents[2])
    return Settings.load(path, code_root=code_root)


def _store(settings):
    """The approval store; its runtime-wide lock refuses while the service runs."""
    from .uvc_approvals import ApprovalStorageError, ApprovalStore
    try:
        return ApprovalStore(settings)
    except ApprovalStorageError as error:
        if isinstance(error.__cause__, BlockingIOError):
            raise AdminRefused("service_running") from None
        raise AdminRefused("approval_state_unavailable") from None


def _approvals(store, settings) -> dict:
    """Each configured source's stored state (read only: no session is started)."""
    from .uvc_approvals import ApprovalStorageError
    try:
        return {source.source_id: store.load(source.source_id)
                for source in settings.capture.sources}
    except ApprovalStorageError:
        raise AdminRefused("approval_state_unavailable") from None


def _latched(store) -> frozenset:
    """Record every persisted duplicated-serial latch in the runtime-wide set, then read it.

    A source's latch lives with its approval and disappears when that
    approval is replaced or removed (PR #412 review); the set keeps the
    serial unapprovable for good, so it never reconnects automatically
    (SPECIFICATION §4.4). Records of sources no longer configured are
    included (Codex P2 on PR #412).
    """
    from .uvc_approvals import ApprovalStorageError
    try:
        digests = store.recorded_latches()
        if digests:
            store.add_latched(digests)
        return store.latched_digests()
    except ApprovalStorageError:
        raise AdminRefused("approval_state_unavailable") from None


def _scan(discovery):
    from .uvc_discovery import LinuxDiscovery
    try:
        result = (discovery or LinuxDiscovery()).scan()
    except Exception:
        raise AdminRefused("camera_scan_incomplete") from None
    return tuple(result.devices), result.failures


def _holders(device, approvals) -> list[UUID]:
    """Sources whose approved camera is this device (by serial identity, PR #412 review).

    The full evidence includes a per-boot instance token, so only the strong
    (serial) key identifies a camera across restarts.
    """
    key = device.strong_key
    return [source for source, state in approvals.items()
            if key is not None and getattr(state, "approved", None) is not None
            and state.approved.strong_key == key]


def _candidates(settings, discovery) -> list[str]:
    from .uvc_approvals import strong_key_digest
    store = _store(settings)
    try:
        approvals = _approvals(store, settings)
        latched = _latched(store)
    finally:
        store.close()
    devices, failures = _scan(discovery)
    lines = []
    for device in devices:
        shared = (device.serial is not None
                  and sum(other.strong_key == device.strong_key for other in devices) > 1)
        serial = ("absent" if device.serial is None else "shared" if shared
                  else "latched" if strong_key_digest(device) in latched else "present")
        holders = ",".join(str(source) for source in _holders(device, approvals)) or "-"
        lines.append(f"candidate {candidate_label(device)} usb={device.vendor}:{device.product} "
                     f"serial={serial} formats={','.join(device.formats) or '-'} "
                     f"approved_for={holders}")
    if not devices:
        lines.append("no candidates")
    if failures:
        lines.append(f"devices not inspected: {failures}")
    return lines


def _approve(settings, discovery, source_id: UUID, label: str, *, confirm) -> list[str]:
    from .uvc_capture import CaptureRefused, UvcCapture, UvcSourceConfig
    from .uvc_pipeline import MjpegProfile
    configured = {source.source_id: source for source in settings.capture.sources}
    if source_id not in configured:
        raise AdminRefused("source_not_configured")
    from .uvc_approvals import strong_key_digest
    store = _store(settings)
    try:
        approvals = _approvals(store, settings)
        latched = _latched(store)
    finally:
        store.close()
    devices, failures = _scan(discovery)
    if failures:
        # A device that could not be inspected might be the label's twin.
        raise AdminRefused("camera_scan_incomplete")
    matches = [device for device in devices if candidate_label(device) == label]
    if not matches:
        raise AdminRefused("candidate_not_found")
    if len(matches) > 1:
        raise AdminRefused("candidate_label_ambiguous")
    device = matches[0]
    if device.serial is None:
        # Without a serial the approval would last only while the
        # descriptor this command never keeps open stays open.
        raise AdminRefused("camera_without_serial")
    if (sum(other.strong_key == device.strong_key for other in devices) > 1
            or strong_key_digest(device) in latched):
        # A shared (or latched) serial is never reconnected after a restart
        # (PR #412 review): the approval would be unusable.
        raise AdminRefused("camera_serial_not_unique")
    if any(holder != source_id for holder in _holders(device, approvals)):
        # Two sources on one camera both latch `identity_ambiguous` at start.
        raise AdminRefused("camera_approved_for_another_source")
    profile = configured[source_id]
    word = confirm(f"Approve camera {label} usb={device.vendor}:{device.product} for source "
                   f"{source_id} profile={profile.width}x{profile.height}@{profile.fps}/MJPG; "
                   f"the Agent uses it from its next start. Type {APPROVE_WORD} to confirm: ")
    if word != APPROVE_WORD:
        raise AdminRefused("owner_confirmation_declined")
    # Only this source's session is started (and released on close).
    capture = None
    try:
        try:
            capture = UvcCapture(
                settings, [UvcSourceConfig(source_id, MjpegProfile(profile.width, profile.height,
                                                                   profile.fps))],
                launcher=_NoPipeline(), **({} if discovery is None else {"discovery": discovery}))
        except AdminRefused:
            raise
        except Exception as error:
            if isinstance(getattr(error, "__cause__", None), BlockingIOError):
                raise AdminRefused("service_running") from None
            raise AdminRefused("approval_state_unavailable") from None
        # Re-checked under the approval store's lock (PR #412 review): a
        # concurrent approval of this camera for another source, or a latch
        # set meanwhile, is seen here.
        locked = {source: capture.store.load(source) for source in configured}
        if strong_key_digest(device) in _latched(capture.store):
            raise AdminRefused("camera_serial_not_unique")
        if any(holder != source_id for holder in _holders(device, locked)):
            raise AdminRefused("camera_approved_for_another_source")
        fresh = capture.candidates(source_id)
        current = [candidate for candidate in fresh if candidate_label(candidate) == label]
        if len(current) != 1:
            raise AdminRefused("candidate_unavailable")
        # Re-checked on the fresh scan (Codex P2 on PR #412): a same-serial
        # camera connected at the prompt would make the approval unusable.
        if sum(other.strong_key == current[0].strong_key for other in fresh) > 1:
            raise AdminRefused("camera_serial_not_unique")
        # From just before the write: an interruption must not report a
        # refusal for an approval that was stored (PR #412 review).
        _block_interruptions()
        try:
            capture.approve(source_id, current[0])
        except (CaptureRefused, ValueError):
            # The camera changed, vanished or became ambiguous meanwhile.
            _unblock_interruptions()
            raise AdminRefused("candidate_unavailable") from None
        _ignore_interruptions()
        _unblock_interruptions()
    except CaptureRefused:
        raise AdminRefused("candidate_unavailable") from None
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                raise AdminRefused("capture_state_not_released") from None
    return [f"camera approved: source_id={source_id} candidate={label}",
            "next: start the service; the approval applies on start"]


class _Interrupted(Exception):
    pass


_SIGNALS = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)


def _ignore_interruptions() -> None:
    for signum in _SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def _block_interruptions() -> None:
    signal.pthread_sigmask(signal.SIG_BLOCK, _SIGNALS)


def _unblock_interruptions() -> None:
    # A signal held while blocked is delivered now: to the refusal handler
    # if nothing was stored, or ignored (SIG_IGN) once it was.
    signal.pthread_sigmask(signal.SIG_UNBLOCK, _SIGNALS)


def _interrupt(signum, frame):
    # A hang-up or stop while waiting at the prompt still releases the
    # approval session in `finally` (PR #412 review).
    raise _Interrupted()


def _revoke(settings, source_id: UUID, *, confirm) -> list[str]:
    """Remove a source's camera approval, so the camera can be approved again."""
    from .uvc_approvals import ApprovalStorageError
    if source_id not in {source.source_id for source in settings.capture.sources}:
        raise AdminRefused("source_not_configured")
    store = _store(settings)
    try:
        state = store.load(source_id)
        if state is None or state.approved is None:
            raise AdminRefused("source_not_approved")
        # A latch of this approval is kept in the runtime-wide set first, so
        # removing the approval never makes that serial approvable again.
        _latched(store)
        word = confirm(f"Remove the camera approval of source {source_id}; the Agent will not "
                       f"use any camera for it until one is approved again. "
                       f"Type {REVOKE_WORD} to confirm: ")
        if word != REVOKE_WORD:
            raise AdminRefused("owner_confirmation_declined")
        _block_interruptions()
        try:
            token = store.start_session(source_id).session_token
            store.save(source_id, None, True, session_token=token, serial_ambiguous=False,
                       release=True)
        except ApprovalStorageError:
            _unblock_interruptions()
            raise AdminRefused("approval_state_unavailable") from None
        _ignore_interruptions()
        _unblock_interruptions()
    finally:
        store.close()
    return [f"camera approval removed: source_id={source_id}",
            "next: approve a camera for it with 'approve', then start the service"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description=(
        "Local camera approval on the capture node. Run as the service account with the "
        "service stopped."))
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("candidates", "list connected cameras by label (no serial or path)"),
                       ("approve", "approve a connected camera for a configured source"),
                       ("revoke", "remove a configured source's camera approval")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True)
        if name in ("approve", "revoke"):
            command.add_argument("source", help="the source UUID of the capture section")
        if name == "approve":
            command.add_argument("candidate", help="the label 'candidates' printed")
    return parser


def main(argv=None, *, settings_loader=_settings, discovery=None,
         confirm: Callable[[str], str] = read_confirmation) -> int:
    args = _parser().parse_args(argv)
    previous = {}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    try:
        for signum in _SIGNALS:
            previous[signum] = signal.signal(signum, _interrupt)
        if os.geteuid() == 0:
            raise AdminRefused("run_as_service_account")
        source_id = None
        if args.command in ("approve", "revoke"):
            try:
                source_id = UUID(args.source)
            except ValueError:
                raise AdminRefused("source_id_rejected") from None
            if str(source_id) != args.source.lower():
                raise AdminRefused("source_id_rejected")
        if args.command == "approve":
            if not _LABEL.fullmatch(args.candidate):
                raise AdminRefused("candidate_label_rejected")
        try:
            settings = settings_loader(args.config)
        except ConfigurationError:
            raise AdminRefused("config_invalid") from None
        if os.geteuid() != settings.service_uid:
            raise AdminRefused("run_as_service_account")
        if settings.capture is None:
            raise AdminRefused("capture_unconfigured")
        if args.command == "candidates":
            lines = _candidates(settings, discovery)
        elif args.command == "revoke":
            lines = _revoke(settings, source_id, confirm=confirm)
        else:
            lines = _approve(settings, discovery, source_id, args.candidate, confirm=confirm)
    except AdminRefused as refused:
        print(f"{PROG}: refused: {refused.reason}", file=sys.stderr)
        return 2
    except _Interrupted:
        print(f"{PROG}: refused: interrupted", file=sys.stderr)
        return 2
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        # Every path, an unexpected exception included, leaves the caller's
        # signal mask as it was (PR #412 review).
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
