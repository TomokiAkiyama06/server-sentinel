"""Local camera approval on the capture node (Issue #14), stdlib only.

Commands, run as the Agent's service account (never root) with the service
stopped::

    python -m media_capture_agent.capture_admin candidates --config <agent config>
    python -m media_capture_agent.capture_admin approve --config <agent config> \\
        <source id> <candidate label>

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
changes when the device is re-plugged. ``approve`` persists an approval of
the exact current device for one configured source through
``UvcCapture.approve`` (identity re-verified, a duplicate serial latched as
ambiguous), then closes cleanly so the next service start reconnects by
serial.

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
import sys
import zipimport
from typing import Callable
from uuid import UUID

from .config import ConfigurationError, Settings


PROG = "python -m media_capture_agent.capture_admin"
APPROVE_WORD = "APPROVE"
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
        with open(descriptor, "r+", encoding="utf-8", closefd=False, buffering=1) as terminal:
            terminal.write(prompt)
            terminal.flush()
            line = terminal.readline(256)
    except (OSError, UnicodeError):
        raise AdminRefused("controlling_terminal_required") from None
    finally:
        os.close(descriptor)
    return line.strip()


def _settings(path: Path) -> Settings:
    location = Path(__file__).absolute()
    code_root = (Path(__loader__.archive).resolve().parents[1]
                 if isinstance(__loader__, zipimport.zipimporter) else location.parents[2])
    return Settings.load(path, code_root=code_root)


def _capture(settings, *, discovery=None):
    from .uvc_approvals import ApprovalStorageError
    from .uvc_capture import UvcCapture, UvcSourceConfig
    from .uvc_pipeline import MjpegProfile
    sources = [UvcSourceConfig(source.source_id,
                               MjpegProfile(source.width, source.height, source.fps))
               for source in settings.capture.sources]
    try:
        return UvcCapture(settings, sources, launcher=_NoPipeline(),
                          **({} if discovery is None else {"discovery": discovery}))
    except ApprovalStorageError as error:
        if isinstance(error.__cause__, BlockingIOError):
            raise AdminRefused("service_running") from None
        raise AdminRefused("approval_state_unavailable") from None


def _approved_for(capture, settings, device) -> str:
    holders = []
    for source in settings.capture.sources:
        state = capture.store.load(source.source_id)
        approved = getattr(state, "approved", None)
        if approved is not None and approved.to_record() == device.to_record():
            holders.append(str(source.source_id))
    return ",".join(holders) or "-"


def _candidates(capture, settings) -> list[str]:
    from .uvc_capture import CaptureRefused
    try:
        devices = capture.candidates(settings.capture.sources[0].source_id)
    except CaptureRefused:
        raise AdminRefused("camera_scan_incomplete") from None
    serials = [device.serial for device in devices if device.serial is not None]
    lines = []
    for device in devices:
        serial = ("absent" if device.serial is None
                  else "shared" if serials.count(device.serial) > 1 else "present")
        lines.append(f"candidate {candidate_label(device)} usb={device.vendor}:{device.product} "
                     f"serial={serial} formats={','.join(device.formats) or '-'} "
                     f"approved_for={_approved_for(capture, settings, device)}")
    return lines or ["no candidates"]


def _approve(capture, settings, source_id: UUID, label: str, *, confirm) -> list[str]:
    from .uvc_capture import CaptureRefused
    if source_id not in {source.source_id for source in settings.capture.sources}:
        raise AdminRefused("source_not_configured")
    try:
        devices = capture.candidates(source_id)
    except CaptureRefused:
        raise AdminRefused("camera_scan_incomplete") from None
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
    profile = next(source for source in settings.capture.sources if source.source_id == source_id)
    word = confirm(f"Approve camera {label} usb={device.vendor}:{device.product} for source "
                   f"{source_id} profile={profile.width}x{profile.height}@{profile.fps}/MJPG; "
                   f"the Agent uses it from its next start. Type {APPROVE_WORD} to confirm: ")
    if word != APPROVE_WORD:
        raise AdminRefused("owner_confirmation_declined")
    try:
        capture.approve(source_id, device)
    except CaptureRefused:
        raise AdminRefused("candidate_unavailable") from None
    return [f"camera approved: source_id={source_id} candidate={label}",
            "next: start the service; the approval applies on start"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description=(
        "Local camera approval on the capture node. Run as the service account with the "
        "service stopped."))
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("candidates", "list connected cameras by label (no serial or path)"),
                       ("approve", "approve a connected camera for a configured source")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True)
        if name == "approve":
            command.add_argument("source", help="the source UUID of the capture section")
            command.add_argument("candidate", help="the label 'candidates' printed")
    return parser


def main(argv=None, *, settings_loader=_settings, discovery=None,
         confirm: Callable[[str], str] = read_confirmation) -> int:
    args = _parser().parse_args(argv)
    capture = None
    try:
        if os.geteuid() == 0:
            raise AdminRefused("run_as_service_account")
        source_id = None
        if args.command == "approve":
            try:
                source_id = UUID(args.source)
            except ValueError:
                raise AdminRefused("source_id_rejected") from None
            if str(source_id) != args.source.lower() or not _LABEL.fullmatch(args.candidate):
                raise AdminRefused("source_id_rejected" if str(source_id) != args.source.lower()
                                   else "candidate_label_rejected")
        try:
            settings = settings_loader(args.config)
        except ConfigurationError:
            raise AdminRefused("config_invalid") from None
        if os.geteuid() != settings.service_uid:
            raise AdminRefused("run_as_service_account")
        if settings.capture is None:
            raise AdminRefused("capture_unconfigured")
        capture = _capture(settings, discovery=discovery)
        if args.command == "candidates":
            lines = _candidates(capture, settings)
        else:
            lines = _approve(capture, settings, source_id, args.candidate, confirm=confirm)
    except AdminRefused as refused:
        print(f"{PROG}: refused: {refused.reason}", file=sys.stderr)
        return 2
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                print(f"{PROG}: warning: capture_state_not_released", file=sys.stderr)
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
