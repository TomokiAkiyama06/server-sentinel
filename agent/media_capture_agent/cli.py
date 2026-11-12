"""Native CLI. Secrets, paths and configuration values never appear in diagnostics."""

import argparse
import json
from pathlib import Path
import signal
import sys
import threading
import zipimport

from .config import ConfigurationError, Settings
from .ingest_session import IngestSession
from .pairing import NodeCredentialStore
from .runtime import Agent, UnconfiguredIngestSession
from .storage import DEVICE_NUMBERS_STALE, MediaStore, StorageRefused


# Stable, identifier-free validation failure codes. Exactly one is reported per
# failure; nothing configured or observed (UUIDs, device numbers, paths, mount
# sources, sizes, usernames, exception text) is ever printed. Changing a code is
# a CLI contract change (agent/README.md, MANUAL_TEST.md).
CHECK_REASONS = frozenset({
    "config_invalid", "mount_missing", "media_root_on_root_filesystem",
    "mount_point_is_root", "mount_source_mismatch", "mount_device_mismatch",
    "mount_identity_mismatch", "filesystem_uuid_mismatch", "mount_readonly",
    "mount_replaced", "mount_inventory_unavailable", "media_root_unavailable",
    "media_root_owner_mismatch", "media_root_permissions_too_open",
    "not_writable_by_service_account", "insufficient_free_space", "storage_unavailable",
    "service_account_mismatch", "runtime_root_unavailable", "runtime_root_permissions_unsafe",
    "runtime_root_not_writable", "node_identity_mismatch", "node_credential_unavailable",
    "capture_pipeline_unavailable", "capture_state_unavailable",
    "check_failed",
})

# Accepted-but-degraded findings `--check` reports without failing (Issue #324).
CHECK_WARNINGS = frozenset({DEVICE_NUMBERS_STALE})
CHECK_WARNING = "media-capture-agent: local deployment validation warning: "

# MediaStore refusals (StorageRefused.diagnostic) -> public reason code.
_STORAGE_REASONS = {
    "invalid_storage_path": "config_invalid",
    "mount_missing": "mount_missing",
    "media_root_unavailable": "media_root_unavailable",
    "storage_path_unavailable": "media_root_unavailable",
    "media_root_on_root_filesystem": "media_root_on_root_filesystem",
    "mount_point_is_root": "mount_point_is_root",
    "mount_source_mismatch": "mount_source_mismatch",
    "mount_device_mismatch": "mount_device_mismatch",
    "mount_identity_mismatch": "mount_identity_mismatch",
    "stable_device_mismatch": "filesystem_uuid_mismatch",
    "mount_readonly": "mount_readonly",
    "mount_replaced": "mount_replaced",
    "media_root_replaced": "mount_replaced",
    "mount_inventory_unavailable": "mount_inventory_unavailable",
    "media_root_owner_mismatch": "media_root_owner_mismatch",
    "media_root_permissions_too_open": "media_root_permissions_too_open",
    "media_root_not_writable": "not_writable_by_service_account",
    "insufficient_free_space": "insufficient_free_space",
    "storage_unavailable": "storage_unavailable",
}

# Agent construction refusals (runtime account/root checks) -> public code.
_RUNTIME_REASONS = {
    "dedicated_nonroot_account_required": "service_account_mismatch",
    "storage_path_unavailable": "runtime_root_unavailable",
    "invalid_storage_path": "config_invalid",
    "runtime_root_ownership": "runtime_root_permissions_unsafe",
    "runtime_root_not_writable": "runtime_root_not_writable",
    "node_identity_mismatch": "node_identity_mismatch",
    "node_credential_unavailable": "node_credential_unavailable",
}


def check_reason(exc, *, runtime=False):
    """Map a failure to exactly one fixed code; unknown errors -> check_failed."""
    if isinstance(exc, ConfigurationError):
        return "config_invalid"
    # Issue #14: the configured capture's failures (imported here, when a
    # failure is being reported).
    from .uvc_approvals import ApprovalStorageError
    from .uvc_capture import CaptureRefused
    from .uvc_pipeline import PipelineError
    if isinstance(exc, PipelineError):
        return "capture_pipeline_unavailable"
    if isinstance(exc, (ApprovalStorageError, CaptureRefused)):
        return "capture_state_unavailable"
    if isinstance(exc, StorageRefused):
        table = _RUNTIME_REASONS if runtime else _STORAGE_REASONS
        return table.get(getattr(exc, "diagnostic", None), "check_failed")
    return "check_failed"


def _capture_launcher(settings):
    """The trusted GStreamer launcher of the `capture` section, or None (Issue #14).

    Checks the root-owned `gst-launch-1.0`, its two plugins, the sandbox
    helper and Landlock (`uvc_pipeline.GStreamerLauncher`); a failure is
    `capture_pipeline_unavailable`.
    """
    if settings.capture is None:
        return None
    from .uvc_pipeline import GStreamerLauncher
    return GStreamerLauncher(settings.capture.gst_launch)


def _capture(settings, launcher):
    """The UVC capture of the configured sources and the live preview consumer."""
    from .preview import PreviewTap
    from .uvc_capture import UvcCapture, UvcSourceConfig
    from .uvc_pipeline import MjpegProfile
    sources = [UvcSourceConfig(source.source_id,
                               MjpegProfile(source.width, source.height, source.fps))
               for source in settings.capture.sources]
    capture = UvcCapture(settings, sources, launcher=launcher)
    try:
        preview = PreviewTap((source.source_id, capture.frames(source.source_id))
                             for source in sources)
    except BaseException:
        capture.close()
        raise
    return capture, preview


def main(argv=None):
    parser = argparse.ArgumentParser(prog="media-capture-agent")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="validate local deployment and exit")
    parser.add_argument("--json", action="store_true",
                        help="with --check, print only a JSON ok/reason object to stdout")
    args = parser.parse_args(argv)
    if args.json and not args.check:
        parser.error("--json requires --check")
    agent = None
    store = None
    capture = preview = sender = None
    stopped = threading.Event()
    previous = {}
    runtime_phase = False
    try:
        # A release lives at destination/version/media-capture-agent. Exclude
        # the whole destination, including siblings of this release directory.
        # Checkout execution instead excludes the complete repository.
        location = Path(__file__).absolute()
        code_root = (Path(__loader__.archive).resolve().parents[1]
                     if isinstance(__loader__, zipimport.zipimporter) else location.parents[2])
        settings = Settings.load(args.config, code_root=code_root)
        store = MediaStore(settings)
        runtime_phase = True
        # Issue #14: the ingest session opens only with a configured endpoint;
        # `--check` builds it but never connects.
        credentials = NodeCredentialStore(settings.runtime_root, owner_uid=settings.service_uid)
        session = (IngestSession(credentials, settings.main_ingest, settings.node_id)
                   if settings.main_ingest is not None
                   else UnconfiguredIngestSession(credentials))
        # The Agent's account, runtime-root and node-identity checks come
        # first (#116: fail closed before any capture; PR #412 review).
        agent = Agent(settings, store, session=session)
        launcher = _capture_launcher(settings)
        if launcher is not None and not args.check:
            # The approval store holds a runtime-wide lock, so `--check`
            # (also run by the installer while the service runs) only checks
            # the pipeline launcher; the service opens the cameras.
            capture, preview = _capture(settings, launcher)
<<<<<<< HEAD
        agent = Agent(settings, store, session=session, capture=capture)
        if preview is not None and isinstance(session, IngestSession):
            # Issue #14 (option A): the newest JPEG of each source to the Main.
            from .live_sender import LiveSender
            sender = LiveSender(session, preview,
                                [source.source_id for source in settings.capture.sources])
=======
            agent.capture = capture
>>>>>>> feat/issue-14-agent-capture-wiring
        runtime_phase = False
        if args.check:
            store.check()
            # Issue #324: an accepted renumbering passes with one fixed,
            # value-free warning; device numbers are never printed.
            warnings = [DEVICE_NUMBERS_STALE] if store.device_numbers_stale else []
            if args.json:
                print(json.dumps({"ok": True, "warnings": warnings} if warnings
                                 else {"ok": True}))
            else:
                print("media-capture-agent: local deployment validation passed")
                for warning in warnings:
                    print(CHECK_WARNING + warning, file=sys.stderr)
            return 0
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stopped.set())
        while not stopped.is_set():
            heartbeat = agent.tick()
            # Operational status only; no media, device paths or raw exceptions.
            print(json.dumps({"service": "media-capture-agent",
                              "node_state": heartbeat["node_state"],
                              "reasons": heartbeat["node_reasons"]}), flush=True)
            # A new session's first acknowledgement gives the clock exchange:
            # send the next heartbeat at once rather than a whole interval
            # later (once per session; `Agent.tick`).
            stopped.wait(0 if agent.clock_refresh_due else settings.heartbeat_seconds)
    except Exception as exc:  # noqa: BLE001 - report a fixed code, never exception text
        reason = check_reason(exc, runtime=runtime_phase)
        if args.json:
            print(json.dumps({"ok": False, "reason": reason}))
        else:
            print("media-capture-agent: local deployment validation failed: " + reason,
                  file=sys.stderr)
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
<<<<<<< HEAD
        if sender is not None:
            sender.close()
        if agent is not None:
            agent.close()
        else:
            if capture is not None:
                capture.close()
            if store is not None:
                store.close()
=======
        try:
            if agent is not None:
                agent.close()
            else:
                if capture is not None:
                    capture.close()
                if store is not None:
                    store.close()
        except Exception:  # noqa: BLE001 - a fixed code, never exception text
            # A camera pipeline that could not be reaped keeps its recovery
            # marker armed (the next start requires re-approval).
            print("media-capture-agent: shutdown failed: capture_cleanup_failed",
                  file=sys.stderr)
            if preview is not None:
                preview.close()
            return 1
>>>>>>> feat/issue-14-agent-capture-wiring
        if preview is not None:
            preview.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
