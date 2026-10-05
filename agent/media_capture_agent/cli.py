"""Native CLI. Secrets, paths and configuration values never appear in diagnostics."""

import argparse
import json
from pathlib import Path
import signal
import sys
import threading
import zipimport

from .config import ConfigurationError, Settings
from .runtime import Agent
from .storage import MediaStore, StorageRefused


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
    "check_failed",
})

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
    if isinstance(exc, StorageRefused):
        table = _RUNTIME_REASONS if runtime else _STORAGE_REASONS
        return table.get(getattr(exc, "diagnostic", None), "check_failed")
    return "check_failed"


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
        agent = Agent(settings, store)
        runtime_phase = False
        if args.check:
            store.check()
            if args.json:
                print(json.dumps({"ok": True}))
            else:
                print("media-capture-agent: local deployment validation passed")
            return 0
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stopped.set())
        while not stopped.is_set():
            heartbeat = agent.tick()
            # Operational status only; no media, device paths or raw exceptions.
            print(json.dumps({"service": "media-capture-agent",
                              "node_state": heartbeat["node_state"],
                              "reasons": heartbeat["node_reasons"]}), flush=True)
            stopped.wait(settings.heartbeat_seconds)
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
        if agent is not None:
            agent.close()
        elif store is not None:
            store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
