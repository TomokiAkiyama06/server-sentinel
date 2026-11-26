"""The Owner's local ring command on the capture node (Issue #16 PR D), stdlib only.

Commands, run as the Agent's service account (never root) with the service
stopped::

    python -m media_capture_agent.ring_admin status --config <agent config>
    python -m media_capture_agent.ring_admin configure --config <agent config> \\
        --mode capacity --value 100GiB
    python -m media_capture_agent.ring_admin configure --config <agent config> \\
        --mode duration --value 86400
    python -m media_capture_agent.ring_admin delete-incident --config <agent config> <incident id>

Only the Owner may choose the ring's mode and value or delete a protected
incident early (Issue #16 acceptance). This is the Owner's local boundary,
the same model as ``capture_admin``: whoever can run this as the service
account already controls the Agent's runtime state, and each change needs a
typed word (``CONFIGURE``, ``DELETE``) read from the controlling terminal
(``/dev/tty``, never stdin or argv). A Main Server path (step-up from the
dashboard) is a later change.

``configure`` takes the segment profiles from the deployment's ``ring``
section and asks the ring core to admit the mode and value: it refuses
(fixed reason words from ``DiskRing.configure``) a value that cannot keep 10
minutes before a loss and record the 10 minutes after it at the same time,
counting existing protected incidents, other use of the filesystem and the
safety reserve. ``capacity`` takes bytes or a ``MiB``/``GiB``/``TiB`` suffix;
``duration`` takes seconds. ``status`` prints the mode and value, the
estimate (bytes for a duration, duration for a capacity), ordinary and
protected usage, filesystem free, the safety reserve, the state and every
protected incident with its bytes, expiry and state. ``delete-incident``
removes one protected incident early; segments still inside the ordinary
ring stay until the ring trims them.

The service holds the approval store's lock and the ring ledger's lock, so
every command refuses ``service_running`` while it runs. While the service is
stopped there is no clock exchange with the Main, so the clock is passed as
untrusted: the ring then never trims or completes on its basis.
Refusals are one fixed word.
"""
from __future__ import annotations

import argparse
import datetime
import os
from pathlib import Path
import re
import signal
import sys
import time
from typing import Callable
from uuid import UUID

from .capture_admin import (_SIGNALS, AdminRefused, _block_interruptions, _ignore_interruptions,
                            _interrupt, _Interrupted, _settings, _store, _unblock_interruptions,
                            read_confirmation)
from .config import ConfigurationError


PROG = "python -m media_capture_agent.ring_admin"
CONFIGURE_WORD = "CONFIGURE"
DELETE_WORD = "DELETE"
_CAPACITY = re.compile(r"([1-9][0-9]{0,18})(MiB|GiB|TiB)?")
_UNITS = {None: 1, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}
GIB = 1 << 30


class _LocalOwner:
    """The typed word on the controlling terminal is the Owner's authorization."""

    def require_owner(self, operation):
        pass

    def require_preserve(self):
        from .ring_models import RingRefused
        raise RingRefused("authenticated_preserve_required")


def parse_value(mode: str, text: str) -> int:
    if mode == "capacity":
        match = _CAPACITY.fullmatch(text)
        if match is None:
            raise AdminRefused("ring_value_rejected")
        return int(match.group(1)) * _UNITS[match.group(2)]
    if not re.fullmatch(r"[1-9][0-9]{0,9}", text):
        raise AdminRefused("ring_value_rejected")
    return int(text)


def _utc(microseconds) -> str:
    if microseconds is None:
        return "-"
    moment = datetime.datetime.fromtimestamp(microseconds / 1_000_000, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _bytes(value) -> str:
    if value is None:
        return "-"
    return f"{value} ({value / GIB:.2f} GiB)"


class _Session:
    """The service is stopped (approval lock), then the media store and ring."""

    def __init__(self, settings, store_factory=None):
        from .ring import DiskRing
        from .ring_models import RingRefused
        from .storage import MediaStore, StorageRefused
        self.approvals = _store(settings)
        self.store = self.ring = None
        try:
            try:
                self.store = (store_factory or MediaStore)(settings)
            except StorageRefused:
                raise AdminRefused("storage_unavailable") from None
            try:
                self.ring = DiskRing(settings, self.store,
                                     ledger_maximum_bytes=settings.ring.ledger_maximum_bytes,
                                     authority=_LocalOwner())
            except RingRefused:
                raise AdminRefused("ring_state_unavailable") from None
        except BaseException:
            self.close()
            raise

    def close(self):
        for closer in (self.ring, self.store, self.approvals):
            if closer is not None:
                try:
                    closer.close()
                except Exception:  # noqa: BLE001 - closing never reports details
                    pass


def _now_us(clock) -> int:
    return int(clock() * 1_000_000)


def _status_lines(ring, now_us) -> list[str]:
    status = ring.status(now_us=now_us, clock_trusted=False)
    if ring.config is None:
        lines = ["ring: not configured (use 'configure')"]
    else:
        unit = "bytes" if ring.config.mode == "capacity" else "seconds"
        lines = [f"mode={ring.config.mode} value={ring.config.value} {unit}"]
        if ring.config.mode == "capacity":
            duration = status.get("estimated_duration_us")
            lines.append("estimated_duration_seconds="
                         + ("-" if duration is None else str(duration // 1_000_000)))
        lines += [f"projected_maximum_bytes={_bytes(status.get('projected_maximum_bytes'))}",
                  f"projected_expected_bytes={_bytes(status.get('projected_expected_bytes'))}",
                  f"ordinary_bytes={_bytes(status.get('ordinary_allocated_bytes'))}",
                  f"protected_bytes={_bytes(status.get('protected_allocated_bytes'))}",
                  f"filesystem_free_bytes={_bytes(status.get('filesystem_free'))}",
                  f"safety_reserve_bytes={_bytes(status.get('safety_reserve'))}"]
    lines.append(f"state={status.get('state')} reason={status.get('reason')}")
    rows = ring.db.execute("SELECT id FROM incidents WHERE state != 'deleted' "
                           "ORDER BY start").fetchall()
    for row in rows:
        item = ring.incident(UUID(row["id"]), now_us=now_us)
        lines.append(
            f"incident {item['incident_id']} reason={item['trigger_reason']} "
            f"state={item['state']} from={_utc(item['started_at_us'])} "
            f"to={_utc(item['target_end_us'])} bytes={item['byte_length']} "
            f"expires={_utc(item['expires_at_us'])}")
    if not rows:
        lines.append("incidents: none")
    return lines


def _configure(settings, mode, value, *, confirm, clock, store_factory=None) -> list[str]:
    from .ring_models import RingConfig, RingRefused
    from .ring_service import ring_profiles
    session = _Session(settings, store_factory)
    try:
        try:
            config = RingConfig(mode, value)
        except RingRefused as exc:
            raise AdminRefused(str(exc)) from None
        profiles = ring_profiles(settings)
        shown = (f"{value} bytes ({value / GIB:.2f} GiB)" if mode == "capacity"
                 else f"{value} seconds")
        word = confirm(f"Set the ring to {mode} {shown} for {len(profiles)} source(s) "
                       f"(maximum bitrates from the deployment). Type {CONFIGURE_WORD} "
                       f"to confirm: ")
        if word != CONFIGURE_WORD:
            raise AdminRefused("owner_confirmation_declined")
        _block_interruptions()
        try:
            session.ring.configure(config, profiles, now_us=_now_us(clock), clock_trusted=False)
        except RingRefused as exc:
            _unblock_interruptions()
            raise AdminRefused(str(exc)) from None
        _ignore_interruptions()
        _unblock_interruptions()
        return ["ring configured", *_status_lines(session.ring, _now_us(clock)),
                "next: start the service"]
    finally:
        session.close()


def _delete(settings, identifier, *, confirm, clock, store_factory=None) -> list[str]:
    from .ring_models import RingRefused
    session = _Session(settings, store_factory)
    try:
        now = _now_us(clock)
        try:
            item = session.ring.incident(identifier, now_us=now)
        except RingRefused as exc:
            raise AdminRefused(str(exc)) from None
        if item["state"] == "deleted":
            raise AdminRefused("incident_not_found")
        word = confirm(f"Delete protected incident {identifier} ({item['trigger_reason']}, "
                       f"{_utc(item['started_at_us'])} to {_utc(item['target_end_us'])}, "
                       f"{item['byte_length']} bytes) before it expires; this cannot be "
                       f"undone. Type {DELETE_WORD} to confirm: ")
        if word != DELETE_WORD:
            raise AdminRefused("owner_confirmation_declined")
        _block_interruptions()
        try:
            session.ring.delete_incident(identifier, now_us=_now_us(clock), clock_trusted=False)
        except RingRefused as exc:
            _unblock_interruptions()
            raise AdminRefused(str(exc)) from None
        _ignore_interruptions()
        _unblock_interruptions()
        return [f"incident deleted: {identifier}"]
    finally:
        session.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description=(
        "The Owner's local ring command. Run as the service account with the service stopped."))
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (("status", "show the ring's mode, usage and protected incidents"),
                       ("configure", "set the ring's mode and value"),
                       ("delete-incident", "delete one protected incident before it expires")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--config", type=Path, required=True)
        if name == "configure":
            command.add_argument("--mode", choices=("capacity", "duration"), required=True)
            command.add_argument("--value", required=True,
                                 help="capacity: bytes or N MiB/GiB/TiB; duration: seconds")
        if name == "delete-incident":
            command.add_argument("incident", help="the incident id 'status' printed")
    return parser


def main(argv=None, *, settings_loader=_settings,
         confirm: Callable[[str], str] = read_confirmation, clock=time.time,
         store_factory=None) -> int:
    args = _parser().parse_args(argv)
    previous = {}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    try:
        for signum in _SIGNALS:
            previous[signum] = signal.signal(signum, _interrupt)
        if os.geteuid() == 0:
            raise AdminRefused("run_as_service_account")
        value = identifier = None
        if args.command == "configure":
            value = parse_value(args.mode, args.value)
        if args.command == "delete-incident":
            try:
                identifier = UUID(args.incident)
            except ValueError:
                raise AdminRefused("incident_id_rejected") from None
            if str(identifier) != args.incident.lower():
                raise AdminRefused("incident_id_rejected")
        try:
            settings = settings_loader(args.config)
        except ConfigurationError:
            raise AdminRefused("config_invalid") from None
        if os.geteuid() != settings.service_uid:
            raise AdminRefused("run_as_service_account")
        if settings.ring is None:
            raise AdminRefused("ring_unconfigured")
        if args.command == "status":
            session = _Session(settings, store_factory)
            try:
                lines = _status_lines(session.ring, _now_us(clock))
            finally:
                session.close()
        elif args.command == "configure":
            lines = _configure(settings, args.mode, value, confirm=confirm, clock=clock,
                               store_factory=store_factory)
        else:
            lines = _delete(settings, identifier, confirm=confirm, clock=clock,
                            store_factory=store_factory)
    except AdminRefused as refused:
        print(f"{PROG}: refused: {refused.reason}", file=sys.stderr)
        return 2
    except _Interrupted:
        print(f"{PROG}: refused: interrupted", file=sys.stderr)
        return 2
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
