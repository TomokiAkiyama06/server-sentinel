"""Time rules of the lifecycle inventory (#47, split in #256).

The services' retention cutoffs at the verify time, the "written after the
record" bounds, and the future-time check (no time the services compare
later may lie beyond the verify time plus the clock-skew allowance).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.audit.store import DEFAULT_RETENTION as AUDIT_RETENTION
from app.detection.owner import store as owner_store
from app.storage.retention import DAY_MS, RetentionPeriods

from ._common import _utc_instant
from .presence import _presence_instant


# The clock skew tolerated between the services' clocks and the verify
# time; the services define none of their own for these tables, so this is
# the same 5 minutes the capture-node certificate profile allows.
CLOCK_SKEW_ALLOWANCE = timedelta(minutes=5)


def _future_times(current: dict, limit: datetime) -> dict:
    """Times the services compare later that lie beyond ``limit``, by section.

    Presence clocks, tombstones, unresolved-marker times, the override start,
    the timeline gap and Owner-release audit times; pending integrity rows
    and overflow slots; security/admin, integrity, storage-state and
    Owner-template audit times; pairing audit times; notification event
    times. An override expiry is
    legitimately in the future and PresenceService sets no longest
    duration, so it is not bounded.
    """
    found: dict = {}

    def late(section, item, moment):
        # A time that does not parse (wrong type, malformed, out of range)
        # is invalid; one that parses must not lie beyond the limit.
        if moment is None:
            found.setdefault(section, []).append({"id": item, "reason": "invalid_time"})
        elif moment > limit:
            found.setdefault(section, []).append({"id": item, "reason": "future_time"})
    presence = current.get("presence") or {}
    for key, value in sorted((presence.get("clocks") or {}).items()):
        late("presence", f"clocks:{key}", _presence_instant(value))
    for key, value in sorted((presence.get("completed_events") or {}).items()):
        late("presence", f"completed_events:{key}", _presence_instant(value))
    for key, value in sorted((presence.get("expired_unresolved") or {}).items()):
        late("presence", f"expired_unresolved:{key}", _presence_instant(value["since"]))
    if presence.get("override"):
        late("presence", "override:owner", _presence_instant(presence["override"].get("started")))
    for target, at, _, _ in presence.get("cleared_events") or ():
        late("presence", f"cleared_events:{target}", _presence_instant(at))
    gap = current.get("presence_timeline_gap") or {}
    if gap.get("open"):
        late("presence_timeline_gap", "gap", max(
            (moment for moment in (_presence_instant(gap.get("since")),
                                   _presence_instant(gap.get("latest"))) if moment),
            default=None))
    integrity = current.get("integrity_delivery") or {}
    for row_id, at in sorted((integrity.get("pending_at") or {}).items()):
        late("integrity_delivery", f"pending:{row_id}", _utc_instant(at))
    for kind, state, at in integrity.get("overflow") or ():
        late("integrity_delivery", f"overflow:{kind}:{state}", _utc_instant(at))
    # A source cursor end beyond the verify time would make append() refuse
    # every later segment (RECORDING_TIMELINE_REGRESSION).
    for source_id, cursor in sorted((current.get("recording_source_cursors") or {}).items()):
        end = cursor[2] if isinstance(cursor, list) and len(cursor) == 3 else None
        late("recordings", f"cursor:{source_id}", _epoch_instant(1)(end))
    audit = current.get("audit") or {}
    for name, section, parse in (
            ("security_admin", "audit_security_admin", _epoch_instant(1000)),
            ("integrity", "audit_integrity", _utc_instant),
            ("presence", "audit_presence", _presence_instant),
            ("storage_state", "audit_storage_state", _epoch_instant(1))):
        for row_id, value in sorted(((audit.get(name) or {}).get("times") or {}).items()):
            late(section, row_id, parse(value))
    template_audit = (current.get("owner_template") or {}).get("audit") or {}
    for row_id, value in sorted((template_audit.get("times") or {}).items()):
        late("owner_template", f"audit:{row_id}", _utc_instant(value))
    for row in (current.get("security_state") or {}).get("pairing_audit") or ():
        late("security_state", f"pairing_audit:{row[0]}", _epoch_instant(1000)(row[3]))
    # A notification time beyond the verify time would be counted by every
    # later count_since() and kept by expire() until then plus the retention
    # (#132). A malformed one is already a notification_events invalid_value.
    for event_id, value in sorted((current.get("notification_events") or {}).items()):
        moment = (_utc_instant(value[1]) if isinstance(value, list) and len(value) == 3
                  else None)
        if moment is not None:
            late("notification_events", event_id, moment)
    return found


def _epoch_instant(per_millisecond: int):
    """Parse an integer epoch time (``per_millisecond`` units per ms: 1000 for
    microseconds, 1 for milliseconds) as the services store it; None for a
    wrong type, a negative value or one beyond the representable range."""
    def parse(value):
        if type(value) is not int or value < 0:
            return None
        try:
            return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                milliseconds=value / per_millisecond if per_millisecond != 1 else value)
        except (OverflowError, ValueError):
            return None
    return parse


def _written_after(recorded_at) -> dict:
    """Predicates for a row time written at or after the record (none if unknown)."""
    try:
        since = datetime.fromisoformat(recorded_at)
    except (TypeError, ValueError):
        return {"iso": None, "ms": None}
    since_ms = int(since.timestamp() * 1000)

    def iso(value):
        moment = _utc_instant(value)
        return moment is not None and moment >= since
    return {"iso": iso, "ms": lambda value: isinstance(value, int) and value >= since_ms}


def _retention_rules(now: datetime) -> dict:
    """The service's own retention cutoffs at ``now`` (verify time).

    Main runs these with code defaults (no deployment setting changes them):
    AuditStore.cleanup_expired_batch() deletes security/admin audit rows
    with occurred_at_us below now - 90 days and integrity_audit rows with
    ``at`` below that instant's ISO text; StorageAudit.expire() deletes
    storage_state_audit rows with at_ms below now - 90 days;
    RetentionService.expired() deletes unstarred complete / gapped /
    interrupted recordings whose ended_ms is at most now - 20 days.
    OwnerTemplateStore.cleanup_expired_batch() deletes Owner-template audit
    rows older than the store's own retention when the store is registered
    for audit retention. PresenceService.expire_audit() deletes
    presence_audit rows whose ``at`` lies before now - 90 days, and
    expire_history() removes observations received before now - 20 days
    (before now - 90 days while a delivery is unfinished); Main schedules
    both for its scene timeline (Issue #205).
    """
    periods = RetentionPeriods()
    cutoff = now - AUDIT_RETENTION
    cutoff_us = int(cutoff.timestamp()) * 1_000_000 + cutoff.microsecond
    now_ms = int(now.timestamp() * 1000)
    audit_ms = now_ms - periods.audit_days * DAY_MS
    presence_audit = now - timedelta(days=periods.audit_days)
    return {
        "presence_audit": lambda value: (_presence_instant(value) is not None
                                         and _presence_instant(value) < presence_audit),
        "presence_expiry": {"recording": now - timedelta(days=periods.recording_days),
                            "audit": presence_audit},
        "security_admin": lambda value: isinstance(value, int) and value < cutoff_us,
        "integrity": lambda value: (_utc_instant(value) is not None
                                    and _utc_instant(value) < cutoff),
        "storage_state": lambda value: isinstance(value, int) and value < audit_ms,
        "recording_cutoff_ms": now_ms - periods.recording_days * DAY_MS,
        # NotificationEventStore.expire(): ``at < cutoff`` as stored text.
        "notification_events_cutoff": cutoff.astimezone(timezone.utc).isoformat(),
        # OwnerTemplateStore's own default (Main constructs it with it).
        "owner_template": lambda value: (
            _utc_instant(value) is not None
            and _utc_instant(value) < now - owner_store.DEFAULT_AUDIT_RETENTION),
    }
