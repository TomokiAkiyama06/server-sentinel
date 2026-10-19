"""Integrity / notification section of the lifecycle inventory (#47, split in #256).

The Owner-approved hardware baseline as a keyed digest, the pending and
overflowed integrity notifications (which leave only once delivered or
promoted), the notification history of every kind, and the survival and
readability of the recomputed integrity / recording-health status rows.
"""

from __future__ import annotations

import json
from uuid import uuid5

from app.detection.roi.calibration import COLUMNS as ROI_COLUMNS, decode_history_row
from app.integrity.model import Finding, Kind, State
from app.media.health.service import HealthState, Stage as HealthStage
from app.notifications.service import NotificationKind
from app.monitoring.runtime import EVENT_NAMESPACE

from ._common import _canonical_uuid, _compare_keyed, _int, _keyed, _row_order, _utc_instant


_INTEGRITY_KINDS = ("hardware_integrity_failure", "hardware_integrity_warning")


def _integrity_delivery(connection, tables, salt: str) -> dict | None:
    """Pending hardware-integrity notifications and coalesced overflow.

    Pending outbox rows are kept as keyed digests (findings may name
    hardware). IntegrityStore.deliver() deletes a row only after the
    monitoring bridge durably recorded its notification event, whose ID is
    uuid5(EVENT_NAMESPACE, "integrity-outbox:<row id>"); the integrity event
    IDs are kept so verify can require that acceptance. Overflow slots hold
    only a category and state and leave only by promotion into a new outbox
    row (above the recorded AUTOINCREMENT sequence).
    """
    if not {"integrity_outbox", "integrity_overflow"} <= tables:
        return None
    sequence = (connection.execute(
        "SELECT seq FROM sqlite_sequence WHERE name = 'integrity_outbox'").fetchone()
        if "sqlite_sequence" in tables else None)
    events = {}
    if "notification_events" in tables:
        events = {row[0]: [row[1], row[2]] for row in connection.execute(
            "SELECT event_id, kind, at FROM notification_events WHERE kind IN (?, ?)",
            _INTEGRITY_KINDS)}
    pending = connection.execute(
        "SELECT id, at, immediate, findings FROM integrity_outbox WHERE delivered = 0").fetchall()
    return {
        "pending": {str(row["id"]): _keyed(salt, ["integrity-outbox-v1", row["at"],
                                                  row["immediate"], row["findings"]])
                    for row in pending},
        # Category / state pairs and times only, to match promoted slots.
        "pending_findings": {str(row["id"]): _finding_categories(row["findings"])
                             for row in pending},
        "pending_at": {str(row["id"]): row["at"] for row in pending},
        # The notification kind and time its delivery records, per row.
        "pending_class": {str(row["id"]): [_INTEGRITY_KINDS[0] if row["immediate"]
                                           else _INTEGRITY_KINDS[1], row["at"]]
                          for row in pending},
        "overflow": sorted([row[0], row[1], row[2]] for row in connection.execute(
            "SELECT kind, state, at FROM integrity_overflow")),
        "sequence": 0 if sequence is None else sequence[0],
        "notification_events": events,
    }


def _finding_categories(findings: str) -> list:
    try:
        return sorted([item.get("kind"), item.get("state")] for item in json.loads(findings))
    except (ValueError, TypeError, AttributeError):
        return []


def _integrity_event_id(row_id: int) -> str:
    return str(uuid5(EVENT_NAMESPACE, f"integrity-outbox:{int(row_id)}"))


def _notification_class(slot: tuple) -> tuple | None:
    """The (notification kind, time) a promoted slot's delivered event carries."""
    kind, state, at = slot
    try:
        immediate = Finding(Kind(kind), State(state), "COALESCED_PENDING_WARNING").immediate
    except ValueError:
        return None
    return (_INTEGRITY_KINDS[0] if immediate else _INTEGRITY_KINDS[1], at)


def _promotion_evidence(slot: tuple, row_id: int, current: dict) -> bool:
    """Whether new outbox row ``row_id`` proves the promotion of ``slot``.

    _promote_overflow() writes one row per slot with the slot's time and a
    single finding of its category and state; only a still-pending row shows
    that. Once delivered the row is deleted and leaves only its notification
    event (time and failure / warning kind, no category or state), which an
    unrelated row of the same kind and time would match as well, so it is no
    proof.
    """
    kind, state, at = slot
    key = str(row_id)
    return (key in current["pending"] and current["pending_at"].get(key) == at
            and current["pending_findings"].get(key) == [[kind, state]])


def _compare_integrity_delivery(baseline: dict | None, current: dict | None) -> dict:
    """A pending notification leaves only once its event was durably accepted."""
    # IntegrityStore.deliver() parses each pending row's time and promotion
    # copies a slot's time into one: both must be in the store's format.
    invalid = [] if not current else (
        [{"id": f"pending:{row_id}", "reason": "invalid_time"}
         for row_id, at in sorted(current["pending_at"].items()) if _utc_instant(at) is None]
        + [{"id": f"overflow:{kind}:{state}", "reason": "invalid_time"}
           for kind, state, at in current["overflow"] if _utc_instant(at) is None])
    if invalid:
        return {"status": "failed", "failed": invalid}
    if not baseline or not (baseline["pending"] or baseline["overflow"]):
        return {"status": "empty", "failed": []}
    current = current or {"pending": {}, "pending_findings": {}, "pending_at": {},
                          "overflow": [], "sequence": 0, "notification_events": {}}
    accepted = current["notification_events"]
    failed = []
    expected = baseline.get("pending_class") or {}
    for row_id, digest in baseline["pending"].items():
        if row_id in current["pending"]:
            if current["pending"][row_id] != digest:
                failed.append({"id": f"pending:{row_id}", "reason": "changed"})
        elif _integrity_event_id(int(row_id)) not in accepted:
            failed.append({"id": f"pending:{row_id}", "reason": "missing"})
        elif row_id not in expected:
            failed.append({"id": f"pending:{row_id}", "reason": "unverifiable"})
        elif accepted[_integrity_event_id(int(row_id))] != expected[row_id]:
            # _integrity_sink() records the row's failure / warning kind
            # (from its immediate flag) at the row's own time.
            failed.append({"id": f"pending:{row_id}", "reason": "changed"})
    # Each removed slot needs its own new, still-pending outbox row (created
    # after the recorded AUTOINCREMENT sequence), every row consumed at most
    # once: a maximum bipartite matching between slots and evidencing rows.
    remaining = {tuple(item) for item in current["overflow"]}
    removed = [tuple(item) for item in baseline["overflow"] if tuple(item) not in remaining]
    new_ids = range(baseline["sequence"] + 1, current["sequence"] + 1)
    candidates = [[row_id for row_id in new_ids if _promotion_evidence(slot, row_id, current)]
                  for slot in removed]
    # Delivered new rows leave only (kind, time): such a row may be the
    # slot's promotion but cannot prove it, so that slot is unverifiable.
    delivered = {tuple(accepted[_integrity_event_id(row_id)]) for row_id in new_ids
                 if str(row_id) not in current["pending"]
                 and _integrity_event_id(row_id) in accepted}
    owner = {}

    def assign(index, seen):
        for row_id in candidates[index]:
            if row_id in seen:
                continue
            seen.add(row_id)
            if row_id not in owner or assign(owner[row_id], seen):
                owner[row_id] = index
                return True
        return False
    for index, slot in enumerate(removed):
        if not assign(index, set()):
            kind, state, _ = slot
            reason = "unverifiable" if _notification_class(slot) in delivered else "missing"
            failed.append({"id": f"overflow:{kind}:{state}", "reason": reason})
    return {"status": "failed" if failed else "preserved", "failed": failed}


def _integrity_baseline(connection, tables, salt: str) -> dict | None:
    """The Owner-approved hardware baseline as its revision and a keyed digest.

    The inventory text holds hardware identifiers, so only a keyed digest of
    it is kept.
    """
    if "integrity_baseline" not in tables:
        return None
    row = connection.execute(
        "SELECT revision, inventory FROM integrity_baseline WHERE singleton = 1").fetchone()
    if row is None:
        return {"approved": False}
    return {"approved": True, "revision": row["revision"],
            "inventory_digest": _keyed(salt, ["integrity-baseline-v1", row["inventory"]])}


def _notification_events(connection, tables) -> dict | None:
    """The local fault / notification history, every kind (#132).

    NotificationEventStore.upsert() writes kind, time and confirmed flag
    once and later rewrites only the delivery result and accepted_at
    (DECLARED_MUTABLE);
    expire() removes rows older than the shared 90-day retention. The daily
    summary counts these rows, and the deterministic event IDs deduplicate
    redelivery, so a lost row hides a fault and may repeat an alert.
    """
    if "notification_events" not in tables:
        return None
    return {str(row[0]): [row[1], row[2], row[3]] for row in connection.execute(
        "SELECT event_id, kind, at, confirmed FROM notification_events")}


_STATUS_TABLES = ("integrity_status", "recording_health_status")


def _status_rows(connection, tables) -> dict:
    """Whether each recomputed status singleton exists (#132).

    Their values are recomputed at startup and daily (DECLARED_MUTABLE); no
    service deletes the row, so one present at record time stays.
    """
    return {name: (None if name not in tables else connection.execute(
        f"SELECT COUNT(*) FROM {name} WHERE singleton = 1").fetchone()[0] == 1)
        for name in _STATUS_TABLES}


_NOTIFICATION_KINDS = frozenset(item.value for item in NotificationKind)


def _status_domain_errors(connection, tables) -> list:
    """The #132 tables' values, as their services write and read them back.

    - recording_source_discontinuities: RecordingStore._publish() writes a
      source UUID, the cursor end and the new segment start (a zero-length
      marker for a stream change without a time gap) and the one reason
      ``stream_discontinuity``;
    - roi_calibration_history: CalibrationArchive.append() admits only the
      next version under the identifier of the first one, so every source /
      profile holds versions 1..n under one identifier, and every row must
      read back through decode_history_row(), the function
      CalibrationArchive.load() uses (decodable metadata whose embedded
      source / profile / version / identifier is the row key);
    - notification_events: NotificationEventStore.get() parses the event
      UUID, the kind and the time (written as UTC ISO text, which
      count_since() and expire() compare as text);
    - integrity_status / recording_health_status: what IntegrityStore.latest()
      and RecordingHealthStatusStore.latest() parse, and delivery_blocked
      set exactly while an overflow slot exists (IntegrityStore.record() and
      _promote_overflow() derive it so). A status row lost since the record
      is reported by status_rows.
    """
    errors = []

    def rows(table, sql):
        return connection.execute(sql).fetchall() if table in tables else ()

    def bad(section, item):
        errors.append([section, item, "invalid_value"])
    for row in rows("recording_source_discontinuities",
                    "SELECT source_id, start_ms, end_ms, reason "
                    "FROM recording_source_discontinuities"):
        if not (_canonical_uuid(row[0]) and _int(row[1]) and _int(row[2])
                and row[1] <= row[2] and row[3] == "stream_discontinuity"):
            bad("recording_source_discontinuities", f"marker:{row[0]}:{row[1]}:{row[2]}")
    histories: dict = {}
    for row in rows("roi_calibration_history",
                    f"SELECT {', '.join(ROI_COLUMNS)} FROM roi_calibration_history"):
        histories.setdefault((str(row[0]), str(row[1])), []).append((row[2], row[3]))
        try:
            decode_history_row(row)
        except Exception:
            bad("roi_calibration_history", f"{row[0]}/{row[1]}/{row[2]}")
    for (source, profile), versions in sorted(histories.items()):
        numbers = sorted((item[0] for item in versions), key=_row_order)
        if (not (_canonical_uuid(source) and _canonical_uuid(profile))
                or numbers != list(range(1, len(versions) + 1))
                or len({_row_order(item[1]) for item in versions}) != 1
                or not _canonical_uuid(versions[0][1])):
            bad("roi_calibration_history", f"{source}/{profile}")
    for row in rows("notification_events",
                    "SELECT event_id, kind, at FROM notification_events"):
        if not (_canonical_uuid(row[0]) and row[1] in _NOTIFICATION_KINDS
                and _utc_instant(row[2]) is not None):
            bad("notification_events", str(row[0]))
    overflow = bool(rows("integrity_overflow", "SELECT 1 FROM integrity_overflow LIMIT 1"))
    status = rows("integrity_status",
                  "SELECT at, findings, delivery_blocked FROM integrity_status")
    if "integrity_status" in tables:
        for row in status:
            try:
                [Finding(Kind(item["kind"]), State(item["state"]), item["reason"])
                 for item in json.loads(row[1])]
                valid = (_utc_instant(row[0]) is not None and row[2] in (0, 1)
                         and row[2] == int(overflow))
            except Exception:
                valid = False
            if not valid:
                bad("status_rows", "integrity_status")
    for row in rows("recording_health_status",
                    "SELECT at, state, stages FROM recording_health_status"):
        try:
            HealthState(row[1])
            stages = json.loads(row[2])
            valid = (_utc_instant(row[0]) is not None and isinstance(stages, list)
                     and all(isinstance(stage, str) and HealthStage(stage) for stage in stages))
        except Exception:
            valid = False
        if not valid:
            bad("status_rows", "recording_health_status")
    return errors


def _compare_notification_events(baseline: dict | None, current: dict | None,
                                 cutoff: str) -> dict:
    """Kind, time and confirmed flag never change; a row leaves only by
    NotificationEventStore.expire(), which deletes ``at`` older than the
    90-day retention compared as text (``cutoff``, at verify time)."""
    result = _compare_keyed(baseline, current)
    if result["status"] == "empty":
        result["retention_expired"] = []
        return result
    if current is None:
        result["failed"].append({"id": None, "reason": "table_missing"})
    failed, expired = [], []
    for entry in result["failed"]:
        recorded = (baseline or {}).get(entry["id"])
        if (entry["reason"] == "missing" and current is not None
                and isinstance(recorded, list) and len(recorded) == 3
                and isinstance(recorded[1], str) and recorded[1] < cutoff):
            expired.append(entry["id"])
        else:
            failed.append(entry)
    result.update(status="failed" if failed else "preserved", failed=failed,
                  retention_expired=sorted(expired))
    return result


def _compare_status_rows(baseline: dict | None, current: dict | None) -> dict:
    """A recomputed status row recorded present still exists (its values are
    DECLARED_MUTABLE); a missing table is a table_missing failure."""
    recorded = [name for name, present in sorted((baseline or {}).items()) if present]
    if not recorded:
        return {"status": "empty", "failed": [], "preserved": []}
    current = current or {}
    failed = [{"id": name, "reason": "table_missing" if current.get(name) is None
               else "missing"} for name in recorded if current.get(name) is not True]
    return {"status": "failed" if failed else "preserved", "failed": failed,
            "preserved": [name for name in recorded if current.get(name) is True]}
