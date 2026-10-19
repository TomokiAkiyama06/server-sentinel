"""Audit-chain section of the lifecycle inventory (#47, split in #256).

A per-row and a chained SHA-256 over every retained audit row, and the
comparison that accepts only the owning service's retention (and the
rowid allocator's reuse of a retained-out ID) as a removal.
"""

from __future__ import annotations

from datetime import datetime
import hashlib

from ._common import _digest


CHAIN_SEED = hashlib.sha256(b"server-sentinel-lifecycle-audit-chain-v1").hexdigest()


def _chain(rows: list[tuple[str, str]]) -> str:
    chain = CHAIN_SEED
    for row_id, row_digest in rows:
        chain = hashlib.sha256(f"{chain}:{row_id}:{row_digest}".encode()).hexdigest()
    return chain


def _audit_table(connection, tables, table, columns, order, time_column=None) -> dict | None:
    if table not in tables:
        return None
    rows = connection.execute(
        f"SELECT {', '.join(columns)} FROM {table} ORDER BY {order}").fetchall()
    digests = [(str(row[0]), _digest([table, *tuple(row)])) for row in rows]
    result = {"rows": [[row_id, digest] for row_id, digest in digests],
              "chain_sha256": _chain(digests)}
    if time_column is not None:
        # The row time the service's retention compares (not secret).
        result["times"] = {str(row[0]): row[time_column] for row in rows}
    return result


def _audit(connection, tables) -> dict:
    return {
        "security_admin": _audit_table(
            connection, tables, "security_admin_audit_records",
            ("id", "actor_category", "action", "target_kind", "target_logical_id",
             "occurred_at_us", "outcome"), "occurred_at_us, id", "occurred_at_us"),
        "integrity": _audit_table(
            connection, tables, "integrity_audit", ("id", "at", "actor", "revision"), "id",
            "at"),
        "presence": _audit_table(
            connection, tables, "presence_audit",
            ("sequence", "action", "actor", "at", "state", "target"), "sequence", "at"),
        "storage_state": _audit_table(
            connection, tables, "storage_state_audit",
            ("id", "at_ms", "previous_state", "current_state"), "id", "at_ms"),
    }


def _compare_audit(baseline: dict | None, current: dict | None, expired=None,
                   fresh=None) -> dict:
    """Audit rows stay identical, except rows the service's retention removed.

    ``expired`` judges a recorded row's time against the service's retention
    rule at verify time; a missing row it accepts is listed under
    ``retention_expired`` and never counted as preserved. Tables keyed by
    INTEGER PRIMARY KEY without AUTOINCREMENT reuse the highest id once
    retention removed it, so a recorded row that retention may have removed
    whose id now holds a row written after the record (``fresh``) is that
    case: the recorded row is retention-expired and the new one appended.
    """
    if baseline is not None and current is None:
        # The table existed at record time and is gone or unreadable now,
        # even if it was empty then.
        return {"status": "failed", "preserved_rows": 0,
                "failed": [{"id": None, "reason": "table_missing"}],
                "appended": [], "chain_match": None, "retention_expired": []}
    if not baseline or not baseline["rows"]:
        return {"status": "empty", "preserved_rows": 0, "failed": [],
                "appended": [row[0] for row in (current or {"rows": []})["rows"]],
                "chain_match": None, "retention_expired": []}
    failed, kept, retained_out = [], [], []
    if current is None:
        # The table itself is gone or unreadable: retention deletes rows,
        # never the table, so nothing counts as retention-expired.
        expired = None
        failed.append({"id": None, "reason": "table_missing"})
    current_rows = dict((row_id, digest) for row_id, digest in (current or {"rows": []})["rows"])
    times = baseline.get("times") or {}
    current_times = (current or {}).get("times") or {}
    reused = []
    for row_id, digest in baseline["rows"]:
        if row_id not in current_rows:
            if expired is not None and row_id in times and expired(times[row_id]):
                retained_out.append(row_id)
            else:
                failed.append({"id": row_id, "reason": "missing"})
        elif current_rows[row_id] != digest:
            if (expired is not None and fresh is not None and row_id in times
                    and expired(times[row_id])):
                reused.append(row_id)
            else:
                failed.append({"id": row_id, "reason": "changed"})
        else:
            kept.append((row_id, digest))
    if reused and not _reuse_consistent(baseline, current_rows, current_times, kept, reused,
                                        expired, fresh):
        failed.extend({"id": row_id, "reason": "changed"} for row_id in reused)
        reused = []
    retained_out.extend(reused)
    # The chain recomputed over the recorded rows must match the record, so
    # a rewritten or reordered baseline row list is refused too.
    chain_match = not failed and _chain(
        [tuple(row) for row in baseline["rows"]]) == baseline["chain_sha256"]
    if not failed and not chain_match:
        failed.append({"id": None, "reason": "chain_mismatch"})
    baseline_ids = {row[0] for row in baseline["rows"]}
    return {"status": "failed" if failed else "preserved",
            "preserved_rows": len(kept),
            "failed": failed,
            "appended": [row_id for row_id in current_rows
                         if row_id not in baseline_ids or row_id in reused],
            "chain_match": chain_match,
            "retention_expired": retained_out}


def _reuse_consistent(baseline, current_rows, current_times, kept, reused,
                      expired, fresh) -> bool:
    """Whether reused ids are exactly what SQLite's rowid allocator gives.

    Without AUTOINCREMENT a new row takes max(rowid) + 1. Retention deletes
    the oldest rows, so an id is freed for reuse only when every row above
    it was removed. With R the highest recorded id still present unchanged,
    every recorded row above R must have been due for removal, and the rows
    now above R must all be new since the record, not themselves due,
    numbered exactly R+1..R+k with times not decreasing in id order. Any
    other arrangement (an interleaving that cannot be told apart included)
    fails closed.
    """
    try:
        remaining = max((int(row_id) for row_id, _ in kept), default=0)
        recorded = {int(row_id): row_id for row_id, _ in baseline["rows"]}
        above = sorted((int(row_id), row_id) for row_id in current_rows if int(row_id) > remaining)
    except (TypeError, ValueError):
        return False
    times = baseline.get("times") or {}
    if any(number > remaining and not expired(times.get(row_id))
           for number, row_id in recorded.items() if row_id not in dict(kept)):
        return False
    if any(int(row_id) <= remaining for row_id in reused):
        return False
    if [number for number, _ in above] != list(range(remaining + 1, remaining + 1 + len(above))):
        return False
    moments = [current_times.get(row_id) for _, row_id in above]
    if not all(value is not None and fresh(value) and not expired(value) for value in moments):
        return False
    try:
        ordered = [datetime.fromisoformat(value) if isinstance(value, str) else value
                   for value in moments]
        return all(earlier <= later for earlier, later in zip(ordered, ordered[1:]))
    except (TypeError, ValueError):
        return False
