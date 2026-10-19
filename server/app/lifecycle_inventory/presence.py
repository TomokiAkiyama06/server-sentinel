"""PresenceService section of the lifecycle inventory (#47, split in #256).

The open presence timeline gap (which may only grow) and the durable
presence state, compared under the transitions PresenceService performs:
tombstones, unresolved markers, observations as keyed digests, delivery
jobs, source facts, clocks, outbox sessions and the Owner override.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from app.presence.delivery import ActionResult
from app.presence.models import InvalidObservation, timestamp as presence_timestamp
from app.presence.service import PresenceService

from ._common import _keyed


_GAP_COUNTS = ("refused", "rejected", "lost", "interrupted")


def _timeline_gap(connection, tables) -> dict | None:
    """The durable presence timeline-loss record (no observation content).

    PresenceService keeps one open gap until the Owner clears it (audited);
    it never clears automatically. The other durable presence state is in
    _presence().
    """
    if "presence_timeline_gap" not in tables:
        return None
    row = connection.execute(
        "SELECT since, latest, refused, rejected, lost, interrupted "
        "FROM presence_timeline_gap WHERE singleton = 1").fetchone()
    return {"open": False} if row is None else {"open": True, **dict(row)}


def _compare_timeline_gap(baseline: dict | None, current: dict | None) -> dict:
    """A recorded gap may only grow; losing or shrinking it hides timeline loss."""
    if current and current.get("open") and (
            _presence_instant(current.get("since")) is None
            or _presence_instant(current.get("latest")) is None):
        return {"status": "failed", "failed": [{"id": "gap", "reason": "invalid_time"}],
                "appended": []}
    if not baseline or not baseline.get("open"):
        return {"status": "empty", "failed": [],
                "appended": ["gap"] if current and current.get("open") else []}
    current = current or {"open": False}
    if not current.get("open"):
        failed = [{"id": "gap", "reason": "missing"}]
    elif (current["since"] != baseline["since"]
          or _presence_instant(current["latest"]) is None
          or _presence_instant(baseline["latest"]) is None
          or _presence_instant(current["latest"]) < _presence_instant(baseline["latest"])
          or any(current[key] < baseline[key] for key in _GAP_COUNTS)):
        failed = [{"id": "gap", "reason": "changed"}]
    else:
        failed = []
    return {"status": "failed" if failed else "preserved", "failed": failed,
            "preserved": [] if failed else ["gap"]}


def _presence(connection, tables, salt: str, live_outbox: bool | None) -> dict:
    """Durable presence state whose loss replays, duplicates or hides work.

    - completed-event tombstones (a delayed replay of a completed critical
      event stays a duplicate) and expired-unresolved markers (evidence /
      notification stays unavailable after its payload expired);
    - retained observations (keyed digest of kind, source, receipt time and
      payload; never the content), their delivery jobs and source-fact
      digests (a restamped replay is checked against them);
    - the high-water clocks (losing one would accept stale or replayed
      observations as trusted);
    - open outbox session rows and whether a live outbox held them at record
      time (``live_outbox``, the service's own committed-lock probe): a held
      row may end in a clean close, a stale one only in an interrupted gap;
    - the Owner override.

    Not inventoried: presence_inputs (live inputs with their own validity
    windows) and presence_delivery_fairness (the round-robin cursor between
    delivery classes); losing them replays nothing and hides no failure.
    """
    def rows(table, sql):
        return connection.execute(sql).fetchall() if table in tables else None

    def keyed_rows(table, sql, key, value):
        found = rows(table, sql)
        return None if found is None else {key(row): value(row) for row in found}
    clocks = {}
    for table, prefix in (("presence_clock", "observation"), ("presence_control_clock", "control")):
        found = rows(table, f"SELECT latest FROM {table}")
        if found:
            clocks[prefix] = found[0][0]
    for table, prefix in (("presence_source_clock", "source"),
                          ("presence_critical_source_clock", "critical_source")):
        for row in rows(table, f"SELECT source, latest_occurred FROM {table}") or ():
            clocks[f"{prefix}:{row[0]}"] = row[1]
    override = rows("presence_override",
                    "SELECT state, actor, started, expires FROM presence_override")
    return {
        "completed_events": keyed_rows(
            "presence_completed_events", "SELECT id, expired_at FROM presence_completed_events",
            lambda row: row[0], lambda row: row[1]),
        "expired_unresolved": keyed_rows(
            "presence_expired_unresolved",
            "SELECT action, events, since FROM presence_expired_unresolved",
            lambda row: row[0], lambda row: {"events": row[1], "since": row[2]}),
        "observations": keyed_rows(
            "presence_observations",
            "SELECT id, kind, source, received, payload FROM presence_observations",
            lambda row: row[0],
            lambda row: _keyed(salt, ["presence-observation-v1", *tuple(row)[1:]])),
        # The main-host receipt time timeline retention compares (not
        # secret, like the audit row times), so verification can tell an
        # observation expire_history() removed from one that was lost.
        "observation_received": keyed_rows(
            "presence_observations", "SELECT id, received FROM presence_observations",
            lambda row: row[0], lambda row: row[1]),
        # Observations the Owner released (clear_unresolved_critical_event()
        # appends this audit row in the same transaction).
        "cleared_events": None if "presence_audit" not in tables else sorted(
            [row[0], row[1], row[2], _keyed(salt, ["presence-actor-v1", row[3]])]
            for row in connection.execute(
                "SELECT target, at, state, actor FROM presence_audit "
                "WHERE action='critical_event_cleared'") if _presence_clear_row(row)),
        # Owner principals (keyed), the identities PresenceService._owner()
        # audits for an Owner-only action.
        "owner_actors": None if "access_principals" not in tables else sorted(
            _keyed(salt, ["presence-actor-v1", row[0]]) for row in connection.execute(
                "SELECT id FROM access_principals WHERE role='owner' "
                "AND revoked_at_us IS NULL")),
        "deliveries": keyed_rows(
            "presence_deliveries",
            "SELECT observation, action, state, attempts, generation, requeued "
            "FROM presence_deliveries",
            lambda row: f"{row[0]}:{row[1]}",
            lambda row: {"observation": row[0], "state": row[2], "attempts": row[3],
                         "generation": row[4], "requeued": bool(row[5])}),
        "source_facts": keyed_rows(
            "presence_source_facts", "SELECT id, digest FROM presence_source_facts",
            lambda row: row[0], lambda row: _keyed(salt, ["presence-source-fact-v1", row[1]])),
        "clocks": clocks,
        "outbox_sessions": None if "presence_outbox_sessions" not in tables else sorted(
            _keyed(salt, ["presence-outbox-session-v1", row[0]])
            for row in rows("presence_outbox_sessions",
                            "SELECT token FROM presence_outbox_sessions")),
        "outbox_live": live_outbox,
        "override": None if not override else dict(override[0]),
    }


# PresenceService queues and accepts only these delivery actions.
_PRESENCE_ACTIONS = frozenset({"evidence", "notification"})


def _presence_instant(value):
    """A presence time as PresenceService writes it (models.timestamp():
    UTC, microseconds), parsed; None for anything else, so evidence is
    compared as instants and never as differently formatted text."""
    try:
        moment = datetime.fromisoformat(value)
        return moment if presence_timestamp(moment) == value else None
    except (TypeError, ValueError, AttributeError, InvalidObservation):
        return None


def _presence_clear_row(row) -> bool:
    """Whether a clear audit row has the shape the service writes.

    PresenceService writes presence_audit itself (no separate record type):
    target is str(identifier) of a UUID, at is timestamp(now) (aware ISO
    time), actor is the Owner UUID string from _owner().
    """
    target, at, _, actor = tuple(row)
    try:
        return (str(UUID(target)) == target and str(UUID(actor)) == actor
                and _presence_instant(at) is not None)
    except (TypeError, ValueError, AttributeError):
        return False


def _outbox_live(database: Path) -> bool | None:
    """PresenceService's read-only committed-session probe for this database.

    True when a live outbox holds a committed session; False or None (no
    proof) otherwise. It opens the lock file read-only and never creates it.
    """
    probe = SimpleNamespace(database=SimpleNamespace(path=database))
    return PresenceService._committed_session_held(probe)


_DELIVERY_RESULTS = frozenset(item.value for item in ActionResult)


def _delivery_advanced(before: dict, after: dict) -> bool:
    """Whether a delivery job moved only as PresenceService moves it.

    'delivered' is final; attempts and generation never fall and an Owner
    requeue mark never clears. A claim ('submitting') increments both; a
    return to 'pending' from any other state is only the audited Owner
    requeue, which sets the mark and advances the generation; any other
    state is a recorded outcome of an attempt. Attempts rise only with a
    claim, which also advances the generation, so they never rise by more
    than the generation; a generation rising by more than the attempts
    means a requeue, so the mark is set.
    """
    if after == before:
        return True
    if (before["state"] == "delivered" or after["observation"] != before["observation"]
            or after["attempts"] < before["attempts"]
            or after["generation"] < before["generation"]
            or before["requeued"] > after["requeued"]):
        return False
    # A claim adds one attempt and one generation together; the Owner
    # requeue adds a generation alone and sets the sticky requeue mark.
    claims_or_requeues = after["generation"] - before["generation"]
    attempts = after["attempts"] - before["attempts"]
    if attempts > claims_or_requeues or (claims_or_requeues > attempts
                                         and not after["requeued"]):
        return False
    if after["state"] == "submitting":
        return (after["attempts"] > before["attempts"]
                and after["generation"] > before["generation"])
    if after["state"] == "pending":
        # Unchanged rows returned above; a pending job that moved must have
        # passed through the audited Owner requeue.
        return after["requeued"] and after["generation"] > before["generation"]
    return after["state"] in _DELIVERY_RESULTS


def _compare_presence(baseline: dict | None, current: dict | None,
                      gap_before: dict | None, gap_now: dict | None,
                      expiry: dict | None = None) -> dict:
    """Allow only the transitions PresenceService itself performs.

    ``expiry`` holds the timeline retention cutoffs at verify time
    (``recording`` and ``audit`` instants, see `_retention_rules`). Since Main
    schedules `PresenceService.expire_history()` for its scene timeline
    (Issue #205, Codex PR #296), a recorded observation may leave through it
    too: received before the audit horizon, or before the recording cutoff
    with every recorded delivery job finished (delivered or disabled). Its
    jobs and source fact go with it, a recorded job leaves its tombstone, and
    every recorded job not delivered adds one expired-unresolved event. A job
    finished after the record but before expiry is judged as recorded and
    fails closed, as does a baseline without recorded receipt times. The
    cutoffs come from the verifier's own clock, never the service's: Main
    expires only while its clock is trusted, and a removal of anything younger
    than these cutoffs (as a future-skewed service clock would cause) stays
    `missing`.
    """
    baseline, current = baseline or {}, current or {}
    failed = []

    def fail(name, key, reason="changed"):
        failed.append({"id": f"{name}:{key}", "reason": reason})
    # Every time the service will compare again must be in its own format,
    # recorded or new (an unparsable control clock would make
    # _control_trust() refuse every Owner control operation).
    for key, value in sorted((current.get("clocks") or {}).items()):
        if _presence_instant(value) is None:
            fail("clocks", key, "invalid_time")
    for key, value in sorted((current.get("completed_events") or {}).items()):
        if _presence_instant(value) is None:
            fail("completed_events", key, "invalid_time")
    for key, value in sorted((current.get("expired_unresolved") or {}).items()):
        if _presence_instant(value["since"]) is None:
            fail("expired_unresolved", key, "invalid_time")
    override_now = current.get("override")
    if override_now and (_presence_instant(override_now.get("started")) is None
                         or (override_now.get("expires") is not None
                             and _presence_instant(override_now["expires"]) is None)):
        fail("override", "owner", "invalid_time")
    completed = current.get("completed_events") or {}
    for key, value in (baseline.get("completed_events") or {}).items():
        if completed.get(key) != value:
            fail("completed_events", key, "missing" if key not in completed else "changed")
    expired = current.get("expired_unresolved") or {}
    for key, value in (baseline.get("expired_unresolved") or {}).items():
        now = expired.get(key)
        if now is None:
            fail("expired_unresolved", key, "missing")
        elif now["since"] != value["since"] or now["events"] < value["events"]:
            fail("expired_unresolved", key)
    # An observation (with its jobs and source fact) leaves only through the
    # Owner's audited clear_unresolved_critical_event(), listed as released,
    # or through PresenceService.expire_history() past its retention, listed
    # as expired (see ``expiry`` above).
    observations = current.get("observations") or {}
    recorded_jobs: dict = {}
    for job in (baseline.get("deliveries") or {}).values():
        recorded_jobs.setdefault(job["observation"], []).append(job["state"])
    # clear_unresolved_critical_event() appends ('critical_event_cleared',
    # actor, at=now, state NULL, target=id) in the transaction that writes
    # the tombstone (expired_at=now): one clear row per target, new since
    # the record.
    def clears(section):
        found: dict = {}
        for target, at, state, actor in (section.get("cleared_events") or ()):
            found.setdefault(target, []).append((at, state, actor))
        return found
    cleared_before, cleared_now = clears(baseline), clears(current)
    # The clearing actor is an Owner (at record or verify time), and the
    # control clock the clear advanced to its time has not moved back.
    owners = set(baseline.get("owner_actors") or ()) | set(current.get("owner_actors") or ())
    control_at = _presence_instant((current.get("clocks") or {}).get("control"))
    path = {}
    received = baseline.get("observation_received") or {}
    for key, value in (baseline.get("observations") or {}).items():
        if key in observations:
            if observations[key] != value:
                fail("observations", key)
            continue
        jobs = recorded_jobs.get(key, [])
        unfinished = [state for state in jobs if state not in ("delivered", "disabled")]
        at = _presence_instant(received.get(key))
        if (expiry is not None and at is not None and key not in cleared_now
                and (at < expiry["audit"] or (at < expiry["recording"] and not unfinished))
                and (not jobs or _presence_instant(completed.get(key)) is not None)):
            path[key] = "expired"
            continue
        # Owner release: at least one unfinished job (its precondition), a
        # single new clear row naming it, and the tombstone it wrote then.
        rows = cleared_now.get(key, [])
        if (key not in cleared_before and len(rows) == 1 and rows[0][1] is None
                and rows[0][2] in owners and control_at is not None
                and control_at >= _presence_instant(rows[0][0])
                and unfinished and completed.get(key) == rows[0][0]):
            path[key] = "released"
            continue
        fail("observations", key, "missing")
    # An observation recorded after the baseline and released inside the
    # window: the same single valid clear row, tombstone and clock; its jobs
    # were never recorded, so only bounds apply to its events below.
    recorded_observations = baseline.get("observations") or {}
    late_released = 0
    for key, rows in sorted(cleared_now.items()):
        if (key in recorded_observations or key in observations or key in cleared_before
                or len(rows) != 1 or rows[0][1] is not None or rows[0][2] not in owners
                or control_at is None or control_at < _presence_instant(rows[0][0])
                or completed.get(key) != rows[0][0]):
            continue
        path[key] = "released"
        late_released += 1
    deliveries = current.get("deliveries") or {}
    # The Owner release adds one expired-unresolved event per removed job
    # neither delivered nor disabled at clear time, in the transaction that
    # writes the tombstone. Those states are judged as recorded: a job of a
    # released observation delivered inside the window before the clear
    # leaves fewer events than counted here and fails closed.
    # A job leaves only with its released observation (the release deletes
    # every job of it, delivered ones included).
    needed: Counter = Counter()
    for key, job in (baseline.get("deliveries") or {}).items():
        if key not in deliveries:
            if job["observation"] not in path:
                fail("deliveries", key, "missing")
            elif path[job["observation"]] == "expired":
                # expire_history() counts every job not delivered, a
                # disabled one included.
                if job["state"] != "delivered":
                    needed[key.rsplit(":", 1)[1]] += 1
            elif job["state"] not in ("delivered", "disabled"):
                needed[key.rsplit(":", 1)[1]] += 1
        elif job["observation"] in path:
            # The release deletes all jobs of the observation atomically.
            fail("deliveries", key, "retained")
        elif not _delivery_advanced(job, deliveries[key]):
            fail("deliveries", key)
    # No job, recorded or new, may point at an observation that is gone,
    # and jobs and unresolved markers name only the service's actions.
    for key, job in sorted(deliveries.items()):
        if job["observation"] not in observations:
            fail("deliveries", key, "orphaned")
        if key.rsplit(":", 1)[1] not in _PRESENCE_ACTIONS:
            fail("deliveries", key, "unknown_action")
    for action in sorted(expired):
        if action not in _PRESENCE_ACTIONS:
            fail("expired_unresolved", action, "unknown_action")
    # Tombstones and expired-unresolved events appear only through releases:
    # no tombstone for anything else, and each action's events rise by
    # exactly the released jobs neither delivered nor disabled.
    for key in sorted(set(completed) - set(baseline.get("completed_events") or {})):
        if key not in path:
            fail("completed_events", key, "unexplained")
    # Each observation created since the record and released adds at least
    # one event (its release needs an unfinished job) and at most one per
    # action (one job per action: evidence, notification).
    recorded = baseline.get("expired_unresolved") or {}
    extra_total = 0
    for action in sorted(set(recorded) | set(expired) | set(needed)):
        added = ((expired.get(action) or {}).get("events", 0)
                 - (recorded.get(action) or {}).get("events", 0))
        if action in recorded and action not in expired:
            continue  # reported missing above
        if not needed[action] <= added <= needed[action] + late_released:
            fail("expired_unresolved", action, "unexplained")
        extra_total += max(0, added - needed[action])
    if extra_total < late_released:
        failed.append({"id": "expired_unresolved", "reason": "unexplained"})
    # A source fact is written with its observation and deleted with it.
    facts = current.get("source_facts") or {}
    for key, value in (baseline.get("source_facts") or {}).items():
        if key in facts:
            if key in path:
                fail("source_facts", key, "retained")
            elif facts[key] != value:
                fail("source_facts", key)
        elif key in observations:
            fail("source_facts", key, "missing")
    for key in sorted(facts):
        if key not in observations and key not in path:
            fail("source_facts", key, "orphaned")
    clocks = current.get("clocks") or {}
    for key, value in (baseline.get("clocks") or {}).items():
        if key not in clocks:
            fail("clocks", key, "missing")
        elif (_presence_instant(clocks[key]) is None or _presence_instant(value) is None
              or _presence_instant(clocks[key]) < _presence_instant(value)):
            fail("clocks", key, "changed")
    # A row a live outbox held may end in its clean close; a stale row is
    # consumed only by converting it into an interrupted timeline gap.
    removed = set(baseline.get("outbox_sessions") or ()) - set(current.get("outbox_sessions") or ())
    if removed and baseline.get("outbox_live") is not True:
        before = (gap_before or {}).get("interrupted", 0) if (gap_before or {}).get("open") else 0
        after = (gap_now or {}).get("interrupted", 0) if (gap_now or {}).get("open") else 0
        if after - before < len(removed):
            fail("outbox_sessions", len(removed), "missing")
    # _retire_override() drops an Owner override only once the control clock
    # (advanced in the same transaction) has reached its expiry.
    override = baseline.get("override")
    if override and current.get("override") != override:
        expires, control_now = (_presence_instant(override["expires"]),
                                _presence_instant(clocks.get("control")))
        expired_out = (current.get("override") is None and expires is not None
                       and control_now is not None and expires <= control_now)
        if not expired_out:
            fail("override", "owner")
    has_rows = any(baseline.get(name) for name in (
        "completed_events", "expired_unresolved", "observations", "deliveries",
        "source_facts", "clocks", "outbox_sessions", "override"))
    status = "failed" if failed else ("preserved" if has_rows else "empty")
    return {"status": status, "failed": failed,
            "released": sorted(key for key, how in path.items() if how == "released"),
            "retention_expired": sorted(key for key, how in path.items() if how == "expired")}


_PRESENCE_AUDIT_ACTIONS = frozenset({
    "critical_action_requeued", "critical_degradation_cleared", "critical_event_cleared",
    "hint_set", "override_cancelled", "override_expired", "override_set",
    "timeline_gap_cleared"})
_DELIVERY_STATES = frozenset({"pending", "submitting"}) | _DELIVERY_RESULTS
