"""Deployment-local preservation inventory for update / rollback (Issue #47).

``record`` captures, from a read-only view of the Main Server runtime tree:

- per-recording content evidence keyed by the recording logical ID: a SHA-256,
  size and hard-link count of every linked segment file as stored on disk
  (the recording store serves only single-link files) with the segment's
  source, catalog bounds and the catalog fields that control integrity,
  playback or retention (byte length, stream / sequence, codec, container,
  capture node, critical flag), the starred and critical flags, and the catalog
  start, target end and ended boundaries (the manifest clips playback to the
  target end), the event link and the explicit discontinuity markers;
- a per-row and a chained SHA-256 over every retained audit row
  (``security_admin_audit_records``, ``integrity_audit``, ``presence_audit``
  and ``storage_state_audit``), so a rewritten middle row is detected even
  when counts and boundary timestamps match;
- the open presence timeline gap, which may only grow, and the durable
  presence state (tombstones, unresolved markers, retained observations as
  keyed digests, delivery jobs, source facts, clocks, outbox sessions, the
  Owner override) under the transitions the presence service performs;
- the Owner-approved hardware baseline revision and a keyed inventory digest;
- per registered camera source: type, keyed digests of the Owner-entered
  name and role label, capabilities digest, enabled flag, capture node, digests of
  the desired capture profile and detection bindings, and a keyed digest of
  the durable UVC approval identity (never device facts; volatile health
  excluded); the registry's ``max_active_video_sources``;
- for a configured Owner-template store: whether it exists, its generation,
  keyed digests of the template and provenance (never template bytes or
  embeddings) and its audit rows / chain;
- Owner presence and, per nonidentifying principal / invitation logical ID,
  the independent ``live:view`` / ``recordings:view`` grants, revocation
  state, authorization revision, a keyed digest and the (only rising)
  signature counter per usable (unrevoked and consistent) credential, every
  invitation validity field and a keyed digest of its secret digest.

Keyed digests are HMAC-SHA-256 under a random per-baseline salt stored in the
baseline.

``verify`` recomputes the same inventory and compares it with a recorded one.
Rows or recordings that exist only in the current state are listed as
``appended`` and never counted as preserved. An inventory section that is empty
reports ``empty`` rather than success, so a comparison cannot pass vacuously.

Never written: principal external identities or display names, credential IDs,
public keys or labels, invitation / session secret or token digests, session
identity bindings, permission-bearing URLs, media bytes, or audit row contents (only their digests). Container
duration probing and decodable-playback samples need a codec and are left to
the manual procedure in ``MANUAL_TEST.md`` section V; the output marks them
``manual``. The output file is created exclusively with mode 0600 and is
refused inside the runtime root, the installed package / virtual environment,
the whole installation destination (``<destination>`` of
``<destination>/releases/<version>/venv``, including ``current``), or any Git
checkout. Keep it, including its digests and logical IDs,
deployment-local.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
import sqlite3
import stat
import sys
from urllib.parse import quote
from types import SimpleNamespace
from uuid import UUID, uuid5

from app.cameras.uvc.persistence import ApprovalStore
from app.detection.owner import store as owner_store
from app.integrity.model import Finding, Kind, State
from app.monitoring.runtime import EVENT_NAMESPACE
from app.presence.delivery import ActionResult
from app.presence.service import PresenceService


FORMAT = "server-sentinel-lifecycle-inventory"
FORMAT_VERSION = 1
CHAIN_SEED = hashlib.sha256(b"server-sentinel-lifecycle-audit-chain-v1").hexdigest()
_CHUNK = 1024 * 1024

# Coverage items that must be non-empty before a comparison can be a success.
COVERAGE = (
    "ordinary_recording", "starred_recording", "camera_source", "audit_record",
    "owner", "live_view_only_grant", "recordings_view_only_grant", "revocation",
)
NOT_APPLICABLE = {
    # No capture node exists in the Main-only lifecycle environment; the
    # complete deployment acceptance of Issue #28 verifies these.
    "capture_agent_protected_incidents": "not_applicable (#16 / #28)",
}
# Durable tables this tool does not inventory yet (#132); the report lists
# them so a pass is never read as covering them.
NOT_INVENTORIED = (
    "recording_source_discontinuities", "recording_source_cursors",
    "roi_calibration_history", "notification_events", "uvc_approvals.session_token",
    "integrity_status", "recording_health_status",
)

MANUAL = {
    "container_duration": "manual",
    "decode_verification": "manual",
}

EXIT_PRESERVED = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_EMPTY = 3


class InventoryError(RuntimeError):
    """Refused or failed without echoing deployment paths or stored values."""


@dataclass(frozen=True)
class RuntimeTree:
    root: Path

    @property
    def database(self) -> Path:
        return self.root / "state" / "state.sqlite3"

    @property
    def recordings(self) -> Path:
        return self.root / "recordings"


def _digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _absolute(path: Path, what: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise InventoryError(f"{what} must be an absolute path without '..'")
    return path


def _connect_read_only(database: Path) -> sqlite3.Connection:
    try:
        info = os.lstat(database)
    except OSError:
        raise InventoryError("state database is unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise InventoryError("state database is unavailable")
    try:
        # mode=ro never creates a database or a fallback file; query_only also
        # refuses any statement that would write.
        connection = sqlite3.connect(
            "file:" + quote(str(database)) + "?mode=ro", uri=True,
            timeout=5, isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
    except sqlite3.Error:
        raise InventoryError("state database is unavailable") from None
    return connection


def _file_digest(directory: Path, segment_id: str) -> tuple[str | None, int | None, int | None]:
    """SHA-256, size and hard-link count of a segment file as stored."""
    try:
        name = UUID(segment_id).hex + ".seg"
    except ValueError:
        return None, None, None
    try:
        descriptor = os.open(directory / name,
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY)
    except OSError:
        return None, None, None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, None, None
        digest, size = hashlib.sha256(), 0
        while chunk := os.read(descriptor, _CHUNK):
            digest.update(chunk)
            size += len(chunk)
        return digest.hexdigest(), size, info.st_nlink
    finally:
        os.close(descriptor)


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _recordings(connection, tables) -> dict | None:
    """The recording catalog, read inside the snapshot transaction.

    Segment files are hashed afterwards by _hash_recordings(), outside the
    transaction, so a long hash never blocks service writers.
    """
    if not {"recordings", "recording_links", "recording_segments"} <= tables:
        return None
    result = {}
    rows = connection.execute(
        "SELECT id, source_id, event_id, status, starred, critical, start_ms, target_end_ms, "
        "ended_ms FROM recordings WHERE status != 'deleting' ORDER BY id").fetchall()
    for row in rows:
        segments = connection.execute(
            "SELECT s.id, s.source_id, s.capture_node_id, s.stream_id, s.sequence, "
            "s.start_ms, s.end_ms, s.codec, s.container, s.byte_length, s.sha256, s.critical, "
            "s.state "
            "FROM recording_segments s "
            "JOIN recording_links l ON l.segment_id = s.id "
            # Every linked segment, whatever its state, as manifest() reads
            # them: a hidden non-ready link would later degrade playback.
            "WHERE l.recording_id = ? ORDER BY s.start_ms, s.id",
            (row["id"],)).fetchall()
        items = []
        for segment in segments:
            items.append({
                "segment_id": segment["id"], "state": segment["state"],
                # Filled by _hash_recordings() after the transaction.
                "sha256": None, "bytes": None, "link_count": None, "catalog_match": False,
                "_catalog_sha256": segment["sha256"],
                "source_id": segment["source_id"],
                "start_ms": segment["start_ms"], "end_ms": segment["end_ms"],
                "media_ms": segment["end_ms"] - segment["start_ms"],
                # Catalog fields that control integrity, playback or retention:
                # byte_length (integrity), stream_id / sequence (manifest
                # discontinuities), codec / container (player selection),
                # capture node provenance and the critical retention flag.
                "catalog": {
                    "byte_length": segment["byte_length"],
                    "stream_id": segment["stream_id"], "sequence": segment["sequence"],
                    "codec": segment["codec"], "container": segment["container"],
                    "capture_node_id": segment["capture_node_id"],
                    "critical": bool(segment["critical"]),
                },
            })
        # Explicit gap markers returned by RecordingStore.manifest(); the
        # table has no key, so they are kept as a sorted multiset.
        discontinuities = sorted([item["start_ms"], item["end_ms"], item["reason"]]
                                 for item in connection.execute(
            "SELECT start_ms, end_ms, reason FROM recording_discontinuities "
            "WHERE recording_id = ?", (row["id"],)))
        result[row["id"]] = {
            "source_id": row["source_id"],
            # RecordingStore.event_manifest() groups recordings by event_id.
            "event_id": row["event_id"],
            "status": row["status"],
            "starred": bool(row["starred"]),
            "critical": bool(row["critical"]),
            "start_ms": row["start_ms"],
            # Both boundaries are kept separately: RecordingStore.manifest()
            # clips segments and computes gaps against target_end_ms.
            "target_end_ms": row["target_end_ms"],
            "ended_ms": row["ended_ms"],
            "segment_media_ms": sum(item["media_ms"] for item in items),
            "segments": items,
            "discontinuities": discontinuities,
            "content_sha256": None,
            "container_duration": "manual",
            "decode_verification": "manual",
        }
    return result


def _hash_recordings(recordings: dict | None, directory: Path) -> None:
    """Hash every catalogued segment file, outside any database transaction.

    A ready segment's bytes are immutable, so hashing after the snapshot is
    equivalent; a file changed or removed meanwhile shows up as a change.
    """
    for recording in (recordings or {}).values():
        for item in recording["segments"]:
            digest, size, links = _file_digest(directory, item["segment_id"])
            expected = item.pop("_catalog_sha256")
            # RecordingStore._integrity() needs the digest and the catalog
            # byte_length to match a file with exactly one hard link.
            item.update(sha256=digest, bytes=size, link_count=links,
                        catalog_match=(digest is not None and digest == expected
                                       and size == item["catalog"]["byte_length"]
                                       and links == 1))
        recording["content_sha256"] = _digest(
            [[item["segment_id"], item["sha256"]] for item in recording["segments"]])


def _chain(rows: list[tuple[str, str]]) -> str:
    chain = CHAIN_SEED
    for row_id, row_digest in rows:
        chain = hashlib.sha256(f"{chain}:{row_id}:{row_digest}".encode()).hexdigest()
    return chain


def _audit_table(connection, tables, table, columns, order) -> dict | None:
    if table not in tables:
        return None
    rows = connection.execute(
        f"SELECT {', '.join(columns)} FROM {table} ORDER BY {order}").fetchall()
    digests = [(str(row[0]), _digest([table, *tuple(row)])) for row in rows]
    return {"rows": [[row_id, digest] for row_id, digest in digests],
            "chain_sha256": _chain(digests)}


def _audit(connection, tables) -> dict:
    return {
        "security_admin": _audit_table(
            connection, tables, "security_admin_audit_records",
            ("id", "actor_category", "action", "target_kind", "target_logical_id",
             "occurred_at_us", "outcome"), "occurred_at_us, id"),
        "integrity": _audit_table(
            connection, tables, "integrity_audit", ("id", "at", "actor", "revision"), "id"),
        "presence": _audit_table(
            connection, tables, "presence_audit",
            ("sequence", "action", "actor", "at", "state", "target"), "sequence"),
        "storage_state": _audit_table(
            connection, tables, "storage_state_audit",
            ("id", "at_ms", "previous_state", "current_state"), "id"),
    }


def _keyed(salt: str, value: object) -> str:
    """HMAC-SHA-256 under the per-inventory random salt.

    Used for stable but sensitive material (camera identity, credential
    public material, the Owner template) so the baseline never holds the raw
    value and the digest is no stable cross-file identifier. Whoever holds the
    baseline (and so its salt) can still test a guessed value, so the file
    stays deployment-local.
    """
    message = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)
    return hmac.new(bytes.fromhex(salt), message.encode(), hashlib.sha256).hexdigest()


UNREADABLE_APPROVAL = "unreadable"


def _approval_digest(row, salt: str) -> str:
    """A keyed digest of the durable UVC approval, never the device facts.

    The stored evidence is parsed exactly as ApprovalStore._state() restores
    it (every required key, DeviceEvidence validation), so evidence the
    service could not load raises instead of hashing. The digest covers the
    identity identity.same_physical_camera() compares and the durable latch
    flags: a unique serial binds by its strong key (vendor, product, serial,
    interface), so a new device node or port is the same camera; without a
    serial, or when the serial is ambiguous, only the live instance names the
    camera, so its node, topology, device number and instance marker are
    covered and a swap to another same-model camera is a change. By-id
    aliases, advertised formats and the session token are mutable or
    per-session and excluded.
    """
    state = ApprovalStore._state(
        (row["evidence"], row["requires_approval"], None, row["serial_ambiguous"], 0))
    evidence = state.approved
    identity = (evidence.strong_key
                if evidence.strong_key is not None and not state.serial_ambiguous
                else evidence.live_instance_key)
    return _keyed(salt, ["uvc-approval-v3", list(identity), state.requires_approval,
                         state.serial_ambiguous])


def _sources(connection, tables, salt: str) -> dict | None:
    """Stable operational configuration per source; volatile health is excluded."""
    if "camera_sources" not in tables:
        return None
    approvals = {}
    if "uvc_approvals" in tables:
        for row in connection.execute(
                "SELECT source_id, evidence, requires_approval, serial_ambiguous "
                "FROM uvc_approvals"):
            try:
                approvals[row["source_id"]] = _approval_digest(row, salt)
            except (ValueError, TypeError, KeyError, AttributeError):
                # Never comparable as preserved; see compare().
                approvals[row["source_id"]] = UNREADABLE_APPROVAL
    bindings = {}
    if "detection_bindings" in tables:
        for row in connection.execute(
                "SELECT source_id, binding_id, kind, version, enabled, thresholds, config "
                "FROM detection_bindings ORDER BY source_id, binding_id"):
            bindings.setdefault(row["source_id"], []).append(
                [row["binding_id"], row["kind"], row["version"], bool(row["enabled"]),
                 row["thresholds"], row["config"]])
    return {row["id"]: {
        "source_type": row["source_type"],
        "enabled": bool(row["enabled"]),
        "capture_node_id": row["capture_node_id"],
        # Owner-entered text (name, role label) may name a person or place,
        # so only keyed digests are kept; capabilities (advertised formats,
        # video-only flag, written at Owner approval) are non-identifying.
        "name_digest": _keyed(salt, ["source-name-v1", row["name"]]),
        "role_digest": _keyed(salt, ["source-role-v1", row["role_label"]]),
        "capabilities_sha256": _digest(row["capabilities"]),
        "desired_capture_profile_sha256": _digest(row["desired_capture_profile"]),
        "detection_bindings_sha256": _digest(bindings.get(row["id"], [])),
        "uvc_approval_sha256": approvals.get(row["id"]),
    } for row in connection.execute(
        "SELECT id, source_type, name, role_label, enabled, capture_node_id, capabilities, "
        "desired_capture_profile FROM camera_sources ORDER BY id")}


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
    if not baseline or not baseline.get("open"):
        return {"status": "empty", "failed": [],
                "appended": ["gap"] if current and current.get("open") else []}
    current = current or {"open": False}
    if not current.get("open"):
        failed = [{"id": "gap", "reason": "missing"}]
    elif (current["since"] != baseline["since"] or current["latest"] < baseline["latest"]
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
    state is a recorded outcome of an attempt.
    """
    if after == before:
        return True
    if (before["state"] == "delivered" or after["observation"] != before["observation"]
            or after["attempts"] < before["attempts"]
            or after["generation"] < before["generation"]
            or before["requeued"] > after["requeued"]):
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
                      gap_before: dict | None, gap_now: dict | None) -> dict:
    """Allow only the transitions PresenceService itself performs."""
    baseline, current = baseline or {}, current or {}
    failed = []

    def fail(name, key, reason="changed"):
        failed.append({"id": f"{name}:{key}", "reason": reason})
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
    # Retention and Owner release remove an observation (with its jobs and
    # source fact) only while writing its completed tombstone.
    observations = current.get("observations") or {}
    for key, value in (baseline.get("observations") or {}).items():
        if key in observations:
            if observations[key] != value:
                fail("observations", key)
        elif key not in completed:
            fail("observations", key, "missing")
    deliveries = current.get("deliveries") or {}
    # Retention and the Owner's clear_unresolved_critical_event() both add
    # one expired-unresolved event per removed job that was not delivered,
    # in the same transaction as the tombstone. A job recorded unresolved
    # that is gone must be covered by that increase (one delivered and then
    # expired inside the window is also reported; do not run retention then).
    needed = {}
    for key, job in (baseline.get("deliveries") or {}).items():
        if key not in deliveries:
            if job["observation"] not in completed:
                fail("deliveries", key, "missing")
            elif job["state"] != "delivered":
                action = key.rsplit(":", 1)[1]
                needed.setdefault(action, []).append(key)
        elif not _delivery_advanced(job, deliveries[key]):
            fail("deliveries", key)
    recorded = baseline.get("expired_unresolved") or {}
    for action, keys in needed.items():
        added = ((expired.get(action) or {}).get("events", 0)
                 - (recorded.get(action) or {}).get("events", 0))
        if added < len(keys):
            for key in keys:
                fail("deliveries", key, "missing")
    facts = current.get("source_facts") or {}
    for key, value in (baseline.get("source_facts") or {}).items():
        if key in facts:
            if facts[key] != value:
                fail("source_facts", key)
        elif key in observations:
            fail("source_facts", key, "missing")
    clocks = current.get("clocks") or {}
    for key, value in (baseline.get("clocks") or {}).items():
        if key not in clocks or clocks[key] < value:
            fail("clocks", key, "missing" if key not in clocks else "changed")
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
        expired_out = (current.get("override") is None and override["expires"] is not None
                       and override["expires"] <= clocks.get("control", ""))
        if not expired_out:
            fail("override", "owner")
    has_rows = any(baseline.get(name) for name in (
        "completed_events", "expired_unresolved", "observations", "deliveries",
        "source_facts", "clocks", "outbox_sessions", "override"))
    status = "failed" if failed else ("preserved" if has_rows else "empty")
    return {"status": status, "failed": failed}


def _security_state(connection, tables, salt: str) -> dict:
    """Revocation and invalidation state that must only ever move one way.

    Pairing credentials and capture nodes once revoked stay revoked; pairing
    key bindings are never deleted, rebound or un-revoked (keys as keyed
    digests); an invalidated human session never becomes valid again; the
    access authorization generation never decreases.
    """
    def query(table, sql):
        return connection.execute(sql).fetchall() if table in tables else None
    not_after = ("not_after" if "pairing_node_credentials" in tables
                 and "not_after" in _columns(connection, "pairing_node_credentials")
                 else "NULL AS not_after")
    credentials = query("pairing_node_credentials",
                        "SELECT node_id, state, public_key_digest, credential_serial_digest, "
                        f"{not_after} FROM pairing_node_credentials")
    enrollments = query("pairing_enrollments",
                        "SELECT id, node_id, public_key_digest, state FROM pairing_enrollments "
                        "WHERE state IN ('activated', 'pending', 'consumed')")
    renewals = query("pairing_node_renewals",
                     "SELECT node_id, public_key_digest, credential_serial_digest, not_after "
                     "FROM pairing_node_renewals")

    def material(row):
        # What PairingLedger.admits() authenticates, as keyed digests; the
        # key reference matches the pairing_key_bindings key below.
        return {"material": _keyed(salt, ["pairing-credential-v1", row["public_key_digest"],
                                          row["credential_serial_digest"]]),
                "key_ref": _keyed(salt, ["pairing-key-v1", row["public_key_digest"]]),
                "not_after": row["not_after"]}
    bindings = query("pairing_key_bindings",
                     "SELECT public_key_digest, node_id, revoked FROM pairing_key_bindings")
    nodes = query("capture_nodes", "SELECT id, health_state FROM capture_nodes")
    sessions = query("access_sessions", "SELECT id, invalidated_at_us FROM access_sessions")
    generation = query("access_deployment_state",
                       "SELECT authorization_generation FROM access_deployment_state")
    return {
        "pairing_credentials": None if credentials is None else {
            row["node_id"]: {"revoked": row["state"] == "revoked", **material(row)}
            for row in credentials},
        "pairing_renewals": None if renewals is None else {
            row["node_id"]: material(row) for row in renewals},
        # Activated enrollments (a final state: PairingLedger never deletes
        # or changes them) and open ones (pending / consumed, the only states
        # activate() can still complete): id, node and key binding reference.
        "pairing_activations": None if enrollments is None else sorted(
            [row["id"], row["node_id"], _keyed(salt, ["pairing-key-v1", row["public_key_digest"]])]
            for row in enrollments if row["state"] == "activated"),
        "pairing_enrollments_open": None if enrollments is None else sorted(
            [row["id"], row["node_id"], _keyed(salt, ["pairing-key-v1", row["public_key_digest"]])]
            for row in enrollments if row["state"] != "activated"),
        "pairing_key_bindings": None if bindings is None else {
            _keyed(salt, ["pairing-key-v1", row[0]]): {"node_id": row[1], "revoked": bool(row[2])}
            for row in bindings},
        "capture_nodes_revoked": None if nodes is None else {
            row[0]: row[1] == "revoked" for row in nodes},
        "sessions_invalidated": None if sessions is None else {
            row[0]: row[1] is not None for row in sessions},
        "authorization_generation": generation[0][0] if generation else None,
    }


def _by_enrollment(items) -> bool:
    return items is not None and all(isinstance(item, list) and len(item) == 3 for item in items)


def _compare_pairing(baseline: dict, current: dict) -> list:
    """The capture-node pairing ledger, checked against PairingLedger itself.

    Every mutation of the ledger tables is one of these operations (keys are
    keyed digests here; ``live`` means bound to the node and not revoked):

    - approve(node, key): a new pending enrollment; binds the key live
      (_bind_key() refuses a key bound elsewhere or revoked).
    - redeem(): pending -> consumed, or pending -> expired.
    - activate(claim): consumed -> activated; binds its key live; the node's
      credential becomes (key, serial, not_after) and active (inserted or
      overwritten); any staged renewal is deleted.
    - stage_renewal(node, key): needs an active credential and a key other
      than its own; binds a new key live, or retries the currently staged
      key; writes the single staged row.
    - promotion in admits(): the credential becomes the staged material and
      expiry, the staged key stays live, the staged row is deleted.
    - revoke(node): the active credential -> revoked, pending / consumed
      enrollments -> revoked, the staged row deleted, every binding of the
      node revoked, all in one transaction.

    Nothing deletes an enrollment, a credential or a binding, rebinds a key
    or un-revokes a binding. Hence every current state satisfies:

    - each active credential's key is live for its node;
    - a staged renewal belongs to an active credential, uses another key,
      and that key is live for its node;
    - an open (pending / consumed) enrollment's key is live for its node; an
      activated enrollment's key is bound (perhaps revoked) to its node.

    And per node, record -> verify is a composition of those operations:
    activated enrollments stay; a recorded binding keeps its node and never
    un-revokes, and once any of a node's recorded live bindings, or a binding
    first seen now, is revoked (only revoke() does that) all of the node's
    recorded bindings are; a revoked credential stays
    revoked with the same material; an active one stays, becomes the staged
    renewal (promotion) or an identity a post-record activation installed,
    and may then be revoked, in which case its recorded bindings and its key
    are revoked and nothing is staged; a staged row stays exactly, is retried
    with its own key while the credential is unchanged, is replaced by a key
    newly bound since the record, or leaves by promotion, revocation or a
    fresh pairing. A credential first seen now needs a post-record activation
    of its key.
    """
    failed = []

    def fail(table, key, reason):
        failed.append({"id": f"{table}:{key}", "reason": reason})
    bindings = current.get("pairing_key_bindings") or {}
    credentials = current.get("pairing_credentials") or {}
    renewals = current.get("pairing_renewals") or {}
    recorded_credentials = baseline.get("pairing_credentials") or {}
    staged = baseline.get("pairing_renewals") or {}
    # None when the baseline could not see the bindings: then no key counts
    # as newly bound since the record (fail closed).
    recorded_bindings = baseline.get("pairing_key_bindings")
    recorded_activations = baseline.get("pairing_activations")
    recorded_open = baseline.get("pairing_enrollments_open")
    activations_now = current.get("pairing_activations") or ()
    open_now = current.get("pairing_enrollments_open") or ()

    def live(node, key_ref):
        binding = bindings.get(key_ref) or {}
        return binding.get("node_id") == node and binding.get("revoked") is False

    def newly_bound(key_ref):
        return recorded_bindings is not None and key_ref not in recorded_bindings

    # -- invariants of every current state --------------------------------
    for node, after in sorted(credentials.items()):
        if not after["revoked"] and not live(node, after["key_ref"]):
            fail("pairing_credentials", node, "unbound")
    for node, renewal in sorted(renewals.items()):
        owner = credentials.get(node)
        if (owner is None or owner["revoked"] or owner["key_ref"] == renewal["key_ref"]
                or not live(node, renewal["key_ref"])):
            fail("pairing_renewals", node, "unbound")
    if _by_enrollment(open_now) and _by_enrollment(activations_now):
        for enrollment, node, key_ref in open_now:
            if not live(node, key_ref):
                fail("pairing_enrollments", enrollment, "unbound")
        for enrollment, node, key_ref in activations_now:
            if (bindings.get(key_ref) or {}).get("node_id") != node:
                fail("pairing_enrollments", enrollment, "unbound")

    # -- enrollments: recorded activations stay; which ones are fresh ------
    if _by_enrollment(recorded_activations) and _by_enrollment(activations_now):
        now_by_id = {item[0]: tuple(item[1:]) for item in activations_now}
        for item in recorded_activations:
            if item[0] not in now_by_id:
                fail("pairing_activations", item[0], "missing")
            elif now_by_id[item[0]] != tuple(item[1:]):
                fail("pairing_activations", item[0], "changed")
    elif recorded_activations:
        failed.append({"id": "pairing_activations", "reason": "unverifiable"})
    # Only an enrollment activated after the record explains a new identity:
    # one open at record time, unchanged, or one created since, whose key
    # approve() newly bound (a key already recorded as bound or activated is
    # a historical identity). A baseline without these lists accepts none.
    fresh = set()
    if (_by_enrollment(recorded_activations) and _by_enrollment(recorded_open)
            and _by_enrollment(activations_now) and recorded_bindings is not None):
        recorded_ids = {item[0] for item in recorded_activations}
        opened = {item[0]: tuple(item[1:]) for item in recorded_open}
        historical = {tuple(item[1:]) for item in recorded_activations}
        for enrollment, node, key_ref in activations_now:
            pair = (node, key_ref)
            if enrollment in recorded_ids:
                continue
            if (opened.get(enrollment) == pair if enrollment in opened
                    else pair not in historical and newly_bound(key_ref)):
                fresh.add(pair)

    # -- bindings: never deleted, rebound or un-revoked; revoked per node --
    revoked_nodes = set()
    for key_ref, binding in (recorded_bindings or {}).items():
        now = bindings.get(key_ref)
        if now is None:
            fail("pairing_key_bindings", key_ref, "missing")
        elif now["node_id"] != binding["node_id"] or (binding["revoked"] and not now["revoked"]):
            fail("pairing_key_bindings", key_ref, "changed")
        elif now["revoked"] and not binding["revoked"]:
            revoked_nodes.add(binding["node_id"])
    if recorded_bindings is not None:
        # _bind_key() inserts live bindings; one already revoked was revoked
        # by revoke() of its node since the record.
        revoked_nodes.update(binding["node_id"] for key_ref, binding in bindings.items()
                             if binding["revoked"] and key_ref not in recorded_bindings)
    for node in sorted(revoked_nodes):
        # revoke() revokes every binding the node then held at once.
        if any(binding["node_id"] == node and not (bindings.get(key_ref) or {}).get("revoked")
               for key_ref, binding in recorded_bindings.items()):
            fail("pairing_key_bindings", node, "partially_revoked")

    # -- credentials ------------------------------------------------------
    def installed(node, after):
        """Material a ledger path since the record could have installed."""
        before, renewal = recorded_credentials.get(node), staged.get(node)
        same = (before is not None and after["material"] == before["material"]
                and after["not_after"] == before["not_after"])
        promoted = (before is not None and not before["revoked"] and renewal is not None
                    and after["material"] == renewal["material"]
                    and after["not_after"] == renewal["not_after"])
        return same or promoted or (node, after["key_ref"]) in fresh
    for node, after in sorted(credentials.items()):
        before = recorded_credentials.get(node)
        if before is not None and before["revoked"]:
            # Re-pairing a revoked node is refused here (fail closed).
            if not after["revoked"]:
                fail("pairing_credentials", node, "revocation_reversed")
            elif (after["material"], after["not_after"]) != (before["material"],
                                                             before["not_after"]):
                fail("pairing_credentials", node, "changed")
            continue
        if not installed(node, after):
            fail("pairing_credentials", node, "changed")
        if after["revoked"] and recorded_bindings is not None:
            # revoke(): every binding the node held then is revoked, the
            # credential's own key included, and the staged row is gone.
            held = [key_ref for key_ref, binding in recorded_bindings.items()
                    if binding["node_id"] == node] + [after["key_ref"]]
            if not all((bindings.get(key_ref) or {}).get("revoked") for key_ref in held):
                fail("pairing_credentials", node, "revocation_incomplete")
    for node in sorted(set(recorded_credentials) - set(credentials)):
        fail("pairing_credentials", node, "missing")

    # -- staged renewals --------------------------------------------------
    for node, renewal in sorted(renewals.items()):
        recorded = staged.get(node)
        before, after = recorded_credentials.get(node), credentials.get(node)
        unchanged = (before is not None and after is not None
                     and (after["material"], after["not_after"], after["revoked"])
                     == (before["material"], before["not_after"], before["revoked"]))
        if recorded is not None and renewal["key_ref"] == recorded["key_ref"]:
            # Kept or retried with its own key: nothing consumed it, so the
            # credential is exactly as recorded.
            if not unchanged:
                fail("pairing_renewals", node, "changed")
        elif not newly_bound(renewal["key_ref"]):
            # Any other staged key was bound by stage_renewal() since the record.
            fail("pairing_renewals", node, "changed")
    for node, renewal in sorted(staged.items()):
        if node in renewals:
            continue
        after = credentials.get(node)
        # Consumed by promotion, discarded by revocation or a fresh pairing.
        if not (after is not None and (after["revoked"]
                                       or after["material"] == renewal["material"]
                                       or (node, after["key_ref"]) in fresh)):
            fail("pairing_renewals", node, "missing")
    return failed


def _compare_security_state(baseline: dict | None, current: dict | None) -> dict:
    baseline, current = baseline or {}, current or {}
    failed = []
    now = current.get("capture_nodes_revoked") or {}
    for key, revoked in (baseline.get("capture_nodes_revoked") or {}).items():
        if key not in now:
            failed.append({"id": f"capture_nodes_revoked:{key}", "reason": "missing"})
        elif revoked and not now[key]:
            failed.append({"id": f"capture_nodes_revoked:{key}", "reason": "revocation_reversed"})
    failed.extend(_compare_pairing(baseline, current))
    # A session row may be purged, but an invalidated one never revives.
    now = current.get("sessions_invalidated") or {}
    for key, invalidated in (baseline.get("sessions_invalidated") or {}).items():
        if invalidated and key in now and not now[key]:
            failed.append({"id": f"sessions_invalidated:{key}", "reason": "revocation_reversed"})
    before, after = baseline.get("authorization_generation"), current.get("authorization_generation")
    if before is not None and (after is None or after < before):
        failed.append({"id": "authorization_generation", "reason": "decreased"})
    return {"status": "failed" if failed else "preserved", "failed": failed}


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
    if not baseline or not (baseline["pending"] or baseline["overflow"]):
        return {"status": "empty", "failed": []}
    current = current or {"pending": {}, "pending_findings": {}, "pending_at": {},
                          "overflow": [], "sequence": 0, "notification_events": {}}
    accepted = current["notification_events"]
    failed = []
    for row_id, digest in baseline["pending"].items():
        if row_id in current["pending"]:
            if current["pending"][row_id] != digest:
                failed.append({"id": f"pending:{row_id}", "reason": "changed"})
        elif _integrity_event_id(int(row_id)) not in accepted:
            failed.append({"id": f"pending:{row_id}", "reason": "missing"})
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


def _registry_settings(connection, tables) -> dict | None:
    if "camera_registry_settings" not in tables:
        return None
    row = connection.execute(
        "SELECT max_active_video_sources FROM camera_registry_settings WHERE id = 1").fetchone()
    return {"max_active_video_sources": None if row is None else row[0]}


def _owner_template(root: Path | None, salt: str, owner: int) -> dict:
    """The separate private Owner-template store, as digests only.

    Records whether the store was configured for this run and whether its
    database exists, so its appearance or disappearance is a change; the
    enrollment generation and enrolled flag; keyed digests of the template
    and its model provenance (never the template bytes or any embedding);
    and per-row / chained evidence over owner_template_audit.

    The store is accepted only under the filesystem invariants
    OwnerTemplateStore enforces, checked by the store's own
    open_private_root() against ``owner`` (the service account owning the
    state database; this tool usually runs as root). A layout that would
    expose the biometric template is recorded as ``unsafe`` and never read.
    """
    if root is None:
        return {"configured": False}
    root = _absolute(root, "owner template root")
    try:
        descriptor, exists = owner_store.open_private_root(root, owner=owner)
    except FileNotFoundError:
        return {"configured": True, "state": "absent"}
    except (OSError, owner_store.OwnerError):
        return {"configured": True, "state": "unsafe"}
    try:
        if not exists:
            return {"configured": True, "state": "absent"}
        # Bound to the verified directory, so no component can be swapped
        # between the check and the open.
        connection = _connect_read_only(
            Path(f"/proc/self/fd/{descriptor}/owner-template.sqlite3"))
    except InventoryError:
        raise InventoryError("owner template database is unavailable") from None
    finally:
        os.close(descriptor)
    try:
        connection.execute("BEGIN")
        tables = _tables(connection)
        if not {"owner_template", "owner_template_audit"} <= tables:
            return {"configured": True, "state": "uninitialized"}
        row = connection.execute(
            "SELECT generation, template, provenance FROM owner_template "
            "WHERE singleton = 1").fetchone()
        result = {
            "configured": True, "state": "present",
            "generation": None if row is None else row["generation"],
            "enrolled": row is not None and row["template"] is not None,
            "template_digest": None if row is None or row["template"] is None
            else _keyed(salt, ["owner-template-v1", bytes(row["template"]).hex()]),
            "provenance_digest": None if row is None or row["provenance"] is None
            else _keyed(salt, ["owner-provenance-v1", row["provenance"]]),
            "audit": _audit_table(connection, tables, "owner_template_audit",
                                  ("id", "at", "actor", "operation", "generation"), "id"),
        }
        connection.execute("COMMIT")
        return result
    except sqlite3.Error:
        raise InventoryError("owner template database could not be read") from None
    finally:
        connection.close()


def _compare_sources(baseline: dict | None, current: dict | None) -> dict:
    """Keyed comparison; approval evidence the service cannot load never passes."""
    result = _compare_keyed(baseline, current)
    current = current or {}
    for key in list(result["preserved"]):
        if current[key].get("uvc_approval_sha256") == UNREADABLE_APPROVAL:
            result["preserved"].remove(key)
            result["failed"].append({"id": key, "reason": "unreadable_approval_evidence"})
    if result["status"] != "empty":
        result["status"] = "failed" if result["failed"] else "preserved"
    return result


def _sign_counts_advanced(base: dict, now: dict) -> bool:
    """Whether a principal changed only by credential signature counters rising.

    The same credentials must remain, each counter equal or higher; any
    decrease rolls back the authenticator clone-detection floor.
    """
    if ({key: value for key, value in base.items() if key != "active_credentials"}
            != {key: value for key, value in now.items() if key != "active_credentials"}):
        return False
    before, after = base["active_credentials"], now["active_credentials"]
    return ([item[0] for item in before] == [item[0] for item in after]
            and all(new[1] >= old[1] for old, new in zip(before, after)))


def _compare_principals(baseline: dict | None, current: dict | None) -> dict:
    """Keyed comparison where only credential signature counters may rise."""
    result = _compare_keyed(baseline, current)
    if result["status"] == "empty":
        return result
    advanced = []
    for entry in list(result["failed"]):
        key = entry["id"]
        if entry["reason"] == "changed" and _sign_counts_advanced(baseline[key], current[key]):
            result["failed"].remove(entry)
            result["preserved"].append(key)
            advanced.append(key)
    result.update(status="failed" if result["failed"] else "preserved",
                  preserved=sorted(result["preserved"]), sign_counts_advanced=sorted(advanced))
    return result


def _compare_owner_template(baseline: dict | None, current: dict | None) -> dict:
    baseline = baseline or {"configured": False}
    current = current or {"configured": False}
    if not baseline["configured"] and not current["configured"]:
        return {"status": "not_configured", "failed": []}
    # An unsafe layout exposes the template: never preserved, even unchanged.
    unsafe = "unsafe" in (baseline.get("state"), current.get("state"))
    failed = [{"id": "state", "reason": "unsafe"}] if unsafe else []
    failed += [{"id": key, "reason": "changed"}
              for key in ("configured", "state", "generation", "enrolled",
                          "template_digest", "provenance_digest")
              if baseline.get(key) != current.get(key)]
    audit = None
    if baseline.get("audit") is not None or current.get("audit") is not None:
        audit = _compare_audit(baseline.get("audit"), current.get("audit"))
        failed.extend({"id": f"audit:{item['id']}", "reason": item["reason"]}
                      for item in audit["failed"])
    return {"status": "failed" if failed else "preserved", "failed": failed,
            "audit": audit}


def _access(connection, tables, salt: str) -> dict | None:
    if not {"access_principals", "access_principal_permissions",
            "access_invitations", "access_credentials"} <= tables:
        return None
    principals = {}
    # Only logical IDs and authorization state: never external_identity,
    # display_name, credential IDs / keys, or secret / token digests.
    credential_columns = _columns(connection, "access_credentials")
    consistent = (" AND inconsistent_at_us IS NULL"
                  if "inconsistent_at_us" in credential_columns else "")
    eligible = ("backup_eligible" if "backup_eligible" in credential_columns
                else "NULL AS backup_eligible")
    generation = None
    if "access_deployment_state" in tables:
        generation = connection.execute(
            "SELECT authorization_generation FROM access_deployment_state "
            "WHERE singleton = 1").fetchone()
        generation = None if generation is None else generation[0]
    for row in connection.execute(
            "SELECT id, role, status, authorization_revision, revoked_at_us "
            "FROM access_principals ORDER BY id"):
        permissions = sorted(item[0] for item in connection.execute(
            "SELECT permission FROM access_principal_permissions WHERE principal_id = ?",
            (row["id"],)))
        # A credential marked inconsistent is unusable, like a revoked one.
        # Each usable credential is kept as a keyed digest of its stable
        # authentication material plus its signature counter (not secret),
        # which verification lets only advance: a lower counter would roll
        # back the clone-detection floor. Backup state is excluded.
        credentials = sorted([_keyed(salt, [
            "credential-v1", bytes(item["credential_id"]).hex(), bytes(item["public_key"]).hex(),
            item["algorithm"], None if item["backup_eligible"] is None
            else bool(item["backup_eligible"])]), item["sign_count"]]
            for item in connection.execute(
                f"SELECT credential_id, public_key, algorithm, sign_count, {eligible} "
                "FROM access_credentials WHERE principal_id = ? AND revoked_at_us IS NULL"
                + consistent, (row["id"],)))
        principals[row["id"]] = {
            "role": row["role"], "status": row["status"],
            "authorization_revision": row["authorization_revision"],
            "revoked": row["revoked_at_us"] is not None,
            "permissions": permissions, "active_credential_count": len(credentials),
            "active_credentials": credentials,
        }
    # Every field that decides whether the code can still be redeemed. The
    # secret digest itself is never written, only a keyed digest of it, so a
    # replaced enrollment binding is a change.
    attempts = ("attempt_count" if "attempt_count" in _columns(connection, "access_invitations")
                else "NULL AS attempt_count")
    invitations = {row["id"]: {
        "principal_id": row["principal_id"],
        "redeemed": row["redeemed_at_us"] is not None,
        "revoked": row["revoked_at_us"] is not None,
        "principal_revision": row["principal_revision"],
        "deployment_generation": row["deployment_generation"],
        "deployment_generation_current": row["deployment_generation"] == generation,
        "issued_at_us": row["issued_at_us"],
        "expires_at_us": row["expires_at_us"],
        "attempt_count": row["attempt_count"],
        "secret_binding": _keyed(salt, ["invitation-secret-v1", bytes(row["secret_digest"]).hex()]),
    } for row in connection.execute(
        "SELECT id, secret_digest, principal_id, principal_revision, deployment_generation, "
        "issued_at_us, "
        f"expires_at_us, redeemed_at_us, revoked_at_us, {attempts} "
        "FROM access_invitations ORDER BY id")}
    return {"principals": principals, "invitations": invitations}


def _coverage(inventory: dict) -> dict:
    recordings = inventory["recordings"] or {}
    audit = inventory["audit"]["security_admin"] or {"rows": []}
    access = inventory["access"] or {"principals": {}, "invitations": {}}
    others = [item for item in access["principals"].values() if item["role"] != "owner"]

    def present(flag: bool) -> str:
        return "present" if flag else "empty"
    return {
        "ordinary_recording": present(any(
            not r["starred"] and _evidenced(r) for r in recordings.values())),
        "starred_recording": present(any(
            r["starred"] and _evidenced(r) for r in recordings.values())),
        "camera_source": present(bool(inventory["camera_sources"])),
        "audit_record": present(bool(audit["rows"])),
        "owner": present(any(item["role"] == "owner" for item in access["principals"].values())),
        "live_view_only_grant": present(any(
            item["permissions"] == ["live:view"] for item in others)),
        "recordings_view_only_grant": present(any(
            item["permissions"] == ["recordings:view"] for item in others)),
        "revocation": present(
            any(item["revoked"] for item in access["principals"].values())
            or any(item["revoked"] for item in access["invitations"].values())),
    }


def collect(runtime_root: Path, *, salt: str | None = None,
            owner_template_root: Path | None = None) -> dict:
    """Read the runtime tree without writing to it.

    ``salt`` is the baseline's approval-digest salt when verifying; a new
    random one is drawn when recording.
    """
    salt = secrets.token_hex(32) if salt is None else salt
    tree = RuntimeTree(_absolute(runtime_root, "runtime root"))
    connection = _connect_read_only(tree.database)
    try:
        # One short read transaction gives a consistent snapshot of every
        # table; no file is hashed while it is open (DELETE journal mode: a
        # held read lock would make service writers time out).
        connection.execute("BEGIN")
        tables = _tables(connection)
        schema_version = None
        if "schema_migrations" in tables:
            schema_version = connection.execute(
                "SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        inventory = {
            "format": FORMAT, "format_version": FORMAT_VERSION,
            "schema_version": schema_version,
            "recordings": _recordings(connection, tables),
            "audit": _audit(connection, tables),
            "camera_sources": _sources(connection, tables, salt),
            "access": _access(connection, tables, salt),
            "camera_registry_settings": _registry_settings(connection, tables),
            "presence_timeline_gap": _timeline_gap(connection, tables),
            "presence": _presence(connection, tables, salt, _outbox_live(tree.database)),
            "integrity_baseline": _integrity_baseline(connection, tables, salt),
            "security_state": _security_state(connection, tables, salt),
            "integrity_delivery": _integrity_delivery(connection, tables, salt),
        }
        connection.execute("COMMIT")
    except sqlite3.Error:
        raise InventoryError("state database could not be read") from None
    finally:
        connection.close()
    _hash_recordings(inventory["recordings"], tree.recordings)
    inventory["owner_template"] = _owner_template(
        owner_template_root, salt, os.lstat(tree.database).st_uid)
    inventory["inventory_salt"] = salt
    inventory["coverage"] = _coverage(inventory)
    inventory["not_applicable"] = dict(NOT_APPLICABLE)
    inventory["not_inventoried"] = {name: "not_inventoried (#132)" for name in NOT_INVENTORIED}
    inventory["manual"] = dict(MANUAL)
    return inventory


def _compare_keyed(baseline: dict | None, current: dict | None, *,
                   declared: frozenset[str] = frozenset(), rewrite_only=None) -> dict:
    if not baseline:
        return {"status": "empty", "preserved": [], "failed": [],
                "appended": sorted(current or {}), "declared_rewrites": []}
    current = current or {}
    preserved, failed, rewrites = [], [], []
    for key, value in sorted(baseline.items()):
        if key not in current:
            failed.append({"id": key, "reason": "missing"})
        elif current[key] == value:
            preserved.append(key)
        elif key in declared and rewrite_only is not None and rewrite_only(value, current[key]):
            rewrites.append(key)
        else:
            failed.append({"id": key, "reason": "changed"})
    return {"status": "failed" if failed else "preserved",
            "preserved": preserved, "failed": failed,
            "appended": sorted(set(current) - set(baseline)),
            "declared_rewrites": rewrites}


_REWRITTEN_SEGMENT_FIELDS = ("sha256", "bytes")


def _without_media_bytes(item: dict) -> dict:
    """A recording with only the evidence a declared byte rewrite may change.

    A documented rewrite of stored bytes changes each file's digest and size
    and the catalog byte length that must match it; it never changes the
    star / critical flags, boundaries, event link, discontinuities, segment
    set, sources, stream / sequence, codec, container or capture node.
    """
    segments = []
    for segment in item["segments"]:
        kept = {key: value for key, value in segment.items()
                if key not in _REWRITTEN_SEGMENT_FIELDS}
        kept["catalog"] = {key: value for key, value in segment["catalog"].items()
                           if key != "byte_length"}
        segments.append(kept)
    return {**{key: value for key, value in item.items() if key != "content_sha256"},
            "segments": segments}


def _declared_rewrite_only(base: dict, now: dict) -> bool:
    # The rewritten result must itself be servable: readable and matching its
    # catalog digest, byte length and single-link invariant.
    return (_evidenced(now) and all(segment["catalog_match"] for segment in now["segments"])
            and _without_media_bytes(base) == _without_media_bytes(now))


def _evidenced(item: dict) -> bool:
    # A link to a segment that is not 'ready' (a publication never finished)
    # is not servable evidence, so such a recording is never preserved.
    return bool(item["segments"]) and all(
        segment.get("state") == "ready" and segment["sha256"] is not None
        for segment in item["segments"])


# Statuses an 'active' recording may reach (store.py: stop / reconcile /
# interrupted-at-startup); 'deleting' rows are not inventoried.
_ACTIVE_SUCCESSORS = frozenset({"active", "complete", "gapped", "interrupted"})


def _valid_growth(base: dict, now: dict) -> bool:
    """Whether a recording active at record time only grew as the store allows.

    Source, start, starred and critical flags are immutable; the status may only move to
    an allowed successor; the target end may only stay or move earlier (the
    store never extends target_end_ms); a still-active recording has no ended
    boundary; a stopped (complete / gapped) one ends exactly at its target and
    an interrupted one exactly where startup recovery puts it; every recorded
    segment must be present and identical unless a closing early stop trimmed
    it (_trimmed_by_stop()); every current segment, old or new, must come
    from the recording's own source, overlap its current target window (the
    only segments the store links), be readable and match its catalog digest;
    and the markers not in the record must be exactly those the store adds
    while publishing the newly linked segments.
    """
    if (base["status"] != "active" or now["status"] not in _ACTIVE_SUCCESSORS
            or not _evidenced(base) or not _evidenced(now)):
        return False
    if any(now.get(key) != base.get(key)
           for key in ("source_id", "event_id", "start_ms", "starred", "critical")):
        return False
    start, target = now["start_ms"], now["target_end_ms"]
    if not start < target <= base["target_end_ms"]:
        return False
    if now["ended_ms"] != _expected_ended(now):
        return False
    if not all(segment["catalog_match"] and segment["source_id"] == now["source_id"]
               and segment["start_ms"] < target and segment["end_ms"] > start
               for segment in now["segments"]):
        return False
    # The store adds markers while publishing and, on stop, drops only those
    # wholly outside the new target window; every recorded marker the current
    # window still overlaps must remain.
    remaining = Counter(tuple(item) for item in now["discontinuities"])
    for marker_start, marker_end, reason in base["discontinuities"]:
        key = (marker_start, marker_end, reason)
        if remaining[key]:
            remaining[key] -= 1
        elif not (marker_start >= target or marker_end <= start):
            return False
    now_segments = {item["segment_id"]: item for item in now["segments"]}
    dropped = [item for item in base["segments"] if item["segment_id"] not in now_segments]
    if not all(now_segments[item["segment_id"]] == item for item in base["segments"]
               if item["segment_id"] in now_segments):
        return False
    if dropped and not _trimmed_by_stop(base, now, dropped):
        return False
    return _appended_publications_valid(base, now, remaining)


def _trimmed_by_stop(base: dict, now: dict, dropped: list) -> bool:
    """Whether recorded segment links left only by a closing early stop.

    RecordingStore.finish() closing a stop (status 'complete', possibly
    re-labelled 'gapped') deletes exactly the links to segments wholly
    outside the stopped window (start_ms >= stop or end_ms <= start); the
    store only ever linked segments overlapping the recorded window, so these
    are segments starting at or after the earlier stop. A starred or critical
    (protected) recording is never accepted this way: no shipped caller stops
    early, and such a drop is indistinguishable from hiding protected media,
    so verification fails closed.
    """
    if (now["status"] not in ("complete", "gapped") or base["starred"] or base["critical"]
            or not now["target_end_ms"] < base["target_end_ms"]):
        return False
    return all(item["start_ms"] >= now["target_end_ms"] or item["end_ms"] <= now["start_ms"]
               for item in dropped)


def _expected_ended(now: dict) -> int | None:
    """The ended boundary the store writes for each status an active row reaches.

    finish() (stop or deadline) writes ended_ms = target_end_ms for 'complete'
    and only re-labels that row 'gapped'; startup recovery writes
    MIN(target_end_ms, latest linked segment end) for 'interrupted'; an
    'active' row has none.
    """
    if now["status"] == "active":
        return None
    if now["status"] in ("complete", "gapped"):
        return now["target_end_ms"]
    return min(now["target_end_ms"], max(item["end_ms"] for item in now["segments"]))


def _appended_publications_valid(base: dict, now: dict, remaining: Counter) -> bool:
    """Whether newly linked segments and markers match store publications.

    RecordingStore.append() refuses a segment that starts before the source
    cursor ends or repeats / rewinds the cursor's sequence on the same stream
    (RECORDING_TIMELINE_REGRESSION), so every new segment follows every
    recorded one. RecordingStore._publish() adds one marker per linked
    recording while publishing a segment that does not continue the source
    cursor (another stream_id, or a sequence other than the cursor's plus one):
    ('stream_discontinuity', cursor end, new segment start). The recording
    already linked a recorded segment, so that cursor is the linked segment
    published just before the new one. Such a marker always overlaps the
    target window, so a stop never drops it.
    """
    recorded = {item["segment_id"] for item in base["segments"]}
    ordered = sorted(now["segments"], key=lambda item: (item["start_ms"], item["end_ms"]))
    first_new = next((index for index, item in enumerate(ordered)
                      if item["segment_id"] not in recorded), len(ordered))
    if first_new == 0 or any(item["segment_id"] in recorded for item in ordered[first_new:]):
        return False
    allowed: Counter = Counter()
    for prior, segment in zip(ordered[first_new - 1:], ordered[first_new:]):
        same_stream = segment["catalog"]["stream_id"] == prior["catalog"]["stream_id"]
        if segment["start_ms"] < prior["end_ms"] or (
                same_stream and segment["catalog"]["sequence"] <= prior["catalog"]["sequence"]):
            return False
        contiguous = (same_stream
                      and segment["catalog"]["sequence"] == prior["catalog"]["sequence"] + 1)
        if not contiguous:
            allowed[(prior["end_ms"], segment["start_ms"], "stream_discontinuity")] += 1
    # The store adds the marker in the same transaction that links the
    # segment, so each one must be present exactly once.
    return +remaining == allowed


def _compare_recordings(baseline: dict | None, current: dict | None, *,
                        declared: frozenset[str]) -> dict:
    result = _compare_keyed(baseline, current, declared=declared,
                            rewrite_only=_declared_rewrite_only)
    if result["status"] == "empty":
        return result
    current = current or {}
    preserved, failed, in_progress = [], list(result["failed"]), []
    for key in result["preserved"]:
        if _evidenced(current[key]):
            preserved.append(key)
        else:
            failed.append({"id": key, "reason": "no_readable_segment_evidence"})
    for entry in list(failed):
        key = entry["id"]
        base = baseline[key]
        now = current.get(key)
        if entry["reason"] != "changed" or base["status"] != "active" or now is None:
            continue
        if _valid_growth(base, now):
            failed.remove(entry)
            preserved.append(key)
            in_progress.append(key)
    result.update(status="failed" if failed else "preserved",
                  preserved=sorted(preserved), failed=failed,
                  in_progress_at_record=sorted(in_progress))
    return result


def _compare_audit(baseline: dict | None, current: dict | None) -> dict:
    if not baseline or not baseline["rows"]:
        return {"status": "empty", "preserved_rows": 0, "failed": [],
                "appended": [row[0] for row in (current or {"rows": []})["rows"]],
                "chain_match": None}
    current_rows = dict((row_id, digest) for row_id, digest in (current or {"rows": []})["rows"])
    failed, kept = [], []
    for row_id, digest in baseline["rows"]:
        if row_id not in current_rows:
            failed.append({"id": row_id, "reason": "missing"})
        elif current_rows[row_id] != digest:
            failed.append({"id": row_id, "reason": "changed"})
        else:
            kept.append((row_id, digest))
    # The chain is recomputed over the baseline row order, so a reordering or
    # a changed row anywhere in the retained set breaks it.
    chain_match = not failed and _chain(kept) == baseline["chain_sha256"]
    if not failed and not chain_match:
        failed.append({"id": None, "reason": "chain_mismatch"})
    baseline_ids = {row[0] for row in baseline["rows"]}
    return {"status": "failed" if failed else "preserved",
            "preserved_rows": len(kept),
            "failed": failed,
            "appended": [row_id for row_id in current_rows if row_id not in baseline_ids],
            "chain_match": chain_match}


def compare(baseline: dict, current: dict, *, declared_rewrites=()) -> dict:
    if (not isinstance(baseline, dict) or baseline.get("format") != FORMAT
            or baseline.get("format_version") != FORMAT_VERSION):
        raise InventoryError("baseline is not a lifecycle inventory")
    declared = frozenset(str(item) for item in declared_rewrites)
    unknown = declared - set(baseline.get("recordings") or {})
    if unknown:
        raise InventoryError("declared rewrite is not a recorded recording logical ID")
    access_base = baseline.get("access") or {}
    access_now = current.get("access") or {}
    access_owner = any(item["role"] == "owner"
                       for item in (access_now.get("principals") or {}).values())
    sections = {
        "recordings": _compare_recordings(baseline.get("recordings"),
                                          current.get("recordings"), declared=declared),
        "audit_security_admin": _compare_audit(
            baseline["audit"].get("security_admin"), current["audit"].get("security_admin")),
        "audit_integrity": _compare_audit(
            baseline["audit"].get("integrity"), current["audit"].get("integrity")),
        "audit_presence": _compare_audit(
            baseline["audit"].get("presence"), current["audit"].get("presence")),
        "audit_storage_state": _compare_audit(
            baseline["audit"].get("storage_state"), current["audit"].get("storage_state")),
        "camera_sources": _compare_sources(baseline.get("camera_sources"),
                                           current.get("camera_sources")),
        "camera_registry_settings": _compare_keyed(
            baseline.get("camera_registry_settings"), current.get("camera_registry_settings")),
        "presence_timeline_gap": _compare_timeline_gap(
            baseline.get("presence_timeline_gap"), current.get("presence_timeline_gap")),
        "presence": _compare_presence(
            baseline.get("presence"), current.get("presence"),
            baseline.get("presence_timeline_gap"), current.get("presence_timeline_gap")),
        "integrity_baseline": _compare_keyed(
            {"baseline": baseline["integrity_baseline"]}
            if baseline.get("integrity_baseline") is not None else None,
            {"baseline": current["integrity_baseline"]}
            if current.get("integrity_baseline") is not None else None),
        "integrity_delivery": _compare_integrity_delivery(
            baseline.get("integrity_delivery"), current.get("integrity_delivery")),
        "security_state": _compare_security_state(
            baseline.get("security_state"), current.get("security_state")),
        "owner_template": _compare_owner_template(baseline.get("owner_template"),
                                                  current.get("owner_template")),
        "access_principals": _compare_principals(access_base.get("principals"),
                                                 access_now.get("principals")),
        "access_invitations": _compare_keyed(access_base.get("invitations"),
                                             access_now.get("invitations")),
    }
    empty_coverage = sorted(key for key, value in baseline["coverage"].items()
                            if value != "present")
    failed = any(section["status"] == "failed" for section in sections.values())
    if baseline["coverage"].get("owner") == "present" and not access_owner:
        failed = True
    if failed:
        status = "failed"
    elif empty_coverage or any(section["status"] == "empty" and name in {
            "recordings", "audit_security_admin", "camera_sources",
            "access_principals", "access_invitations"}
            for name, section in sections.items()):
        status = "empty"
    elif sections["recordings"]["declared_rewrites"]:
        status = "preserved_except_declared_rewrites"
    else:
        status = "preserved"
    return {
        "format": FORMAT + "-verification", "format_version": FORMAT_VERSION,
        "status": status,
        "schema_version": {"baseline": baseline.get("schema_version"),
                           "current": current.get("schema_version")},
        "owner_present": access_owner,
        "empty_coverage": empty_coverage,
        "sections": sections,
        "not_applicable": dict(NOT_APPLICABLE),
        "not_inventoried": {name: "not_inventoried (#132)" for name in NOT_INVENTORIED},
        "manual": dict(MANUAL),
    }


def _inside_git_checkout(path: Path) -> bool:
    # Same marker rule as the recording store: a worktree's ``.git`` file or a
    # clone's ``.git/HEAD``.
    return any((parent / ".git").is_file() or (parent / ".git" / "HEAD").is_file()
               for parent in (path, *path.parents))


def _installation_root(prefix: Path) -> Path | None:
    """The whole installed tree containing this interpreter's venv, if any.

    The installer lays out ``<destination>/releases/<version>/venv`` with
    ``<destination>/current`` pointing at a release, so the destination covers
    every release and the ``current`` / ``previous`` links. Other venvs (e.g.
    a development one) only refuse themselves, never their parent directory.
    """
    release = prefix.parent
    if prefix.name == "venv" and release.parent.name == "releases":
        return release.parent.parent
    return None


def _refused_roots(runtime_root: Path) -> tuple[Path, ...]:
    roots = [runtime_root, Path(__file__).resolve().parents[1]]
    if sys.prefix != sys.base_prefix:
        prefix = Path(sys.prefix)
        try:
            prefix = prefix.resolve(strict=False)
        except (OSError, RuntimeError):
            pass
        roots.append(prefix)
        installation = _installation_root(prefix)
        if installation is not None:
            roots.append(installation)
    resolved = []
    for root in roots:
        try:
            resolved.append(root.resolve(strict=False))
        except (OSError, RuntimeError):
            resolved.append(root)
    return tuple(resolved)


def safe_output_path(output: Path, runtime_root: Path) -> Path:
    """Return the destination, refusing runtime, installation and checkout trees."""
    output = _absolute(output, "output")
    runtime_root = _absolute(runtime_root, "runtime root")
    try:
        parent = output.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise InventoryError("output directory is unavailable") from None
    if not parent.is_dir():
        raise InventoryError("output directory is unavailable")
    target = parent / output.name
    for root in _refused_roots(runtime_root):
        if target == root or root in target.parents:
            raise InventoryError(
                "output must be outside the runtime root and the installed release")
    if _inside_git_checkout(parent):
        raise InventoryError("output must be outside any repository checkout")
    return target


def write_private(output: Path, runtime_root: Path, document: dict) -> Path:
    target = safe_output_path(output, runtime_root)
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        raise InventoryError("output already exists; choose a new file") from None
    except OSError:
        raise InventoryError("output could not be created") from None
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target


def _summary_record(inventory: dict) -> list[str]:
    recordings = inventory["recordings"] or {}
    lines = [f"lifecycle inventory recorded: {len(recordings)} recording(s), "
             f"{len((inventory['audit']['security_admin'] or {'rows': []})['rows'])} "
             "security/admin audit row(s)"]
    mismatched = sum(1 for item in recordings.values()
                     if not all(segment["catalog_match"] for segment in item["segments"]))
    if mismatched:
        lines.append(f"warning: {mismatched} recording(s) have segment files that are "
                     "missing or differ from the catalog digest")
    for key, value in inventory["coverage"].items():
        lines.append(f"coverage {key}: {value}")
    for key, value in {**inventory["not_applicable"], **inventory["not_inventoried"],
                       **inventory["manual"]}.items():
        lines.append(f"{key}: {value}")
    return lines


def _summary_verify(report: dict) -> list[str]:
    # Value-free: statuses and counts only, never IDs or digests.
    lines = [f"lifecycle inventory verification: {report['status']}"]
    for name, section in report["sections"].items():
        preserved = section.get("preserved_rows", len(section.get("preserved", [])))
        lines.append(
            f"{name}: {section['status']} preserved={preserved} "
            f"failed={len(section['failed'])} appended={len(section.get('appended', []))} "
            f"declared_rewrites={len(section.get('declared_rewrites', []))}")
    for key in report["empty_coverage"]:
        lines.append(f"coverage {key}: empty (not counted as preserved)")
    for key, value in {**report["not_applicable"], **report["not_inventoried"],
                       **report["manual"]}.items():
        lines.append(f"{key}: {value}")
    return lines


def read_private(path: Path) -> dict:
    """Read a baseline only if it is still as private as write_private() left it.

    A regular file, not a symlink, owned by the invoking user or root, with no
    group/other access; anything else may have been read or replaced.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY)
    except OSError:
        raise InventoryError("baseline could not be read") from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (os.geteuid(), 0)
                or info.st_mode & 0o077):
            raise InventoryError("baseline is not private (expected a 0600 regular file "
                                 "owned by this user or root)")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return json.loads(handle.read())
    except (OSError, ValueError):
        raise InventoryError("baseline could not be read") from None
    finally:
        os.close(descriptor)


def _baseline_salt(baseline) -> str:
    salt = baseline.get("inventory_salt") if isinstance(baseline, dict) else None
    if not isinstance(salt, str) or len(salt) != 64 or any(
            character not in "0123456789abcdef" for character in salt):
        raise InventoryError("baseline is not a lifecycle inventory")
    return salt


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.lifecycle_inventory",
        description="Record or verify a deployment-local preservation inventory.")
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record")
    record.add_argument("--runtime-root", type=Path, required=True)
    record.add_argument("--output", type=Path, required=True)
    owner_help = ("the private Owner-template store directory, when the deployment configures "
                  "one; give it to both record and verify")
    record.add_argument("--owner-template-root", type=Path, help=owner_help)
    verify = commands.add_parser("verify")
    verify.add_argument("--runtime-root", type=Path, required=True)
    verify.add_argument("--baseline", type=Path, required=True)
    verify.add_argument("--report", type=Path)
    verify.add_argument("--owner-template-root", type=Path, help=owner_help)
    verify.add_argument("--declared-rewrite", action="append", default=[],
                        metavar="RECORDING_LOGICAL_ID")
    args = parser.parse_args(arguments)
    try:
        if args.command == "record":
            # Validate the destination before reading anything.
            safe_output_path(args.output, args.runtime_root)
            inventory = collect(args.runtime_root, owner_template_root=args.owner_template_root)
            write_private(args.output, args.runtime_root, inventory)
            print("\n".join(_summary_record(inventory)))
            empty = any(value != "present" for value in inventory["coverage"].values())
            return EXIT_EMPTY if empty else EXIT_PRESERVED
        if args.report is not None:
            safe_output_path(args.report, args.runtime_root)
        baseline = read_private(_absolute(args.baseline, "baseline"))
        current = collect(args.runtime_root, salt=_baseline_salt(baseline),
                          owner_template_root=args.owner_template_root)
        report = compare(baseline, current, declared_rewrites=args.declared_rewrite)
        if args.report is not None:
            write_private(args.report, args.runtime_root, report)
        print("\n".join(_summary_verify(report)))
        if report["status"] == "failed":
            return EXIT_FAILED
        if report["status"] == "empty":
            return EXIT_EMPTY
        return EXIT_PRESERVED
    except InventoryError as exc:
        print(f"lifecycle inventory refused: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
