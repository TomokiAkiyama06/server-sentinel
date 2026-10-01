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
from datetime import datetime, timedelta, timezone
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

from app.audit.store import DEFAULT_RETENTION as AUDIT_RETENTION
from app.cameras.uvc.persistence import ApprovalStore
from app.detection.owner import store as owner_store
from app.integrity.model import Finding, Kind, State
from app.media.recording.model import Limits as RecordingLimits, Segment
from app.monitoring.runtime import EVENT_NAMESPACE
from app.presence.delivery import ActionResult
from app.presence.models import timestamp as presence_timestamp
from app.presence.service import PresenceService
from app.storage.retention import DAY_MS, RetentionPeriods
from app.storage.schema import APPLICATION_MIGRATIONS


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

# Every Main-database table the inventory reads. A table recorded present
# must still exist at verify time, whatever its comparator does with an
# empty or absent section (a table dropped while empty is still a loss).
INVENTORIED_TABLES = (
    "recordings", "recording_links", "recording_segments", "recording_discontinuities",
    "security_admin_audit_records", "integrity_audit", "presence_audit", "storage_state_audit",
    "camera_sources", "uvc_approvals", "detection_bindings", "camera_registry_settings",
    "access_principals", "access_principal_permissions", "access_credentials",
    "access_invitations", "access_deployment_state", "access_sessions",
    "presence_timeline_gap", "presence_clock", "presence_control_clock",
    "presence_source_clock", "presence_critical_source_clock", "presence_override",
    "presence_completed_events", "presence_expired_unresolved", "presence_observations",
    "presence_deliveries", "presence_source_facts", "presence_outbox_sessions",
    "pairing_node_credentials", "pairing_enrollments", "pairing_node_renewals",
    "pairing_key_bindings", "capture_nodes",
    "integrity_outbox", "integrity_overflow", "notification_events", "integrity_baseline",
    "schema_migrations",
)

# Migration-created tables deliberately left out: per-session or derived
# state whose loss replays nothing and hides no failure (beside the
# NOT_INVENTORIED ones above, still to be covered by #132).
TRANSIENT_TABLES = {
    "access_webauthn_challenges": "short-lived single-use WebAuthn challenges",
    "application_metadata": "foundation key/value scaffold, unused by stored evidence",
    "notification_schedule": "daily-summary schedule cursor",
    "presence_delivery_fairness": "round-robin cursor between delivery classes",
    "presence_inputs": "live presence inputs with their own validity windows",
    "recording_selftest": "identifier of the current self-test artifact",
    "setup_wizard_steps": "setup wizard progress",
}

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
            ("sequence", "action", "actor", "at", "state", "target"), "sequence"),
        "storage_state": _audit_table(
            connection, tables, "storage_state_audit",
            ("id", "at_ms", "previous_state", "current_state"), "id", "at_ms"),
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
    approvals, latched = {}, {}
    if "uvc_approvals" in tables:
        for row in connection.execute(
                "SELECT source_id, evidence, requires_approval, serial_ambiguous "
                "FROM uvc_approvals"):
            try:
                approvals[row["source_id"]] = _approval_digest(row, salt)
            except (ValueError, TypeError, KeyError, AttributeError):
                # Never comparable as preserved; see compare().
                approvals[row["source_id"]] = UNREADABLE_APPROVAL
            # The durable Owner re-approval latch (already inside the digest),
            # kept apart so a latch-only difference can be named.
            latched[row["source_id"]] = bool(row["requires_approval"])
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
        "uvc_requires_approval": latched.get(row["id"]),
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
        # Receipt times expire_history() compares (no content).
        "observation_received": keyed_rows(
            "presence_observations", "SELECT id, received FROM presence_observations",
            lambda row: row[0], lambda row: row[1]),
        # Observations the Owner released (clear_unresolved_critical_event()
        # appends this audit row in the same transaction).
        "cleared_events": None if "presence_audit" not in tables else sorted(
            row[0] for row in connection.execute(
                "SELECT target FROM presence_audit WHERE action='critical_event_cleared'")),
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
                      rules: dict | None = None) -> dict:
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
    # An observation (with its jobs and source fact) leaves only through
    # PresenceService.expire_history() once expired, or the Owner's audited
    # clear_unresolved_critical_event(); both write the completed tombstone
    # of an observation that carried critical jobs.
    observations = current.get("observations") or {}
    received = baseline.get("observation_received") or {}
    recorded_jobs: dict = {}
    for job in (baseline.get("deliveries") or {}).values():
        recorded_jobs.setdefault(job["observation"], []).append(job["state"])
    cleared = set(current.get("cleared_events") or ()) - set(baseline.get("cleared_events") or ())
    rules = rules or {}
    for key, value in (baseline.get("observations") or {}).items():
        if key in observations:
            if observations[key] != value:
                fail("observations", key)
            continue
        at, jobs = received.get(key), recorded_jobs.get(key, [])
        # expire_history(): past the timeline cutoff with no unfinished
        # critical job, or past the audit-retention horizon regardless.
        expired_out = (isinstance(at, str) and "presence_cutoff" in rules
                       and (at < rules["presence_horizon"]
                            or (at < rules["presence_cutoff"]
                                and all(state in ("delivered", "disabled") for state in jobs))))
        released = key in cleared and bool(jobs)
        if not (expired_out or released) or (jobs and key not in completed):
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
                        "SELECT id, node_id, public_key_digest, state FROM pairing_enrollments")
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
            for row in enrollments if row["state"] in ("pending", "consumed")),
        # Every enrollment (any state) with its state, to check transitions.
        "pairing_enrollments": None if enrollments is None else {
            row["id"]: {"node_id": row["node_id"], "state": row["state"],
                        "key_ref": _keyed(salt, ["pairing-key-v1", row["public_key_digest"]])}
            for row in enrollments},
        # Every key an enrollment (any state) names: approve() bound them,
        # while stage_renewal() binds keys no enrollment names.
        "pairing_enrollment_keys": None if enrollments is None else sorted(
            {_keyed(salt, ["pairing-key-v1", row["public_key_digest"]]) for row in enrollments}),
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


# PairingLedger enrollment states reachable from each recorded state, as
# compositions of redeem() (pending -> consumed, or -> expired when its
# process epoch or expiry has passed), activate() (consumed -> activated)
# and revoke() (pending / consumed -> revoked); the rest are final.
_ENROLLMENT_SUCCESSORS = {
    "pending": frozenset({"pending", "consumed", "expired", "activated", "revoked"}),
    "consumed": frozenset({"consumed", "activated", "revoked"}),
    "expired": frozenset({"expired"}),
    "activated": frozenset({"activated"}),
    "revoked": frozenset({"revoked"}),
}


def _compare_pairing(baseline: dict, current: dict) -> list:
    """The capture-node pairing ledger, checked against PairingLedger itself.

    Every mutation of the ledger tables is one of these operations (keys are
    keyed digests here; ``live`` means bound to the node and not revoked):

    - approve(node, key): a new pending enrollment; binds the key live
      (_bind_key() refuses a key bound elsewhere or revoked, but accepts one
      already live for the same node, even a currently staged key).
    - redeem(): pending -> consumed, or pending -> expired (a previous
      process epoch or a passed expiry; nothing else expires enrollments).
    - activate(claim): consumed -> activated; binds its key live; the node's
      credential becomes (key, serial, not_after) and active (inserted or
      overwritten); any staged renewal is deleted.
    - stage_renewal(node, key): needs an active credential and a key other
      than its own; refuses a key any credential, another node's renewal or
      enrollment names; binds a new key live, or retries the currently
      staged key (a key bound by an enrollment of this node is refused, so
      it never stages an enrollment's key); writes the single staged row and
      no enrollment.
    - promotion in admits(): the credential becomes the staged material and
      expiry, the staged key stays live, the staged row is deleted.
    - revoke(node): the active credential -> revoked, pending / consumed
      enrollments -> revoked, the staged row deleted, every binding of the
      node revoked, all in one transaction.

    Nothing deletes an enrollment, a credential or a binding, rebinds a key
    or un-revokes a binding. Hence every current state satisfies:

    - each active credential's key is live for its node;
    - a staged renewal belongs to an active credential, uses another key,
      and that key is live for its node and named by no enrollment, recorded
      or current, in any state (so no activated enrollment's key is staged:
      activate() deletes the renewal and that key can never be staged
      again). Approving a currently staged key would also break this; it is
      reachable through approve() (and command_approve() would offer it as a
      retry) but refused here (fail closed): no enrollment created since the
      record may name a key staged at record time or now, so neither the
      retry path nor any other accepts it. A key both staged and approved
      inside the window, its renewal then gone, leaves no trace and passes;
    - every enrollment's key, in any state, is bound to its node; an open
      (pending / consumed) one's binding is live, a revoked one's is revoked
      (expiry and activation change no binding state), and a revoked one
      new or newly revoked since the record means revoke() of its node ran
      in the window.

    And per node, record -> verify is a composition of those operations,
    each enrollment transition tied to the operation that produces it:

    - every recorded enrollment stays with its node and key; pending may
      become consumed or expired (redeem(); nothing else changes), consumed
      activated (activate()), pending / consumed revoked (revoke()), and the
      other states are final;
    - an enrollment activated since the record means activate() ran: the
      node's credential now holds the key of an enrollment activated since
      the record (only another activation or revoke(), which keeps the key,
      changes it afterwards; a promotion of a renewal staged after it cannot
      show its material and fails closed), and the renewal staged at record
      time is gone;
    - revoke() ran for a node if a recorded open enrollment became revoked
      (only revoke() sets that state), a recorded live binding or a binding
      first seen now is revoked, or its active credential became revoked;
      then every recorded binding of the node and every key of its newly
      revoked enrollments are revoked, none of its recorded open
      enrollments is still open, and its credential is revoked (its key's
      binding too) or holds the key of an activation since the record (a
      re-pairing after the revoke); and since revoke() aborts on a node with
      nothing to revoke, the node had an active credential at record time,
      a recorded open enrollment now revoked, an enrollment created since
      and revoked, or a credential activated since and now revoked;
    - a recorded binding keeps its node and never un-revokes; a revoked
      credential stays revoked with the same material (re-pairing a node
      revoked at record time fails closed); an active one stays, becomes the
      staged renewal (promotion) or an identity a post-record activation
      installed (an enrollment open at record time, or a new one for a key
      newly bound or, as command_approve() retries, already live for the
      node at record time and still, or revoked since only by a complete
      revoke() of the node, but never one staged at record time or now); a
      staged row stays exactly, is retried with its own key
      while the credential is unchanged, is replaced by a key newly bound
      since the record, or leaves by promotion, revocation or a fresh
      pairing; a credential first seen now needs a post-record activation of
      its key.
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
    # A staged key is never an enrollment's key (recorded or current, any
    # state); this also keeps an activated enrollment's key from being staged.
    recorded_keys = baseline.get("pairing_enrollment_keys")
    if renewals and (recorded_keys is None and recorded_activations is not None
                     or current.get("pairing_enrollment_keys") is None):
        failed.append({"id": "pairing_enrollment_keys", "reason": "unverifiable"})
    enrollment_keys = set(recorded_keys or ()) | set(current.get("pairing_enrollment_keys") or ())
    for node, renewal in sorted(renewals.items()):
        if renewal["key_ref"] in enrollment_keys:
            fail("pairing_renewals", node, "enrollment_key")
    # Likewise an enrollment created since the record never names a key
    # staged at record time or now (approve() would accept one, but that
    # composition is refused here: fail closed).
    staged_keys = ({renewal["key_ref"] for renewal in staged.values()}
                   | {renewal["key_ref"] for renewal in renewals.values()})
    recorded_enrollments = baseline.get("pairing_enrollments")
    enrollments_now = current.get("pairing_enrollments") or {}
    for enrollment, item in sorted(enrollments_now.items()):
        if (item["key_ref"] in staged_keys and isinstance(recorded_enrollments, dict)
                and enrollment not in recorded_enrollments):
            fail("pairing_enrollments", enrollment, "enrollment_key")
    # Every enrollment, in every state: approve() bound its key to its node
    # first; an open one's binding is live (revoke() revokes the open
    # enrollments and the bindings together); a revoked one's binding is
    # revoked (only revoke() revokes an enrollment, with every binding of
    # its node); expiry (redeem()) and activation change no binding state.
    for enrollment, item in sorted(enrollments_now.items()):
        binding = bindings.get(item["key_ref"]) or {}
        if binding.get("node_id") != item["node_id"]:
            fail("pairing_enrollments", enrollment, "unbound")
        elif item["state"] in ("pending", "consumed") and binding.get("revoked") is not False:
            fail("pairing_enrollments", enrollment, "unbound")
        elif item["state"] == "revoked" and binding.get("revoked") is not True:
            fail("pairing_enrollments", enrollment, "unbound")

    # -- enrollments: never deleted, node / key fixed, states move forward --
    if isinstance(recorded_enrollments, dict):
        for enrollment, before in sorted(recorded_enrollments.items()):
            after = enrollments_now.get(enrollment)
            if after is None:
                fail("pairing_enrollments", enrollment, "missing")
            elif ((after["node_id"], after["key_ref"]) != (before["node_id"], before["key_ref"])
                  or after["state"] not in _ENROLLMENT_SUCCESSORS.get(before["state"], ())):
                fail("pairing_enrollments", enrollment, "changed")
    elif recorded_activations or recorded_open:
        failed.append({"id": "pairing_enrollments", "reason": "unverifiable"})
    # -- bindings: never deleted, rebound or un-revoked --------------------
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

    # -- enrollment transitions and the operation that made them -----------
    recorded_states = {enrollment: item["state"]
                       for enrollment, item in (recorded_enrollments or {}).items()}
    # Enrollments activate() completed since the record (recorded open ones
    # or ones created since), per node.
    activated_since = {enrollment: item for enrollment, item in enrollments_now.items()
                       if item["state"] == "activated"
                       and recorded_states.get(enrollment) != "activated"}
    activated_keys: dict = {}
    for item in activated_since.values():
        activated_keys.setdefault(item["node_id"], set()).add(item["key_ref"])
    for enrollment, item in sorted(activated_since.items()):
        node = item["node_id"]
        after = credentials.get(node)
        # activate() made its key the node's credential and dropped the staged
        # renewal; later only another activation (or revoke(), which keeps
        # the key) changes that credential. A promotion of a renewal staged
        # after it cannot show its material and fails closed.
        if after is None or after["key_ref"] not in activated_keys[node]:
            fail("pairing_enrollments", enrollment, "activation_unapplied")
        if (node in staged and node in renewals
                and renewals[node]["key_ref"] == staged[node]["key_ref"]):
            fail("pairing_renewals", node, "changed")
    for enrollment, after in sorted(enrollments_now.items()):
        # Only revoke() sets 'revoked', revoking the node as a whole: a
        # recorded open enrollment now revoked, or one created since and
        # already revoked, means revoke() ran in the window.
        before = (recorded_enrollments or {}).get(enrollment)
        if after["state"] == "revoked" and (before is None or before["state"] != "revoked"):
            revoked_nodes.add(after["node_id"])
    for node, before in recorded_credentials.items():
        after = credentials.get(node)
        if not before["revoked"] and after is not None and after["revoked"]:
            revoked_nodes.add(node)

    # -- revoke(): all of it, for any node revoked since the record --------
    revoked_completely = set()
    for node in sorted(revoked_nodes):
        # revoke() revokes every binding the node held (recorded ones and
        # those of its enrollments), every open enrollment, the active
        # credential, and deletes the staged row; afterwards only a fresh
        # approve() / activate() gives the node a live identity again.
        held = [key_ref for key_ref, binding in (recorded_bindings or {}).items()
                if binding["node_id"] == node]
        held += [item["key_ref"] for enrollment, item in (recorded_enrollments or {}).items()
                 if item["node_id"] == node
                 and (enrollments_now.get(enrollment) or {}).get("state") == "revoked"]
        still_open = any(item["node_id"] == node and item["state"] in ("pending", "consumed")
                         and (enrollments_now.get(enrollment) or {}).get("state")
                         in ("pending", "consumed")
                         for enrollment, item in (recorded_enrollments or {}).items())
        # revoke() aborts unless the node had something to revoke then: an
        # active credential or an open enrollment.
        recorded_credential = recorded_credentials.get(node)
        revocable = (
            (recorded_credential is not None and not recorded_credential["revoked"])
            or any(item["node_id"] == node and item["state"] in ("pending", "consumed")
                   and (enrollments_now.get(enrollment) or {}).get("state") == "revoked"
                   for enrollment, item in (recorded_enrollments or {}).items())
            or any(item["node_id"] == node and item["state"] == "revoked"
                   and enrollment not in (recorded_enrollments or {})
                   for enrollment, item in enrollments_now.items())
            or (credentials.get(node) or {}).get("revoked") is True
            and credentials[node]["key_ref"] in activated_keys.get(node, ()))
        after = credentials.get(node)
        if not revocable:
            credential_ok = False
        elif after is None:
            credential_ok = True
        elif after["revoked"]:
            held.append(after["key_ref"])
            credential_ok = True
        else:
            credential_ok = after["key_ref"] in activated_keys.get(node, ())
        if (recorded_bindings is None or still_open or not credential_ok
                or not all((bindings.get(key_ref) or {}).get("revoked") for key_ref in held)):
            fail("pairing_revocation", node, "incomplete")
        else:
            revoked_completely.add(node)

    # Only an enrollment activated after the record explains a new identity:
    # one open at record time, unchanged, or one created since, whose key
    # approve() newly bound or whose key was already live for the same node
    # at record time (an Owner retry through command_approve()). A baseline
    # without these lists accepts none.
    fresh = set()
    if (_by_enrollment(recorded_activations) and _by_enrollment(recorded_open)
            and _by_enrollment(activations_now) and recorded_bindings is not None):
        recorded_ids = {item[0] for item in recorded_activations}
        opened = {item[0]: tuple(item[1:]) for item in recorded_open}
        historical = {tuple(item[1:]) for item in recorded_activations}
        def retried(enrollment, node, key_ref):
            # pairing_cli.command_approve() retries an interrupted, expired
            # or unacknowledged enrollment by approving the same key again
            # for the node its live binding names (PairingLedger.bound_node());
            # approve() then creates a new enrollment for that key. Such an
            # enrollment is new since the record (every recorded one must
            # persist, so an old one cannot be re-labelled) and its key was
            # already live for the same node at record time and still is,
            # unless revoke() of the node, complete as checked above, has
            # revoked it since. A key staged as a renewal (at record time or
            # now) is never one: approving it is the fail-closed case below.
            recorded = recorded_bindings.get(key_ref) or {}
            now = bindings.get(key_ref) or {}
            return (isinstance(recorded_enrollments, dict)
                    and enrollment not in recorded_enrollments
                    and key_ref not in staged_keys
                    and recorded.get("node_id") == node and recorded.get("revoked") is False
                    and (live(node, key_ref)
                         or (node in revoked_completely and now.get("node_id") == node
                             and now.get("revoked") is True)))
        for enrollment, node, key_ref in activations_now:
            pair = (node, key_ref)
            if enrollment in recorded_ids:
                continue
            if enrollment in opened:
                accepted = opened[enrollment] == pair
            else:
                accepted = ((pair not in historical and newly_bound(key_ref))
                            or retried(enrollment, node, key_ref))
            if accepted:
                fresh.add(pair)


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


_UVC_APPROVAL_FIELDS = frozenset({"uvc_approval_sha256", "uvc_requires_approval"})


def _compare_sources(baseline: dict | None, current: dict | None) -> dict:
    """Keyed comparison; approval evidence the service cannot load never passes.

    ReconnectController latches Owner re-approval for a camera without a
    unique serial on every restart (only a live descriptor proves the same
    camera), so such a source that differs only in its approval now held
    for re-approval is reported ``reapproval_required``: still a failure,
    resolved by the Owner re-approving and a new record.
    """
    result = _compare_keyed(baseline, current)
    current = current or {}
    for entry in result["failed"]:
        before, after = (baseline or {}).get(entry["id"]), current.get(entry["id"])
        if entry["reason"] != "changed" or before is None or after is None:
            continue
        differing = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
        if (differing and differing <= _UVC_APPROVAL_FIELDS
                and after.get("uvc_requires_approval") is True
                and after.get("uvc_approval_sha256") != UNREADABLE_APPROVAL):
            entry["reason"] = "reapproval_required"
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
        schema_version, migrations = None, None
        if "schema_migrations" in tables:
            # The applied history migrate() checks entry by entry on startup.
            migrations = [[row[0], row[1], row[2]] for row in connection.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version")]
            schema_version = migrations[-1][0] if migrations else None
        inventory = {
            "format": FORMAT, "format_version": FORMAT_VERSION,
            "schema_version": schema_version,
            "schema_migrations": migrations,
            "tables": sorted(name for name in INVENTORIED_TABLES if name in tables),
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
               and _service_valid_segment(segment)
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


# Segment.validate() with the configuration-independent bounds: the hard
# 20-minute segment ceiling Limits itself enforces and no byte ceiling (the
# deployment's stricter recording_limits are not read here).
_SEGMENT_BOUNDS = RecordingLimits(pre_roll_bytes=1, max_segment_bytes=2**63 - 1,
                                  max_segment_ms=1_200_000, max_active_recordings=1,
                                  max_spool_segments=1, max_segments_per_recording=1)


def _service_valid_segment(segment: dict) -> bool:
    """Whether a linked segment passes RecordingStore.append()'s own check.

    The catalog row is rebuilt as the Segment the store validated (UUID
    source, stream and capture node, sequence and timeline bounds, a
    positive duration, codec / container names) and Segment.validate() runs
    on it; the media bytes are represented by their positive byte length,
    whose file the catalog match already ties to the stored digest.
    """
    catalog = segment["catalog"]
    try:
        Segment(source_id=UUID(segment["source_id"]), stream_id=UUID(catalog["stream_id"]),
                sequence=catalog["sequence"], start_ms=segment["start_ms"],
                end_ms=segment["end_ms"], codec=catalog["codec"],
                container=catalog["container"], data=b"\0",
                capture_node_id=(None if catalog["capture_node_id"] is None
                                 else UUID(catalog["capture_node_id"]))
                ).validate(_SEGMENT_BOUNDS)
    except (ValueError, TypeError, AttributeError):
        return False
    return type(catalog["byte_length"]) is int and catalog["byte_length"] > 0


def _segments_consistent(item: dict) -> bool:
    """Every linked segment is one the store would have linked to ``item``."""
    return all(segment["source_id"] == item["source_id"]
               and segment["start_ms"] < item["target_end_ms"]
               and segment["end_ms"] > item["start_ms"]
               and _service_valid_segment(segment)
               for segment in item["segments"])


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


def _retention_eligible(item: dict, cutoff_ms: int | None) -> bool:
    """RecordingStore.retention_candidates() for RetentionService.expired()."""
    return (cutoff_ms is not None and not item["starred"]
            and item["status"] in ("complete", "gapped", "interrupted")
            and isinstance(item["ended_ms"], int) and item["ended_ms"] <= cutoff_ms)


def _compare_recordings(baseline: dict | None, current: dict | None, *,
                        declared: frozenset[str], retention_cutoff_ms: int | None = None) -> dict:
    result = _compare_keyed(baseline, current, declared=declared,
                            rewrite_only=_declared_rewrite_only)
    if result["status"] == "empty":
        result["retention_expired"] = []
        return result
    if current is None:
        # The recording tables are gone or unreadable: never retention.
        retention_cutoff_ms = None
        result["failed"].append({"id": None, "reason": "table_missing"})
    current = current or {}
    preserved, failed, in_progress = [], [], []
    # A recording automatic retention deletes (with its links and markers,
    # its unshared segments trimmed) is listed apart, never as preserved.
    retained_out = []
    for entry in result["failed"]:
        if (entry["reason"] == "missing"
                and _retention_eligible(baseline[entry["id"]], retention_cutoff_ms)):
            retained_out.append(entry["id"])
        else:
            failed.append(entry)
    for key in result["preserved"]:
        if not _evidenced(current[key]):
            failed.append({"id": key, "reason": "no_readable_segment_evidence"})
        elif not all(segment["catalog_match"] for segment in current[key]["segments"]):
            # Unchanged is not enough: a segment already missing its catalog
            # digest, byte length or single hard link at record time is one
            # RecordingStore._integrity() reports corrupt, so it never
            # verifies as preserved (record warns about it).
            failed.append({"id": key, "reason": "catalog_mismatch"})
        else:
            preserved.append(key)
    for entry in list(failed):
        if entry["reason"] != "changed":
            continue
        key = entry["id"]
        base = baseline[key]
        now = current.get(key)
        if base["status"] != "active" or now is None:
            continue
        if _valid_growth(base, now):
            failed.remove(entry)
            preserved.append(key)
            in_progress.append(key)
    # The single gate every accepted transition passes (unchanged, valid
    # growth incl. an early stop's trim, declared rewrite): each segment the
    # record held must itself have matched its catalog digest, byte length
    # and single hard link then. One RecordingStore._integrity() already
    # reported corrupt is never evidence, even if a later change drops it.
    # The same gate checks every recorded and current segment of an accepted
    # recording against the store's own rules: Segment.validate(), its own
    # source, and an overlap with its target window (the only segments the
    # store links and finish() keeps).
    rewrites = list(result["declared_rewrites"])
    for key, item in sorted(baseline.items()):
        if key not in preserved and key not in rewrites:
            continue
        if not all(segment["catalog_match"] for segment in item["segments"]):
            reason = "catalog_mismatch"
        elif not (_segments_consistent(item) and _segments_consistent(current[key])):
            reason = "invalid_segment"
        else:
            continue
        preserved = [other for other in preserved if other != key]
        in_progress = [other for other in in_progress if other != key]
        rewrites = [other for other in rewrites if other != key]
        failed.append({"id": key, "reason": reason})
    result.update(status="failed" if failed else "preserved",
                  preserved=sorted(preserved), failed=failed,
                  declared_rewrites=rewrites,
                  in_progress_at_record=sorted(in_progress),
                  retention_expired=sorted(retained_out))
    return result


def _compare_audit(baseline: dict | None, current: dict | None, expired=None) -> dict:
    """Audit rows stay identical, except rows the service's retention removed.

    ``expired`` judges a recorded row's time against the service's retention
    rule at verify time; a missing row it accepts is listed under
    ``retention_expired`` and never counted as preserved.
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
    for row_id, digest in baseline["rows"]:
        if row_id not in current_rows:
            if expired is not None and row_id in times and expired(times[row_id]):
                retained_out.append(row_id)
            else:
                failed.append({"id": row_id, "reason": "missing"})
        elif current_rows[row_id] != digest:
            failed.append({"id": row_id, "reason": "changed"})
        else:
            kept.append((row_id, digest))
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
            "appended": [row_id for row_id in current_rows if row_id not in baseline_ids],
            "chain_match": chain_match,
            "retention_expired": retained_out}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _retention_rules(now: datetime) -> dict:
    """The service's own retention cutoffs at ``now`` (verify time).

    Main runs these with code defaults (no deployment setting changes them):
    AuditStore.cleanup_expired_batch() deletes security/admin audit rows
    with occurred_at_us below now - 90 days and integrity_audit rows with
    ``at`` below that instant's ISO text; StorageAudit.expire() deletes
    storage_state_audit rows with at_ms below now - 90 days;
    RetentionService.expired() deletes unstarred complete / gapped /
    interrupted recordings whose ended_ms is at most now - 20 days.
    Presence and Owner-template audit retention does not run in Main, and
    capacity-pressure deletion (RetentionService.oldest()) is never accepted.
    """
    periods = RetentionPeriods()
    cutoff = now - AUDIT_RETENTION
    cutoff_us = int(cutoff.timestamp()) * 1_000_000 + cutoff.microsecond
    now_ms = int(now.timestamp() * 1000)
    audit_ms = now_ms - periods.audit_days * DAY_MS
    return {
        "security_admin": lambda value: isinstance(value, int) and value < cutoff_us,
        "integrity": lambda value: isinstance(value, str) and value < cutoff.isoformat(),
        "storage_state": lambda value: isinstance(value, int) and value < audit_ms,
        "recording_cutoff_ms": now_ms - periods.recording_days * DAY_MS,
        # PresenceService.expire_history(): timeline cutoff and the audit
        # horizon, in its own receipt-time text.
        "presence_cutoff": presence_timestamp(now - timedelta(days=periods.recording_days)),
        "presence_horizon": presence_timestamp(now - timedelta(days=periods.audit_days)),
    }


def _compare_migrations(baseline: list | None, current: list | None) -> dict:
    """The applied migration history the next startup would still accept.

    migrate() reads the history ordered by version, refuses one longer than
    the code's migrations, and requires each row to equal the code's
    migration at the same position (version, name, checksum); it then only
    appends the code's later ones. Migrations are forward-only, so a
    rollback removes none. verify runs after the release has started, so
    the current history must start with the recorded rows unchanged and
    equal this release's whole APPLICATION_MIGRATIONS: no gap, reorder,
    foreign row or missing tail.
    """
    if baseline is None:
        return {"status": "failed" if current is None else "empty",
                "failed": [{"id": None, "reason": "unverifiable"}] if current is None else [],
                "appended": []}
    if current is None:
        return {"status": "failed", "failed": [{"id": None, "reason": "table_missing"}],
                "appended": []}
    failed = []
    by_version = {row[0]: row for row in current}
    for position, row in enumerate(baseline):
        if row[0] not in by_version:
            failed.append({"id": row[0], "reason": "missing"})
        elif position >= len(current) or current[position] != row:
            failed.append({"id": row[0], "reason": "changed"})
    code = [[migration.version, migration.name, migration.checksum]
            for migration in APPLICATION_MIGRATIONS]
    # The exact check migrate() runs on startup.
    if len(current) > len(code) or any(row != expected for row, expected in zip(current, code)):
        failed.append({"id": None, "reason": "history_rejected"})
    elif len(current) < len(code):
        # verify runs after the release started (systemd readiness follows
        # migrate()), so its full catalog is applied. A shorter history means
        # applied rows were removed and the next start would re-run DDL.
        failed.append({"id": None, "reason": "not_migrated"})
    recorded = {row[0] for row in baseline}
    return {"status": "failed" if failed else "preserved", "failed": failed,
            "appended": [row[0] for row in current if row[0] not in recorded]}


def compare(baseline: dict, current: dict, *, declared_rewrites=(), now=None) -> dict:
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
    rules = _retention_rules(now or _utcnow())
    recorded_tables = baseline.get("tables")
    present = set(current.get("tables") or ())
    table_failures = ([{"id": None, "reason": "unverifiable"}] if recorded_tables is None else
                      [{"id": name, "reason": "table_missing"}
                       for name in recorded_tables if name not in present])
    sections = {
        "schema_migrations": _compare_migrations(baseline.get("schema_migrations"),
                                                 current.get("schema_migrations")),
        "tables": {"status": "failed" if table_failures else "preserved",
                   "failed": table_failures, "preserved": sorted(set(recorded_tables or ()) & present)},
        "recordings": _compare_recordings(baseline.get("recordings"),
                                          current.get("recordings"), declared=declared,
                                          retention_cutoff_ms=rules["recording_cutoff_ms"]),
        "audit_security_admin": _compare_audit(
            baseline["audit"].get("security_admin"), current["audit"].get("security_admin"),
            rules["security_admin"]),
        "audit_integrity": _compare_audit(
            baseline["audit"].get("integrity"), current["audit"].get("integrity"),
            rules["integrity"]),
        "audit_presence": _compare_audit(
            baseline["audit"].get("presence"), current["audit"].get("presence")),
        "audit_storage_state": _compare_audit(
            baseline["audit"].get("storage_state"), current["audit"].get("storage_state"),
            rules["storage_state"]),
        "camera_sources": _compare_sources(baseline.get("camera_sources"),
                                           current.get("camera_sources")),
        "camera_registry_settings": _compare_keyed(
            baseline.get("camera_registry_settings"), current.get("camera_registry_settings")),
        "presence_timeline_gap": _compare_timeline_gap(
            baseline.get("presence_timeline_gap"), current.get("presence_timeline_gap")),
        "presence": _compare_presence(
            baseline.get("presence"), current.get("presence"),
            baseline.get("presence_timeline_gap"), current.get("presence_timeline_gap"),
            rules),
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
            f"declared_rewrites={len(section.get('declared_rewrites', []))} "
            f"retention_expired={len(section.get('retention_expired', []))}")
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
