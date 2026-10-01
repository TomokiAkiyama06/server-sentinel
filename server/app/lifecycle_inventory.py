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
- per registered camera source: type, enabled flag, capture node, digests of
  the desired capture profile and detection bindings, and a salted digest of
  the durable UVC approval (never device facts; volatile health excluded);
- Owner presence and, per nonidentifying principal / invitation logical ID,
  the independent ``live:view`` / ``recordings:view`` grants, revocation
  state, authorization revision, usable (unrevoked and consistent) credential
  count, and every non-secret invitation validity field.

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
from uuid import UUID


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


def _recordings(connection, tables, directory: Path) -> dict | None:
    if not {"recordings", "recording_links", "recording_segments"} <= tables:
        return None
    result = {}
    rows = connection.execute(
        "SELECT id, source_id, event_id, status, starred, critical, start_ms, target_end_ms, "
        "ended_ms FROM recordings WHERE status != 'deleting' ORDER BY id").fetchall()
    for row in rows:
        segments = connection.execute(
            "SELECT s.id, s.source_id, s.capture_node_id, s.stream_id, s.sequence, "
            "s.start_ms, s.end_ms, s.codec, s.container, s.byte_length, s.sha256, s.critical "
            "FROM recording_segments s "
            "JOIN recording_links l ON l.segment_id = s.id "
            "WHERE l.recording_id = ? AND s.state = 'ready' ORDER BY s.start_ms, s.id",
            (row["id"],)).fetchall()
        items = []
        for segment in segments:
            digest, size, links = _file_digest(directory, segment["id"])
            items.append({
                "segment_id": segment["id"], "sha256": digest, "bytes": size,
                "link_count": links,
                # RecordingStore._integrity() needs the digest and the catalog
                # byte_length to match a file with exactly one hard link.
                "catalog_match": (digest is not None and digest == segment["sha256"]
                                  and size == segment["byte_length"] and links == 1),
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
            "content_sha256": _digest([[item["segment_id"], item["sha256"]] for item in items]),
            "container_duration": "manual",
            "decode_verification": "manual",
        }
    return result


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


def _approval_digest(row, salt: str) -> str:
    """A salted digest of the durable UVC approval, never the device facts.

    Only the physical identity the approval binds (vendor, product, serial,
    interface: the strong key, or the model when there is no serial) and the
    durable latch flags are covered. Device paths, by-id aliases, topology,
    formats, instance markers and the session token change with re-enumeration
    or a restart and are excluded. The per-inventory random salt keeps the
    digest from being a stable cross-file identifier of a camera serial.
    """
    evidence = json.loads(row["evidence"])
    identity = [evidence.get(key) for key in ("vendor", "product", "serial", "interface")]
    message = json.dumps(["uvc-approval-v1", identity, bool(row["requires_approval"]),
                          bool(row["serial_ambiguous"])], separators=(",", ":"))
    return hmac.new(bytes.fromhex(salt), message.encode(), hashlib.sha256).hexdigest()


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
            except (ValueError, TypeError, AttributeError):
                approvals[row["source_id"]] = "unreadable"
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
        "desired_capture_profile_sha256": _digest(row["desired_capture_profile"]),
        "detection_bindings_sha256": _digest(bindings.get(row["id"], [])),
        "uvc_approval_sha256": approvals.get(row["id"]),
    } for row in connection.execute(
        "SELECT id, source_type, enabled, capture_node_id, desired_capture_profile "
        "FROM camera_sources ORDER BY id")}


def _access(connection, tables) -> dict | None:
    if not {"access_principals", "access_principal_permissions",
            "access_invitations", "access_credentials"} <= tables:
        return None
    principals = {}
    # Only logical IDs and authorization state: never external_identity,
    # display_name, credential IDs / keys, or secret / token digests.
    consistent = (" AND inconsistent_at_us IS NULL"
                  if "inconsistent_at_us" in _columns(connection, "access_credentials") else "")
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
        credentials = connection.execute(
            "SELECT COUNT(*) FROM access_credentials "
            "WHERE principal_id = ? AND revoked_at_us IS NULL" + consistent,
            (row["id"],)).fetchone()[0]
        principals[row["id"]] = {
            "role": row["role"], "status": row["status"],
            "authorization_revision": row["authorization_revision"],
            "revoked": row["revoked_at_us"] is not None,
            "permissions": permissions, "active_credential_count": credentials,
        }
    # Every non-secret field that decides whether the code can still be
    # redeemed; never the secret digest.
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
    } for row in connection.execute(
        "SELECT id, principal_id, principal_revision, deployment_generation, issued_at_us, "
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


def collect(runtime_root: Path, *, salt: str | None = None) -> dict:
    """Read the runtime tree without writing to it.

    ``salt`` is the baseline's approval-digest salt when verifying; a new
    random one is drawn when recording.
    """
    salt = secrets.token_hex(32) if salt is None else salt
    tree = RuntimeTree(_absolute(runtime_root, "runtime root"))
    connection = _connect_read_only(tree.database)
    try:
        # One read transaction gives a consistent catalog snapshot.
        connection.execute("BEGIN")
        tables = _tables(connection)
        schema_version = None
        if "schema_migrations" in tables:
            schema_version = connection.execute(
                "SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        inventory = {
            "format": FORMAT, "format_version": FORMAT_VERSION,
            "schema_version": schema_version,
            "recordings": _recordings(connection, tables, tree.recordings),
            "audit": _audit(connection, tables),
            "camera_sources": _sources(connection, tables, salt),
            "access": _access(connection, tables),
        }
        connection.execute("COMMIT")
    except sqlite3.Error:
        raise InventoryError("state database could not be read") from None
    finally:
        connection.close()
    inventory["approval_salt"] = salt
    inventory["coverage"] = _coverage(inventory)
    inventory["not_applicable"] = dict(NOT_APPLICABLE)
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
    return bool(item["segments"]) and all(
        segment["sha256"] is not None for segment in item["segments"])


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
    segment must be present and identical; every current segment, old or new,
    must come from the recording's own source, overlap its current target
    window (the only segments the store links), be readable and match its
    catalog digest; and the markers not in the record must be exactly those the
    store adds while publishing the newly linked segments.
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
    if not all(now_segments.get(item["segment_id"]) == item for item in base["segments"]):
        return False
    return _appended_publications_valid(base, now, remaining)


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
        "camera_sources": _compare_keyed(baseline.get("camera_sources"),
                                         current.get("camera_sources")),
        "access_principals": _compare_keyed(access_base.get("principals"),
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
    for key, value in {**inventory["not_applicable"], **inventory["manual"]}.items():
        lines.append(f"{key}: {value}")
    return lines


def _summary_verify(report: dict) -> list[str]:
    # Value-free: statuses and counts only, never IDs or digests.
    lines = [f"lifecycle inventory verification: {report['status']}"]
    for name, section in report["sections"].items():
        preserved = section.get("preserved_rows", len(section.get("preserved", [])))
        lines.append(
            f"{name}: {section['status']} preserved={preserved} "
            f"failed={len(section['failed'])} appended={len(section['appended'])} "
            f"declared_rewrites={len(section.get('declared_rewrites', []))}")
    for key in report["empty_coverage"]:
        lines.append(f"coverage {key}: empty (not counted as preserved)")
    for key, value in {**report["not_applicable"], **report["manual"]}.items():
        lines.append(f"{key}: {value}")
    return lines


def _baseline_salt(baseline) -> str:
    salt = baseline.get("approval_salt") if isinstance(baseline, dict) else None
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
    verify = commands.add_parser("verify")
    verify.add_argument("--runtime-root", type=Path, required=True)
    verify.add_argument("--baseline", type=Path, required=True)
    verify.add_argument("--report", type=Path)
    verify.add_argument("--declared-rewrite", action="append", default=[],
                        metavar="RECORDING_LOGICAL_ID")
    args = parser.parse_args(arguments)
    try:
        if args.command == "record":
            # Validate the destination before reading anything.
            safe_output_path(args.output, args.runtime_root)
            inventory = collect(args.runtime_root)
            write_private(args.output, args.runtime_root, inventory)
            print("\n".join(_summary_record(inventory)))
            empty = any(value != "present" for value in inventory["coverage"].values())
            return EXIT_EMPTY if empty else EXIT_PRESERVED
        if args.report is not None:
            safe_output_path(args.report, args.runtime_root)
        try:
            baseline = json.loads(_absolute(args.baseline, "baseline").read_text())
        except (OSError, ValueError):
            raise InventoryError("baseline could not be read") from None
        report = compare(baseline, collect(args.runtime_root, salt=_baseline_salt(baseline)),
                         declared_rewrites=args.declared_rewrite)
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
