"""RecordingStore section of the lifecycle inventory (#47, split in #256).

Reads the recording catalog, the ready pre-roll spool, the per-source
publish cursors, pending journal rows and the per-source pre-roll markers
from the private snapshot, hashes every linked and spooled segment file,
and compares them under the transitions RecordingStore performs: growth of
a recording active at record time, an early stop's trim, retention, the
publication / link rules of ``append()`` / ``_publish()`` / ``finish()`` and
the marker trim of ``_trim()``. See ``server/docs/DEPLOYMENT.md`` for what
is not judged (an interrupted recording's trailing publications, #256).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
from uuid import UUID

from app.media.recording.store import RecordingStore
from app.media.recording.model import MAX_LIMIT_DURATION_MS, Limits as RecordingLimits, Segment
from app.monitoring.config import RECORDING_LIMIT_FIELDS

from . import _common
from ._common import (InventoryError, _canonical_uuid, _compare_keyed, _connect_read_only, _digest,
                      _fail_closed, _hex_digest, _int, _row_order)
from .timing import _retention_rules


_CHUNK = 1024 * 1024


def _file_digest(directory: Path, segment_id: str) -> tuple[str | None, int | None, int | None]:
    """SHA-256, size and hard-link count of a segment file as stored."""
    try:
        name = UUID(segment_id).hex + ".seg"
    except (ValueError, TypeError, AttributeError):
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


def _recordings(connection, tables) -> dict | None:
    """The recording catalog, read from the private snapshot (_snapshot()).

    Segment files are hashed afterwards by _hash_recordings(); nothing here
    holds a lock on the state database.
    """
    if not {"recordings", "recording_links", "recording_segments"} <= tables:
        return None
    result = {}
    rows = connection.execute(
        "SELECT id, source_id, event_id, status, starred, critical, start_ms, target_end_ms, "
        "ended_ms FROM recordings WHERE status != 'deleting' ORDER BY id").fetchall()
    # One query for every link and one for every marker (#132), grouped per
    # recording here, instead of two queries per recording.
    linked: dict = {}
    for segment in connection.execute(
            "SELECT l.recording_id, s.id, s.source_id, s.capture_node_id, s.stream_id, "
            "s.sequence, s.start_ms, s.end_ms, s.codec, s.container, s.byte_length, s.sha256, "
            "s.critical, s.state "
            "FROM recording_segments s "
            "JOIN recording_links l ON l.segment_id = s.id "
            # Every linked segment, whatever its state, as manifest() reads
            # them: a hidden non-ready link would later degrade playback.
            "ORDER BY l.recording_id, s.start_ms, s.id"):
        linked.setdefault(segment["recording_id"], []).append(segment)
    markers: dict = {}
    # A dropped marker table leaves every recorded marker missing (changed)
    # and the table check reports it.
    for item in (connection.execute(
            "SELECT recording_id, start_ms, end_ms, reason FROM recording_discontinuities")
            if "recording_discontinuities" in tables else ()):
        markers.setdefault(item["recording_id"], []).append(
            [item["start_ms"], item["end_ms"], item["reason"]])
    for row in rows:
        segments = linked.get(row["id"], ())
        items = []
        for segment in segments:
            items.append({
                "segment_id": segment["id"], "state": segment["state"],
                # Filled by _hash_recordings() after the transaction.
                "sha256": None, "bytes": None, "link_count": None, "catalog_match": False,
                "_catalog_sha256": segment["sha256"],
                "source_id": segment["source_id"],
                "start_ms": segment["start_ms"], "end_ms": segment["end_ms"],
                "media_ms": (segment["end_ms"] - segment["start_ms"]
                             if type(segment["end_ms"]) is int
                             and type(segment["start_ms"]) is int else None),
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
        discontinuities = sorted(markers.get(row["id"], ()))
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
            "segment_media_ms": (sum(item["media_ms"] for item in items)
                                 if all(item["media_ms"] is not None for item in items)
                                 else None),
            # Owner decision 2026-10-05: a recording with no linked segment
            # (interrupted before any segment, an event over a source with
            # no media) is recorded explicitly as having no evidence; only
            # its row is preserved, never media.
            "evidence": "linked_segments" if items else "no_evidence",
            "segments": items,
            "discontinuities": discontinuities,
            "content_sha256": None,
            "container_duration": "manual",
            "decode_verification": "manual",
        }
    return result


def _spool_segments(connection, tables) -> dict | None:
    """Every ready pre-roll spool row (spool=1), read in the snapshot.

    RecordingStore._start() links each overlapping one into a new recording
    without re-validating it, so its file is checked like linked evidence
    (_hash_spool()). Its stream position also tells which unlinked
    publication moved a source cursor after the record (_prior_publication()).
    """
    if "recording_segments" not in tables:
        return None
    return {row["id"]: {
        "source_id": row["source_id"], "stream_id": row["stream_id"],
        "sequence": row["sequence"], "start_ms": row["start_ms"], "end_ms": row["end_ms"],
        "_catalog": [row["sha256"], row["byte_length"]], "catalog_match": False,
    } for row in connection.execute(
        "SELECT id, source_id, stream_id, sequence, start_ms, end_ms, sha256, byte_length "
        "FROM recording_segments WHERE state = 'ready' AND spool = 1 ORDER BY id")}


def _source_cursors(connection, tables) -> dict | None:
    """The publish cursor per source (stream, sequence, end), as
    RecordingStore._publish() leaves it; a reference for the first
    publication into a recording that had no segment at record time."""
    if "recording_source_cursors" not in tables:
        return None
    return {row["source_id"]: [row["stream_id"], row["sequence"], row["end_ms"]]
            for row in connection.execute(
                "SELECT source_id, stream_id, sequence, end_ms FROM recording_source_cursors")}


def _pending_segments(connection, tables) -> dict | None:
    """Every pending catalog row: RecordingStore._recover() deletes each one
    with its file at the next start, so none may be a published segment."""
    if "recording_segments" not in tables:
        return None
    return {str(row["id"]): {"source_id": row["source_id"], "start_ms": row["start_ms"],
                             "end_ms": row["end_ms"]}
            for row in connection.execute(
                "SELECT id, source_id, start_ms, end_ms FROM recording_segments "
                "WHERE state = 'pending'")}


def _publications_since(connection, tables, cursors) -> dict | None:
    """Every ready catalog segment published after the record, spool flag aside.

    ``cursors`` is the source cursor map the baseline kept: a segment of a
    source starting at or after its recorded cursor end (append() admits
    nothing earlier), or any segment of a source that had no cursor then,
    was published since the record. Linked or not, spooled or released
    (release_source() clears spool on linked segments too). ``None`` when
    recording, or when the baseline kept no cursors.
    """
    if not isinstance(cursors, dict) or "recording_segments" not in tables:
        return None
    result = {}
    for row in connection.execute(
            "SELECT id, source_id, stream_id, sequence, start_ms, end_ms "
            "FROM recording_segments WHERE state = 'ready'"):
        recorded = cursors.get(row["source_id"])
        if type(row["start_ms"]) is not int or type(row["end_ms"]) is not int:
            # Malformed bounds are compared nowhere: the segment row check
            # already reports the row (invalid_value), failing verification.
            continue
        if recorded is None or (isinstance(recorded, list) and len(recorded) == 3
                                and type(recorded[2]) is int
                                and row["start_ms"] >= recorded[2]):
            result[row["id"]] = {
                "source_id": row["source_id"], "stream_id": row["stream_id"],
                "sequence": row["sequence"], "start_ms": row["start_ms"],
                "end_ms": row["end_ms"]}
    return result


def _cursor_rows(connection, tables) -> dict | None:
    """Every column of each source cursor row, to check its transitions."""
    if "recording_source_cursors" not in tables:
        return None
    return {row["source_id"]: {key: row[key] for key in row.keys()}
            for row in connection.execute("SELECT * FROM recording_source_cursors")}


def _cached_digest(directory: Path, segment_id: str, cache: dict | None):
    """_file_digest(), read once per segment ID per run when ``cache`` is given.

    A segment shared by several recordings (overlapping event windows link
    the same pre-roll) or also still in the ready spool is hashed once
    (#132); every holder then sees the same observation of the file.
    """
    if cache is None:
        return _file_digest(directory, segment_id)
    if segment_id not in cache:
        cache[segment_id] = _file_digest(directory, segment_id)
    return cache[segment_id]


def _observed_matches(observed: tuple, catalog: list) -> bool:
    digest, size, links = observed
    return digest is not None and [digest, size] == catalog and links == 1


def _spool_file_matches(directory: Path, segment_id: str, catalog: list) -> bool:
    return _observed_matches(_file_digest(directory, segment_id), catalog)


def _hash_spool(spool: dict | None, directory: Path, database: Path,
                cache: dict | None = None) -> list:
    """Hash every ready spool file outside the snapshot; return the mismatches.

    A file that does not match its catalog digest, byte length or single
    hard link is reported unless its row has since left the ready spool
    (_trim() clears spool=1 before it unlinks an unreferenced file), so a
    live writer's eviction during hashing is not a loss. ``cache`` holds the
    digests _hash_recordings() already read; a mismatch is re-read uncached.
    """
    mismatched = []
    for segment_id, item in (spool or {}).items():
        catalog = item.pop("_catalog")
        # A spool segment also linked into a recording was already read.
        item["catalog_match"] = (_observed_matches(cache[segment_id], catalog)
                                 if cache is not None and segment_id in cache
                                 else _spool_file_matches(directory, segment_id, catalog))
        if not item["catalog_match"]:
            mismatched.append((segment_id, catalog))
    if not mismatched:
        return []
    connection = _connect_read_only(database)
    try:
        still = []
        for segment_id, catalog in mismatched:
            row = connection.execute(
                "SELECT sha256, byte_length FROM recording_segments WHERE id = ? "
                "AND state = 'ready' AND spool = 1", (segment_id,)).fetchone()
            if row is None:
                del spool[segment_id]
            elif ([row[0], row[1]] != catalog
                  or not _spool_file_matches(directory, segment_id, catalog)):
                still.append(segment_id)
            else:
                spool[segment_id]["catalog_match"] = True
    except sqlite3.Error:
        raise InventoryError("state database could not be read") from None
    finally:
        connection.close()
    return sorted(still)


def _hash_recordings(recordings: dict | None, directory: Path, database: Path | None = None,
                     recorded_at: str | None = None, cache: dict | None = None) -> None:
    """Hash every catalogued segment file, outside any database transaction.

    A ready segment's bytes are immutable, so hashing after the snapshot is
    equivalent; a file changed or removed meanwhile shows up as a change,
    except when the service's retention deleted the whole recording after
    the snapshot (_retention_gone()): such a recording is dropped, as if the
    snapshot had been taken after the deletion. Each segment file is read
    once (``cache``, by segment ID), however many recordings link it, so the
    run time grows with the distinct segments and their bytes, not with the
    number of links.
    """
    cache = {} if cache is None else cache
    for recording in (recordings or {}).values():
        for item in recording["segments"]:
            digest, size, links = _cached_digest(directory, item["segment_id"], cache)
            expected = item.pop("_catalog_sha256")
            # RecordingStore._integrity() needs the digest and the catalog
            # byte_length to match a file with exactly one hard link.
            item.update(sha256=digest, bytes=size, link_count=links,
                        catalog_match=(digest is not None and digest == expected
                                       and size == item["catalog"]["byte_length"]
                                       and links == 1))
        recording["content_sha256"] = _digest(
            [[item["segment_id"], item["sha256"]] for item in recording["segments"]])
    if database is not None and recordings:
        for key in _retention_gone(recordings, database, recorded_at):
            del recordings[key]


def _retention_gone(recordings: dict, database: Path, recorded_at: str | None) -> list:
    """Recordings whose files no longer match and that retention removed since.

    Mirrors the spool recheck: a fresh short read shows whether the row is
    gone (or being deleted); only one RetentionService could have removed
    (_retention_eligible() at the snapshot time) counts. Any other mismatch
    stays a failure.
    """
    suspects = [key for key, item in recordings.items()
                if not all(segment["catalog_match"] for segment in item["segments"])]
    if not suspects:
        return []
    try:
        moment = datetime.fromisoformat(recorded_at) if recorded_at else _common._utcnow()
    except (TypeError, ValueError):
        moment = _common._utcnow()
    cutoff = _retention_rules(moment)["recording_cutoff_ms"]
    connection = _connect_read_only(database)
    try:
        gone = []
        for key in suspects:
            row = connection.execute(
                "SELECT status FROM recordings WHERE id = ?", (key,)).fetchone()
            if ((row is None or row[0] == "deleting")
                    and _retention_eligible(recordings[key], cutoff)):
                gone.append(key)
        return gone
    except sqlite3.Error:
        raise InventoryError("state database could not be read") from None
    finally:
        connection.close()


def _source_discontinuities(connection, tables) -> list | None:
    """The per-source pre-roll gap markers (#132).

    RecordingStore._publish() adds one when a published segment does not
    continue the source cursor, and _start() copies every marker overlapping
    a new recording's window into that recording: a lost marker hides a
    stream discontinuity in the next event's playback. The rows hold only a
    source ID, two times and a fixed reason.
    """
    if "recording_source_discontinuities" not in tables:
        return None
    return sorted(([row[0], row[1], row[2], row[3]] for row in connection.execute(
        "SELECT source_id, start_ms, end_ms, reason FROM recording_source_discontinuities")),
        key=_row_order)


_RECORDING_STATUSES = frozenset({"active", "complete", "gapped", "interrupted", "deleting"})


_SEGMENT_INTEGRITY = frozenset({"unchecked", "verified", "corrupt", "missing", "unreadable"})


def _service_valid_segment_row(row, cursors) -> bool:
    try:
        keys = row.keys()
        node = row["capture_node_id"] if "capture_node_id" in keys else None
        RecordingStore._name(row["id"], ".seg")
        Segment(source_id=UUID(row["source_id"]), stream_id=UUID(row["stream_id"]),
                sequence=row["sequence"], start_ms=row["start_ms"], end_ms=row["end_ms"],
                codec=row["codec"], container=row["container"], data=b"\0",
                capture_node_id=None if node is None else UUID(node)).validate(_SEGMENT_BOUNDS)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError):
        return False
    identities = [row["id"], row["source_id"], row["stream_id"]] + ([] if node is None else [node])
    if not (all(_canonical_uuid(value) for value in identities)
            and _int(row["byte_length"], 1) and _hex_digest(row["sha256"])
            and row["state"] in ("pending", "ready") and row["spool"] in (0, 1)
            and ("critical" not in keys or row["critical"] in (0, 1))
            and ("integrity" not in keys or row["integrity"] in _SEGMENT_INTEGRITY)):
        return False
    cursor = None if cursors is None else cursors.get(row["source_id"])
    if cursor is not None and not (_int(cursor[2]) and _int(cursor[3])
                                   and isinstance(cursor[1], str)):
        return False
    if row["state"] == "pending":
        # append() inserts pending rows unspooled and unchecked, only past
        # the source cursor (RECORDING_TIMELINE_REGRESSION otherwise), and
        # _publish() advances the cursor only when the row turns ready. A
        # pending row at or behind the cursor is a published segment that
        # RecordingStore._recover() would delete with its file.
        return (row["spool"] == 0
                and ("integrity" not in keys or row["integrity"] == "unchecked")
                and (cursor is None or (row["start_ms"] >= cursor[3] and not (
                    row["stream_id"] == cursor[1] and row["sequence"] <= cursor[2]))))
    if cursors is None:
        return True
    # _publish() advances the source cursor with every ready segment and
    # append() only admits a segment starting at or after the cursor end, so
    # a ready segment ends at or before its source's cursor. The sequence is
    # not bounded: after a change to another stream, append() checks no
    # sequence, so a resumed stream may restart below rows it already wrote.
    return cursor is not None and row["end_ms"] <= cursor[3]


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


@_fail_closed(False)
def _declared_rewrite_only(base: dict, now: dict) -> bool:
    # The rewritten result must itself be servable: readable and matching its
    # catalog digest, byte length and single-link invariant.
    return (_evidenced(now) and all(segment["catalog_match"] for segment in now["segments"])
            and _without_media_bytes(base) == _without_media_bytes(now))


def _without_evidence(item: dict) -> bool:
    """A recording the store linked no segment to (Owner decision 2026-10-05):
    its row is kept and verified, but it is never preserved evidence."""
    return not item["segments"]


def _evidenced(item: dict) -> bool:
    # A link to a segment that is not 'ready' (a publication never finished)
    # is not servable evidence, so such a recording is never preserved.
    return bool(item["segments"]) and all(
        segment.get("state") == "ready" and segment["sha256"] is not None
        for segment in item["segments"])


def _servable(item: dict) -> bool:
    """Evidence verify can count as preserved (#132): every linked segment is
    ready, readable and matches its catalog digest, byte length and single
    hard link (RecordingStore._integrity()). A recording already corrupt at
    record time never makes a coverage item present."""
    return _evidenced(item) and all(segment["catalog_match"] for segment in item["segments"])


# Statuses an 'active' recording may reach (store.py: stop / reconcile /
# interrupted-at-startup); 'deleting' rows are not inventoried.
_ACTIVE_SUCCESSORS = frozenset({"active", "complete", "gapped", "interrupted"})


@_fail_closed(False)
def _valid_growth(base: dict, now: dict, context: dict | None = None) -> bool:
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
    # A row without evidence may grow too (its first segment published, or
    # closed with none); linked segments must all be readable evidence.
    if (base["status"] != "active" or now["status"] not in _ACTIVE_SUCCESSORS
            or not (_without_evidence(base) or _evidenced(base))
            or not (_without_evidence(now) or _evidenced(now))):
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
    return _appended_publications_valid(base, now, remaining, context or {})


@_fail_closed(False)
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
                                  max_segment_ms=MAX_LIMIT_DURATION_MS, max_active_recordings=1,
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


@_fail_closed(False)
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
    # COALESCE(latest linked end, start_ms): no linked segment ends it at its start.
    return min(now["target_end_ms"], max((item["end_ms"] for item in now["segments"]),
                                         default=now["start_ms"]))


@_fail_closed(False)
def _appended_publications_valid(base: dict, now: dict, remaining: Counter,
                                 context: dict) -> bool:
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
    ordered = sorted(now["segments"], key=lambda item: (item["start_ms"], item["end_ms"]))
    if not base["segments"]:
        # Nothing was linked at record time: the first new segment followed
        # the source cursor recorded then, or an unlinked publication since
        # (_prior_publication()). Its publication adds one marker ending at
        # its start whenever it does not continue that cursor.
        if not ordered:
            return not +remaining
        allowed = _publication_markers(ordered)
        if allowed is None or +(allowed - remaining):
            return False
        extra = list((+remaining - allowed).elements())
        first = ordered[0]
        found, prior = _prior_publication(first, now, context)
        if not found:
            # No recorded cursor (a baseline written before it was kept):
            # at most one marker ending at the segment's start.
            return not extra or (len(extra) == 1 and extra[0][2] == "stream_discontinuity"
                                 and extra[0][0] <= extra[0][1] == first["start_ms"])
        if prior is not None and first["start_ms"] < prior[2]:
            return False  # append() refuses a start before the cursor end
        lower = prior[2] if prior is not None else None
        single = (len(extra) == 1 and extra[0][2] == "stream_discontinuity"
                  and extra[0][1] == first["start_ms"]
                  and (lower is None or lower <= extra[0][0]) and extra[0][0] <= extra[0][1])
        if prior is None or (first["catalog"]["stream_id"] == prior[0]
                             and first["catalog"]["sequence"] == prior[1] + 1):
            # The first publication on the source, or one continuing the
            # cursor: a marker only if an evicted publication came between.
            return not extra or single
        if (not extra and now["status"] != "active"
                and first["start_ms"] <= now["start_ms"]):
            # finish() deletes a marker wholly before the closed window.
            return True
        # The marker is due; it may start later only if an evicted
        # (no longer catalogued) publication moved the cursor in between.
        return single
    recorded = {item["segment_id"] for item in base["segments"]}
    first_new = next((index for index, item in enumerate(ordered)
                      if item["segment_id"] not in recorded), len(ordered))
    if first_new == 0 or any(item["segment_id"] in recorded for item in ordered[first_new:]):
        return False
    allowed = _publication_markers(ordered[first_new - 1:])
    # The store adds the marker in the same transaction that links the
    # segment, so each one must be present exactly once.
    return allowed is not None and +remaining == allowed


def _published_since_record(source_id: str, context: dict) -> list | None:
    """Segments of ``source_id`` published after the record, as catalogued now.

    Every ready catalog row of the source, whatever its spool flag or links,
    that starts at or after the source cursor recorded at record time
    (append() admits nothing earlier), or every one when the source had no
    cursor then (_publications_since()): ``(start, end, stream, sequence,
    segment ID)``. ``None`` when the baseline kept no cursors.
    """
    cursors = context.get("cursors")
    if cursors is None:
        return None
    published = context.get("published")
    if published is not None:
        # The whole ready catalog past the recorded cursors (verify).
        return [(item["start_ms"], item["end_ms"], item["stream_id"], item["sequence"],
                 segment_id) for segment_id, item in published.items()
                if item["source_id"] == source_id]
    # Without that snapshot (a direct compare()), what the inventory lists.
    recorded = cursors.get(source_id)
    floor = None if recorded is None else recorded[2]
    found = {}
    for recording in (context.get("recordings") or {}).values():
        for item in recording["segments"]:
            if item["source_id"] == source_id:
                found[item["segment_id"]] = (item["start_ms"], item["end_ms"],
                                             item["catalog"]["stream_id"],
                                             item["catalog"]["sequence"], item["segment_id"])
    for segment_id, item in (context.get("spool") or {}).items():
        if item["source_id"] == source_id:
            found.setdefault(segment_id, (item["start_ms"], item["end_ms"], item["stream_id"],
                                          item["sequence"], segment_id))
    return [entry for entry in found.values() if floor is None or entry[0] >= floor]


def _overlaps(recording: dict, start_ms, end_ms) -> bool:
    """RecordingStore._publish()'s rule: it links a publication to every
    active recording of its source with ``start_ms < end`` and
    ``target_end_ms > start``."""
    return recording["start_ms"] < end_ms and recording["target_end_ms"] > start_ms


@_fail_closed(True)
def _unlinked_publication(base: dict, now: dict, context: dict) -> bool:
    """Whether a publication the store must have linked to a recording is unlinked.

    One invariant over every recording active at record time (``base``) and
    every publication of its source since the record still catalogued now:
    RecordingStore._publish() links each publication overlapping the window
    of every recording that is active then (_overlaps()), and finish()
    unlinks only segments wholly outside the final window. A publication
    overlapping the current window must therefore be linked whenever it was
    made while the recording was still active, which is certain when

    - the recording is still active now;
    - it was stopped early (its target end moved before the recorded one):
      finish() closes a stop only once the source cursor reaches the stop, so
      every later publication starts at or after it and overlaps nothing; or
    - a segment still linked to it was published later.

    A recording closed at its own deadline or interrupted by a restart may
    miss a late publication legitimately, so a publication after its latest
    linked segment is not judged there (DEPLOYMENT.md limits). Not checked
    when the baseline kept no cursors.
    """
    published = _published_since_record(now["source_id"], context)
    if published is None:
        return False
    linked = {item["segment_id"] for item in now["segments"]}
    certain = now["status"] == "active" or now["target_end_ms"] < base["target_end_ms"]
    latest = max((item["start_ms"] for item in now["segments"]), default=None)
    return any(segment_id not in linked and _overlaps(now, start, end)
               and (certain or (latest is not None and end <= latest))
               for start, end, _, _, segment_id in published)


@_fail_closed(True)
def _missing_trailing_publication(base: dict, now: dict, context: dict) -> bool:
    """Whether the publication the source cursor names left with its link (#161).

    _unlinked_publication() sees only publications still catalogued; one
    removed together with its link and file leaves no row. The source cursor
    still names it: _publish() sets the cursor end to the end of the latest
    publication, and append() refuses a segment without a positive duration,
    so a cursor end inside ``(start_ms, target_end_ms]`` belongs to a
    publication overlapping the window. A cursor end beyond the target end
    belongs to one append() linked exactly when it starts before the target
    end (``start_ms < target_end_ms``, its linking rule): a removed row's
    start is not known, but append() admits it only at or after the end of
    every earlier publication (the recorded cursor end and each publication
    still catalogued since), so it is judged unless that bound already
    reaches the target end. An early stop's legitimate trim (finish() drops
    the links of segments starting at or after the stop, then _trim() may
    remove their rows) is therefore never judged when the segment before it
    reaches the stop; a removed latest segment behind a time gap across the
    target end fails closed (DEPLOYMENT.md limits). When the cursor advanced
    since the record and the recording was certainly active while that
    publication was made (still active now, or stopped early: finish()
    closes a stop only once the cursor reaches it), _publish() linked it and
    finish() kept the link, and _trim() deletes only unlinked rows; the
    segment ending at the cursor end must therefore still be catalogued. A
    recording closed at its own deadline or interrupted by a restart is not
    judged (a lagging source may publish after that close, unlinked, and the
    spool may evict it). Not checked when the baseline kept no cursors or the
    current one is unread.
    """
    cursors, current = context.get("cursors"), context.get("current_cursors")
    if cursors is None or current is None:
        return False
    if not (now["status"] == "active" or now["target_end_ms"] < base["target_end_ms"]):
        return False
    cursor, recorded = current.get(now["source_id"]), cursors.get(now["source_id"])
    if not (isinstance(cursor, list) and len(cursor) == 3 and _int(cursor[2])):
        return False  # a missing or malformed cursor is cursor_regressed / invalid_value
    end = cursor[2]
    if recorded is not None and not (isinstance(recorded, list) and len(recorded) == 3
                                     and _int(recorded[2]) and end > recorded[2]):
        return False  # not advanced since the record (or malformed: reported elsewhere)
    if not now["start_ms"] < end:
        return False  # wholly before the window: never linked
    published = _published_since_record(now["source_id"], context)
    if published is None or any(item[1] == end for item in published):
        return False  # still catalogued: _unlinked_publication() checks its link
    if end <= now["target_end_ms"]:
        return True
    # Straddling the target end, or wholly after it: append() linked it iff
    # it started before the target end, and it started at or after the end
    # of every earlier publication.
    floor = max([item[1] for item in published if item[1] < end]
                + ([recorded[2]] if recorded is not None else []), default=None)
    return floor is None or floor < now["target_end_ms"]


def _prior_publication(first: dict, now: dict, context: dict) -> tuple:
    """The cursor ``first`` was published after: ``(known, (stream, sequence, end) | None)``.

    It is the source cursor recorded at record time, advanced by the latest
    segment of the source published after it, still catalogued now and
    ending by ``first``'s start, that _publish() did not have to link to
    ``now`` (one overlapping its window is a required link, never a cursor
    explanation; _unlinked_publication() fails it). ``None`` as the cursor:
    the source had none and nothing was published before ``first`` (its
    first publication adds no marker). Not known when the baseline kept no
    cursors. A publication evicted from the spool since is not visible; the
    caller allows for that.
    """
    published = _published_since_record(now["source_id"], context)
    if published is None:
        return False, None
    prior = context["cursors"].get(now["source_id"])
    later = [(end, stream_id, sequence) for start, end, stream_id, sequence, segment_id
             in published if segment_id != first["segment_id"] and end <= first["start_ms"]
             and not _overlaps(now, start, end)]
    if later:
        end, stream_id, sequence = max(later)
        prior = [stream_id, sequence, end]
    return True, prior


def _publication_markers(ordered: list) -> Counter | None:
    """The markers publishing ``ordered[1:]`` after ``ordered[0]`` adds, or
    None when that order is one append() refuses."""
    allowed: Counter = Counter()
    for prior, segment in zip(ordered, ordered[1:]):
        same_stream = segment["catalog"]["stream_id"] == prior["catalog"]["stream_id"]
        if segment["start_ms"] < prior["end_ms"] or (
                same_stream and segment["catalog"]["sequence"] <= prior["catalog"]["sequence"]):
            return None
        contiguous = (same_stream
                      and segment["catalog"]["sequence"] == prior["catalog"]["sequence"] + 1)
        if not contiguous:
            allowed[(prior["end_ms"], segment["start_ms"], "stream_discontinuity")] += 1
    return allowed


@_fail_closed(False)
def _retention_eligible(item: dict, cutoff_ms: int | None) -> bool:
    """RecordingStore.retention_candidates() for RetentionService.expired()."""
    return (cutoff_ms is not None and not item["starred"]
            and item["status"] in ("complete", "gapped", "interrupted")
            and isinstance(item["ended_ms"], int) and item["ended_ms"] <= cutoff_ms)


def _compare_recordings(baseline: dict | None, current: dict | None, *,
                        declared: frozenset[str], retention_cutoff_ms: int | None = None,
                        context: dict | None = None) -> dict:
    result = _compare_keyed(baseline, current, declared=declared,
                            rewrite_only=_declared_rewrite_only)
    if result["status"] == "empty":
        result["retention_expired"] = []
        result["no_evidence"] = []
        return result
    if current is None:
        # The recording tables are gone or unreadable: never retention.
        retention_cutoff_ms = None
        result["failed"].append({"id": None, "reason": "table_missing"})
    current = current or {}
    preserved, failed, in_progress, without = [], [], [], []
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
        if _without_evidence(current[key]):
            # Its row survived unchanged; there is no media to preserve.
            without.append(key)
        elif not _evidenced(current[key]):
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
        if _valid_growth(base, now, context):
            failed.remove(entry)
            # Growth from a row without evidence keeps it out of preserved.
            (without if _without_evidence(base) else preserved).append(key)
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
    # Every recording active at record time, changed or not: each overlapping
    # publication since the record that the store linked is still linked,
    # including the latest one the source cursor names (#161).
    for key, base in sorted(baseline.items()):
        if (base["status"] == "active" and key in current
                and (_unlinked_publication(base, current[key], context or {})
                     or _missing_trailing_publication(base, current[key], context or {}))):
            preserved = [other for other in preserved if other != key]
            in_progress = [other for other in in_progress if other != key]
            without = [other for other in without if other != key]
            rewrites = [other for other in rewrites if other != key]
            if not any(entry["id"] == key for entry in failed):
                failed.append({"id": key, "reason": "changed"})
    for key, item in sorted(baseline.items()):
        if key not in preserved and key not in rewrites and key not in without:
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
        without = [other for other in without if other != key]
        failed.append({"id": key, "reason": reason})
    # RecordingStore._recover() deletes every pending row with its file at
    # the next start. A segment published at record time (linked or in the
    # ready spool), or one starting behind the source cursor recorded then
    # (append() admits nothing there), is never pending again.
    context = context or {}
    recorded_ready = {segment["segment_id"] for item in baseline.values()
                      for segment in item["segments"] if segment.get("state") == "ready"}
    recorded_ready |= set(context.get("recorded_spool") or ())
    cursors = context.get("cursors") or {}
    for segment_id, row in sorted((context.get("pending") or {}).items()):
        floor = cursors.get(row.get("source_id"))
        behind = (isinstance(floor, list) and len(floor) == 3 and type(floor[2]) is int
                  and type(row.get("start_ms")) is int and row["start_ms"] < floor[2])
        if segment_id in recorded_ready or behind:
            failed.append({"id": f"segment:{segment_id}", "reason": "published_segment_pending"})
    # A source cursor is never deleted and its end never moves back
    # (_publish() only advances it; release_source() only clears active).
    current_cursors = context.get("current_cursors")
    if current_cursors is not None:
        for source_id, recorded in sorted(cursors.items()):
            now_cursor = current_cursors.get(source_id)
            if not (isinstance(now_cursor, list) and len(now_cursor) == 3
                    and isinstance(recorded, list) and len(recorded) == 3
                    and _int(now_cursor[2]) and _int(recorded[2])
                    and now_cursor[2] >= recorded[2]):
                failed.append({"id": f"cursor:{source_id}", "reason": "cursor_regressed"})
    # A cursor changes only with a publication, which advances its end and
    # sets active (_publish()), or release_source(), which only clears
    # active. With its end unchanged every other column stays as recorded
    # (a rewritten stream or sequence would make the next same-stream append
    # fail RECORDING_TIMELINE_REGRESSION); an advanced end is checked against
    # the catalogued publication it names (_domain_errors()).
    recorded_rows, current_rows = context.get("cursor_rows") or (None, None)
    for source_id, before in sorted((recorded_rows or {}).items()):
        after = (current_rows or {}).get(source_id)
        if current_rows is None or after is None:
            continue  # missing: cursor_regressed
        if after.get("end_ms") != before.get("end_ms"):
            # Moved forward only with a publication: append() admits a
            # same-stream segment only with a higher sequence, and
            # _publish() writes the end with that segment's stream and
            # sequence (another stream: any sequence). A backward move is
            # cursor_regressed; a catalogued last segment is compared exactly
            # by the domain checks.
            # _publish() always leaves the advanced cursor active (#165): an
            # inactive one is not counted by append() against
            # RECORDING_SOURCE_LIMIT, so another source could take its slot.
            # Main never calls release_source(); if it ever does, a release
            # after a publication inside the window fails closed here.
            same_stream = after.get("stream_id") == before.get("stream_id")
            advanced = (_int(after.get("end_ms")) and _int(before.get("end_ms"))
                        and after["end_ms"] > before["end_ms"])
            if advanced and (after.get("active") != 1 or (
                    same_stream
                    and not (_int(after.get("sequence")) and _int(before.get("sequence"))
                             and after["sequence"] > before["sequence"]))):
                failed.append({"id": f"cursor:{source_id}", "reason": "cursor_changed"})
            continue
        unchanged = all(after.get(key) == value for key, value in before.items()
                        if key != "active")
        released = after.get("active") == before.get("active") or (
            before.get("active") == 1 and after.get("active") == 0)
        if not (unchanged and released and set(after) == set(before)):
            failed.append({"id": f"cursor:{source_id}", "reason": "cursor_changed"})
    # A recording that appeared since the record is listed as appended,
    # but its segments must still be ones the store would have linked.
    for key in result.get("appended", ()):
        if not _segments_consistent(current[key]):
            failed.append({"id": key, "reason": "invalid_segment"})
    result.update(status="failed" if failed else "preserved",
                  preserved=sorted(preserved), failed=failed,
                  no_evidence=sorted(without),
                  declared_rewrites=rewrites,
                  in_progress_at_record=sorted(in_progress),
                  retention_expired=sorted(retained_out))
    return result


# RecordingStore._trim()'s duration cutoff. Main builds its recording limits
# from RECORDING_LIMIT_FIELDS (monitoring configuration), which does not
# include pre_roll_ms, so every Main store runs with the Limits default. Were
# it ever made configurable, the largest value Limits admits is used instead:
# a marker is then accepted as trimmed only where any configuration trims it
# (a legitimate trim under a shorter window fails loudly, never the reverse).
_PRE_ROLL_MS = (RecordingLimits.__dataclass_fields__["pre_roll_ms"].default
                if "pre_roll_ms" not in RECORDING_LIMIT_FIELDS else MAX_LIMIT_DURATION_MS)


def _marker_trimmed(marker, spool: dict | None, cursor_rows: dict | None) -> bool:
    """Whether RecordingStore itself removed a source pre-roll marker.

    Only two paths delete one:

    - _trim() deletes a marker whose end is at or before T = (latest
      segment end of its source) - pre_roll_ms, its duration cutoff. Its
      byte / count eviction unspools segments but never deletes a marker,
      so an evicted spool alone is no evidence. _publish() sets the source
      cursor end to the end of the latest publication and append() runs
      _trim() right after it (or _recover() at the next start), with that
      segment still catalogued: the marker leaves exactly once the cursor
      end reaches ``end + pre_roll_ms``. The cursor end is compared with
      its recorded value and the catalog elsewhere (cursor_regressed /
      cursor_changed / invalid_value).
    - release_source() deletes every marker of the source and leaves its
      cursor inactive (only a later publication sets it active again, which
      the first rule then judges).

    Both also clear the spool flag of every segment of the source ending at
    or before the marker's end in the same transaction (a later publication
    starts past the cursor, beyond it), so a ready spool segment of the
    source still ending there is a loss either way.
    """
    source, end = marker[0], marker[2]
    if spool is None or cursor_rows is None or not _int(end):
        return False
    if any(item.get("source_id") == source
           and (not _int(item.get("end_ms")) or item["end_ms"] <= end)
           for item in spool.values()):
        return False
    cursor = cursor_rows.get(source)
    if not isinstance(cursor, dict):
        return False
    released = cursor.get("active") == 0
    trimmed = _int(cursor.get("end_ms")) and cursor["end_ms"] >= end + _PRE_ROLL_MS
    return bool(released or trimmed)


def _compare_source_discontinuities(baseline: list | None, current: list | None,
                                    spool: dict | None, cursor_rows: dict | None) -> dict:
    """Recorded markers stay, except those the duration trim or a release removed."""
    if not baseline:
        return {"status": "empty", "failed": [], "preserved_rows": 0,
                "appended": [_row_order(item) for item in current or ()]}
    if current is None:
        return {"status": "failed", "failed": [{"id": None, "reason": "table_missing"}]}
    remaining = Counter(_row_order(item) for item in current)
    preserved, trimmed, failed = 0, [], []
    for item in baseline:
        key = _row_order(item)
        if remaining[key]:
            remaining[key] -= 1
            preserved += 1
        elif _marker_trimmed(item, spool, cursor_rows):
            trimmed.append(key)
        else:
            failed.append({"id": f"marker:{item[0]}:{item[1]}:{item[2]}", "reason": "missing"})
    return {"status": "failed" if failed else "preserved", "failed": failed,
            "preserved_rows": preserved, "trimmed": trimmed,
            "appended": sorted(key for key, count in remaining.items() for _ in range(count))}
