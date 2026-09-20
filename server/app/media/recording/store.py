"""Single-writer durable segment spool and recording manifests.

The owning worker serializes calls; no network listener, decoder, background
thread, retention policy or implicit directory creation is provided here.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from uuid import UUID, uuid4
import fcntl
import hashlib
import os
import sqlite3
import stat
import threading

from .model import Limits, RecordingError, Segment, SegmentValidator, StoragePolicy


MAX_RECORDING_MS = 1_200_000


def _control_operation(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        self._check()
        with self._control_reservation():
            return method(self, *args, **kwargs)
    return guarded


@dataclass(frozen=True)
class RootIdentity:
    device: int
    inode: int


def _directory(path: Path) -> int:
    """Walk every component without following symlinks, including parents."""
    if not path.is_absolute() or ".." in path.parts:
        raise RecordingError("RECORDING_ROOT_UNAVAILABLE")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class RecordingStore:
    def __init__(self, connection: sqlite3.Connection, root: Path,
                 expected_root: RootIdentity, limits: Limits,
                 policy: StoragePolicy, validator: SegmentValidator):
        self.db = connection
        self.root = root
        self.expected_root = expected_root
        self.limits = limits
        self.policy = policy
        self.validator = validator
        self._owner = threading.get_ident()
        self._fd = -1
        self._failed = False
        self._reservation_active = False
        # The installed image uses /app/app/... without a checkout marker;
        # a fixed checkout parent count would accidentally identify '/' there.
        code_root = Path(__file__).resolve().parents[2]
        if root == code_root or code_root in root.parents:
            raise RecordingError("RECORDING_ROOT_INSIDE_CHECKOUT")
        # Also exclude another checkout/worktree instead of trusting this path.
        if any((parent / ".git").is_file() or (parent / ".git" / "HEAD").is_file()
               for parent in (root, *root.parents)):
            raise RecordingError("RECORDING_ROOT_INSIDE_CHECKOUT")
        try:
            self._fd = _directory(root)
            self._verify_root()
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.db.in_transaction:
                raise RecordingError("RECORDING_DATABASE_BUSY")
            if (self.db.execute("PRAGMA synchronous").fetchone()[0] < 2
                    or self.db.execute("PRAGMA journal_mode").fetchone()[0]
                    not in {"delete", "truncate", "persist", "wal"}):
                raise RecordingError("RECORDING_DATABASE_NOT_DURABLE")
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys = ON")
            self._recover()
        except (OSError, sqlite3.Error) as exc:
            self.close()
            if isinstance(exc, BlockingIOError):
                raise RecordingError("RECORDING_WRITER_BUSY") from None
            raise RecordingError("RECORDING_STORAGE_UNAVAILABLE") from None
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _check(self, *, allow_failed: bool = False) -> None:
        if self._fd < 0 or (self._failed and not allow_failed) or threading.get_ident() != self._owner:
            raise RecordingError("RECORDING_WRITER_UNAVAILABLE")
        self._verify_root()

    def _verify_root(self) -> None:
        descriptor = -1
        try:
            descriptor = _directory(self.root)
            current = os.fstat(descriptor)
            pinned = os.fstat(self._fd)
            identity = RootIdentity(current.st_dev, current.st_ino)
            if (identity != self.expected_root
                    or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)
                    or current.st_uid != os.geteuid() or current.st_mode & 0o077):
                raise RecordingError("RECORDING_ROOT_UNAVAILABLE")
        except OSError:
            raise RecordingError("RECORDING_ROOT_UNAVAILABLE") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @contextmanager
    def _control_reservation(self):
        owns_reservation = not self._reservation_active
        if owns_reservation:
            self.policy.admit_control()
            self._reservation_active = True
        try:
            yield
        finally:
            if owns_reservation:
                self._release_reservation()

    def control_reservation(self):
        """Reserve storage for one caller-owned audited control transaction."""
        self._check()
        return self._control_reservation()

    def _release_reservation(self):
        self._reservation_active = False
        try:
            self.policy.release()
        except BaseException:
            self._failed = True
            raise

    @contextmanager
    def _transaction(self):
        if self.db.in_transaction:
            raise RecordingError("RECORDING_DATABASE_BUSY")
        with self._control_reservation():
            try:
                self.db.execute("BEGIN IMMEDIATE")
                yield
                # Connection.commit() is a documented no-op when Python
                # sqlite3 runs with autocommit=True, even after explicit BEGIN.
                # Use SQL so the durable transaction closes in either mode.
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    @staticmethod
    def _name(segment_id: str, extension: str) -> str:
        # Even database contents cannot turn into an arbitrary path.
        return UUID(segment_id).hex + extension

    def _unlink(self, segment_id: str, extension: str) -> None:
        self._verify_root()
        try:
            os.unlink(self._name(segment_id, extension), dir_fd=self._fd)
        except FileNotFoundError:
            pass

    @_control_operation
    def _recover(self) -> None:
        # A journal row is committed before any media file exists. Only those
        # identified artifacts may be removed after interrupted publication.
        pending = self.db.execute(
            "SELECT id FROM recording_segments WHERE state='pending'"
        ).fetchall()
        for row in pending:
            self._unlink(row["id"], ".part")
            self._unlink(row["id"], ".seg")
        os.fsync(self._fd)
        with self._transaction():
            self.db.execute("DELETE FROM recording_segments WHERE state='pending'")
            self.db.execute(
                "UPDATE recordings SET status='interrupted', ended_ms="
                "MIN(target_end_ms,COALESCE((SELECT MAX(s.end_ms) FROM recording_segments s "
                "JOIN recording_links l ON l.segment_id=s.id WHERE l.recording_id=recordings.id),"
                "start_ms)) WHERE status='active'"
            )
        self._trim()
        # A normal delete transaction removes links before its cleanup can be
        # interrupted. Do not turn an inconsistent deletion journal into media
        # loss during startup: preserve the linked evidence and leave the
        # worker unavailable for an explicit recovery decision.
        if self.db.execute(
                "SELECT 1 FROM recordings r JOIN recording_links l ON l.recording_id=r.id "
                "WHERE r.status='deleting' LIMIT 1"
        ).fetchone():
            raise RecordingError("RECORDING_RECOVERY_REQUIRED")
        with self._transaction():
            self.db.execute("DELETE FROM recordings WHERE status='deleting'")

    def _write(self, segment_id: str, data: bytes) -> None:
        self._verify_root()
        descriptor = os.open(
            self._name(segment_id, ".part"),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=self._fd,
        )
        try:
            remaining = memoryview(data)
            while remaining:
                count = os.write(descriptor, remaining)
                if count <= 0:
                    raise OSError("short write")
                remaining = remaining[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._verify_root()
        # Generated random names are unique and never accepted from callers.
        os.link(self._name(segment_id, ".part"), self._name(segment_id, ".seg"),
                src_dir_fd=self._fd, dst_dir_fd=self._fd, follow_symlinks=False)
        os.unlink(self._name(segment_id, ".part"), dir_fd=self._fd)
        os.fsync(self._fd)

    def append(self, segment: Segment) -> UUID:
        """Persist an independently decodable segment from a trusted muxer.

        start/end are UTC milliseconds mapped by the upstream stream clock,
        not raw camera PTS. Sequence and generation remain separately auditable.
        A failed publication remains pending and blocks another append until
        reopening recovers it; it can never become healthy recorded media.
        """
        self._check()
        segment.validate(self.limits)
        self.validator.validate(segment)
        if self.db.execute("SELECT 1 FROM recording_segments WHERE state='pending'").fetchone():
            raise RecordingError("RECORDING_RECOVERY_REQUIRED")
        source_id = str(segment.source_id)
        source_count = self.db.execute(
            "SELECT COUNT(*) FROM recording_source_cursors WHERE active=1"
        ).fetchone()[0]
        known = self.db.execute(
            "SELECT 1 FROM recording_source_cursors WHERE source_id=? AND active=1", (source_id,)
        ).fetchone()
        if not known and source_count >= self.limits.max_sources:
            raise RecordingError("RECORDING_SOURCE_LIMIT")
        prior = self.db.execute(
            "SELECT * FROM recording_source_cursors WHERE source_id=?",
            (source_id,),
        ).fetchone()
        if prior and (segment.start_ms < prior["end_ms"] or
                      (str(segment.stream_id) == prior["stream_id"]
                       and segment.sequence <= prior["sequence"])):
            raise RecordingError("RECORDING_TIMELINE_REGRESSION")
        active = self.db.execute(
            "SELECT * FROM recordings WHERE source_id=? AND status='active' "
            "AND start_ms<? AND target_end_ms>?",
            (source_id, segment.end_ms, segment.start_ms),
        ).fetchall()
        for recording in active:
            count = self.db.execute("SELECT COUNT(*) FROM recording_links WHERE recording_id=?",
                                    (recording["id"],)).fetchone()[0]
            if count >= self.limits.max_segments_per_recording:
                raise RecordingError("RECORDING_SEGMENT_LIMIT")
        critical = any(row["critical"] for row in active)
        self.policy.admit(len(segment.data), critical=critical)
        self._reservation_active = True
        segment_id = str(uuid4())
        try:
            with self._transaction():
                self.db.execute(
                    "INSERT INTO recording_segments "
                    "(id,source_id,capture_node_id,stream_id,sequence,start_ms,end_ms,"
                    "codec,container,byte_length,sha256,state,spool,critical) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',0,?)",
                    (segment_id, source_id,
                     str(segment.capture_node_id) if segment.capture_node_id else None,
                     str(segment.stream_id), segment.sequence, segment.start_ms,
                     segment.end_ms, segment.codec, segment.container, len(segment.data),
                     hashlib.sha256(segment.data).hexdigest(), int(critical)),
                )
            self._write(segment_id, segment.data)
            self._publish(segment_id, segment, active, prior)
            self._trim()
            return UUID(segment_id)
        except (OSError, sqlite3.Error):
            self._failed = True
            raise RecordingError("RECORDING_WRITE_FAILED") from None
        except BaseException:
            # Cancellation and expected-root failures can also interrupt a
            # journaled publication. Refuse all further operations until recovery.
            self._failed = True
            raise
        finally:
            self._release_reservation()

    def _publish(self, segment_id, segment, active, prior):
        with self._transaction():
            self.db.execute(
                "UPDATE recording_segments SET state='ready',spool=1,integrity='verified' WHERE id=?",
                (segment_id,),
            )
            self.db.execute(
                "INSERT INTO recording_source_cursors VALUES (?,?,?,?,?,1) "
                "ON CONFLICT(source_id) DO UPDATE SET stream_id=excluded.stream_id, "
                "sequence=excluded.sequence,end_ms=excluded.end_ms, "
                "capture_node_id=excluded.capture_node_id,active=1",
                (str(segment.source_id), str(segment.stream_id), segment.sequence, segment.end_ms,
                 str(segment.capture_node_id) if segment.capture_node_id else None),
            )
            if prior and (str(segment.stream_id) != prior["stream_id"]
                          or segment.sequence != prior["sequence"] + 1):
                self.db.execute(
                    "INSERT OR IGNORE INTO recording_source_discontinuities VALUES (?,?,?,?)",
                    (str(segment.source_id), prior["end_ms"], segment.start_ms,
                     "stream_discontinuity"),
                )
            for recording in active:
                self.db.execute("INSERT INTO recording_links VALUES (?,?)",
                                (recording["id"], segment_id))
                if prior and (str(segment.stream_id) != prior["stream_id"]
                              or segment.sequence != prior["sequence"] + 1):
                    self.db.execute("INSERT INTO recording_discontinuities VALUES (?,?,?,?)",
                                    (recording["id"], prior["end_ms"], segment.start_ms,
                                     "stream_discontinuity"))

    @_control_operation
    def _trim(self) -> None:
        """Evict only unreferenced media; linked evidence survives spool eviction."""
        self._verify_root()
        with self._transaction():
            self.db.execute(
                "UPDATE recording_segments SET spool=0 WHERE spool=1 AND end_ms <= "
                "(SELECT MAX(b.end_ms) FROM recording_segments b "
                "WHERE b.source_id=recording_segments.source_id)-?",
                (self.limits.pre_roll_ms,),
            )
            rows = self.db.execute(
                "SELECT id,byte_length FROM recording_segments WHERE spool=1 ORDER BY end_ms,id"
            ).fetchall()
            total = sum(row["byte_length"] for row in rows)
            remaining = len(rows)
            for row in rows:
                if (total <= self.limits.pre_roll_bytes
                        and remaining <= self.limits.max_spool_segments):
                    break
                self.db.execute("UPDATE recording_segments SET spool=0 WHERE id=?", (row["id"],))
                total -= row["byte_length"]
                remaining -= 1
            self.db.execute(
                "DELETE FROM recording_source_discontinuities WHERE end_ms <= "
                "(SELECT MAX(s.end_ms) FROM recording_segments s "
                "WHERE s.source_id=recording_source_discontinuities.source_id)-?",
                (self.limits.pre_roll_ms,),
            )
        unused = self.db.execute(
            "SELECT id FROM recording_segments WHERE spool=0 AND state='ready' "
            "AND NOT EXISTS (SELECT 1 FROM recording_links WHERE segment_id=recording_segments.id)"
        ).fetchall()
        for row in unused:
            self._unlink(row["id"], ".seg")
            os.fsync(self._fd)
            with self._transaction():
                self.db.execute("DELETE FROM recording_segments WHERE id=?", (row["id"],))

    @_control_operation
    def release_source(self, source_id: UUID) -> None:
        """Explicitly release a disabled source's spool, preserving recording links."""
        self._check()
        if not isinstance(source_id, UUID):
            raise ValueError("invalid source identity")
        with self._transaction():
            self.db.execute("UPDATE recording_source_cursors SET active=0 WHERE source_id=?",
                            (str(source_id),))
            self.db.execute("UPDATE recording_segments SET spool=0 WHERE source_id=?",
                            (str(source_id),))
            self.db.execute("DELETE FROM recording_source_discontinuities WHERE source_id=?",
                            (str(source_id),))
        try:
            self._trim()
        except BaseException:
            # Cursor and spool state are already committed.  A failed cleanup
            # leaves the writer unable to make a safe next mutation, so require
            # an explicit close/reopen recovery boundary.
            self._failed = True
            raise

    def start_event(self, event_id: UUID, source_ids: tuple[UUID, ...], at_ms: int,
                    *, pre_ms: int = 30_000, post_ms: int = 120_000,
                    critical: bool = False) -> tuple[UUID, ...]:
        if not isinstance(event_id, UUID) or type(at_ms) is not int:
            raise ValueError("invalid event identity")
        if (type(pre_ms) is not int or type(post_ms) is not int or pre_ms < 0
                or post_ms <= 0 or pre_ms + post_ms > MAX_RECORDING_MS):
            raise ValueError("invalid event window")
        return self._start(source_ids, at_ms - pre_ms, at_ms + post_ms,
                           event_id=event_id, critical=critical)

    def start_manual(self, source_id: UUID, at_ms: int,
                     *, duration_ms: int = MAX_RECORDING_MS) -> UUID:
        if (type(at_ms) is not int or type(duration_ms) is not int
                or not 0 < duration_ms <= MAX_RECORDING_MS):
            raise ValueError("invalid manual duration")
        return self._start((source_id,), at_ms, at_ms + duration_ms)[0]

    def _start(self, sources, start_ms, end_ms, *, event_id=None, critical=False):
        self._check()
        if (type(start_ms) is not int or type(end_ms) is not int or start_ms < 0 or end_ms >= 2**63
                or type(critical) is not bool or not sources
                or len(sources) > self.limits.max_sources or len(set(sources)) != len(sources)
                or any(not isinstance(source, UUID) for source in sources)):
            raise ValueError("invalid recording request")
        # Even metadata-only starts need storage admission. The common policy
        # accounts for journal overhead and can suppress ordinary/manual work.
        self.policy.admit(0, critical=critical)
        self._reservation_active = True
        try:
            with self._transaction():
                if event_id and self.db.execute(
                        "SELECT 1 FROM recordings WHERE event_id=?", (str(event_id),)).fetchone():
                    raise RecordingError("RECORDING_EVENT_EXISTS")
                count = self.db.execute(
                    "SELECT COUNT(*) FROM recordings WHERE status='active'"
                ).fetchone()[0]
                if count + len(sources) > self.limits.max_active_recordings:
                    raise RecordingError("RECORDING_ACTIVE_LIMIT")
                identities = tuple(uuid4() for _ in sources)
                for source_id, recording_id in zip(sources, identities):
                    count = self.db.execute(
                        "SELECT COUNT(*) FROM recording_segments WHERE source_id=? "
                        "AND state='ready' AND spool=1 AND start_ms<? AND end_ms>?",
                        (str(source_id), end_ms, start_ms),
                    ).fetchone()[0]
                    if count > self.limits.max_segments_per_recording:
                        raise RecordingError("RECORDING_SEGMENT_LIMIT")
                    self.db.execute(
                        "INSERT INTO recordings "
                        "(id,source_id,event_id,start_ms,target_end_ms,ended_ms,status,critical) "
                        "VALUES (?,?,?,?,?,NULL,'active',?)",
                        (str(recording_id), str(source_id), str(event_id) if event_id else None,
                         start_ms, end_ms, int(critical)),
                    )
                    self.db.execute(
                        "INSERT INTO recording_links SELECT ?,id FROM recording_segments "
                        "WHERE source_id=? AND state='ready' AND spool=1 AND start_ms<? AND end_ms>?",
                        (str(recording_id), str(source_id), end_ms, start_ms),
                    )
                    self.db.execute(
                        "INSERT INTO recording_discontinuities SELECT ?,start_ms,end_ms,reason "
                        "FROM recording_source_discontinuities WHERE source_id=? "
                        "AND start_ms<? AND end_ms>?",
                        (str(recording_id), str(source_id), end_ms, start_ms),
                    )
            return identities
        finally:
            self._release_reservation()

    def advance(self, now_ms: int) -> None:
        """The owning worker closes deadlines after the bounded segment-close grace."""
        self._check()
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("invalid clock")
        rows = self.db.execute(
            "SELECT id FROM recordings WHERE status='active' "
            "AND target_end_ms + ? <=?", (self.limits.max_segment_ms, now_ms)
        ).fetchall()
        for row in rows:
            self.finish(UUID(row["id"]))

    @_control_operation
    def finish(self, recording_id: UUID, *, stop_ms: int | None = None) -> dict:
        self._check()
        row = self._recording(recording_id)
        if stop_ms is not None:
            if type(stop_ms) is not int or not row["start_ms"] < stop_ms <= row["target_end_ms"]:
                raise ValueError("invalid stop time")
        if row["status"] == "active":
            end_ms = stop_ms or row["target_end_ms"]
            cursor = self.db.execute(
                "SELECT end_ms FROM recording_source_cursors WHERE source_id=?", (row["source_id"],)
            ).fetchone()
            # A manual stop inside a still-open muxed segment remains active
            # through the same bounded close grace used by advance().  This
            # keeps the eventual overlapping segment linkable instead of
            # turning available bytes into a permanent manifest gap.
            close_now = stop_ms is None or (cursor is not None and cursor["end_ms"] >= end_ms)
            with self._transaction():
                self.db.execute(
                    "UPDATE recordings SET target_end_ms=?,ended_ms=?,status=? WHERE id=?",
                    (end_ms, end_ms if close_now else None,
                     "complete" if close_now else "active", str(recording_id)),
                )
                if close_now:
                    # A queued stop can precede segments already appended.
                    # Retain boundary overlap but release data wholly outside
                    # the requested clip.
                    self.db.execute(
                        "DELETE FROM recording_links WHERE recording_id=? AND segment_id IN "
                        "(SELECT id FROM recording_segments WHERE start_ms>=? OR end_ms<=?)",
                        (str(recording_id), end_ms, row["start_ms"]),
                    )
                    self.db.execute(
                        "DELETE FROM recording_discontinuities WHERE recording_id=? "
                        "AND (start_ms>=? OR end_ms<=?)",
                        (str(recording_id), end_ms, row["start_ms"]),
                    )
            if close_now:
                try:
                    self._trim()
                except BaseException:
                    self._failed = True
                    raise
        result = self.manifest(recording_id)
        if result["status"] == "gapped" or (result["gaps"] and result["status"] == "complete"):
            with self._transaction():
                self.db.execute("UPDATE recordings SET status='gapped' WHERE id=?", (str(recording_id),))
            result["status"] = "gapped"
        return result

    def _recording(self, recording_id):
        if not isinstance(recording_id, UUID):
            raise ValueError("invalid recording identity")
        row = self.db.execute("SELECT * FROM recordings WHERE id=?", (str(recording_id),)).fetchone()
        if row is None:
            raise RecordingError("RECORDING_NOT_FOUND")
        return row

    def _integrity(self, segment):
        descriptor = -1
        try:
            self._verify_root()
            descriptor = os.open(self._name(segment["id"], ".seg"),
                                 os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 dir_fd=self._fd)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_size != segment["byte_length"]
                    or info.st_size > self.limits.max_segment_bytes):
                return "corrupt"
            digest = hashlib.sha256()
            remaining = info.st_size
            while remaining:
                part = os.read(descriptor, min(65_536, remaining))
                if not part:
                    return "corrupt"
                remaining -= len(part)
                digest.update(part)
            return "verified" if digest.hexdigest() == segment["sha256"] else "corrupt"
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unreadable"
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def manifest(self, recording_id: UUID) -> dict:
        """Local metadata only; caller must authorize any eventual browser route.

        Integrity means stored bytes match the muxer's bytes. Playback/decoding
        validation remains a separate codec adapter responsibility.
        """
        self._check()
        row = self._recording(recording_id)
        segments = self.db.execute(
            "SELECT s.* FROM recording_segments s JOIN recording_links l ON l.segment_id=s.id "
            "WHERE l.recording_id=? ORDER BY s.start_ms,s.id", (str(recording_id),)
        ).fetchall()
        result = dict(row)
        result["segments"] = []
        result["gaps"] = []
        result["pending"] = []
        cursor = row["start_ms"]
        end = row["target_end_ms"]
        for segment in segments:
            start = max(row["start_ms"], segment["start_ms"])
            stop = min(end, segment["end_ms"])
            if stop <= start:
                continue
            if start > cursor:
                result["gaps"].append({"start_ms": cursor, "end_ms": start, "reason": "unavailable"})
            integrity = self._integrity(segment)
            item = dict(segment)
            item.update(clip_start_ms=start, clip_end_ms=stop, integrity=integrity)
            result["segments"].append(item)
            if integrity != "verified":
                result["gaps"].append({"start_ms": start, "end_ms": stop, "reason": integrity})
            cursor = max(cursor, stop)
        if cursor < end:
            bucket = "pending" if row["status"] == "active" else "gaps"
            reason = "awaiting_media" if bucket == "pending" else "unavailable"
            result[bucket].append({"start_ms": cursor, "end_ms": end, "reason": reason})
        discontinuities = self.db.execute(
            "SELECT start_ms,end_ms,reason FROM recording_discontinuities "
            "WHERE recording_id=? AND start_ms<? AND end_ms>? ORDER BY start_ms",
            (str(recording_id), end, row["start_ms"]),
        ).fetchall()
        result["discontinuities"] = [dict(item) for item in discontinuities]
        for previous, current in zip(segments, segments[1:]):
            if (previous["stream_id"] != current["stream_id"]
                    or current["sequence"] != previous["sequence"] + 1):
                marker = {"start_ms": previous["end_ms"], "end_ms": current["start_ms"],
                          "reason": "stream_discontinuity"}
                if marker not in result["discontinuities"]:
                    result["discontinuities"].append(marker)
        bounded = []
        seen = set()
        for marker in result["discontinuities"]:
            if marker["start_ms"] >= end or marker["end_ms"] <= row["start_ms"]:
                continue
            key = (max(row["start_ms"], marker["start_ms"]),
                   min(end, marker["end_ms"]), marker["reason"])
            if key not in seen:
                bounded.append({"start_ms": key[0], "end_ms": key[1], "reason": key[2]})
                seen.add(key)
        result["discontinuities"] = bounded
        result["byte_length"] = sum(item["byte_length"] for item in result["segments"])
        if result["status"] == "complete" and (result["gaps"] or result["discontinuities"]):
            result["status"] = "gapped"
        result["integrity_persisted"] = True
        try:
            with self._transaction():
                for item in result["segments"]:
                    self.db.execute("UPDATE recording_segments SET integrity=? WHERE id=?",
                                    (item["integrity"], item["id"]))
                if result["status"] != row["status"]:
                    self.db.execute("UPDATE recordings SET status=? WHERE id=?",
                                    (result["status"], str(recording_id)))
        except RecordingError as exc:
            if str(exc) not in {"STORAGE_HARD_STOP", "STORAGE_PRESSURE"}:
                raise
            # Read-only playback/integrity reporting remains useful on a full
            # disk. The denied update is explicit and never crosses the reserve.
            result["integrity_persisted"] = False
        return result

    def event_manifest(self, event_id: UUID) -> dict:
        self._check()
        if not isinstance(event_id, UUID):
            raise ValueError("invalid event identity")
        rows = self.db.execute(
            "SELECT id FROM recordings WHERE event_id=? ORDER BY source_id", (str(event_id),)
        ).fetchall()
        if not rows:
            raise RecordingError("RECORDING_EVENT_NOT_FOUND")
        return {"event_id": str(event_id),
                "recordings": [self.manifest(UUID(row["id"])) for row in rows]}

    @_control_operation
    def set_starred(self, recording_id: UUID, starred: bool) -> None:
        """Domain operation; an Owner-authorized caller is mandatory upstream."""
        self._check()
        self._recording(recording_id)
        if type(starred) is not bool:
            raise ValueError("invalid starred state")
        with self._transaction():
            self.db.execute("UPDATE recordings SET starred=? WHERE id=?",
                            (int(starred), str(recording_id)))

    def set_starred_on(self, connection, recording_id: UUID, starred: bool) -> None:
        """Transactional Owner integration; connection must be this writer's."""
        self._check()
        if connection is not self.db or not connection.in_transaction:
            raise RecordingError("RECORDING_DATABASE_BUSY")
        self._recording(recording_id)
        if type(starred) is not bool:
            raise ValueError("invalid starred state")
        with self._control_reservation():
            connection.execute(
                "UPDATE recordings SET starred=? WHERE id=?",
                (int(starred), str(recording_id)),
            )

    def usage_bytes(self, *, starred_only: bool = False, critical_only: bool = False) -> int:
        """Unique journaled bytes, conservatively including pending writes.

        This is media accounting, not statvfs free space. The admission service
        must separately include metadata, unknown files and other filesystem use.
        """
        self._check(allow_failed=True)
        if type(starred_only) is not bool or type(critical_only) is not bool:
            raise ValueError("invalid usage request")
        filters = []
        if starred_only:
            filters.append("EXISTS (SELECT 1 FROM recording_links l JOIN recordings r "
                           "ON r.id=l.recording_id WHERE l.segment_id=s.id AND r.starred=1)")
        if critical_only:
            filters.append("((s.state='pending' AND s.critical=1) OR EXISTS "
                           "(SELECT 1 FROM recording_links l JOIN recordings r ON r.id=l.recording_id "
                           "WHERE l.segment_id=s.id AND r.critical=1))")
        return self.db.execute(
            "SELECT COALESCE(SUM(byte_length),0) FROM recording_segments s "
            + ("WHERE " + " AND ".join(filters) if filters else "")
        ).fetchone()[0]

    @staticmethod
    def _page(limit, offset=0):
        if (type(limit) is not int or not 1 <= limit <= 1000
                or type(offset) is not int or offset < 0 or offset >= 2**63):
            raise ValueError("invalid recording page")

    def list_recordings(self, *, limit: int, offset: int = 0) -> tuple[dict, ...]:
        """Bounded local summaries; human access still requires recordings:view."""
        self._check()
        self._page(limit, offset)
        rows = self.db.execute(
            "SELECT * FROM recordings WHERE status!='deleting' ORDER BY start_ms DESC,id LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def retention_candidates(self, *, before_ms: int | None, limit: int) -> tuple[dict, ...]:
        self._check()
        self._page(limit)
        if before_ms is not None and (type(before_ms) is not int or not 0 <= before_ms < 2**63):
            raise ValueError("invalid retention cutoff")
        rows = self.db.execute(
            "SELECT * FROM recordings WHERE starred=0 AND status IN ('complete','gapped','interrupted') "
            "AND (? IS NULL OR ended_ms<=?) ORDER BY ended_ms,id LIMIT ?",
            (before_ms, before_ms, limit),
        ).fetchall()
        return tuple(dict(row) for row in rows)

    @_control_operation
    def delete_recording(self, recording_id: UUID, *, owner_requested: bool = False) -> int:
        """Delete one eligible recording; return actual unique media bytes reclaimed.

        Owner authorization is checked by the calling service, never inferred
        from this flag. Automatic retention cannot delete starred or active work.
        Links held by other recordings or the pre-roll spool remain intact.
        """
        self._check()
        if type(owner_requested) is not bool:
            raise ValueError("invalid deletion request")
        with self._transaction():
            before = self.prepare_delete_on(
                self.db, recording_id, owner_requested=owner_requested,
            )
        return self.finish_prepared_delete(recording_id, before)

    def prepare_delete_on(self, connection, recording_id: UUID, *,
                          owner_requested: bool) -> int:
        """Journal logical deletion inside a caller-owned audit transaction."""
        self._check()
        if (connection is not self.db or not connection.in_transaction
                or type(owner_requested) is not bool):
            raise RecordingError("RECORDING_DATABASE_BUSY")
        with self._control_reservation():
            before = self.usage_bytes()
            row = self._recording(recording_id)
            if row["status"] == "active" or (row["starred"] and not owner_requested):
                raise RecordingError("RECORDING_DELETE_REFUSED")
            connection.execute(
                "UPDATE recordings SET status='deleting' WHERE id=?", (str(recording_id),)
            )
            connection.execute(
                "DELETE FROM recording_links WHERE recording_id=?", (str(recording_id),)
            )
            connection.execute(
                "DELETE FROM recording_discontinuities WHERE recording_id=?", (str(recording_id),)
            )
        return before

    @_control_operation
    def finish_prepared_delete(self, recording_id: UUID, before: int) -> int:
        """Complete media cleanup after the durable deletion journal commits."""
        self._check()
        if type(before) is not int or before < 0:
            raise ValueError("invalid deletion accounting")
        try:
            self._trim()
            with self._transaction():
                self.db.execute("DELETE FROM recordings WHERE id=?", (str(recording_id),))
            return before - self.usage_bytes()
        except BaseException:
            self._failed = True
            raise
