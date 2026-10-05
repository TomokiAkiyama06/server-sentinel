"""Durable precedence, neutral history, and presence-independent critical work."""

from contextlib import ExitStack, closing, contextmanager
from dataclasses import replace
from datetime import timedelta
import fcntl
import json
import os
import sqlite3
import stat
import threading
import time
from uuid import UUID, uuid4

from .access import DenyAccess
from .delivery import ActionResult
from .models import (CRITICAL, InvalidObservation, Kind, Observation, PresenceState, Quality,
                     Value, timestamp, utc)
from app.storage.database import PinnedDatabase
from app.storage.retention import RetentionPeriods


ARMED = "armed"
UNAVAILABLE = "unavailable"
UNKNOWN = "unknown"

# Kinds whose `occurred_at` is a capture-source timestamp. Health, storage,
# recording, presence and configuration facts are dated by the main host, so
# they neither advance nor are checked against a source's clock high-water
# mark: a main-host health stamp must not make a later-processed source
# observation from that camera look reordered.
SOURCE_CLOCK = frozenset({Kind.PERSON, Kind.MOTION, Kind.OWNER_ENTRY, Kind.OWNER_EXIT,
                          Kind.ANONYMOUS_ENTRY, Kind.ANONYMOUS_EXIT, *CRITICAL})
# Critical observations are recorded synchronously while other source facts
# wait in the bounded `TimelineOutbox`, so the two reach presence out of source
# order by design. Each keeps its own per-source high-water mark: a critical
# write never makes an earlier staged crossing look reordered, and ordering
# within either path is still checked.
SOURCE_CLOCK_TABLES = {kind: "presence_critical_source_clock" if kind in CRITICAL else "presence_source_clock"
                       for kind in SOURCE_CLOCK}
# Payload fields a producer stamps at the moment presence receives the fact.
RECEIPT_FIELDS = ("received_at", "clock_trusted", "confirmed")


# How long an outbox open waits for the committed-session lock. Only
# read-only status probes take it (shared, for an instant) while the session
# mutex is held, so a short bounded wait covers them; a lock still held after
# it is not a probe and fails the open.
COMMITTED_LOCK_WAIT = 2.0
COMMITTED_LOCK_POLL = 0.005


# The first 16 bytes of every SQLite database file. Header bytes 18 and 19
# are the file-format write and read versions: 2 selects WAL, which is
# persistent in the file itself rather than per connection.
SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_FORMAT = 2
WAL_SIDECARS = ("-wal", "-shm")


def _wal_database(path):
    """Whether the file at ``path`` is a SQLite database in WAL mode.

    A missing file is not WAL here: the read-only open that follows fails
    instead of creating it. An empty or foreign file is not WAL either, and a
    rollback-journal read never creates a file beside the database.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY)
    except FileNotFoundError:
        return False
    except OSError:
        raise ValueError("database location is unavailable") from None
    try:
        header = os.pread(descriptor, 20, 0)
    finally:
        os.close(descriptor)
    return len(header) == 20 and header[:16] == SQLITE_MAGIC and WAL_FORMAT in (header[18], header[19])


def _sidecars_present(path):
    """Whether both WAL sidecars already exist as regular files beside ``path``."""
    for suffix in WAL_SIDECARS:
        try:
            info = os.lstat(path.with_name(path.name + suffix))
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode):
            return False
    return True


# Outbox sessions that are live in this process, per database file. A status
# or clear from another `PresenceService` instance over the same database in
# this process reads the owning outbox's in-memory backlog from here.
_LIVE_SESSIONS = {}
_LIVE_SESSIONS_LOCK = threading.Lock()


def _lock_committed(descriptor):
    """Take the committed-session lock exclusively, waiting out status probes."""
    deadline = time.monotonic() + COMMITTED_LOCK_WAIT
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise RuntimeError("timeline committed-session lock stayed held") from None
            time.sleep(COMMITTED_LOCK_POLL)


class TimelineSession:
    """An open outbox session: its durable token and the locks that prove it live.

    ``descriptor`` holds the session mutex from the start of the open. The
    committed lock is taken only once the session row has committed, so a
    reader that sees it held knows the open converted every stale row.
    """

    def __init__(self, token, descriptor):
        self.token = token
        self._descriptor = descriptor
        self._committed = None
        # Loss the outbox holding this session has counted but not yet
        # written to the durable marker. The outbox replaces it with a reader
        # of its own counts, so Owner status sees that loss before it lands.
        self.unpersisted = lambda: 0
        # Staged facts awaiting a successful write, that loss count and the
        # facts quarantined after a permanent build fault, read in one critical
        # section of the outbox so a fact moving between them is never missed
        # by a status read.
        self.backlog = lambda: (0, self.unpersisted(), 0)
        # Consecutive flushes a transient storage, database or clock failure
        # stopped before the head fact was written.
        self.failures = lambda: 0

    @property
    def live(self):
        return self._descriptor is not None

    def release(self):
        """Release the locks; the kernel does the same when the process dies."""
        committed, self._committed = self._committed, None
        descriptor, self._descriptor = self._descriptor, None
        if committed is not None:
            os.close(committed)
        if descriptor is not None:
            os.close(descriptor)


class PresenceService:
    def __init__(self, database, *, access=None, evidence=None, notifications=None,
                 reservation=None, detection=None, storage_status=None,
                 periods: RetentionPeriods = RetentionPeriods()):
        if not isinstance(periods, RetentionPeriods):
            raise ValueError("retention periods required")
        self.database = database
        self.periods = periods
        self.access = access or DenyAccess()
        self.evidence = evidence
        self.notifications = notifications
        # Storage admission port supplied by #21, such as
        # `MainStoragePolicy.control`: a callable returning a reservation
        # context manager. Presence holds it for the whole write, so the hard
        # filesystem reserve is honoured and the reservation is released again.
        self.reservation = reservation
        # Optional read-only storage health probe from #21, such as a bounded
        # wrapper over MainStoragePolicy.status(). Status reads use it instead
        # of taking a write reservation of their own.
        self.storage_status = storage_status
        # Injected by the reviewed #24 detector supervisor. Absent means unknown
        # detection health here; this module never claims a detector is running.
        self.detection = detection

    @contextmanager
    def _read(self):
        """A connection for status and history reads that never writes unadmitted.

        Reads must never create a database: SQLite's ``mode=ro`` opens an
        existing file or fails, with no check-then-create window if the file
        or its mount disappears. A ``PinnedDatabase`` keeps its pin checks, so
        a replaced or unlinked file at the same path is refused instead of read.

        A read normally takes no storage reservation. A WAL database is the
        exception: when its ``-wal``/``-shm`` sidecars are missing, SQLite
        creates them even for a ``mode=ro`` connection whenever the directory
        is writable, and a read-only connection can never remove them again.
        That read therefore runs under the storage reservation, through a
        no-create read-write connection with ``query_only`` set, so the
        sidecars it creates are removed again when it closes as the last
        connection. A refused or missing reservation fails the read instead of
        writing outside it. ``immutable`` is never used: it would read a file
        a live writer is changing as if nothing could change it.
        """
        with ExitStack() as held:
            path = self.database.path
            if not path.is_absolute() or path.is_symlink():
                raise ValueError("database location is unavailable")
            admitted = _wal_database(path) and not _sidecars_present(path)
            if admitted:
                held.enter_context(self._admission())
            if isinstance(self.database, PinnedDatabase):
                connection = self.database.connect() if admitted else self.database.connect_read_only()
            else:
                connection = sqlite3.connect(path.as_uri() + ("?mode=rw" if admitted else "?mode=ro"),
                                             uri=True, timeout=5, isolation_level=None)
            held.enter_context(closing(connection))
            if admitted:
                connection.execute("PRAGMA query_only=ON")
            connection.row_factory = sqlite3.Row
            yield connection

    def _session_key(self):
        return os.path.realpath(self.database.path)

    def _live_sessions(self):
        """Live outbox sessions of this process over this service's database."""
        key = self._session_key()
        with _LIVE_SESSIONS_LOCK:
            sessions = [session for session in _LIVE_SESSIONS.get(key, ()) if session.live]
            if sessions:
                _LIVE_SESSIONS[key] = sessions
            else:
                _LIVE_SESSIONS.pop(key, None)
            return tuple(sessions)

    def _unpersisted_loss(self):
        """Timeline loss counted by a live outbox of this process but not yet written."""
        return self._outbox_backlog()[1]

    def _outbox_backlog(self):
        """``(pending, unpersisted, quarantined, failures)`` across this process's live outboxes.

        Pending facts are staged and await a successful write; they are not
        loss. Quarantined facts failed to build with a permanent programming
        fault: they are held, not dropped, but will not be written without a
        fix, so they are possible loss. Each session reports its counts
        atomically, so a fact that moves between them between two reads is
        never seen in none of them. Sessions are shared by every
        `PresenceService` over the same database file in this process.
        """
        pending = unpersisted = quarantined = failures = 0
        for session in self._live_sessions():
            try:
                staged, lost, held = session.backlog()
                failed = session.failures()
            except Exception:
                # An unreadable backlog proves neither an empty queue nor the
                # absence of loss.
                staged, lost, held, failed = 1, 1, 0, 0
            pending += staged
            unpersisted += lost
            quarantined += held
            failures += failed
        return pending, unpersisted, quarantined, failures

    def _admission(self):
        """Obtain one storage reservation context for a single durable write.

        The port must return a context manager. A bare admit call would leak a
        reservation that is never released, so the next presence write would be
        refused, and calling a reservation factory without entering it would
        write with no admission at all.
        """
        if self.reservation is None:
            raise RuntimeError("storage admission required")
        held = self.reservation()
        if not (hasattr(held, "__enter__") and hasattr(held, "__exit__")):
            raise RuntimeError("storage admission reservation required")
        return held

    @contextmanager
    def _transaction(self, *, required=True):
        """Admitted durable write. ``required=False`` yields ``None`` when storage refuses.

        Only read-only status reporting uses the optional form, so a refused or
        exhausted volume degrades visibly instead of hiding presence state.
        The reservation stays entered until after the SQLite commit and the
        connection close, and is released even when the write fails.
        """
        with ExitStack() as reserved:
            try:
                reserved.enter_context(self._admission())
            except Exception:
                if required:
                    raise
                yield None
                return
            db = reserved.enter_context(closing(self.database.connect()))
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @staticmethod
    def _clock_trust(db, now, trusted):
        """Evaluate clock trust without writing; reads never advance the marker."""
        if type(trusted) is not bool:
            raise ValueError("explicit clock trust required")
        previous = db.execute("SELECT latest FROM presence_clock WHERE singleton=1").fetchone()
        if previous is not None and timestamp(now) < previous[0]:
            return False
        return trusted

    @classmethod
    def _clock(cls, db, now, trusted):
        result = cls._clock_trust(db, now, trusted)
        if result:
            db.execute("INSERT OR REPLACE INTO presence_clock VALUES (1,?)", (timestamp(now),))
        return result

    @staticmethod
    def _control_trust(db, now, trusted):
        """Evaluate the Owner-control marker, kept apart from observation time.

        Observation receipt times arrive from capture sources, so sharing one
        marker would let a single far-future observation refuse every later
        Owner override, cancellation and hint with no way back.
        """
        if type(trusted) is not bool:
            raise ValueError("explicit clock trust required")
        previous = db.execute("SELECT latest FROM presence_control_clock WHERE singleton=1").fetchone()
        if previous is not None and timestamp(now) < previous[0]:
            return False
        return trusted

    @classmethod
    def _control_clock(cls, db, now, trusted):
        result = cls._control_trust(db, now, trusted)
        if result:
            db.execute("INSERT OR REPLACE INTO presence_control_clock VALUES (1,?)", (timestamp(now),))
        return result

    def _owner(self, context):
        identity = self.access.require_owner(context)
        if not isinstance(identity, UUID):
            raise ValueError("audited owner identity required")
        return str(identity)

    @staticmethod
    def _control_observation(db, state, now):
        observation = Observation(Kind.PRESENCE, now, now, value=Value.CHANGED,
                                  clock_trusted=True, presence_state=PresenceState(state))
        db.execute("INSERT INTO presence_observations(id,kind,source,received,payload) VALUES (?, 'presence',NULL,?,?)",
                   (str(observation.identifier), timestamp(now), json.dumps(observation.payload())))

    def override(self, context, state, *, now, expires_at=None, clock_trusted):
        actor = self._owner(context)
        if not isinstance(state, PresenceState):
            raise ValueError("invalid presence state")
        if expires_at is not None and utc(expires_at) <= utc(now):
            raise ValueError("override expiry must be in the future")
        with self._transaction() as db:
            if not self._control_clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            db.execute("INSERT OR REPLACE INTO presence_override VALUES (1,?,?,?,?)",
                       (state.value, actor, timestamp(now), timestamp(expires_at) if expires_at else None))
            db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('override_set',?,?,?)",
                       (actor, timestamp(now), state.value))
            self._control_observation(db, state, now)
        return self.snapshot(now=now, clock_trusted=clock_trusted)

    def cancel_override(self, context, *, now, clock_trusted):
        actor = self._owner(context)
        with self._transaction() as db:
            if not self._control_clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            row = db.execute("SELECT state FROM presence_override").fetchone()
            db.execute("DELETE FROM presence_override WHERE singleton=1")
            if row:
                db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('override_cancelled',?,?,?)",
                           (actor, timestamp(now), row[0]))
                state = self._effective(db, now, self._clock_trust(db, now, True), True)[0]
                self._control_observation(db, state, now)
        return self.snapshot(now=now, clock_trusted=clock_trusted)

    def set_hint(self, context, state, *, now, valid_until, clock_trusted):
        actor = self._owner(context)
        if not isinstance(state, PresenceState) or utc(valid_until) <= utc(now):
            raise ValueError("invalid presence hint")
        # A schedule is not a high-confidence owner observation or an explicit
        # current-state override. It cannot silently disarm ordinary automation.
        if state == PresenceState.PRESENT:
            state = PresenceState.PROBABLY_PRESENT
        with self._transaction() as db:
            if not self._control_clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            db.execute("INSERT OR REPLACE INTO presence_inputs VALUES ('hint',?,?,?,NULL)",
                       (state.value, timestamp(now), timestamp(valid_until)))
            db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('hint_set',?,?,?)",
                       (actor, timestamp(now), state.value))

    def record(self, observation, *, presence_valid_until=None, restamped=False, source_fact=None):
        """Durably record one observation idempotently by its UUID.

        ``restamped=True`` is for producers that stamp the main-host receipt
        at write time: a replay of an already recorded UUID then carries a new
        receipt time (and the clock trust and confirmation derived from it),
        so only the source fact itself must match for it to be a duplicate.
        A critical fact first stored unconfirmed and then delivered confirmed
        is confirmed in place and queues its critical work once.
        ``source_fact`` is the producer's SHA-256 hex digest of its own source
        fact, for a fact whose payload holds a receipt-derived field that also
        depends on the source, such as an Owner crossing's ``confirmed``. It is
        stored with the observation, and a restamped replay whose digest
        differs from the stored one is an identity conflict even when the
        payloads agree once receipt fields are ignored.
        Contract errors raise `InvalidObservation`; storage and database
        failures raise anything else and may be retried.
        """
        if not isinstance(observation, Observation):
            raise InvalidObservation("typed observation required")
        if presence_valid_until is not None and utc(presence_valid_until) <= utc(observation.received_at):
            raise InvalidObservation("presence validity must be explicit and future")
        if source_fact is not None and (not restamped or type(source_fact) is not str
                                        or len(source_fact) != 64
                                        or any(c not in "0123456789abcdef" for c in source_fact)):
            raise InvalidObservation("restamped source fact digest required")
        with self._transaction() as db:
            existing = db.execute("SELECT payload FROM presence_observations WHERE id=?",
                                  (str(observation.identifier),)).fetchone()
            if existing:
                stored = Observation.from_payload(json.loads(existing[0]))
                digest = db.execute("SELECT digest FROM presence_source_facts WHERE id=?",
                                    (str(observation.identifier),)).fetchone()
                if restamped and (digest[0] if digest else None) != source_fact:
                    # The receipt-independent source fact differs under the
                    # same UUID; ignoring receipt fields must not hide it.
                    raise InvalidObservation("observation identity conflict")
                if self._confirms_critical(stored, observation, restamped=restamped):
                    return self._confirm_critical(db, stored)
                if stored.payload() != observation.payload() and stored.payload() != observation.uncertain().payload():
                    fact = {key: value for key, value in stored.payload().items() if key not in RECEIPT_FIELDS}
                    replay = {key: value for key, value in observation.payload().items()
                              if key not in RECEIPT_FIELDS}
                    if not restamped or fact != replay:
                        raise InvalidObservation("observation identity conflict")
                return stored
            completed = db.execute("SELECT 1 FROM presence_completed_events WHERE id=?",
                                   (str(observation.identifier),)).fetchone()
            if completed:
                # The timeline payload passed its retention horizon after this
                # event's critical actions completed. Recording the identity
                # again would preserve evidence and notify a second time, so a
                # delayed replay stays a duplicate and its payload stays expired.
                return observation
            trusted = self._clock(db, observation.received_at, observation.clock_trusted)
            clock = SOURCE_CLOCK_TABLES.get(observation.kind) if observation.source_id else None
            if clock:
                source = str(observation.source_id)
                high_water = db.execute(f"SELECT latest_occurred FROM {clock} WHERE source=?",
                                        (source,)).fetchone()
                if high_water and timestamp(observation.occurred_at) < high_water["latest_occurred"]:
                    trusted = False
            if not trusted:
                observation = observation.uncertain()
            elif clock:
                db.execute(f"INSERT INTO {clock}(source,latest_occurred) VALUES (?,?) "
                           "ON CONFLICT(source) DO UPDATE SET latest_occurred="
                           "MAX(latest_occurred,excluded.latest_occurred)",
                           (str(observation.source_id), timestamp(observation.occurred_at)))
            payload = json.dumps(observation.payload(), sort_keys=True, separators=(",", ":"))
            db.execute("INSERT INTO presence_observations(id,kind,source,received,payload) VALUES (?,?,?,?,?)",
                       (str(observation.identifier), observation.kind.value,
                        str(observation.source_id) if observation.source_id else None,
                        timestamp(observation.received_at), payload))
            if source_fact is not None:
                db.execute("INSERT OR REPLACE INTO presence_source_facts(id,digest) VALUES (?,?)",
                           (str(observation.identifier), source_fact))
            if observation.kind in {Kind.OWNER_ENTRY, Kind.OWNER_EXIT} and presence_valid_until is not None:
                # Confirmation/high confidence is supplied by the separately
                # reviewed owner-observation pipeline, never guessed numerically.
                usable = (observation.confirmed and trusted and observation.quality == Quality.SUFFICIENT
                          and observation.value == Value.OBSERVED)
                state = (PresenceState.PRESENT if observation.kind == Kind.OWNER_ENTRY else PresenceState.ABSENT)
                if not usable:
                    # The slot still records that the newest owner evidence was
                    # unusable, so an earlier inference stops applying. It is not
                    # a high-confidence observation, so `_effective()` falls
                    # through to any configured hint instead of reporting it.
                    state = PresenceState.UNKNOWN
                db.execute("INSERT OR REPLACE INTO presence_inputs VALUES ('owner_observation',?,?,?,?)",
                           (state.value, timestamp(observation.received_at), timestamp(presence_valid_until),
                            str(observation.identifier)))
            if observation.kind in CRITICAL and observation.confirmed:
                for action in ("evidence", "notification"):
                    db.execute("INSERT INTO presence_deliveries(observation,action,state,attempts) "
                               "VALUES (?,?,'pending',0)",
                               (str(observation.identifier), action))
        return observation

    @staticmethod
    def _confirms_critical(stored, observation, *, restamped):
        """A confirmed delivery of a critical fact stored earlier as unconfirmed.

        Critical confirmation comes from the detector, not from the receipt,
        so it must not be discarded as a receipt field: the confirmed delivery
        still has to queue evidence preservation and notification. Only the
        receipt fields may differ; any other difference stays a conflict.
        """
        if observation.kind not in CRITICAL or not observation.confirmed or stored.confirmed:
            return False
        ignored = RECEIPT_FIELDS if restamped else ("clock_trusted", "confirmed")
        fact = {key: value for key, value in stored.payload().items() if key not in ignored}
        replay = {key: value for key, value in observation.payload().items() if key not in ignored}
        return fact == replay

    @staticmethod
    def _confirm_critical(db, stored):
        """Record the confirmation and queue its critical work exactly once.

        The stored receipt and clock trust are kept; confirmation is never
        withdrawn again by a later unconfirmed replay of the same identity.
        """
        confirmed = replace(stored, confirmed=True)
        db.execute("UPDATE presence_observations SET payload=? WHERE id=?",
                   (json.dumps(confirmed.payload(), sort_keys=True, separators=(",", ":")),
                    str(confirmed.identifier)))
        for action in ("evidence", "notification"):
            db.execute("INSERT OR IGNORE INTO presence_deliveries(observation,action,state,attempts) "
                       "VALUES (?,?,'pending',0)", (str(confirmed.identifier), action))
        return confirmed

    def complete_action(self, identifier, action, result, *, generation=None):
        """Record the outcome of one critical delivery attempt.

        `generation` binds the completion to the claim that produced the
        callback. A callback from a superseded attempt, such as one arriving
        after an Owner requeue or after a later claim, is then ignored instead
        of cancelling the resubmission or overwriting a newer outcome.
        Completing without a generation stays available for an operator who
        resolves a stranded action deliberately and out of band.
        """
        if not isinstance(identifier, UUID) or action not in {"evidence", "notification"}:
            raise ValueError("invalid action identity")
        if not isinstance(result, ActionResult):
            raise ValueError("explicit delivery result required")
        if generation is not None and type(generation) is not int:
            raise ValueError("invalid delivery generation")
        with self._transaction() as db:
            # A later failure cannot erase an already confirmed completion.
            scope = "" if generation is None else " AND generation=?"
            arguments = [result.value, str(identifier), action]
            if generation is not None:
                arguments.append(generation)
            db.execute("UPDATE presence_deliveries SET state=? WHERE observation=? AND action=? "
                       "AND state!='delivered'" + scope, tuple(arguments))

    def requeue_action(self, context, identifier, action, *, now, clock_trusted):
        """Owner-approved resubmission of an unresolved critical action.

        Automatic dispatch never retries an outcome it could not confirm,
        because the external side effect may already have happened. Recovery is
        therefore an explicit, audited Owner decision that accepts the risk of a
        duplicate preservation or notification, and it is the only way a
        stranded critical action returns to the queue.
        """
        actor = self._owner(context)
        if not isinstance(identifier, UUID) or action not in {"evidence", "notification"}:
            raise ValueError("invalid action identity")
        with self._transaction() as db:
            if not self._control_clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            job = db.execute("SELECT state FROM presence_deliveries WHERE observation=? AND action=?",
                             (str(identifier), action)).fetchone()
            if job is None or job["state"] in {"delivered", "pending"}:
                raise ValueError("no unresolved critical action")
            # The retained attempt count would otherwise sort this recovered
            # action behind every fresh zero-attempt job, so an explicit Owner
            # recovery leads the queue instead of being starved by new work. The
            # new generation retires callbacks from the superseded attempt.
            db.execute("UPDATE presence_deliveries SET state='pending',requeued=1,"
                       "generation=generation+1 WHERE observation=? AND action=?",
                       (str(identifier), action))
            # The audit names which duplicate-risk resubmission was approved.
            db.execute("INSERT INTO presence_audit(action,actor,at,state,target) "
                       "VALUES ('critical_action_requeued',?,?,NULL,?)",
                       (actor, timestamp(now), f"{action}:{identifier}"))
        return action

    def clear_expired_degradation(self, context, action, *, now, clock_trusted):
        """Owner-confirmed clearing of an expired unresolved critical marker.

        The event payload is gone, so only the Owner can decide that the
        stranded action was handled outside ServerSentinel. Clearing is audited
        and never happens automatically.
        """
        actor = self._owner(context)
        if action not in {"evidence", "notification"}:
            raise ValueError("invalid action identity")
        with self._transaction() as db:
            if not self._control_clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            cursor = db.execute("DELETE FROM presence_expired_unresolved WHERE action=?", (action,))
            if not cursor.rowcount:
                raise ValueError("no expired critical degradation")
            db.execute("INSERT INTO presence_audit(action,actor,at,state,target) "
                       "VALUES ('critical_degradation_cleared',?,?,NULL,?)",
                       (actor, timestamp(now), action))

    def clear_unresolved_critical_event(self, context, identifier, *, now, clock_trusted):
        """Owner-confirmed release of retained unresolved critical work.

        This is an explicit out-of-band resolution, never a successful delivery:
        unresolved actions keep their action-only degradation markers while the
        observation payload and delivery rows are released.  The identity
        tombstone prevents a delayed replay from resubmitting the work.
        """
        actor = self._owner(context)
        if not isinstance(identifier, UUID):
            raise ValueError("invalid critical observation identity")
        with self._transaction() as db:
            if not self._control_clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            rows = db.execute("SELECT action FROM presence_deliveries WHERE observation=? "
                              "AND state NOT IN ('delivered','disabled')", (str(identifier),)).fetchall()
            if not rows:
                raise ValueError("no unresolved critical event")
            db.execute("INSERT OR IGNORE INTO presence_completed_events(id,expired_at) VALUES (?,?)",
                       (str(identifier), timestamp(now)))
            db.executemany("INSERT INTO presence_expired_unresolved(action,events,since) VALUES (?,1,?) "
                           "ON CONFLICT(action) DO UPDATE SET events=events+excluded.events",
                           [(row["action"], timestamp(now)) for row in rows])
            db.execute("DELETE FROM presence_deliveries WHERE observation=?", (str(identifier),))
            db.execute("DELETE FROM presence_observations WHERE id=?", (str(identifier),))
            db.execute("DELETE FROM presence_source_facts WHERE id=?", (str(identifier),))
            db.execute("INSERT INTO presence_audit(action,actor,at,state,target) "
                       "VALUES ('critical_event_cleared',?,?,NULL,?)",
                       (actor, timestamp(now), str(identifier)))

    @staticmethod
    def _gap(db):
        row = db.execute("SELECT since, latest, refused, rejected, lost, interrupted "
                         "FROM presence_timeline_gap WHERE singleton=1").fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _add_gap(db, now, *, refused=0, rejected=0, lost=0, interrupted=0):
        counts = (refused, rejected, lost, interrupted)
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("non-negative gap counts required")
        if not any(counts):
            return
        at = timestamp(now)
        db.execute("INSERT INTO presence_timeline_gap(singleton,since,latest,refused,rejected,lost,interrupted) "
                   "VALUES (1,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET latest=excluded.latest, "
                   "refused=refused+excluded.refused, rejected=rejected+excluded.rejected, "
                   "lost=lost+excluded.lost, interrupted=interrupted+excluded.interrupted",
                   (at, at, *counts))

    def _session_lock(self):
        """Exclusive advisory lock beside the database, held for a session's life.

        Called only inside an admitted transaction: the first call creates the
        lock file, which is a filesystem write like any other.

        The kernel releases it when the holding process dies, so a session
        row found while the lock is free belongs to an outbox that is gone.
        """
        path = self.database.path
        descriptor = os.open(path.with_name(path.name + ".timeline-session.lock"),
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            raise RuntimeError("another timeline outbox session is open") from None
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _committed_lock_file(self):
        """Open (creating it if needed) the committed-session lock file, unlocked.

        Created inside the admitted open transaction like the session lock;
        the lock itself is taken only after that transaction commits.
        """
        path = self.database.path
        return os.open(path.with_name(path.name + ".timeline-session.committed.lock"),
                       os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)

    def _committed_session_held(self):
        """Read-only probe: whether a live outbox holds a committed session now.

        The session mutex alone is not enough: a replacement holds it while
        its open is still in flight, before the stale rows are converted into
        the marker, and that open may stall or roll back. Only the committed
        lock, taken after the open committed, proves the rows are owned.

        The lock file is opened without ``O_CREAT``, so a status read never
        creates it: a missing file means no session was ever committed there.
        A probe that cannot be completed proves nothing and returns None.
        """
        path = self.database.path
        try:
            descriptor = os.open(path.with_name(path.name + ".timeline-session.committed.lock"),
                                 os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return False
        except OSError:
            return None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError:
            return None
        finally:
            # Closing the descriptor also drops the probe's own shared lock.
            os.close(descriptor)
        return False

    def _orphaned_sessions(self, db):
        """Session rows no live outbox holds: evidence of an interrupted gap.

        Returns ``(orphaned, foreign)``. ``foreign`` is True when the rows are
        owned by a live outbox in another process: its in-memory backlog
        (staged facts and counted but unwritten loss) cannot be read from here.

        `open_timeline_session()` converts such rows into the durable marker,
        but a restart whose replacement session cannot open (a refused
        volume, a clock or database fault) never gets there. Status must not
        report a healthy timeline in the meantime. A row held by a live
        session of this process is not orphaned. With no such session here,
        a committed lock held elsewhere means another process's live outbox
        owns the rows, since its committed open already converted any stale
        ones. A lock that is free, missing or unprobeable, or an open still in
        flight that holds only the session mutex, leaves every row reported
        as orphaned. Rows are read before the probe, and the marker after it,
        so a conversion that commits in between is seen in the marker.
        """
        live = {session.token for session in self._live_sessions()}
        tokens = [row[0] for row in db.execute("SELECT token FROM presence_outbox_sessions")]
        orphaned = [token for token in tokens if token not in live]
        if orphaned and not live and self._committed_session_held() is True:
            return 0, True
        return len(orphaned), False

    def open_timeline_session(self, *, now):
        """Start the durable outbox session; returns ``(session, gap marker or None)``.

        Only one outbox session per database can be open: a second one is
        refused while the first holds the session lock. A session row found
        once the lock is free therefore belongs to an outbox that never closed
        cleanly, so whatever it had staged may be lost. It is recorded as an
        interrupted gap: a restart is never assumed to be clean. A false
        positive is cleared by the Owner (`clear_timeline_gap`), never here.
        """
        session = None
        try:
            with self._transaction() as db:
                # The lock file is created here, under the storage reservation
                # the transaction already holds, so a refused volume never
                # gains even a directory entry from an outbox start.
                session = TimelineSession(str(uuid4()), self._session_lock())
                session._committed = self._committed_lock_file()
                stale = db.execute("SELECT count(*) FROM presence_outbox_sessions").fetchone()[0]
                if stale:
                    self._add_gap(db, now, interrupted=stale)
                    db.execute("DELETE FROM presence_outbox_sessions")
                db.execute("INSERT INTO presence_outbox_sessions(token,opened) VALUES (?,?)",
                           (session.token, timestamp(now)))
                gap = self._gap(db)
            # Only now, with the stale rows converted and the new row durable,
            # may a reader in another process treat the rows as owned. If this
            # fails the committed row stays behind, reported as orphaned and
            # converted into an interrupted gap by the next open. A status read
            # in another process may hold a shared probe on it for an instant;
            # that is waited out rather than failing a clean open.
            _lock_committed(session._committed)
        except BaseException:
            if session is not None:
                session.release()
            raise
        with _LIVE_SESSIONS_LOCK:
            _LIVE_SESSIONS.setdefault(self._session_key(), []).append(session)
        return session, gap

    def record_timeline_gap(self, *, now, refused=0, rejected=0, lost=0, close=None):
        """Durably add outbox loss counts; ``close`` is the session to end cleanly.

        Counts are only ever added, so a write that committed and then raised
        and is retried overstates the gap rather than hiding it. Only a
        committed close removes the session row and then releases its lock; a
        failed close keeps both, and a process that exits after it leaves the
        row for the next start to record as interrupted. A close whose row is
        missing cannot prove a clean session and is recorded as interrupted.
        """
        if close is not None and not isinstance(close, TimelineSession):
            raise ValueError("timeline session required")
        with self._transaction() as db:
            self._add_gap(db, now, refused=refused, rejected=rejected, lost=lost)
            if close is not None:
                cursor = db.execute("DELETE FROM presence_outbox_sessions WHERE token=?", (close.token,))
                if not cursor.rowcount:
                    self._add_gap(db, now, interrupted=1)
            gap = self._gap(db)
        if close is not None:
            close.release()
        return gap

    def timeline_session_recorded(self, session):
        """Read-only: whether ``session`` still has its durable session row.

        Used after a close raised, to tell a close that never committed (the
        row stays) from one that committed and then failed (the row is gone).
        An unreadable database raises, so the outcome stays ambiguous.
        """
        if not isinstance(session, TimelineSession):
            raise ValueError("timeline session required")
        with self._read() as db:
            return db.execute("SELECT 1 FROM presence_outbox_sessions WHERE token=?",
                              (session.token,)).fetchone() is not None

    def timeline_gap(self):
        """Read-only durable timeline gap marker, or None when there is none.

        A missing database is an unreadable marker, never created here: this
        read takes no storage reservation.
        """
        with self._read() as db:
            return self._gap(db)

    def clear_timeline_gap(self, context, *, now, clock_trusted):
        """Owner-confirmed clearing of the durable timeline gap marker.

        The lost facts are not recoverable, so only the Owner can accept the
        gap, for example after an interrupted-restart false positive. Clearing
        is audited with the cleared counts and never happens automatically.
        Loss a live outbox has counted but not yet written refuses the clear:
        the Owner cannot accept a gap that is not yet on record, and the
        outbox's next flush writes it. Owner status reports that loss either
        way, so a clear never makes status look healthy while it is pending.
        """
        actor = self._owner(context)
        with self._transaction() as db:
            if not self._control_clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            if self._unpersisted_loss():
                raise ValueError("unpersisted timeline loss pending")
            if self._orphaned_sessions(db)[1]:
                # The owning outbox is in another process: loss it has counted
                # but not yet written cannot be seen from here, so the Owner
                # cannot accept the gap through this process.
                raise ValueError("timeline outbox is owned by another process")
            gap = self._gap(db)
            if gap is None:
                raise ValueError("no timeline gap")
            db.execute("DELETE FROM presence_timeline_gap WHERE singleton=1")
            target = ",".join(f"{key}={gap[key]}" for key in ("refused", "rejected", "lost", "interrupted"))
            db.execute("INSERT INTO presence_audit(action,actor,at,state,target) "
                       "VALUES ('timeline_gap_cleared',?,?,NULL,?)",
                       (actor, timestamp(now), target))
            return gap

    def dispatch_pending(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("invalid dispatch limit")
        # Submission is separate from observation ingestion. Claim durably,
        # release the SQLite lock, then invoke the port. A process crash in this
        # interval leaves submitting/queued visibly unresolved; it never causes
        # a blind retry of a potentially completed external side effect.
        #
        # Batches alternate durably between fresh work and a recovered action's
        # unavailable backlog whenever both exist. Thus either stream remains
        # live under continuous arrival from the other.
        available = tuple(action for action, port in
                          (("evidence", self.evidence), ("notification", self.notifications))
                          if port is not None)
        with self._transaction() as db:
            # A claimed submission is never reclaimed here. Its outcome is
            # unknown, and a concurrent or re-entrant dispatcher may still be
            # inside that port call, so rewriting the row would either duplicate
            # an external side effect or discard a completion that is about to
            # land. It stays visibly unresolved in the status snapshot and
            # returns to the queue only through an Owner-approved requeue.
            next_row = db.execute("SELECT next_state FROM presence_delivery_fairness WHERE singleton=1").fetchone()
            fresh = db.execute(
                "SELECT job.observation,job.action FROM presence_deliveries job "
                "JOIN presence_observations item ON item.id=job.observation "
                "WHERE job.state='pending' "
                "ORDER BY job.requeued DESC,job.attempts,item.sequence,job.action LIMIT ?", (limit,)).fetchall()
            recovered = []
            if available:
                recovered = db.execute(
                    "SELECT job.observation,job.action FROM presence_deliveries job "
                    "JOIN presence_observations item ON item.id=job.observation "
                    "WHERE job.state='unavailable' AND job.action IN (" + ",".join("?" * len(available)) + ") "
                    "ORDER BY job.attempts,item.sequence,job.action LIMIT ?", (*available, limit)).fetchall()
            groups = {"pending": fresh, "unavailable": recovered}
            selected_state = next_row[0] if next_row else "pending"
            if not groups[selected_state]:
                selected_state = "unavailable" if selected_state == "pending" else "pending"
            pending = groups[selected_state]
            if fresh and recovered:
                following = "unavailable" if selected_state == "pending" else "pending"
                db.execute("INSERT INTO presence_delivery_fairness VALUES (1,?) "
                           "ON CONFLICT(singleton) DO UPDATE SET next_state=excluded.next_state", (following,))
        for row in pending:
            with self._transaction() as db:
                job = db.execute("SELECT * FROM presence_deliveries WHERE observation=? AND action=?",
                                 tuple(row)).fetchone()
                # Retention expiry or another dispatcher may have resolved or
                # removed this row between the selection and this claim.
                if job is None or job["state"] not in {"pending", "unavailable"}:
                    continue
                port = self.evidence if row["action"] == "evidence" else self.notifications
                if port is None:
                    db.execute("UPDATE presence_deliveries SET state='unavailable' WHERE observation=? AND action=?", tuple(row))
                    continue
                payload = db.execute("SELECT payload FROM presence_observations WHERE id=?", (row["observation"],)).fetchone()[0]
                observation = Observation.from_payload(json.loads(payload))
                # Each claim gets its own generation, so a callback can only
                # complete the attempt it belongs to.
                claim = job["generation"] + 1
                db.execute("UPDATE presence_deliveries SET state='submitting',attempts=attempts+1,"
                           "generation=? WHERE observation=? AND action=?", (claim, *row))
            def complete(result, identifier=observation.identifier, action=row["action"], claim=claim):
                self.complete_action(identifier, action, result, generation=claim)
            try:
                result = port(observation, complete)
                if not isinstance(result, ActionResult):
                    result = ActionResult.UNCERTAIN
            except Exception:
                result = ActionResult.UNCERTAIN
            with self._transaction() as db:
                # Synchronous callbacks may already have completed the job, and
                # a later claim or an Owner requeue supersedes this one.
                db.execute("UPDATE presence_deliveries SET state=? WHERE observation=? AND action=? "
                           "AND state='submitting' AND generation=?",
                           (result.value, row["observation"], row["action"], claim))

    def process_critical(self, detector):
        """Run the supplied critical detector in every presence state."""
        observation = detector()
        if not isinstance(observation, Observation) or observation.kind not in CRITICAL:
            raise ValueError("critical observation required")
        return self.record(observation)

    @staticmethod
    def _effective(db, now, trusted, control_trusted):
        override = db.execute("SELECT * FROM presence_override WHERE singleton=1").fetchone()
        # An elapsed expiry stops applying immediately, whether or not the
        # durable retirement write has been admitted yet. Expiry follows the
        # Owner-control marker, so observation timestamps cannot keep an
        # expired override alive.
        if override and not (override["expires"] and control_trusted
                             and override["expires"] <= timestamp(now)):
            return PresenceState(override["state"]), "manual_override", override["expires"]
        # Inference from observations needs observation-clock trust, while an
        # Owner-configured hint is control input and follows the control marker.
        # Otherwise one skewed source timestamp would also discard the Owner's
        # own configuration.
        for slot, usable in (("owner_observation", trusted), ("hint", control_trusted)):
            if not usable:
                continue
            item = db.execute("SELECT * FROM presence_inputs WHERE slot=? AND observed<=? AND valid_until>?",
                              (slot, timestamp(now), timestamp(now))).fetchone()
            # Only a high-confidence owner observation outranks a configured
            # hint. An unusable one holds no projection, so it invalidates
            # the earlier inference without masking a still valid hint.
            if item and PresenceState(item["state"]) != PresenceState.UNKNOWN:
                return PresenceState(item["state"]), slot, None
        return PresenceState.UNKNOWN, "unknown", None

    def _retire_override(self, now):
        """Retire an expired override durably; report (retired, storage admitted)."""
        retired = admitted = False
        with self._transaction(required=False) as db:
            if db is not None:
                admitted = True
                override = db.execute("SELECT * FROM presence_override WHERE singleton=1").fetchone()
                if override is None or not override["expires"] or override["expires"] > timestamp(now):
                    retired = True
                elif self._control_clock(db, now, True):
                    db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('override_expired',NULL,?,?)",
                               (timestamp(now), override["state"]))
                    db.execute("DELETE FROM presence_override WHERE singleton=1")
                    state = self._effective(db, now, self._clock_trust(db, now, True), True)[0]
                    self._control_observation(db, state, now)
                    retired = True
        return retired, admitted

    def _detection_path(self):
        if self.detection is None:
            return UNKNOWN
        try:
            reported = self.detection()
        except Exception:
            # A failing health probe is unknown health, never a healthy claim.
            return UNKNOWN
        if type(reported) is not bool:
            return UNKNOWN
        return ARMED if reported else UNAVAILABLE

    def _persistence_path(self, denied):
        """Report storage admission without reserving write capacity for a read.

        Entering a reservation here would make every status read take the
        deployment's bounded control allowance, contend with the writer that
        owns it and, on a full volume, drive a state transition from a read
        path. The status therefore never calls the admission port at all. It
        uses the injected read-only storage health probe and the admission a
        write in this snapshot actually observed. Without such a probe the
        health of the volume is simply unknown here, and a configured port is
        never reported as armed on configuration alone.
        """
        if denied or self.reservation is None:
            return UNAVAILABLE
        if self.storage_status is None:
            return UNKNOWN
        try:
            reported = self.storage_status()
        except Exception:
            return UNKNOWN
        if type(reported) is not bool:
            return UNKNOWN
        return ARMED if reported else UNAVAILABLE

    def _critical_paths(self, unresolved, denied):
        """Report configured/known critical-path availability, never a fixed armed.

        ``armed`` means the path is configured and is not disarmed by any
        presence state; it is not a liveness guarantee for an external worker.
        A durable delivery outcome that did not complete the critical action,
        including a failed or uncertain submission, keeps its path reported as
        unavailable until that work is resolved.
        ``pending_critical_actions`` still reports unfinished critical work.
        """
        paths = {
            "critical_detection": self._detection_path(),
            "critical_persistence": self._persistence_path(denied),
            "critical_evidence": ARMED if self.evidence is not None and "evidence" not in unresolved else UNAVAILABLE,
            "critical_notifications": ARMED if self.notifications is not None and "notification" not in unresolved else UNAVAILABLE,
        }
        return {**paths, "critical_paths_degraded": any(value != ARMED for value in paths.values())}

    def snapshot(self, *, now, clock_trusted):
        """Read-only status. A refused or exhausted volume never hides presence.

        This is an internal projection with no authorization check. Critical
        path health is Owner information, so a future route must delegate to
        `owner_status()` and must never expose this payload to a `live:view`
        identity or to any unauthenticated surface.
        """
        with self._read() as db:
            control_trusted = self._control_trust(db, now, clock_trusted)
            override = db.execute("SELECT * FROM presence_override WHERE singleton=1").fetchone()
        expired = bool(override and override["expires"] and control_trusted
                       and override["expires"] <= timestamp(now))
        # An expired override stops applying even when the durable retirement
        # write is refused; the pending flag keeps that difference visible.
        retired, admitted = self._retire_override(now) if expired else (True, True)
        # Loss a live outbox has counted but not yet written is a gap too. It
        # is read before the durable marker: the outbox commits the marker
        # before it drops its count, so a loss is always seen in one of them.
        # Staged facts are read in the same step: a staged fact leaves the
        # backlog only after its write committed, so it is either still
        # pending here or already in the timeline read below.
        pending, unpersisted, quarantined, failures = self._outbox_backlog()
        with self._read() as db:
            trusted = self._clock_trust(db, now, clock_trusted)
            control_trusted = self._control_trust(db, now, clock_trusted)
            state, basis, expires = self._effective(db, now, trusted, control_trusted)
            failed = db.execute("SELECT count(*) FROM presence_deliveries "
                                "WHERE state NOT IN ('delivered','disabled')").fetchone()[0]
            # Every delivery that has not completed its critical action degrades
            # its path: a failed or uncertain outcome, a disabled or unavailable
            # action, and a submission whose completion is unconfirmed, which an
            # interrupted worker leaves behind for good. Reporting armed there
            # would claim a healthy safety path for work that never happened.
            unresolved = {row[0] for row in db.execute(
                "SELECT DISTINCT action FROM presence_deliveries WHERE state IN "
                "('disabled','unavailable','failed','uncertain','submitting','queued')")}
            # Retention expiry removes the delivery row but not the fact that
            # the critical action never completed.
            unresolved |= {row[0] for row in db.execute(
                "SELECT action FROM presence_expired_unresolved")}
            # Session rows are read before the marker: an open that converts
            # them commits both at once, so they are seen in one of the two.
            orphaned, foreign = self._orphaned_sessions(db)
            # A durable timeline gap stays visible across restarts until the
            # Owner clears it; it is Owner information like the paths below.
            gap = self._gap(db)
        # The reported state is only as trustworthy as the marker behind its
        # basis: Owner control for an override or hint, observation receipt for
        # an inferred owner observation. A skewed source timestamp must not
        # withhold the suppression an accepted Owner override asks for, and the
        # separate observation flag keeps that skew visible.
        if foreign:
            # A live outbox in another process owns the session: its staged
            # facts and unwritten loss are invisible here, which proves
            # neither an empty queue nor the absence of loss.
            pending, unpersisted = pending + 1, unpersisted + 1
        timing = {"manual_override": control_trusted, "hint": control_trusted,
                  "owner_observation": trusted}.get(basis, trusted and control_trusted)
        return {"state": state.value, "basis": basis, "override_expires_at": expires,
                "clock_degraded": not timing,
                "observation_clock_degraded": not trusted,
                "suppress_ordinary": state == PresenceState.PRESENT and timing,
                **self._critical_paths(unresolved, not admitted),
                "override_expiry_pending": not retired,
                "pending_critical_actions": failed,
                "timeline_gap": gap is not None or unpersisted > 0 or orphaned > 0 or quarantined > 0,
                "timeline_gap_detail": gap,
                "timeline_gap_unpersisted": unpersisted,
                # Sessions that never closed cleanly and that no replacement
                # has yet converted into the marker: possible, not proven, loss.
                "timeline_gap_orphaned_sessions": orphaned,
                # Staged facts a transient storage, database or clock failure
                # holds back: not loss, so not part of timeline_gap, but the
                # timeline is incomplete until they are written.
                "timeline_pending": pending > 0,
                "timeline_pending_count": pending,
                # Facts held back after a permanent build fault (a programming
                # error, not storage): possible loss until fixed, never dropped.
                "timeline_quarantined_count": quarantined,
                # Consecutive flushes a transient failure stopped; a growing
                # count is a stuck outbox rather than a passing refusal.
                "timeline_flush_failures": failures,
                # False when the owning outbox lives in another process and
                # its in-memory backlog is reported as unknown rather than empty.
                "timeline_backlog_visible": not foreign}

    def owner_status(self, context, *, now, clock_trusted):
        self._owner(context)
        return self.snapshot(now=now, clock_trusted=clock_trusted)

    def audit(self, context):
        self._owner(context)
        with self._read() as db:
            return [dict(row) for row in db.execute("SELECT * FROM presence_audit ORDER BY sequence")]

    def expire_audit(self, *, now, limit=1000):
        """Apply the main 90-day audit policy to owner-control history.

        This is a maintenance operation for the same retention workflow that
        expires storage-state audit rows. It is bounded and storage-admitted so
        a full or unsafe volume cannot silently report a completed cleanup.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid audit retention limit")
        cutoff = timestamp(utc(now) - timedelta(days=self.periods.audit_days))
        with self._transaction() as db:
            cursor = db.execute("DELETE FROM presence_audit WHERE sequence IN "
                                "(SELECT sequence FROM presence_audit WHERE at<? "
                                "ORDER BY at,sequence LIMIT ?)", (cutoff, limit))
        return cursor.rowcount

    def expire_history(self, *, now, limit=1000):
        """Bound timeline metadata to the main recording-retention period.

        Unfinished critical delivery is retained even after ordinary timeline
        expiry, so cleanup cannot discard evidence or notification work.
        An event whose critical actions already completed keeps a compact
        identity tombstone once its timeline payload expires, so a delayed
        replay of the same identity cannot repeat those side effects. Only
        events that carried critical delivery are tombstoned, because replaying
        any other expired observation queues no action.

        A durably disabled delivery is the one unfinished action that does not
        hold its observation back, because disabling is a configuration decision
        rather than pending work. It expires on the ordinary schedule and leaves
        a per-action degradation marker instead, so expiry cannot let the
        snapshot report that path as armed again while the tombstone stops a
        replay from re-queuing it. Any other action that never completed leaves
        the same marker when the bounded exception below finally expires it.

        The retention exception is bounded by the main audit-retention period.
        A permanently unresolved action would otherwise keep its observation,
        and every later one, on disk without limit. At that horizon the payload
        is released like any other expired observation while the identity
        tombstone and the per-action degradation marker remain, so the path
        stays degraded and the work is never reported as completed.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid timeline retention limit")
        cutoff = timestamp(utc(now) - timedelta(days=self.periods.recording_days))
        horizon = timestamp(utc(now) - timedelta(days=self.periods.audit_days))
        with self._transaction() as db:
            rows = db.execute("SELECT item.id FROM presence_observations item "
                              "WHERE (item.received<? AND NOT EXISTS (SELECT 1 FROM presence_deliveries job "
                              "WHERE job.observation=item.id AND job.state NOT IN ('delivered','disabled'))) "
                              "OR item.received<? "
                              "ORDER BY item.received,item.sequence LIMIT ?",
                              (cutoff, horizon, limit)).fetchall()
            identifiers = [(row[0],) for row in rows]
            db.executemany("INSERT OR IGNORE INTO presence_completed_events(id,expired_at) "
                           "SELECT DISTINCT observation,? FROM presence_deliveries WHERE observation=?",
                           [(timestamp(now), row[0]) for row in rows])
            db.executemany("INSERT INTO presence_expired_unresolved(action,events,since) "
                           "SELECT action,count(*),? FROM presence_deliveries "
                           "WHERE observation=? AND state!='delivered' GROUP BY action "
                           "ON CONFLICT(action) DO UPDATE SET events=events+excluded.events",
                           [(timestamp(now), row[0]) for row in rows])
            db.executemany("DELETE FROM presence_deliveries WHERE observation=?", identifiers)
            db.executemany("DELETE FROM presence_observations WHERE id=?", identifiers)
            db.executemany("DELETE FROM presence_source_facts WHERE id=?", identifiers)
        return len(rows)

    @staticmethod
    def _cursor(after):
        if after is None:
            return None
        if (not isinstance(after, dict) or set(after) != {"received_at", "sequence"}
                or type(after["received_at"]) is not str or type(after["sequence"]) is not int
                or after["sequence"] < 0):
            raise ValueError("invalid timeline cursor")
        return after["received_at"], after["sequence"]

    def history(self, context, *, received_from, received_to, limit=100, after=None):
        """Receipt-ordered observation window; pages concatenate in that order.

        Main-host receipt order, with the durable sequence only as a tie-break,
        is the single key used by the SQL page, the cursor and the response.
        Mixing it with occurrence order would make concatenated pages neither
        chronological nor complete once sources report out of occurrence order.
        Each item keeps its own occurrence time, quality and attribution; the
        timeline never presents that order as established causality.
        """
        self.access.require_recordings(context)
        if utc(received_from) >= utc(received_to) or type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("invalid timeline window")
        cursor = self._cursor(after)
        window = [timestamp(received_from), timestamp(received_to)]
        page = ""
        if cursor is not None:
            page = "AND (received>? OR (received=? AND sequence>?)) "
            window += [cursor[0], cursor[0], cursor[1]]
        with self._read() as db:
            rows = db.execute("SELECT sequence,received,payload FROM presence_observations "
                              "WHERE received>=? AND received<? " + page
                              + "ORDER BY received,sequence LIMIT ?", (*window, limit)).fetchall()
        items = [{**json.loads(row["payload"]), "sequence": row["sequence"]} for row in rows]
        uncertain = any(not item["clock_trusted"] or item["uncertainty_us"] for item in items)
        return {"items": items, "ordering_basis": "received_at", "ordering_degraded": uncertain,
                "causality": "not_inferred",
                "next_cursor": ({"received_at": rows[-1]["received"], "sequence": rows[-1]["sequence"]}
                                if rows else after)}
