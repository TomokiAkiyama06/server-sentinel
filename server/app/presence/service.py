"""Durable precedence, neutral history, and presence-independent critical work."""

from contextlib import closing, contextmanager
import json
from uuid import UUID

from .access import DenyAccess
from .delivery import ActionResult
from .models import (CRITICAL, Kind, Observation, PresenceState, Quality, Value,
                     timestamp, utc)


ARMED = "armed"
UNAVAILABLE = "unavailable"
UNKNOWN = "unknown"


class PresenceService:
    def __init__(self, database, *, access=None, evidence=None, notifications=None,
                 write_guard=None, detection=None):
        self.database = database
        self.access = access or DenyAccess()
        self.evidence = evidence
        self.notifications = notifications
        self.write_guard = write_guard
        # Injected by the reviewed #24 detector supervisor. Absent means unknown
        # detection health here; this module never claims a detector is running.
        self.detection = detection

    @contextmanager
    def _transaction(self, *, required=True):
        """Admitted durable write. ``required=False`` yields ``None`` when storage refuses.

        Only read-only status reporting uses the optional form, so a refused or
        exhausted volume degrades visibly instead of hiding presence state.
        """
        if self.write_guard is None:
            if not required:
                yield None
                return
            raise RuntimeError("storage admission required")
        try:
            self.write_guard()
        except Exception:
            if required:
                raise
            yield None
            return
        with closing(self.database.connect()) as db:
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
            if not self._clock(db, now, clock_trusted):
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
            if not self._clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            row = db.execute("SELECT state FROM presence_override").fetchone()
            db.execute("DELETE FROM presence_override WHERE singleton=1")
            if row:
                db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('override_cancelled',?,?,?)",
                           (actor, timestamp(now), row[0]))
                self._control_observation(db, self._effective(db, now, True)[0], now)
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
            if not self._clock(db, now, clock_trusted):
                raise ValueError("trusted control timestamp required")
            db.execute("INSERT OR REPLACE INTO presence_inputs VALUES ('hint',?,?,?,NULL)",
                       (state.value, timestamp(now), timestamp(valid_until)))
            db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('hint_set',?,?,?)",
                       (actor, timestamp(now), state.value))

    def record(self, observation, *, presence_valid_until=None):
        if not isinstance(observation, Observation):
            raise ValueError("typed observation required")
        if presence_valid_until is not None and utc(presence_valid_until) <= utc(observation.received_at):
            raise ValueError("presence validity must be explicit and future")
        with self._transaction() as db:
            existing = db.execute("SELECT payload FROM presence_observations WHERE id=?",
                                  (str(observation.identifier),)).fetchone()
            if existing:
                stored = Observation.from_payload(json.loads(existing[0]))
                if stored.payload() != observation.payload() and stored.payload() != observation.uncertain().payload():
                    raise ValueError("observation identity conflict")
                return stored
            trusted = self._clock(db, observation.received_at, observation.clock_trusted)
            if observation.source_id:
                previous = db.execute("SELECT payload FROM presence_observations WHERE source=? ORDER BY sequence DESC LIMIT 1",
                                      (str(observation.source_id),)).fetchone()
                if previous and observation.occurred_at < Observation.from_payload(json.loads(previous[0])).occurred_at:
                    trusted = False
            if not trusted:
                observation = observation.uncertain()
            payload = json.dumps(observation.payload(), sort_keys=True, separators=(",", ":"))
            db.execute("INSERT INTO presence_observations(id,kind,source,received,payload) VALUES (?,?,?,?,?)",
                       (str(observation.identifier), observation.kind.value,
                        str(observation.source_id) if observation.source_id else None,
                        timestamp(observation.received_at), payload))
            if observation.kind in {Kind.OWNER_ENTRY, Kind.OWNER_EXIT} and presence_valid_until is not None:
                # Confirmation/high confidence is supplied by the separately
                # reviewed owner-observation pipeline, never guessed numerically.
                usable = (observation.confirmed and trusted and observation.quality == Quality.SUFFICIENT
                          and observation.value == Value.OBSERVED)
                state = (PresenceState.PRESENT if observation.kind == Kind.OWNER_ENTRY else PresenceState.ABSENT)
                if not usable:
                    state = PresenceState.UNKNOWN
                db.execute("INSERT OR REPLACE INTO presence_inputs VALUES ('owner_observation',?,?,?,?)",
                           (state.value, timestamp(observation.received_at), timestamp(presence_valid_until),
                            str(observation.identifier)))
            if observation.kind in CRITICAL and observation.confirmed:
                for action in ("evidence", "notification"):
                    db.execute("INSERT INTO presence_deliveries VALUES (?,?,'pending',0)",
                               (str(observation.identifier), action))
        return observation

    def complete_action(self, identifier, action, result):
        if not isinstance(identifier, UUID) or action not in {"evidence", "notification"}:
            raise ValueError("invalid action identity")
        if not isinstance(result, ActionResult):
            raise ValueError("explicit delivery result required")
        with self._transaction() as db:
            # A later failure cannot erase an already confirmed completion.
            db.execute("UPDATE presence_deliveries SET state=? WHERE observation=? AND action=? "
                       "AND state!='delivered'", (result.value, str(identifier), action))

    def dispatch_pending(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("invalid dispatch limit")
        # Submission is separate from observation ingestion. Claim durably,
        # release the SQLite lock, then invoke the port. A process crash in this
        # interval leaves submitting/queued visibly unresolved; it never causes
        # a blind retry of a potentially completed external side effect.
        #
        # The bounded batch is ordered, so a backlog of still unavailable or
        # repeatedly attempted work cannot starve newly queued critical
        # evidence and notification jobs: never attempted rows lead, pending
        # precedes unavailable, and equal work is dispatched in receipt order.
        with closing(self.database.connect()) as db:
            pending = db.execute(
                "SELECT job.observation,job.action FROM presence_deliveries job "
                "JOIN presence_observations item ON item.id=job.observation "
                "WHERE job.state IN ('pending','unavailable') "
                "ORDER BY job.attempts, job.state='unavailable', item.sequence, job.action "
                "LIMIT ?", (limit,)).fetchall()
        for row in pending:
            with self._transaction() as db:
                job = db.execute("SELECT * FROM presence_deliveries WHERE observation=? AND action=?",
                                 tuple(row)).fetchone()
                if job["state"] not in {"pending", "unavailable"}:
                    continue
                port = self.evidence if row["action"] == "evidence" else self.notifications
                if port is None:
                    db.execute("UPDATE presence_deliveries SET state='unavailable' WHERE observation=? AND action=?", tuple(row))
                    continue
                payload = db.execute("SELECT payload FROM presence_observations WHERE id=?", (row["observation"],)).fetchone()[0]
                observation = Observation.from_payload(json.loads(payload))
                db.execute("UPDATE presence_deliveries SET state='submitting',attempts=attempts+1 "
                           "WHERE observation=? AND action=?", tuple(row))
            def complete(result, identifier=observation.identifier, action=row["action"]):
                self.complete_action(identifier, action, result)
            try:
                result = port(observation, complete)
                if not isinstance(result, ActionResult):
                    result = ActionResult.UNCERTAIN
            except Exception:
                result = ActionResult.UNCERTAIN
            with self._transaction() as db:
                # Synchronous callbacks may already have completed the job.
                db.execute("UPDATE presence_deliveries SET state=? WHERE observation=? AND action=? "
                           "AND state='submitting'", (result.value, row["observation"], row["action"]))

    def process_critical(self, detector):
        """Run the supplied critical detector in every presence state."""
        observation = detector()
        if not isinstance(observation, Observation) or observation.kind not in CRITICAL:
            raise ValueError("critical observation required")
        return self.record(observation)

    @staticmethod
    def _effective(db, now, trusted):
        override = db.execute("SELECT * FROM presence_override WHERE singleton=1").fetchone()
        # An elapsed expiry stops applying immediately, whether or not the
        # durable retirement write has been admitted yet.
        if override and not (override["expires"] and trusted and override["expires"] <= timestamp(now)):
            return PresenceState(override["state"]), "manual_override", override["expires"]
        if trusted:
            for slot in ("owner_observation", "hint"):
                item = db.execute("SELECT * FROM presence_inputs WHERE slot=? AND observed<=? AND valid_until>?",
                                  (slot, timestamp(now), timestamp(now))).fetchone()
                if item:
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
                elif self._clock(db, now, True):
                    db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('override_expired',NULL,?,?)",
                               (timestamp(now), override["state"]))
                    db.execute("DELETE FROM presence_override WHERE singleton=1")
                    self._control_observation(db, self._effective(db, now, True)[0], now)
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

    def _critical_paths(self, *, persistence_denied):
        """Report configured/known critical-path availability, never a fixed armed.

        ``armed`` means the path is configured and is not disarmed by any
        presence state; it is not a liveness guarantee for an external worker.
        ``pending_critical_actions`` still reports unfinished critical work.
        """
        paths = {
            "critical_detection": self._detection_path(),
            "critical_persistence": UNAVAILABLE if (self.write_guard is None or persistence_denied) else ARMED,
            "critical_evidence": ARMED if self.evidence is not None else UNAVAILABLE,
            "critical_notifications": ARMED if self.notifications is not None else UNAVAILABLE,
        }
        return {**paths, "critical_paths_degraded": any(value != ARMED for value in paths.values())}

    def snapshot(self, *, now, clock_trusted):
        """Read-only status. A refused or exhausted volume never hides presence."""
        with closing(self.database.connect()) as db:
            trusted = self._clock_trust(db, now, clock_trusted)
            override = db.execute("SELECT * FROM presence_override WHERE singleton=1").fetchone()
        expired = bool(override and override["expires"] and trusted
                       and override["expires"] <= timestamp(now))
        # An expired override stops applying even when the durable retirement
        # write is refused; the pending flag keeps that difference visible.
        retired, admitted = self._retire_override(now) if expired else (True, True)
        with closing(self.database.connect()) as db:
            trusted = self._clock_trust(db, now, clock_trusted)
            state, basis, expires = self._effective(db, now, trusted)
            failed = db.execute("SELECT count(*) FROM presence_deliveries "
                                "WHERE state NOT IN ('delivered','disabled')").fetchone()[0]
        return {"state": state.value, "basis": basis, "override_expires_at": expires,
                "clock_degraded": not trusted,
                "suppress_ordinary": state == PresenceState.PRESENT and trusted,
                **self._critical_paths(persistence_denied=not admitted),
                "override_expiry_pending": not retired,
                "pending_critical_actions": failed}

    def owner_status(self, context, *, now, clock_trusted):
        self._owner(context)
        return self.snapshot(now=now, clock_trusted=clock_trusted)

    def audit(self, context):
        self._owner(context)
        with closing(self.database.connect()) as db:
            return [dict(row) for row in db.execute("SELECT * FROM presence_audit ORDER BY sequence")]

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
        with closing(self.database.connect()) as db:
            rows = db.execute("SELECT sequence,received,payload FROM presence_observations "
                              "WHERE received>=? AND received<? " + page
                              + "ORDER BY received,sequence LIMIT ?", (*window, limit)).fetchall()
        items = [{**json.loads(row["payload"]), "sequence": row["sequence"]} for row in rows]
        uncertain = any(not item["clock_trusted"] or item["uncertainty_us"] for item in items)
        return {"items": items, "ordering_basis": "received_at", "ordering_degraded": uncertain,
                "causality": "not_inferred",
                "next_cursor": ({"received_at": rows[-1]["received"], "sequence": rows[-1]["sequence"]}
                                if rows else after)}
