"""Durable precedence, neutral history, and presence-independent critical work."""

from contextlib import closing, contextmanager
import json
from uuid import UUID

from .access import DenyAccess
from .delivery import ActionResult
from .models import (CRITICAL, Kind, Observation, PresenceState, Quality, Value,
                     timestamp, utc)


class PresenceService:
    def __init__(self, database, *, access=None, evidence=None, notifications=None, write_guard=None):
        self.database = database
        self.access = access or DenyAccess()
        self.evidence = evidence
        self.notifications = notifications
        self.write_guard = write_guard

    @contextmanager
    def _transaction(self):
        if self.write_guard is None:
            raise RuntimeError("storage admission required")
        self.write_guard()
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
    def _clock(db, now, trusted):
        if type(trusted) is not bool:
            raise ValueError("explicit clock trust required")
        stamp = timestamp(now)
        previous = db.execute("SELECT latest FROM presence_clock WHERE singleton=1").fetchone()
        if previous is not None and stamp < previous[0]:
            return False
        if trusted:
            db.execute("INSERT OR REPLACE INTO presence_clock VALUES (1,?)", (stamp,))
        return trusted

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
        with closing(self.database.connect()) as db:
            pending = db.execute("SELECT observation,action FROM presence_deliveries "
                                 "WHERE state IN ('pending','unavailable') LIMIT ?", (limit,)).fetchall()
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
        if override:
            return PresenceState(override["state"]), "manual_override", override["expires"]
        if trusted:
            for slot in ("owner_observation", "hint"):
                item = db.execute("SELECT * FROM presence_inputs WHERE slot=? AND observed<=? AND valid_until>?",
                                  (slot, timestamp(now), timestamp(now))).fetchone()
                if item:
                    return PresenceState(item["state"]), slot, None
        return PresenceState.UNKNOWN, "unknown", None

    def snapshot(self, *, now, clock_trusted):
        with self._transaction() as db:
            trusted = self._clock(db, now, clock_trusted)
            override = db.execute("SELECT * FROM presence_override WHERE singleton=1").fetchone()
            expired = False
            if override and override["expires"] and trusted and override["expires"] <= timestamp(now):
                db.execute("INSERT INTO presence_audit(action,actor,at,state) VALUES ('override_expired',NULL,?,?)",
                           (timestamp(now), override["state"]))
                db.execute("DELETE FROM presence_override WHERE singleton=1")
                expired = True
            state, basis, expires = self._effective(db, now, trusted)
            if expired:
                self._control_observation(db, state, now)
            failed = db.execute("SELECT count(*) FROM presence_deliveries WHERE state NOT IN ('delivered','disabled')").fetchone()[0]
            return {"state": state.value, "basis": basis, "override_expires_at": expires,
                    "clock_degraded": not trusted,
                    "suppress_ordinary": state == PresenceState.PRESENT and trusted,
                    "critical_detection_armed": True, "critical_evidence_armed": True,
                    "critical_notifications_armed": True, "pending_critical_actions": failed}

    def owner_status(self, context, *, now, clock_trusted):
        self._owner(context)
        return self.snapshot(now=now, clock_trusted=clock_trusted)

    def audit(self, context):
        self._owner(context)
        with closing(self.database.connect()) as db:
            return [dict(row) for row in db.execute("SELECT * FROM presence_audit ORDER BY sequence")]

    def history(self, context, *, received_from, received_to, limit=100, after_sequence=0):
        self.access.require_recordings(context)
        if (utc(received_from) >= utc(received_to) or type(limit) is not int or not 1 <= limit <= 500
                or type(after_sequence) is not int or after_sequence < 0):
            raise ValueError("invalid timeline window")
        with closing(self.database.connect()) as db:
            rows = db.execute("SELECT sequence,payload FROM presence_observations WHERE received>=? "
                              "AND received<? AND sequence>? ORDER BY sequence LIMIT ?",
                              (timestamp(received_from), timestamp(received_to), after_sequence, limit)).fetchall()
        items = [{**json.loads(row["payload"]), "sequence": row["sequence"]} for row in rows]
        uncertain = any(not item["clock_trusted"] or item["uncertainty_us"] for item in items)
        basis = "received_at" if uncertain else "occurred_at"
        items.sort(key=lambda item: (item[basis], item["sequence"]))
        return {"items": items, "ordering_basis": basis, "ordering_degraded": uncertain,
                "causality": "not_inferred", "next_sequence": max((row["sequence"] for row in rows), default=after_sequence)}
