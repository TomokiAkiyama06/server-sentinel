"""Durable precedence, neutral history, and presence-independent critical work."""

from contextlib import ExitStack, closing, contextmanager
from datetime import timedelta
import json
from uuid import UUID

from .access import DenyAccess
from .delivery import ActionResult
from .models import (CRITICAL, Kind, Observation, PresenceState, Quality, Value,
                     timestamp, utc)
from app.storage.retention import RetentionPeriods


ARMED = "armed"
UNAVAILABLE = "unavailable"
UNKNOWN = "unknown"


class PresenceService:
    def __init__(self, database, *, access=None, evidence=None, notifications=None,
                 reservation=None, detection=None):
        self.database = database
        self.access = access or DenyAccess()
        self.evidence = evidence
        self.notifications = notifications
        # Storage admission port supplied by #21, such as
        # `MainStoragePolicy.control`: a callable returning a reservation
        # context manager. Presence holds it for the whole write, so the hard
        # filesystem reserve is honoured and the reservation is released again.
        self.reservation = reservation
        # Injected by the reviewed #24 detector supervisor. Absent means unknown
        # detection health here; this module never claims a detector is running.
        self.detection = detection

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
            completed = db.execute("SELECT 1 FROM presence_completed_events WHERE id=?",
                                   (str(observation.identifier),)).fetchone()
            if completed:
                # The timeline payload passed its retention horizon after this
                # event's critical actions completed. Recording the identity
                # again would preserve evidence and notify a second time, so a
                # delayed replay stays a duplicate and its payload stays expired.
                return observation
            trusted = self._clock(db, observation.received_at, observation.clock_trusted)
            if observation.source_id:
                source = str(observation.source_id)
                high_water = db.execute("SELECT latest_occurred FROM presence_source_clock WHERE source=?",
                                        (source,)).fetchone()
                if high_water and timestamp(observation.occurred_at) < high_water["latest_occurred"]:
                    trusted = False
            if not trusted:
                observation = observation.uncertain()
            elif observation.source_id:
                db.execute("INSERT INTO presence_source_clock(source,latest_occurred) VALUES (?,?) "
                           "ON CONFLICT(source) DO UPDATE SET latest_occurred="
                           "MAX(latest_occurred,excluded.latest_occurred)",
                           (str(observation.source_id), timestamp(observation.occurred_at)))
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

    def complete_action(self, identifier, action, result):
        if not isinstance(identifier, UUID) or action not in {"evidence", "notification"}:
            raise ValueError("invalid action identity")
        if not isinstance(result, ActionResult):
            raise ValueError("explicit delivery result required")
        with self._transaction() as db:
            # A later failure cannot erase an already confirmed completion.
            db.execute("UPDATE presence_deliveries SET state=? WHERE observation=? AND action=? "
                       "AND state!='delivered'", (result.value, str(identifier), action))

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
            # recovery leads the queue instead of being starved by new work.
            db.execute("UPDATE presence_deliveries SET state='pending',requeued=1 "
                       "WHERE observation=? AND action=?", (str(identifier), action))
            db.execute("INSERT INTO presence_audit(action,actor,at,state) "
                       "VALUES ('critical_action_requeued',?,?,NULL)", (actor, timestamp(now)))
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
            db.execute("INSERT INTO presence_audit(action,actor,at,state) "
                       "VALUES ('critical_degradation_cleared',?,?,NULL)", (actor, timestamp(now)))

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

    def _persistence_path(self):
        """Probe current storage admission without creating a presence write.

        The probed reservation is entered and released immediately, so the
        status read neither holds nor leaks the deployment's write admission.
        """
        try:
            with self._admission():
                pass
        except Exception:
            return UNAVAILABLE
        return ARMED

    def _critical_paths(self, unresolved):
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
            "critical_persistence": self._persistence_path(),
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
        with closing(self.database.connect()) as db:
            control_trusted = self._control_trust(db, now, clock_trusted)
            override = db.execute("SELECT * FROM presence_override WHERE singleton=1").fetchone()
        expired = bool(override and override["expires"] and control_trusted
                       and override["expires"] <= timestamp(now))
        # An expired override stops applying even when the durable retirement
        # write is refused; the pending flag keeps that difference visible.
        retired, _admitted = self._retire_override(now) if expired else (True, None)
        with closing(self.database.connect()) as db:
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
        # The reported state is only as trustworthy as the marker behind its
        # basis: Owner control for an override or hint, observation receipt for
        # an inferred owner observation. A skewed source timestamp must not
        # withhold the suppression an accepted Owner override asks for, and the
        # separate observation flag keeps that skew visible.
        timing = {"manual_override": control_trusted, "hint": control_trusted,
                  "owner_observation": trusted}.get(basis, trusted and control_trusted)
        return {"state": state.value, "basis": basis, "override_expires_at": expires,
                "clock_degraded": not timing,
                "observation_clock_degraded": not trusted,
                "suppress_ordinary": state == PresenceState.PRESENT and timing,
                **self._critical_paths(unresolved),
                "override_expiry_pending": not retired,
                "pending_critical_actions": failed}

    def owner_status(self, context, *, now, clock_trusted):
        self._owner(context)
        return self.snapshot(now=now, clock_trusted=clock_trusted)

    def audit(self, context):
        self._owner(context)
        with closing(self.database.connect()) as db:
            return [dict(row) for row in db.execute("SELECT * FROM presence_audit ORDER BY sequence")]

    def expire_audit(self, *, now, limit=1000):
        """Apply the main 90-day audit policy to owner-control history.

        This is a maintenance operation for the same retention workflow that
        expires storage-state audit rows. It is bounded and storage-admitted so
        a full or unsafe volume cannot silently report a completed cleanup.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid audit retention limit")
        cutoff = timestamp(utc(now) - timedelta(days=RetentionPeriods().audit_days))
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

        A critical action that never completed, such as a durably disabled
        delivery, leaves a per-action degradation marker behind. Expiring its
        row must not let the snapshot report that path as armed again, because
        the action still did not happen and the tombstone stops a replay from
        re-queuing it.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid timeline retention limit")
        cutoff = timestamp(utc(now) - timedelta(days=RetentionPeriods().recording_days))
        with self._transaction() as db:
            rows = db.execute("SELECT item.id FROM presence_observations item "
                              "WHERE item.received<? AND NOT EXISTS (SELECT 1 FROM presence_deliveries job "
                              "WHERE job.observation=item.id AND job.state NOT IN ('delivered','disabled')) "
                              "ORDER BY item.received,item.sequence LIMIT ?", (cutoff, limit)).fetchall()
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
