"""Presence DDL; the application migration aggregator assigns its final slot.

`app/storage/schema.py` registers this migration so the ordinary application
startup creates these tables. No import here has startup side effects.
"""

from app.storage.migrations import Migration


def presence_migration(version: int) -> Migration:
    return Migration(version, "presence_timeline", (
        "CREATE TABLE presence_observations (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
        "id TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, source TEXT, received TEXT NOT NULL, payload TEXT NOT NULL)",
        "CREATE INDEX presence_received ON presence_observations(received, sequence)",
        "CREATE TABLE presence_inputs (slot TEXT PRIMARY KEY, state TEXT NOT NULL, "
        "observed TEXT NOT NULL, valid_until TEXT NOT NULL, observation TEXT)",
        "CREATE TABLE presence_override (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "state TEXT NOT NULL, actor TEXT NOT NULL, started TEXT NOT NULL, expires TEXT)",
        # `target` names the logical object an Owner operation acted on, such as
        # the critical action and event identity of an approved resubmission. It
        # holds no observation content.
        "CREATE TABLE presence_audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
        "action TEXT NOT NULL, actor TEXT, at TEXT NOT NULL, state TEXT, target TEXT)",
        "CREATE INDEX presence_audit_time ON presence_audit(at, sequence)",
        "CREATE TABLE presence_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), latest TEXT NOT NULL)",
        # Owner-control time is tracked apart from source observation time, so a
        # single far-future observation cannot lock out Owner presence control.
        "CREATE TABLE presence_control_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "latest TEXT NOT NULL)",
        "CREATE TABLE presence_source_clock (source TEXT PRIMARY KEY, latest_occurred TEXT NOT NULL)",
        # `requeued` marks work an Owner explicitly recovered, so its retained
        # attempt count cannot push it behind an endless stream of fresh jobs.
        # `generation` identifies the claim a completion callback belongs to, so
        # a callback from a superseded attempt cannot overwrite a newer one.
        "CREATE TABLE presence_deliveries (observation TEXT REFERENCES presence_observations(id), "
        "action TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL, "
        "requeued INTEGER NOT NULL DEFAULT 0 CHECK(requeued IN (0,1)), "
        "generation INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(observation, action))",
        "CREATE TABLE presence_delivery_fairness (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "next_state TEXT NOT NULL CHECK(next_state IN ('pending','unavailable')))",
        # Identity-only tombstones for completed critical events whose timeline
        # payload expired; they carry no observation content.
        "CREATE TABLE presence_completed_events (id TEXT PRIMARY KEY, expired_at TEXT NOT NULL)",
        # Durable degradation markers for critical actions that never completed
        # before their timeline payload expired; per action, no event content.
        "CREATE TABLE presence_expired_unresolved (action TEXT PRIMARY KEY, "
        "events INTEGER NOT NULL, since TEXT NOT NULL)",
    ))


def presence_gap_migration(version: int) -> Migration:
    """Durable timeline-gap marker, the outbox session that proves a clean close,
    the source-fact digests that keep restamped replays comparable, and the
    separate source clock of synchronously recorded critical observations.

    The marker holds counts and times only, never observation content. A
    session row left behind by an outbox that did not close cleanly is itself
    evidence of an interrupted gap: staged facts may have been lost.
    """
    return Migration(version, "presence_timeline_gap", (
        "CREATE TABLE presence_timeline_gap (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "since TEXT NOT NULL, latest TEXT NOT NULL, "
        "refused INTEGER NOT NULL DEFAULT 0 CHECK(refused>=0), "
        "rejected INTEGER NOT NULL DEFAULT 0 CHECK(rejected>=0), "
        "lost INTEGER NOT NULL DEFAULT 0 CHECK(lost>=0), "
        "interrupted INTEGER NOT NULL DEFAULT 0 CHECK(interrupted>=0))",
        # The open outbox session, removed only by that session's clean close.
        # A second session is refused by a lock beside the database, so a row
        # found by a new session belongs to an outbox that is gone.
        "CREATE TABLE presence_outbox_sessions (token TEXT PRIMARY KEY, opened TEXT NOT NULL)",
        # Digest of the producer-supplied source fact of a restamped
        # observation, such as the tracker's own confirmation of a crossing,
        # which the receipt-derived payload fields cannot preserve. It holds a
        # hash only and is removed together with its observation.
        "CREATE TABLE presence_source_facts (id TEXT PRIMARY KEY, "
        "digest TEXT NOT NULL CHECK(length(digest)=64))",
        # Per-source high-water mark of synchronously recorded critical
        # observations, kept apart from the staged-fact mark so the intended
        # reordering between the two paths is never mistaken for a clock fault.
        "CREATE TABLE presence_critical_source_clock (source TEXT PRIMARY KEY, latest_occurred TEXT NOT NULL)",
    ))
