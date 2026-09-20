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
        "CREATE TABLE presence_audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
        "action TEXT NOT NULL, actor TEXT, at TEXT NOT NULL, state TEXT)",
        "CREATE INDEX presence_audit_time ON presence_audit(at, sequence)",
        "CREATE TABLE presence_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), latest TEXT NOT NULL)",
        # Owner-control time is tracked apart from source observation time, so a
        # single far-future observation cannot lock out Owner presence control.
        "CREATE TABLE presence_control_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "latest TEXT NOT NULL)",
        "CREATE TABLE presence_source_clock (source TEXT PRIMARY KEY, latest_occurred TEXT NOT NULL)",
        # `requeued` marks work an Owner explicitly recovered, so its retained
        # attempt count cannot push it behind an endless stream of fresh jobs.
        "CREATE TABLE presence_deliveries (observation TEXT REFERENCES presence_observations(id), "
        "action TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL, "
        "requeued INTEGER NOT NULL DEFAULT 0 CHECK(requeued IN (0,1)), PRIMARY KEY(observation, action))",
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
