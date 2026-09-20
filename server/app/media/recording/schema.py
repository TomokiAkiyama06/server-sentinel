"""Recording DDL; the application migration aggregator assigns its final slot."""

from app.storage.migrations import Migration


RECORDING_STATEMENTS = (
    "CREATE TABLE recording_source_cursors (source_id TEXT PRIMARY KEY, "
    "stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, end_ms INTEGER NOT NULL, "
    "capture_node_id TEXT, active INTEGER NOT NULL CHECK(active IN (0,1)))",
    "CREATE TABLE recording_segments ("
    "id TEXT PRIMARY KEY, source_id TEXT NOT NULL, capture_node_id TEXT, "
    "stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, start_ms INTEGER NOT NULL, "
    "end_ms INTEGER NOT NULL, codec TEXT NOT NULL, container TEXT NOT NULL, "
    "byte_length INTEGER NOT NULL, sha256 TEXT NOT NULL, "
    "state TEXT NOT NULL CHECK(state IN ('pending','ready')), "
    "spool INTEGER NOT NULL CHECK(spool IN (0,1)), "
    "critical INTEGER NOT NULL DEFAULT 0 CHECK(critical IN (0,1)), "
    "integrity TEXT NOT NULL DEFAULT 'unchecked', "
    "UNIQUE(source_id, stream_id, sequence))",
    "CREATE INDEX recording_segment_time ON recording_segments(source_id,start_ms,end_ms)",
    "CREATE TABLE recordings (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, "
    "event_id TEXT, start_ms INTEGER NOT NULL, target_end_ms INTEGER NOT NULL, "
    "ended_ms INTEGER, status TEXT NOT NULL, critical INTEGER NOT NULL, "
    "starred INTEGER NOT NULL DEFAULT 0 CHECK(starred IN (0,1)))",
    "CREATE INDEX recording_event_id ON recordings(event_id)",
    "CREATE TABLE recording_links (recording_id TEXT NOT NULL REFERENCES recordings(id), "
    "segment_id TEXT NOT NULL REFERENCES recording_segments(id), "
    "PRIMARY KEY(recording_id,segment_id))",
    "CREATE TABLE recording_discontinuities (recording_id TEXT NOT NULL REFERENCES recordings(id), "
    "start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL, reason TEXT NOT NULL)",
    "CREATE TABLE recording_source_discontinuities ("
    "source_id TEXT NOT NULL, start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL, "
    "reason TEXT NOT NULL, PRIMARY KEY(source_id,start_ms,end_ms,reason))",
)


def recording_migration(version: int) -> Migration:
    return Migration(version, "durable_recording", RECORDING_STATEMENTS)
