"""Append-only migration for the collection-based camera registry."""

from app.storage.migrations import Migration


REGISTRY_MIGRATION = Migration(2, "camera_registry", (
    "CREATE TABLE camera_registry_settings ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), "
    "max_active_video_sources INTEGER NOT NULL CHECK (max_active_video_sources > 0))",
    "INSERT INTO camera_registry_settings VALUES (1, 4)",
    "CREATE TABLE capture_nodes ("
    "id TEXT PRIMARY KEY, name TEXT NOT NULL, "
    "health_state TEXT NOT NULL CHECK (health_state IN "
    "('online', 'degraded', 'offline', 'revoked')), "
    "last_seen_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE camera_sources ("
    "id TEXT PRIMARY KEY, capture_node_id TEXT REFERENCES capture_nodes(id), "
    "source_type TEXT NOT NULL CHECK (source_type IN ('local_uvc', 'remote_agent')), "
    "name TEXT NOT NULL, role_label TEXT, "
    "enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)), "
    "capabilities TEXT NOT NULL, desired_capture_profile TEXT, negotiated_capture_profile TEXT, "
    "health_state TEXT NOT NULL CHECK (health_state IN "
    "('online', 'degraded', 'offline', 'manual_intervention_required')), "
    "image_quality_state TEXT NOT NULL, last_seen_at TEXT, "
    "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
    "CHECK ((source_type = 'local_uvc' AND capture_node_id IS NULL) OR "
    "(source_type = 'remote_agent' AND capture_node_id IS NOT NULL AND capture_node_id != id)))",
    "CREATE INDEX camera_sources_node ON camera_sources(capture_node_id)",
    "CREATE TABLE detection_bindings ("
    "source_id TEXT NOT NULL REFERENCES camera_sources(id) ON DELETE CASCADE, "
    "binding_id TEXT NOT NULL, kind TEXT NOT NULL, version INTEGER NOT NULL CHECK (version > 0), "
    "enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)), "
    "thresholds TEXT NOT NULL, config TEXT NOT NULL, PRIMARY KEY (source_id, binding_id))",
))
