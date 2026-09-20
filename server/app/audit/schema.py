"""Deployment-local audit schema, separate from factual timeline events."""

from app.storage.migrations import Migration


AUDIT_MIGRATION = Migration(5, "security_admin_audit", (
    "CREATE TABLE security_admin_audit_records ("
    "id TEXT PRIMARY KEY, actor_category TEXT NOT NULL, action TEXT NOT NULL, "
    "target_kind TEXT NOT NULL, target_logical_id TEXT NOT NULL, "
    "occurred_at_us INTEGER NOT NULL, outcome TEXT NOT NULL, "
    "CHECK(actor_category IN ('owner','system','invited_user','capture_node','unauthenticated')), "
    "CHECK(outcome IN ('succeeded','failed','denied')))",
    "CREATE INDEX security_admin_audit_time_idx "
    "ON security_admin_audit_records(occurred_at_us, id)",
    "CREATE TRIGGER security_admin_audit_no_update "
    "BEFORE UPDATE ON security_admin_audit_records BEGIN "
    "SELECT RAISE(ABORT, 'audit records are immutable'); END",
))
