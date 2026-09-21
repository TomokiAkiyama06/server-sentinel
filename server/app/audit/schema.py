"""Deployment-local audit schema, separate from factual timeline events."""

from app.storage.migrations import Migration


AUDIT_STATEMENTS = (
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
)


def audit_migration(version: int) -> Migration:
    """Place the audit DDL at a caller-assigned slot, like other modules.

    The application aggregator owns the ordering; this module never pins a
    version so an append-only catalog can grow without renumbering.
    """
    return Migration(version, "security_admin_audit", AUDIT_STATEMENTS)
