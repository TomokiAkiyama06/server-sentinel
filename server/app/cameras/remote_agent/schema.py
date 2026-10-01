"""Schema for the dependency-free capture-node pairing ledger."""
from app.storage.migrations import Migration


PAIRING_MIGRATION = Migration(11, "pairing_ledger", (
    "CREATE TABLE pairing_enrollments ("
    "id TEXT PRIMARY KEY, node_id TEXT NOT NULL, public_key_digest TEXT NOT NULL, "
    "code_digest TEXT NOT NULL, process_epoch TEXT NOT NULL, expires_at REAL NOT NULL, "
    "state TEXT NOT NULL CHECK (state IN ('pending', 'expired', 'consumed', 'activated', 'revoked'))) ",
    "CREATE INDEX pairing_enrollments_pending ON pairing_enrollments(state, expires_at)",
    "CREATE TABLE pairing_node_credentials ("
    "node_id TEXT PRIMARY KEY, public_key_digest TEXT NOT NULL, "
    "credential_serial_digest TEXT NOT NULL, "
    "state TEXT NOT NULL CHECK (state IN ('active', 'revoked'))) ",
))


def pairing_renewal_migration(version: int) -> Migration:
    """Issue #13 automatic renewal: credential expiry plus one staged renewal per node.

    A staged renewal is admitted at most once as a promotion that atomically
    supersedes the active credential; revocation deletes it.

    ``pairing_key_bindings`` permanently records every node public key the
    ledger has approved, activated or staged (Owner decision 2026-09-30): a
    key is never rebound to another node, and a revoked key is never reused.
    Rows are never deleted. Existing rows are backfilled; keys superseded
    before this migration are not recoverable. If a legacy database holds one
    key digest under two node IDs (any states), the migration fails closed and
    startup is blocked instead of silently picking one binding; the conflicting
    legacy rows need explicit Owner remediation before the upgrade can proceed.
    Likewise, a digest that is revoked somewhere yet still live elsewhere (an
    active credential, or a pending or consumed enrollment; the old schema
    allowed re-approving a revoked key) fails the migration closed: the Owner
    must revoke the live use or remove it before upgrading, because a revoked
    key is never reused.
    """
    return Migration(version, "pairing_credential_renewal", (
        "ALTER TABLE pairing_node_credentials ADD COLUMN not_after REAL",
        "CREATE TABLE pairing_node_renewals ("
        "node_id TEXT PRIMARY KEY REFERENCES pairing_node_credentials(node_id), "
        "public_key_digest TEXT NOT NULL, credential_serial_digest TEXT NOT NULL, "
        "not_after REAL NOT NULL)",
        "CREATE TABLE pairing_key_bindings ("
        "public_key_digest TEXT PRIMARY KEY, node_id TEXT NOT NULL, "
        "revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)))",
        # A revoked key that is still live (an active credential, or a pending
        # or consumed enrollment) is a mixed history the old schema allowed by
        # re-approving a revoked key. Any such digest violates CHECK (0) and
        # fails the migration closed; the table never survives a migration.
        "CREATE TABLE pairing_legacy_revoked_key_still_live ("
        "public_key_digest TEXT NOT NULL CHECK (0))",
        "INSERT INTO pairing_legacy_revoked_key_still_live (public_key_digest) "
        "SELECT public_key_digest FROM pairing_node_credentials WHERE state = 'revoked' "
        "UNION SELECT public_key_digest FROM pairing_enrollments WHERE state = 'revoked' "
        "INTERSECT SELECT public_key_digest FROM ("
        "SELECT public_key_digest FROM pairing_node_credentials WHERE state = 'active' "
        "UNION ALL SELECT public_key_digest FROM pairing_enrollments "
        "WHERE state IN ('pending', 'consumed'))",
        "DROP TABLE pairing_legacy_revoked_key_still_live",
        # Deliberately not INSERT OR IGNORE: a legacy key digest held by two
        # node IDs violates the primary key and fails the migration closed.
        "INSERT INTO pairing_key_bindings (public_key_digest, node_id, revoked) "
        "SELECT public_key_digest, node_id, MAX(revoked) FROM ("
        "SELECT public_key_digest, node_id, state = 'revoked' AS revoked "
        "FROM pairing_node_credentials UNION ALL "
        "SELECT public_key_digest, node_id, state = 'revoked' AS revoked "
        "FROM pairing_enrollments) GROUP BY public_key_digest, node_id",
    ))
