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
    Rows are never deleted. Existing rows are backfilled best-effort; keys
    superseded before this migration are not recoverable.
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
        "INSERT OR IGNORE INTO pairing_key_bindings (public_key_digest, node_id, revoked) "
        "SELECT public_key_digest, node_id, state = 'revoked' FROM pairing_node_credentials",
        "INSERT OR IGNORE INTO pairing_key_bindings (public_key_digest, node_id, revoked) "
        "SELECT public_key_digest, node_id, MAX(state = 'revoked') FROM pairing_enrollments "
        "GROUP BY public_key_digest, node_id",
        "UPDATE pairing_key_bindings SET revoked = 1 WHERE public_key_digest IN ("
        "SELECT public_key_digest FROM pairing_enrollments WHERE state = 'revoked')",
    ))
