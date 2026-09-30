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
    """
    return Migration(version, "pairing_credential_renewal", (
        "ALTER TABLE pairing_node_credentials ADD COLUMN not_after REAL",
        "CREATE TABLE pairing_node_renewals ("
        "node_id TEXT PRIMARY KEY REFERENCES pairing_node_credentials(node_id), "
        "public_key_digest TEXT NOT NULL, credential_serial_digest TEXT NOT NULL, "
        "not_after REAL NOT NULL)",
    ))
