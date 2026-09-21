"""Durable, ceremony-neutral human-access schema.

The WebAuthn verifier will own credential parsing and signature verification.  This
schema only persists opaque credential material and authorization state.
"""

from app.storage.migrations import Migration


def access_migration(version: int) -> Migration:
    return Migration(version, "human_access_foundation", (
        "CREATE TABLE access_deployment_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), authorization_generation INTEGER NOT NULL CHECK(authorization_generation >= 0))",
        "INSERT INTO access_deployment_state VALUES (1, 0)",
        "CREATE TABLE access_principals (id TEXT PRIMARY KEY, external_identity TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','invited_user')), status TEXT NOT NULL CHECK(status IN ('invited','active','revoked')), authorization_revision INTEGER NOT NULL CHECK(authorization_revision >= 0), created_at_us INTEGER NOT NULL, revoked_at_us INTEGER)",
        "CREATE UNIQUE INDEX access_one_owner ON access_principals(role) WHERE role = 'owner'",
        "CREATE TABLE access_principal_permissions (principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, permission TEXT NOT NULL CHECK(permission IN ('live:view','recordings:view')), PRIMARY KEY(principal_id, permission))",
        "CREATE TABLE access_credentials (credential_id BLOB PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, public_key BLOB NOT NULL, algorithm INTEGER NOT NULL, sign_count INTEGER NOT NULL CHECK(sign_count >= 0), enrolled_at_us INTEGER NOT NULL, revoked_at_us INTEGER)",
        "CREATE INDEX access_credentials_principal ON access_credentials(principal_id)",
        "CREATE TABLE access_invitations (id TEXT PRIMARY KEY, secret_digest BLOB NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, principal_revision INTEGER NOT NULL, deployment_generation INTEGER NOT NULL, issued_at_us INTEGER NOT NULL, expires_at_us INTEGER NOT NULL, redeemed_at_us INTEGER, revoked_at_us INTEGER)",
        "CREATE INDEX access_invitations_principal ON access_invitations(principal_id)",
        "CREATE TABLE access_sessions (id TEXT PRIMARY KEY, token_digest BLOB NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, credential_id BLOB NOT NULL REFERENCES access_credentials(credential_id), principal_revision INTEGER NOT NULL, deployment_generation INTEGER NOT NULL, established_at_us INTEGER NOT NULL, last_seen_at_us INTEGER NOT NULL, idle_expires_at_us INTEGER NOT NULL, absolute_expires_at_us INTEGER NOT NULL, invalidated_at_us INTEGER)",
        "CREATE INDEX access_sessions_principal ON access_sessions(principal_id)",
    ))
