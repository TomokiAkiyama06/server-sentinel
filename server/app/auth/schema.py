"""Durable human-access schema.

``app.auth.webauthn`` owns credential parsing and signature verification. This
schema persists only public credential material, the verification outputs that
ADR-0004 allows to persist, and authorization state.
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
        "CREATE TABLE access_sessions (id TEXT PRIMARY KEY, token_digest BLOB NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, credential_id BLOB NOT NULL REFERENCES access_credentials(credential_id), principal_revision INTEGER NOT NULL, deployment_generation INTEGER NOT NULL, established_at_us INTEGER NOT NULL, last_seen_at_us INTEGER NOT NULL, idle_lifetime_us INTEGER NOT NULL CHECK(idle_lifetime_us > 0), idle_expires_at_us INTEGER NOT NULL, absolute_expires_at_us INTEGER NOT NULL, invalidated_at_us INTEGER)",
        "CREATE INDEX access_sessions_principal ON access_sessions(principal_id)",
    ))


def access_webauthn_migration(version: int) -> Migration:
    """Per-person WebAuthn credential state for Issue #10 (ADR-0004).

    Adds only what ADR-0004 allows to persist: the backup-eligibility and
    backup-state flags, the inconsistent-credential marker, an owner-visible
    label and last-use time, the session's user-verification time for owner
    step-up freshness, the invitation attempt counter, and pending ceremony
    challenges. A challenge is stored as its SHA-256 digest only, is bound to
    one ceremony (and to its invitation or session where the ceremony has
    one), and is deleted when it is consumed or expires.
    """
    return Migration(version, "human_access_webauthn", (
        "ALTER TABLE access_credentials ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK(backup_eligible IN (0,1))",
        "ALTER TABLE access_credentials ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0 CHECK(backup_state IN (0,1))",
        "ALTER TABLE access_credentials ADD COLUMN inconsistency_reason TEXT CHECK(inconsistency_reason IS NULL OR inconsistency_reason = 'backup_eligibility_changed')",
        "ALTER TABLE access_credentials ADD COLUMN inconsistent_at_us INTEGER",
        "ALTER TABLE access_credentials ADD COLUMN label TEXT",
        "ALTER TABLE access_credentials ADD COLUMN last_used_at_us INTEGER",
        "ALTER TABLE access_sessions ADD COLUMN last_user_verification_at_us INTEGER",
        "ALTER TABLE access_invitations ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0)",
        "CREATE TABLE access_webauthn_challenges (challenge_digest BLOB PRIMARY KEY, ceremony TEXT NOT NULL CHECK(ceremony IN ('registration','authentication','step_up')), invitation_id TEXT REFERENCES access_invitations(id) ON DELETE CASCADE, session_id TEXT REFERENCES access_sessions(id) ON DELETE CASCADE, issued_at_us INTEGER NOT NULL, expires_at_us INTEGER NOT NULL, CHECK(expires_at_us > issued_at_us), CHECK((ceremony = 'registration') = (invitation_id IS NOT NULL)), CHECK((ceremony = 'step_up') = (session_id IS NOT NULL)))",
        "CREATE INDEX access_webauthn_challenges_expiry ON access_webauthn_challenges(expires_at_us)",
    ))


# Final table definitions after ``access_shared_identity_migration``. Column
# order matches the tables they replace (the store inserts principals
# positionally); only the changes documented on the migration differ.
_PRINCIPALS = ("CREATE TABLE access_principals (id TEXT PRIMARY KEY, external_identity TEXT CHECK(external_identity IS NULL OR length(external_identity) BETWEEN 1 AND 256), display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','invited_user')), status TEXT NOT NULL CHECK(status IN ('invited','active','revoked')), authorization_revision INTEGER NOT NULL CHECK(authorization_revision >= 0), created_at_us INTEGER NOT NULL, revoked_at_us INTEGER)")
_PERMISSIONS = ("CREATE TABLE access_principal_permissions (principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, permission TEXT NOT NULL CHECK(permission IN ('live:view','recordings:view')), PRIMARY KEY(principal_id, permission))")
_CREDENTIALS = ("CREATE TABLE access_credentials (credential_id BLOB PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, public_key BLOB NOT NULL, algorithm INTEGER NOT NULL, sign_count INTEGER NOT NULL CHECK(sign_count >= 0), enrolled_at_us INTEGER NOT NULL, revoked_at_us INTEGER,"
                " backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK(backup_eligible IN (0,1)), backup_state INTEGER NOT NULL DEFAULT 0 CHECK(backup_state IN (0,1)), inconsistency_reason TEXT CHECK(inconsistency_reason IS NULL OR inconsistency_reason = 'backup_eligibility_changed'), inconsistent_at_us INTEGER, label TEXT, last_used_at_us INTEGER)")
_INVITATIONS = ("CREATE TABLE access_invitations (id TEXT PRIMARY KEY, secret_digest BLOB NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, principal_revision INTEGER NOT NULL, deployment_generation INTEGER NOT NULL, issued_at_us INTEGER NOT NULL, expires_at_us INTEGER NOT NULL, redeemed_at_us INTEGER, revoked_at_us INTEGER,"
                " attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0))")
_SESSIONS = ("CREATE TABLE access_sessions (id TEXT PRIMARY KEY, token_digest BLOB NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES access_principals(id) ON DELETE CASCADE, credential_id BLOB NOT NULL REFERENCES access_credentials(credential_id), principal_revision INTEGER NOT NULL, deployment_generation INTEGER NOT NULL, established_at_us INTEGER NOT NULL, last_seen_at_us INTEGER NOT NULL, idle_lifetime_us INTEGER NOT NULL CHECK(idle_lifetime_us > 0), idle_expires_at_us INTEGER NOT NULL, absolute_expires_at_us INTEGER NOT NULL, invalidated_at_us INTEGER,"
             " last_user_verification_at_us INTEGER,"
             " external_identity_binding BLOB CHECK(external_identity_binding IS NULL OR length(external_identity_binding) = 32),"
             " binding_mismatch_audited_at_us INTEGER,"
             " binding_mismatch_suppressed INTEGER NOT NULL DEFAULT 0 CHECK(binding_mismatch_suppressed >= 0),"
             " CHECK(invalidated_at_us IS NULL OR external_identity_binding IS NULL))")
_CHALLENGES = ("CREATE TABLE access_webauthn_challenges (challenge_digest BLOB PRIMARY KEY, ceremony TEXT NOT NULL CHECK(ceremony IN ('registration','authentication','step_up')), invitation_id TEXT REFERENCES access_invitations(id) ON DELETE CASCADE, session_id TEXT REFERENCES access_sessions(id) ON DELETE CASCADE, issued_at_us INTEGER NOT NULL, expires_at_us INTEGER NOT NULL, CHECK(expires_at_us > issued_at_us), CHECK((ceremony = 'registration') = (invitation_id IS NOT NULL)), CHECK((ceremony = 'step_up') = (session_id IS NOT NULL)))")

# (table, copied columns) in parent-before-child order.
_REBUILT = (
    ("access_principals", "id, external_identity, display_name, role, status, authorization_revision, created_at_us, revoked_at_us"),
    ("access_principal_permissions", "principal_id, permission"),
    ("access_credentials", "credential_id, principal_id, public_key, algorithm, sign_count, enrolled_at_us, revoked_at_us, backup_eligible, backup_state, inconsistency_reason, inconsistent_at_us, label, last_used_at_us"),
    ("access_invitations", "id, secret_digest, principal_id, principal_revision, deployment_generation, issued_at_us, expires_at_us, redeemed_at_us, revoked_at_us, attempt_count"),
    ("access_sessions", "id, token_digest, principal_id, credential_id, principal_revision, deployment_generation, established_at_us, last_seen_at_us, idle_lifetime_us, idle_expires_at_us, absolute_expires_at_us, invalidated_at_us, last_user_verification_at_us"),
    ("access_webauthn_challenges", "challenge_digest, ceremony, invitation_id, session_id, issued_at_us, expires_at_us"),
)
_CREATES = dict(zip((name for name, _ in _REBUILT),
                    (_PRINCIPALS, _PERMISSIONS, _CREDENTIALS, _INVITATIONS, _SESSIONS, _CHALLENGES)))


def _shared_identity_statements() -> tuple[str, ...]:
    copy = [f"CREATE TEMP TABLE mig_{name} AS SELECT rowid AS mig_rowid, {columns} FROM main.{name}"
            for name, columns in _REBUILT]
    # Leaf tables first: once every child is gone, dropping a parent has
    # nothing to cascade into, even with foreign keys enforced.
    drop = [f"DROP TABLE main.{name}" for name, _ in reversed(_REBUILT)]
    create = []
    for name, columns in _REBUILT:
        create.append(_CREATES[name])
        create.append(f"INSERT INTO main.{name} (rowid, {columns}) SELECT mig_rowid, {columns} FROM temp.mig_{name} ORDER BY mig_rowid")
    counts = " AND ".join(
        f"(SELECT count(*) FROM temp.mig_{name}) = (SELECT count(*) FROM main.{name})"
        f" AND NOT EXISTS (SELECT mig_rowid, {columns} FROM temp.mig_{name} EXCEPT SELECT rowid, {columns} FROM main.{name})"
        for name, columns in _REBUILT)
    return (
        *copy,
        *drop,
        *create,
        "CREATE UNIQUE INDEX access_one_owner ON access_principals(role) WHERE role = 'owner'",
        "CREATE INDEX access_credentials_principal ON access_credentials(principal_id)",
        "CREATE INDEX access_invitations_principal ON access_invitations(principal_id)",
        "CREATE INDEX access_sessions_principal ON access_sessions(principal_id)",
        "CREATE INDEX access_webauthn_challenges_expiry ON access_webauthn_challenges(expires_at_us)",
        # Verification before the runner commits: every row survived with its
        # rowid and values, and no reference dangles. A failure aborts the
        # whole migration transaction.
        "CREATE TEMP TABLE mig_guard (ok INTEGER NOT NULL CHECK(ok = 1))",
        f"INSERT INTO temp.mig_guard SELECT ({counts}) AND NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check)",
        # The field is now the identity last observed at authentication.
        # Every accepted ceremony before this migration required equality with
        # it, so an active principal's value is exactly that; a principal that
        # never authenticated (invited) or is revoked keeps none.
        "UPDATE access_principals SET external_identity = NULL WHERE status <> 'active'",
        *(f"DROP TABLE temp.mig_{name}" for name, _ in _REBUILT),
        "DROP TABLE temp.mig_guard",
    )


def access_shared_identity_migration(version: int) -> Migration:
    """Make the invitation and passkey the only per-person key (PR #97 review).

    ``access_principals.external_identity`` loses ``NOT NULL UNIQUE``: it
    becomes the optional, non-unique trusted-proxy identity last observed at
    authentication (SPECIFICATION §11.4), because every viewer of the shared
    Tailscale account presents the same login. Sessions gain
    ``external_identity_binding``, the HMAC-SHA-256 of that identity under the
    deployment-local key (``app.auth.session_binding``), cleared on
    invalidation, plus the coalescing state for binding-mismatch audit records
    (``binding_mismatch_audited_at_us`` and the ``binding_mismatch_suppressed``
    count of mismatches not separately audited). Sessions created before this
    migration have no binding and are therefore refused; their holders sign in
    again.

    SQLite cannot drop a UNIQUE constraint in place, and the runner holds one
    transaction with foreign keys enforced, where ``PRAGMA foreign_keys`` is a
    no-op and ``DROP TABLE`` on a parent would cascade-delete its children.
    The access tables are therefore rebuilt together: copied (with rowids) to
    temporary tables, dropped leaf-first so no cascade has anything to reach,
    recreated with their final definitions, refilled parent-first and checked
    row-for-row plus ``foreign_key_check`` before the runner commits.
    """
    return Migration(version, "human_access_shared_identity", _shared_identity_statements())
