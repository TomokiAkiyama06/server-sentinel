"""AccessStore section of the lifecycle inventory (#47, split in #256).

Per nonidentifying principal / invitation logical ID: the independent
``live:view`` / ``recordings:view`` grants, revocation state, keyed
credential digests with their only-rising signature counters, and the
invitation validity fields. Never identities, credential IDs, public keys
or secret digests.
"""

from __future__ import annotations

from app.auth.model import Permission
from app.auth.boot_clock import valid_boot_id
from app.auth.store import MAX_REDEMPTION_ATTEMPTS

from ._common import _blob_hex, _canonical_uuid, _columns, _compare_keyed, _int, _keyed


# The access_credentials columns access_webauthn_migration adds, with the
# value it writes into every existing row (NOT NULL DEFAULT 0, else NULL).
_WEBAUTHN_CREDENTIAL_DEFAULTS = {"backup_eligible": 0, "backup_state": 0,
                                 "inconsistency_reason": None, "inconsistent_at_us": None,
                                 "label": None, "last_used_at_us": None}


def _access_row_errors(connection, tables) -> list:
    """Invitation, session and grant rows as AccessStore writes them."""
    errors = []
    generation = None
    if "access_deployment_state" in tables:
        found = connection.execute("SELECT authorization_generation FROM access_deployment_state "
                                   "WHERE singleton = 1").fetchone()
        generation = None if found is None else found[0]
    revisions = ({row[0]: row[1] for row in connection.execute(
        "SELECT id, authorization_revision FROM access_principals")}
        if "access_principals" in tables else {})

    def lineage(row) -> bool:
        # The principal revision and deployment generation copied at issue
        # time; both only ever advance afterwards.
        revision = revisions.get(row["principal_id"])
        return (_canonical_uuid(row["principal_id"])
                and _int(row["principal_revision"]) and _int(row["deployment_generation"])
                and (revision is None or (_int(revision) and row["principal_revision"] <= revision))
                and (generation is None or (_int(generation)
                                            and row["deployment_generation"] <= generation)))
    if "access_principal_permissions" in tables:
        grants = {item.value for item in Permission}
        for row in connection.execute(
                "SELECT principal_id, permission FROM access_principal_permissions"):
            if not _canonical_uuid(row[0]) or row[1] not in grants:
                errors.append(("access_principals", str(row[0])))
    if "access_invitations" in tables:
        for row in connection.execute("SELECT * FROM access_invitations"):
            keys = row.keys()
            issued, expires = row["issued_at_us"], row["expires_at_us"]
            redeemed, revoked = row["redeemed_at_us"], row["revoked_at_us"]
            attempts = row["attempt_count"] if "attempt_count" in keys else 0
            # PR #234 review: the lookup key and the boot pair of issuance
            # are absent together (issued before that migration) or all
            # present and well formed.
            lookup = row["lookup_key"] if "lookup_key" in keys else None
            boot_id = row["issued_boot_id"] if "issued_boot_id" in keys else None
            boottime = row["issued_boottime_us"] if "issued_boottime_us" in keys else None
            clock_ok = ((lookup is None and boot_id is None and boottime is None)
                        or (isinstance(lookup, bytes) and len(lookup) == 16
                            and valid_boot_id(boot_id) and _int(boottime)))
            valid = (_canonical_uuid(row["id"]) and lineage(row)
                     and isinstance(row["secret_digest"], bytes) and len(row["secret_digest"]) == 32
                     and _int(issued) and _int(expires) and issued < expires
                     and _int(attempts, 0, MAX_REDEMPTION_ATTEMPTS)
                     and clock_ok
                     # Redemption needs an open, unexpired invitation;
                     # revocation only touches unredeemed ones, at the
                     # caller's clock reading with no floor (a wall clock
                     # stepped back can revoke "before" the issue time).
                     and not (redeemed is not None and revoked is not None)
                     and (redeemed is None or (_int(redeemed) and issued <= redeemed < expires))
                     and (revoked is None or _int(revoked)))
            if not valid:
                errors.append(("access_invitations", str(row["id"])))
    if {"access_sessions", "access_credentials"} <= tables:
        owners = {bytes(row[0]): row[1] for row in connection.execute(
            "SELECT credential_id, principal_id FROM access_credentials")
            if isinstance(row[0], (bytes, bytearray, memoryview))}
        for row in connection.execute("SELECT * FROM access_sessions"):
            keys = row.keys()

            def optional(name, low):
                value = row[name] if name in keys else None
                return value is None or _int(value, low)
            established, seen = row["established_at_us"], row["last_seen_at_us"]
            idle, absolute = row["idle_lifetime_us"], row["absolute_expires_at_us"]
            binding = row["external_identity_binding"] if "external_identity_binding" in keys else None
            credential = row["credential_id"]
            # Migration 23 (Issue #10 phase 2 S3): the boot pair of the last
            # user verification is absent together (before it, or an
            # unreadable boot clock) or present, well formed and next to a
            # verification time.
            boot_id = row["last_user_verification_boot_id"] if "last_user_verification_boot_id" in keys else None
            boottime = (row["last_user_verification_boottime_us"]
                        if "last_user_verification_boottime_us" in keys else None)
            verified = row["last_user_verification_at_us"] if "last_user_verification_at_us" in keys else None
            verification_clock_ok = ((boot_id is None and boottime is None)
                                     or (verified is not None and valid_boot_id(boot_id) and _int(boottime)))
            try:
                valid = (_canonical_uuid(row["id"]) and lineage(row)
                         and isinstance(row["token_digest"], bytes) and len(row["token_digest"]) == 32
                         and isinstance(credential, bytes)
                         and owners.get(credential) == row["principal_id"]
                         and _int(established) and _int(seen) and established <= seen
                         and _int(idle, 1) and _int(absolute) and established < absolute
                         and idle <= absolute - established
                         # establish / touch: min(last seen + idle, absolute).
                         and row["idle_expires_at_us"] == min(seen + idle, absolute)
                         # Revocation, grant changes and invalidate-all use
                         # the caller's clock with no floor; only user
                         # verification and the mismatch audit need a
                         # session current at that time.
                         and optional("invalidated_at_us", 0)
                         and optional("last_user_verification_at_us", established)
                         and verification_clock_ok
                         and optional("binding_mismatch_audited_at_us", established)
                         and ("binding_mismatch_suppressed" not in keys
                              or _int(row["binding_mismatch_suppressed"]))
                         and (binding is None or (isinstance(binding, bytes) and len(binding) == 32
                                                  and row["invalidated_at_us"] is None)))
            except TypeError:
                valid = False
            if not valid:
                errors.append(("security_state", f"access_sessions:{row['id']}"))
    return errors


def _sign_counts_advanced(base: dict, now: dict) -> bool:
    """Whether a principal changed only by credential signature counters rising.

    The same credentials must remain, each counter equal or higher; any
    decrease rolls back the authenticator clone-detection floor.
    """
    if ({key: value for key, value in base.items() if key != "active_credentials"}
            != {key: value for key, value in now.items() if key != "active_credentials"}):
        return False
    before, after = base["active_credentials"], now["active_credentials"]
    return ([item[0] for item in before] == [item[0] for item in after]
            and all(_int(new[1]) and _int(old[1]) and new[1] >= old[1]
                    for old, new in zip(before, after)))


def _compare_principals(baseline: dict | None, current: dict | None) -> dict:
    """Keyed comparison where only credential signature counters may rise."""
    result = _compare_keyed(baseline, current)
    if result["status"] == "empty":
        return result
    advanced = []
    for entry in list(result["failed"]):
        key = entry["id"]
        if entry["reason"] == "changed" and _sign_counts_advanced(baseline[key], current[key]):
            result["failed"].remove(entry)
            result["preserved"].append(key)
            advanced.append(key)
    result.update(status="failed" if result["failed"] else "preserved",
                  preserved=sorted(result["preserved"]), sign_counts_advanced=sorted(advanced))
    return result


def _compare_invitations(baseline: dict | None, current: dict | None) -> dict:
    """Keyed comparison that names the known session-revocation side effect.

    A session revocation advances the authorization generation, which ends
    every invitation bound to the recorded one. An invitation that differs
    only in that its recorded current generation is no longer current is
    reported ``generation_advanced``: still a failure (investigate, then
    take a new baseline), but distinguishable from any other change (#161).
    """
    result = _compare_keyed(baseline, current)
    for entry in result["failed"]:
        before, after = (baseline or {}).get(entry["id"]), (current or {}).get(entry["id"])
        if entry["reason"] != "changed" or before is None or after is None:
            continue
        differing = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
        if (differing == {"deployment_generation_current"}
                and before["deployment_generation_current"] is True
                and after["deployment_generation_current"] is False):
            entry["reason"] = "generation_advanced"
    return result


def _access(connection, tables, salt: str) -> dict | None:
    if not {"access_principals", "access_principal_permissions",
            "access_invitations", "access_credentials"} <= tables:
        return None
    principals = {}
    # Only logical IDs and authorization state: never external_identity,
    # display_name, credential IDs / keys, or secret / token digests.
    credential_columns = _columns(connection, "access_credentials")
    consistent = (" AND inconsistent_at_us IS NULL"
                  if "inconsistent_at_us" in credential_columns else "")
    # A column access_webauthn_migration adds is read as the default that
    # migration writes into every existing row (NOT NULL DEFAULT 0), so a
    # baseline recorded before it matches the same row after it (#114).
    eligible = ("backup_eligible" if "backup_eligible" in credential_columns
                else "0 AS backup_eligible")
    generation = None
    if "access_deployment_state" in tables:
        generation = connection.execute(
            "SELECT authorization_generation FROM access_deployment_state "
            "WHERE singleton = 1").fetchone()
        generation = None if generation is None else generation[0]
    for row in connection.execute(
            "SELECT id, role, status, authorization_revision, revoked_at_us "
            "FROM access_principals ORDER BY id"):
        permissions = sorted(item[0] for item in connection.execute(
            "SELECT permission FROM access_principal_permissions WHERE principal_id = ?",
            (row["id"],)))
        # A credential marked inconsistent is unusable, like a revoked one.
        # Each usable credential is kept as a keyed digest of its stable
        # authentication material plus its signature counter (not secret),
        # which verification lets only advance: a lower counter would roll
        # back the clone-detection floor. Backup state is excluded.
        credentials = sorted([_keyed(salt, [
            "credential-v1", _blob_hex(item["credential_id"]), _blob_hex(item["public_key"]),
            item["algorithm"], None if item["backup_eligible"] is None
            else bool(item["backup_eligible"])]), item["sign_count"]]
            for item in connection.execute(
                f"SELECT credential_id, public_key, algorithm, sign_count, {eligible} "
                "FROM access_credentials WHERE principal_id = ? AND revoked_at_us IS NULL"
                + consistent, (row["id"],)))
        principals[row["id"]] = {
            "role": row["role"], "status": row["status"],
            "authorization_revision": row["authorization_revision"],
            "revoked": row["revoked_at_us"] is not None,
            "permissions": permissions, "active_credential_count": len(credentials),
            "active_credentials": credentials,
        }
    # Every field that decides whether the code can still be redeemed. The
    # secret digest itself is never written, only a keyed digest of it, so a
    # replaced enrollment binding is a change.
    attempts = ("attempt_count" if "attempt_count" in _columns(connection, "access_invitations")
                else "0 AS attempt_count")
    invitations = {row["id"]: {
        "principal_id": row["principal_id"],
        "redeemed": row["redeemed_at_us"] is not None,
        "revoked": row["revoked_at_us"] is not None,
        "principal_revision": row["principal_revision"],
        "deployment_generation": row["deployment_generation"],
        "deployment_generation_current": row["deployment_generation"] == generation,
        "issued_at_us": row["issued_at_us"],
        "expires_at_us": row["expires_at_us"],
        "attempt_count": row["attempt_count"],
        "secret_binding": _keyed(salt, ["invitation-secret-v1", bytes(row["secret_digest"]).hex()]),
    } for row in connection.execute(
        "SELECT id, secret_digest, principal_id, principal_revision, deployment_generation, "
        "issued_at_us, "
        f"expires_at_us, redeemed_at_us, revoked_at_us, {attempts} "
        "FROM access_invitations ORDER BY id")}
    return {"principals": principals, "invitations": invitations}


def _usable_owner(item: dict) -> bool:
    """An Owner who can still authenticate, as the passkey ceremony requires.

    PasskeyService._verified_assertion() admits only an active principal
    (store: status 'active', not revoked) with an active credential (not
    revoked, not marked inconsistent), which is what active_credentials
    holds.
    """
    return (item["role"] == "owner" and item["status"] == "active" and not item["revoked"]
            and item["active_credential_count"] > 0)
