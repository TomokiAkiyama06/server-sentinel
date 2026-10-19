"""PairingLedger section of the lifecycle inventory (#47, split in #256).

The one-way security state (``security_state``): pairing credentials,
enrollments, staged renewals, key bindings and capture nodes under the
PairingLedger operation compositions and their audit rows; invalidated
human sessions, the access authorization generation and the
session-revocation exposure marker (#134).
"""

from __future__ import annotations

from collections import Counter
import math

from app.audit.store import AuditStore
from app.cameras.remote_agent.pairing import (_MAX_KEY_BINDINGS_PER_NODE, PairingValidationError,
                                              _certificate_pem)
from app.auth.reservation_store import HUMAN_SESSIONS_ID, REVOCATION_PENDING_KEY

from ._common import _canonical_uuid, _columns, _hex_digest, _int, _keyed


# The actor PairingLedger records for each of its audit actions.
_LEDGER_AUDIT_ACTORS = {
    "approve_capture_node_enrollment": "owner",
    "redeem_capture_node_enrollment": "capture_node",
    "activate_capture_node_credential": "system",
    "revoke_capture_node_pairing": "owner",
}


def _ledger_audit_row(row) -> bool:
    """Whether a stored audit row is one PairingLedger wrote.

    The row must load through AuditStore's own record validation (UUID
    identities, known actor / action / outcome, the action's target kind,
    an aware timestamp) and carry the actor category the ledger uses for
    that action, against a capture node.
    """
    try:
        record = AuditStore._record(row)
    except (ValueError, TypeError, KeyError, OverflowError):
        return False
    return (record.actor_category.value == _LEDGER_AUDIT_ACTORS.get(record.action.value)
            and record.target_kind.value == "capture_node"
            and str(record.target_logical_id) == row["target_logical_id"]
            and str(record.id) == row["id"])


def _security_state(connection, tables, salt: str) -> dict:
    """Revocation and invalidation state that must only ever move one way.

    Pairing credentials and capture nodes once revoked stay revoked; pairing
    key bindings are never deleted, rebound or un-revoked (keys as keyed
    digests); an invalidated human session never becomes valid again; the
    access authorization generation never decreases.
    """
    def query(table, sql):
        return connection.execute(sql).fetchall() if table in tables else None
    not_after = ("not_after" if "pairing_node_credentials" in tables
                 and "not_after" in _columns(connection, "pairing_node_credentials")
                 else "NULL AS not_after")
    credentials = query("pairing_node_credentials",
                        "SELECT node_id, state, public_key_digest, credential_serial_digest, "
                        f"{not_after} FROM pairing_node_credentials")
    enrollments = query("pairing_enrollments",
                        "SELECT id, node_id, public_key_digest, state FROM pairing_enrollments")
    certificate = ("certificate_pem" if "pairing_node_renewals" in tables
                   and "certificate_pem" in _columns(connection, "pairing_node_renewals")
                   else "NULL AS certificate_pem")
    renewals = query("pairing_node_renewals",
                     "SELECT node_id, public_key_digest, credential_serial_digest, not_after, "
                     f"{certificate} FROM pairing_node_renewals")

    def material(row):
        # What PairingLedger.admits() authenticates, as keyed digests; the
        # key reference matches the pairing_key_bindings key below.
        return {"material": _keyed(salt, ["pairing-credential-v1", row["public_key_digest"],
                                          row["credential_serial_digest"]]),
                "key_ref": _keyed(salt, ["pairing-key-v1", row["public_key_digest"]]),
                "not_after": row["not_after"]}
    bindings = query("pairing_key_bindings",
                     "SELECT public_key_digest, node_id, revoked FROM pairing_key_bindings")
    nodes = query("capture_nodes", "SELECT id, health_state FROM capture_nodes")
    # PairingLedger audits each activation / promotion and each revocation
    # in the same transaction, with the audit clock: the only ordering
    # evidence between them (node logical IDs and times, no key material).
    pairing_audit = query(
        "security_admin_audit_records",
        "SELECT id, actor_category, action, target_kind, target_logical_id, occurred_at_us, "
        "outcome FROM security_admin_audit_records WHERE action IN "
        "('approve_capture_node_enrollment', 'redeem_capture_node_enrollment', "
        "'activate_capture_node_credential', 'revoke_capture_node_pairing')")
    if pairing_audit is not None:
        pairing_audit = [row for row in pairing_audit if _ledger_audit_row(row)]
    sessions = query("access_sessions", "SELECT id, invalidated_at_us FROM access_sessions")
    # #134: ReservationSessionRevocation's pending exposure marker and the
    # audit rows of the revocation that alone removes it.
    marker = query("application_metadata",
                   "SELECT value FROM application_metadata WHERE key = "
                   f"'{REVOCATION_PENDING_KEY}'")
    revocations = query(
        "security_admin_audit_records",
        "SELECT id FROM security_admin_audit_records WHERE actor_category = 'system' "
        "AND action = 'invalidate_human_sessions' AND target_kind = 'security_settings' "
        f"AND target_logical_id = '{HUMAN_SESSIONS_ID}' AND outcome = 'succeeded'")
    generation = query("access_deployment_state",
                       "SELECT authorization_generation FROM access_deployment_state")
    return {
        "pairing_credentials": None if credentials is None else {
            row["node_id"]: {"revoked": row["state"] == "revoked", **material(row)}
            for row in credentials},
        # The staged certificate (migration 21) as a keyed digest of its PEM
        # text; None for a row staged before it.
        "pairing_renewals": None if renewals is None else {
            row["node_id"]: {**material(row), "certificate": None
                             if row["certificate_pem"] is None
                             else _keyed(salt, ["pairing-certificate-v1",
                                                str(row["certificate_pem"])])}
            for row in renewals},
        # Activated enrollments (a final state: PairingLedger never deletes
        # or changes them) and open ones (pending / consumed, the only states
        # activate() can still complete): id, node and key binding reference.
        "pairing_activations": None if enrollments is None else sorted(
            [row["id"], row["node_id"], _keyed(salt, ["pairing-key-v1", row["public_key_digest"]])]
            for row in enrollments if row["state"] == "activated"),
        "pairing_enrollments_open": None if enrollments is None else sorted(
            [row["id"], row["node_id"], _keyed(salt, ["pairing-key-v1", row["public_key_digest"]])]
            for row in enrollments if row["state"] in ("pending", "consumed")),
        # Every enrollment (any state) with its state, to check transitions.
        "pairing_enrollments": None if enrollments is None else {
            row["id"]: {"node_id": row["node_id"], "state": row["state"],
                        "key_ref": _keyed(salt, ["pairing-key-v1", row["public_key_digest"]])}
            for row in enrollments},
        # Every key an enrollment (any state) names: approve() bound them,
        # while stage_renewal() binds keys no enrollment names.
        "pairing_enrollment_keys": None if enrollments is None else sorted(
            {_keyed(salt, ["pairing-key-v1", row["public_key_digest"]]) for row in enrollments}),
        "pairing_key_bindings": None if bindings is None else {
            _keyed(salt, ["pairing-key-v1", row[0]]): {"node_id": row[1], "revoked": bool(row[2])}
            for row in bindings},
        "pairing_audit": None if pairing_audit is None else sorted(
            [row["id"], row["action"], row["target_logical_id"], row["occurred_at_us"],
             row["outcome"]] for row in pairing_audit),
        "capture_nodes_revoked": None if nodes is None else {
            row[0]: row[1] == "revoked" for row in nodes},
        "sessions_invalidated": None if sessions is None else {
            row[0]: row[1] is not None for row in sessions},
        "authorization_generation": generation[0][0] if generation else None,
        "session_revocation_pending": None if marker is None else (
            "absent" if not marker else "present" if marker[0][0] == "1" else "invalid"),
        "session_revocation_audit": None if revocations is None else sorted(
            row[0] for row in revocations),
    }


def _by_enrollment(items) -> bool:
    return items is not None and all(isinstance(item, list) and len(item) == 3 for item in items)


# PairingLedger enrollment states reachable from each recorded state, as
# compositions of redeem() (pending -> consumed, or -> expired when its
# process epoch or expiry has passed), activate() (consumed -> activated)
# and revoke() (pending / consumed -> revoked); the rest are final.
_ENROLLMENT_SUCCESSORS = {
    "pending": frozenset({"pending", "consumed", "expired", "activated", "revoked"}),
    "consumed": frozenset({"consumed", "activated", "revoked"}),
    "expired": frozenset({"expired"}),
    "activated": frozenset({"activated"}),
    "revoked": frozenset({"revoked"}),
}


def _audited_before_revocation(node: str, baseline: dict, current: dict,
                               activations: int) -> bool:
    """Whether the node's post-record credential changes all precede its revocation.

    Uses the succeeded activate / revoke audit rows appended since the
    record. Without a revoke row, or with fewer activation rows than
    activations, the order is unknown and the check fails closed.
    """
    if not activations:
        return True
    recorded = {row[0] for row in (baseline.get("pairing_audit") or ())}
    if current.get("pairing_audit") is None:
        return False
    events = [row for row in current["pairing_audit"]
              if row[0] not in recorded and row[2] == node and row[4] == "succeeded"]
    revocations = [row[3] for row in events if row[1] == "revoke_capture_node_pairing"]
    activations_audited = [row[3] for row in events
                           if row[1] == "activate_capture_node_credential"]
    if not revocations or len(activations_audited) < activations:
        return False
    first = min(revocations)
    return all(at < first for at in activations_audited)


def _compare_pairing(baseline: dict, current: dict) -> list:
    """The capture-node pairing ledger, checked against PairingLedger itself.

    Every mutation of the ledger tables is one of these operations (keys are
    keyed digests here; ``live`` means bound to the node and not revoked):

    - approve(node, key): a new pending enrollment; binds the key live
      (_bind_key() refuses a key bound elsewhere or revoked, but accepts one
      already live for the same node, even a currently staged key).
    - redeem(): pending -> consumed, or pending -> expired (a previous
      process epoch or a passed expiry; nothing else expires enrollments).
    - activate(claim): consumed -> activated; binds its key live; the node's
      credential becomes (key, serial, not_after) and active (inserted or
      overwritten); any staged renewal is deleted.
    - stage_renewal(node, key): needs an active credential and a key other
      than its own; refuses a key any credential, another node's renewal or
      enrollment names; binds a new key live, or retries the currently
      staged key (a key bound by an enrollment of this node is refused, so
      it never stages an enrollment's key); writes the single staged row and
      no enrollment.
    - promotion in admits(): the credential becomes the staged material and
      expiry, the staged key stays live, the staged row is deleted.
    - revoke(node): the active credential -> revoked, pending / consumed
      enrollments -> revoked, the staged row deleted, every binding of the
      node revoked, all in one transaction.

    Nothing deletes an enrollment, a credential or a binding, rebinds a key
    or un-revokes a binding. Hence every current state satisfies:

    - credential: every credential's node has an activated enrollment
      (only activate() creates one); an active credential's key is live for
      its node; a revoked credential's node has every binding revoked, no
      pending / consumed enrollment and no staged renewal (what revoke()
      leaves; a revoked node is re-paired only as a new node);
    - binding: every binding's node has an enrollment (approve() binds with
      one; stage_renewal() needs an activated credential); a live binding
      added since the record is an enrollment's key, the staged renewal's
      key or the credential's key;
    - enrollment: an activated one's node has a credential; a revoked one's
      node has no active credential;
    - renewal: a staged renewal belongs to an active credential, uses another key,
      and that key is live for its node and named by no enrollment, recorded
      or current, in any state (so no activated enrollment's key is staged:
      activate() deletes the renewal and that key can never be staged
      again). Approving a currently staged key would also break this; it is
      reachable through approve() (and command_approve() would offer it as a
      retry) but refused here (fail closed): no enrollment created since the
      record may name a key staged at record time or now, so neither the
      retry path nor any other accepts it. A key both staged and approved
      inside the window, its renewal then gone, leaves no trace and passes;
    - enrollment: every enrollment's key, in any state, is bound to its node; an open
      (pending / consumed) one's binding is live, a revoked one's is revoked
      (expiry and activation change no binding state), and a revoked one
      new or newly revoked since the record means revoke() of its node ran
      in the window.

    And per node, record -> verify is a composition of those operations,
    each enrollment transition tied to the operation that produces it:

    - every recorded enrollment stays with its node and key; pending may
      become consumed or expired (redeem(); nothing else changes), consumed
      activated (activate()), pending / consumed revoked (revoke()), and the
      other states are final;
    - an enrollment activated since the record means activate() ran: the
      node's credential now holds the key of an enrollment activated since
      the record (only another activation or revoke(), which keeps the key,
      changes it afterwards; a promotion of a renewal staged after it cannot
      show its material and fails closed), and the renewal staged at record
      time is gone;
    - revoke() ran for a node if a recorded open enrollment became revoked
      (only revoke() sets that state), a recorded live binding or a binding
      first seen now is revoked, or its active credential became revoked;
      then every recorded binding of the node and every key of its newly
      revoked enrollments are revoked, none of its recorded open
      enrollments is still open, and its credential is revoked (its key's
      binding too) or holds the key of an activation since the record (a
      re-pairing after the revoke); and since revoke() aborts on a node with
      nothing to revoke, the node had an active credential at record time,
      a recorded open enrollment now revoked, an enrollment created since
      and revoked, or a credential activated since and now revoked;
    - a recorded binding keeps its node and never un-revokes; a revoked
      credential stays revoked with the same material (re-pairing a node
      revoked at record time fails closed); an active one stays, becomes the
      staged renewal (promotion) or an identity a post-record activation
      installed (an enrollment open at record time, or a new one for a key
      newly bound or, as command_approve() retries, already live for the
      node at record time and still, or revoked since only by a complete
      revoke() of the node, but never one staged at record time or now); a
      staged row stays exactly, is retried with its own key
      while the credential is unchanged, is replaced by a key newly bound
      since the record, or leaves by promotion, revocation or a fresh
      pairing; a credential first seen now needs a post-record activation of
      its key.
    """
    failed = []

    def fail(table, key, reason):
        failed.append({"id": f"{table}:{key}", "reason": reason})
    bindings = current.get("pairing_key_bindings") or {}
    credentials = current.get("pairing_credentials") or {}
    renewals = current.get("pairing_renewals") or {}
    recorded_credentials = baseline.get("pairing_credentials") or {}
    staged = baseline.get("pairing_renewals") or {}
    # None when the baseline could not see the bindings: then no key counts
    # as newly bound since the record (fail closed).
    recorded_bindings = baseline.get("pairing_key_bindings")
    recorded_activations = baseline.get("pairing_activations")
    recorded_open = baseline.get("pairing_enrollments_open")
    activations_now = current.get("pairing_activations") or ()

    def live(node, key_ref):
        binding = bindings.get(key_ref) or {}
        return binding.get("node_id") == node and binding.get("revoked") is False

    def newly_bound(key_ref):
        return recorded_bindings is not None and key_ref not in recorded_bindings

    # -- invariants of every current state --------------------------------
    enrollments_by_node: dict = {}
    for item in (current.get("pairing_enrollments") or {}).values():
        enrollments_by_node.setdefault(item["node_id"], []).append(item["state"])
    for node, after in sorted(credentials.items()):
        if not after["revoked"] and not live(node, after["key_ref"]):
            fail("pairing_credentials", node, "unbound")
        # Only activate() creates a credential, and enrollments stay.
        if "activated" not in enrollments_by_node.get(node, ()):
            fail("pairing_credentials", node, "no_activation")
        # revoke() leaves the node with every binding revoked, no open
        # enrollment and no staged renewal (and, re-paired only as a new
        # node, it gains none afterwards).
        if after["revoked"] and (
                any(binding["node_id"] == node and not binding["revoked"]
                    for binding in bindings.values())
                or any(state in ("pending", "consumed")
                       for state in enrollments_by_node.get(node, ()))
                or node in renewals):
            fail("pairing_credentials", node, "revocation_incomplete")
    for node, states in sorted(enrollments_by_node.items()):
        after = credentials.get(node)
        # activate() writes the credential; only revoke() writes 'revoked',
        # revoking the credential with it.
        if "activated" in states and after is None:
            fail("pairing_enrollments", node, "no_credential")
        if "revoked" in states and after is not None and not after["revoked"]:
            fail("pairing_enrollments", node, "revocation_incomplete")
    # A binding is made by approve() (an enrollment) or stage_renewal()
    # (which needs an activated credential): its node has an enrollment.
    for key_ref, binding in sorted(bindings.items()):
        if binding["node_id"] not in enrollments_by_node:
            fail("pairing_key_bindings", key_ref, "no_enrollment")
    for node, renewal in sorted(renewals.items()):
        owner = credentials.get(node)
        if (owner is None or owner["revoked"] or owner["key_ref"] == renewal["key_ref"]
                or not live(node, renewal["key_ref"])):
            fail("pairing_renewals", node, "unbound")
    # A staged key is never an enrollment's key (recorded or current, any
    # state); this also keeps an activated enrollment's key from being staged.
    recorded_keys = baseline.get("pairing_enrollment_keys")
    if renewals and (recorded_keys is None and recorded_activations is not None
                     or current.get("pairing_enrollment_keys") is None):
        failed.append({"id": "pairing_enrollment_keys", "reason": "unverifiable"})
    enrollment_keys = set(recorded_keys or ()) | set(current.get("pairing_enrollment_keys") or ())
    for node, renewal in sorted(renewals.items()):
        if renewal["key_ref"] in enrollment_keys:
            fail("pairing_renewals", node, "enrollment_key")
    # Likewise an enrollment created since the record never names a key
    # staged at record time or now (approve() would accept one, but that
    # composition is refused here: fail closed).
    staged_keys = ({renewal["key_ref"] for renewal in staged.values()}
                   | {renewal["key_ref"] for renewal in renewals.values()})
    recorded_enrollments = baseline.get("pairing_enrollments")
    enrollments_now = current.get("pairing_enrollments") or {}
    for enrollment, item in sorted(enrollments_now.items()):
        if (item["key_ref"] in staged_keys and isinstance(recorded_enrollments, dict)
                and enrollment not in recorded_enrollments):
            fail("pairing_enrollments", enrollment, "enrollment_key")
    # Every enrollment, in every state: approve() bound its key to its node
    # first; an open one's binding is live (revoke() revokes the open
    # enrollments and the bindings together); a revoked one's binding is
    # revoked (only revoke() revokes an enrollment, with every binding of
    # its node); expiry (redeem()) and activation change no binding state.
    for enrollment, item in sorted(enrollments_now.items()):
        binding = bindings.get(item["key_ref"]) or {}
        if binding.get("node_id") != item["node_id"]:
            fail("pairing_enrollments", enrollment, "unbound")
        elif item["state"] in ("pending", "consumed") and binding.get("revoked") is not False:
            fail("pairing_enrollments", enrollment, "unbound")
        elif item["state"] == "revoked" and binding.get("revoked") is not True:
            fail("pairing_enrollments", enrollment, "unbound")

    # -- enrollments: never deleted, node / key fixed, states move forward --
    if isinstance(recorded_enrollments, dict):
        for enrollment, before in sorted(recorded_enrollments.items()):
            after = enrollments_now.get(enrollment)
            if after is None:
                fail("pairing_enrollments", enrollment, "missing")
            elif ((after["node_id"], after["key_ref"]) != (before["node_id"], before["key_ref"])
                  or after["state"] not in _ENROLLMENT_SUCCESSORS.get(before["state"], ())):
                fail("pairing_enrollments", enrollment, "changed")
    elif recorded_activations or recorded_open:
        failed.append({"id": "pairing_enrollments", "reason": "unverifiable"})
    # -- bindings: never deleted, rebound or un-revoked --------------------
    revoked_nodes = set()
    for key_ref, binding in (recorded_bindings or {}).items():
        now = bindings.get(key_ref)
        if now is None:
            fail("pairing_key_bindings", key_ref, "missing")
        elif now["node_id"] != binding["node_id"] or (binding["revoked"] and not now["revoked"]):
            fail("pairing_key_bindings", key_ref, "changed")
        elif now["revoked"] and not binding["revoked"]:
            revoked_nodes.add(binding["node_id"])
    if recorded_bindings is not None:
        # _bind_key() inserts live bindings; one already revoked was revoked
        # by revoke() of its node since the record.
        revoked_nodes.update(binding["node_id"] for key_ref, binding in bindings.items()
                             if binding["revoked"] and key_ref not in recorded_bindings)

    # -- enrollment transitions and the operation that made them -----------
    recorded_states = {enrollment: item["state"]
                       for enrollment, item in (recorded_enrollments or {}).items()}
    # Enrollments activate() completed since the record (recorded open ones
    # or ones created since), per node.
    activated_since = {enrollment: item for enrollment, item in enrollments_now.items()
                       if item["state"] == "activated"
                       and recorded_states.get(enrollment) != "activated"}
    activated_keys: dict = {}
    for item in activated_since.values():
        activated_keys.setdefault(item["node_id"], set()).add(item["key_ref"])
    for enrollment, item in sorted(activated_since.items()):
        node = item["node_id"]
        after = credentials.get(node)
        # activate() made its key the node's credential and dropped the staged
        # renewal; later only another activation (or revoke(), which keeps
        # the key) changes that credential. A promotion of a renewal staged
        # after it cannot show its material and fails closed.
        if after is None or after["key_ref"] not in activated_keys[node]:
            fail("pairing_enrollments", enrollment, "activation_unapplied")
        if (node in staged and node in renewals
                and renewals[node]["key_ref"] == staged[node]["key_ref"]):
            fail("pairing_renewals", node, "changed")
    for enrollment, after in sorted(enrollments_now.items()):
        # Only revoke() sets 'revoked', revoking the node as a whole: a
        # recorded open enrollment now revoked, or one created since and
        # already revoked, means revoke() ran in the window.
        before = (recorded_enrollments or {}).get(enrollment)
        if after["state"] == "revoked" and (before is None or before["state"] != "revoked"):
            revoked_nodes.add(after["node_id"])
    for node, before in recorded_credentials.items():
        after = credentials.get(node)
        if not before["revoked"] and after is not None and after["revoked"]:
            revoked_nodes.add(node)

    # -- revoke(): all of it, for any node revoked since the record --------
    revoked_completely = set()
    for node in sorted(revoked_nodes):
        # revoke() revokes every binding the node held (recorded ones and
        # those of its enrollments), every open enrollment, the active
        # credential, and deletes the staged row; afterwards only a fresh
        # approve() / activate() gives the node a live identity again.
        # The Owner decision of 2026-10-01 re-pairs a revoked node as a new
        # node with a new key (the pairing CLI approves an unbound key for a
        # fresh node ID), so after revoke() the node itself keeps nothing
        # open or live: every binding of it, recorded or added since, is
        # revoked, no enrollment of it is pending or consumed, and its
        # credential stays revoked.
        held = [key_ref for key_ref, binding in (recorded_bindings or {}).items()
                if binding["node_id"] == node]
        held += [key_ref for key_ref, binding in bindings.items() if binding["node_id"] == node]
        still_open = any(item["node_id"] == node and item["state"] in ("pending", "consumed")
                         for item in enrollments_now.values())
        # revoke() aborts unless the node had something to revoke then: an
        # active credential or an open enrollment.
        recorded_credential = recorded_credentials.get(node)
        revocable = (
            (recorded_credential is not None and not recorded_credential["revoked"])
            or any(item["node_id"] == node and item["state"] in ("pending", "consumed")
                   and (enrollments_now.get(enrollment) or {}).get("state") == "revoked"
                   for enrollment, item in (recorded_enrollments or {}).items())
            or any(item["node_id"] == node and item["state"] == "revoked"
                   and enrollment not in (recorded_enrollments or {})
                   for enrollment, item in enrollments_now.items())
            or (credentials.get(node) or {}).get("revoked") is True
            and credentials[node]["key_ref"] in activated_keys.get(node, ()))
        # Ordering from the audit: an activation since the record on a node
        # revoked in the window must have happened before its first
        # revocation (otherwise it re-opened the node on the same ID), and
        # every such activation and the revocation must be audited.
        # Every accepted credential change writes an activate audit row:
        # each activation since the record and the promotion of the renewal
        # staged at record time (which revoke() deletes, so it cannot follow).
        recorded_credential, staged_row = recorded_credentials.get(node), staged.get(node)
        promoted = int(recorded_credential is not None and not recorded_credential["revoked"]
                       and staged_row is not None and node in credentials
                       and credentials[node]["material"] == staged_row["material"])
        if not _audited_before_revocation(node, baseline, current,
                                          promoted + sum(1 for item in activated_since.values()
                                                         if item["node_id"] == node)):
            fail("pairing_revocation", node, "reopened")
        after = credentials.get(node)
        if not revocable:
            credential_ok = False
        elif after is None:
            credential_ok = True
        else:
            held.append(after["key_ref"])
            credential_ok = after["revoked"]
        if (recorded_bindings is None or still_open or not credential_ok
                or not all((bindings.get(key_ref) or {}).get("revoked") for key_ref in held)):
            fail("pairing_revocation", node, "incomplete")
        else:
            revoked_completely.add(node)

    # -- every binding added since the record, live or revoked, by its key -
    # approve() binds an enrollment's key (the enrollment stays, in some
    # state); stage_renewal() binds the node's staged key, which promotion
    # makes the credential key. A staged key whose renewal a revoke() then
    # deleted stays bound, revoked, with no other trace: accepted only for a
    # node completely revoked in the window that had an active credential
    # in it (at the record, or from an activation before the revocation).
    # A key staged and then superseded while live (re-staged, or its
    # renewal dropped by an activation) has no trace either and fails closed.
    if recorded_bindings is not None:
        enrollment_pairs = {(item["node_id"], item["key_ref"])
                            for item in enrollments_now.values()}
        for key_ref, binding in sorted(bindings.items()):
            node = binding["node_id"]
            if key_ref in recorded_bindings:
                continue
            explained = ((node, key_ref) in enrollment_pairs
                         or (renewals.get(node) or {}).get("key_ref") == key_ref
                         or (credentials.get(node) or {}).get("key_ref") == key_ref)
            if not explained and binding["revoked"]:
                before = recorded_credentials.get(node)
                explained = node in revoked_completely and (
                    (before is not None and not before["revoked"])
                    or any(item["node_id"] == node for item in activated_since.values()))
            if not explained:
                fail("pairing_key_bindings", key_ref, "unexplained")
    # stage_renewal() binds a new key only while the node holds fewer than
    # PairingLedger's cap; approve() is not capped, one binding each.
    held: Counter = Counter(binding["node_id"] for binding in bindings.values())
    approvals: Counter = Counter(item["node_id"] for item in enrollments_now.values())
    for node, count in sorted(held.items()):
        if count > _MAX_KEY_BINDINGS_PER_NODE + approvals[node]:
            fail("pairing_key_bindings", node, "over_capacity")

    # Only an enrollment activated after the record explains a new identity:
    # one open at record time, unchanged, or one created since, whose key
    # approve() newly bound or whose key was already live for the same node
    # at record time (an Owner retry through command_approve()). A baseline
    # without these lists accepts none.
    fresh = set()
    if (_by_enrollment(recorded_activations) and _by_enrollment(recorded_open)
            and _by_enrollment(activations_now) and recorded_bindings is not None):
        recorded_ids = {item[0] for item in recorded_activations}
        opened = {item[0]: tuple(item[1:]) for item in recorded_open}
        historical = {tuple(item[1:]) for item in recorded_activations}
        def retried(enrollment, node, key_ref):
            # pairing_cli.command_approve() retries an interrupted, expired
            # or unacknowledged enrollment by approving the same key again
            # for the node its live binding names (PairingLedger.bound_node());
            # approve() then creates a new enrollment for that key. Such an
            # enrollment is new since the record (every recorded one must
            # persist, so an old one cannot be re-labelled) and its key was
            # already live for the same node at record time and still is,
            # unless revoke() of the node, complete as checked above, has
            # revoked it since. A key staged as a renewal (at record time or
            # now) is never one: approving it is the fail-closed case below.
            recorded = recorded_bindings.get(key_ref) or {}
            now = bindings.get(key_ref) or {}
            return (isinstance(recorded_enrollments, dict)
                    and enrollment not in recorded_enrollments
                    and key_ref not in staged_keys
                    and recorded.get("node_id") == node and recorded.get("revoked") is False
                    and (live(node, key_ref)
                         or (node in revoked_completely and now.get("node_id") == node
                             and now.get("revoked") is True)))
        for enrollment, node, key_ref in activations_now:
            pair = (node, key_ref)
            if enrollment in recorded_ids:
                continue
            if enrollment in opened:
                accepted = opened[enrollment] == pair
            else:
                accepted = ((pair not in historical and newly_bound(key_ref))
                            or retried(enrollment, node, key_ref))
            if accepted:
                fresh.add(pair)


    # -- every accepted transition has the audit row the ledger wrote ------
    # PairingLedger appends, in the transaction that makes the change:
    # approve() 'approve_capture_node_enrollment' succeeded; redeem()
    # 'redeem_capture_node_enrollment' succeeded on consumption, failed on
    # expiry; activate() and a promotion 'activate_capture_node_credential'
    # succeeded; revoke() 'revoke_capture_node_pairing' succeeded.
    # stage_renewal() writes none. Per node, each accepted kind needs at
    # least as many such rows appended since the record.
    required: Counter = Counter()
    for enrollment, item in enrollments_now.items():
        before = (recorded_enrollments or {}).get(enrollment)
        state, node = item["state"], item["node_id"]
        if before is None:
            required[(node, "approve_capture_node_enrollment", "succeeded")] += 1
        was = None if before is None else before["state"]
        if was in (None, "pending") and state in ("consumed", "activated"):
            required[(node, "redeem_capture_node_enrollment", "succeeded")] += 1
        if was in (None, "pending") and state == "expired":
            required[(node, "redeem_capture_node_enrollment", "failed")] += 1
    for item in activated_since.values():
        required[(item["node_id"], "activate_capture_node_credential", "succeeded")] += 1
    for node, before in recorded_credentials.items():
        after, staged_row = credentials.get(node), staged.get(node)
        if (not before["revoked"] and staged_row is not None and after is not None
                and after["material"] == staged_row["material"]):
            required[(node, "activate_capture_node_credential", "succeeded")] += 1
    for node in revoked_nodes:
        required[(node, "revoke_capture_node_pairing", "succeeded")] += 1
    recorded_audit = {row[0] for row in (baseline.get("pairing_audit") or ())}
    appended_audit = Counter((row[2], row[1], row[4]) for row in (current.get("pairing_audit") or ())
                             if row[0] not in recorded_audit)
    for (node, action, outcome), count in sorted(required.items()):
        if appended_audit[(node, action, outcome)] < count:
            fail("pairing_audit", f"{node}:{action}", "unaudited")

    # -- credentials ------------------------------------------------------
    def installed(node, after):
        """Material a ledger path since the record could have installed."""
        before, renewal = recorded_credentials.get(node), staged.get(node)
        same = (before is not None and after["material"] == before["material"]
                and after["not_after"] == before["not_after"])
        promoted = (before is not None and not before["revoked"] and renewal is not None
                    and after["material"] == renewal["material"]
                    and after["not_after"] == renewal["not_after"])
        return same or promoted or (node, after["key_ref"]) in fresh
    for node, after in sorted(credentials.items()):
        before = recorded_credentials.get(node)
        if before is not None and before["revoked"]:
            # Re-pairing a revoked node is refused here (fail closed).
            if not after["revoked"]:
                fail("pairing_credentials", node, "revocation_reversed")
            elif (after["material"], after["not_after"]) != (before["material"],
                                                             before["not_after"]):
                fail("pairing_credentials", node, "changed")
            continue
        if not installed(node, after):
            fail("pairing_credentials", node, "changed")
    for node in sorted(set(recorded_credentials) - set(credentials)):
        fail("pairing_credentials", node, "missing")

    # -- staged renewals --------------------------------------------------
    for node, renewal in sorted(renewals.items()):
        recorded = staged.get(node)
        before, after = recorded_credentials.get(node), credentials.get(node)
        unchanged = (before is not None and after is not None
                     and (after["material"], after["not_after"], after["revoked"])
                     == (before["material"], before["not_after"], before["revoked"]))
        if recorded is not None and renewal["key_ref"] == recorded["key_ref"]:
            # Kept or retried with its own key: nothing consumed it, so the
            # credential is exactly as recorded. A retry replaces only a row
            # staged without a certificate (before migration 21); one that
            # holds a certificate is kept exactly (#123 idempotent retry).
            kept = (recorded.get("certificate") is None
                    or all(renewal.get(field) == recorded.get(field)
                           for field in ("material", "not_after", "certificate")))
            if not (unchanged and kept):
                fail("pairing_renewals", node, "changed")
        elif not newly_bound(renewal["key_ref"]):
            # Any other staged key was bound by stage_renewal() since the record.
            fail("pairing_renewals", node, "changed")
    for node, renewal in sorted(staged.items()):
        if node in renewals:
            continue
        after = credentials.get(node)
        # Consumed by promotion, discarded by revocation or a fresh pairing.
        if not (after is not None and (after["revoked"]
                                       or after["material"] == renewal["material"]
                                       or (node, after["key_ref"]) in fresh)):
            fail("pairing_renewals", node, "missing")
    return failed


def _compare_security_state(baseline: dict | None, current: dict | None) -> dict:
    baseline, current = baseline or {}, current or {}
    failed = []
    now = current.get("capture_nodes_revoked") or {}
    for key, revoked in (baseline.get("capture_nodes_revoked") or {}).items():
        if key not in now:
            failed.append({"id": f"capture_nodes_revoked:{key}", "reason": "missing"})
        elif revoked and not now[key]:
            failed.append({"id": f"capture_nodes_revoked:{key}", "reason": "revocation_reversed"})
    failed.extend(_compare_pairing(baseline, current))
    # A session row may be purged, but an invalidated one never revives.
    now = current.get("sessions_invalidated") or {}
    for key, invalidated in (baseline.get("sessions_invalidated") or {}).items():
        if invalidated and key in now and not now[key]:
            failed.append({"id": f"sessions_invalidated:{key}", "reason": "revocation_reversed"})
    before, after = baseline.get("authorization_generation"), current.get("authorization_generation")
    if before is not None and not (_int(before) and _int(after) and after >= before):
        failed.append({"id": "authorization_generation", "reason": "decreased"})
    # #134: a pending exposure marker leaves only with the revocation
    # ReservationSessionRevocation commits in the same transaction: a new
    # system invalidate_human_sessions audit row, an advanced authorization
    # generation and every recorded session still present invalidated. An
    # unreadable marker still counts as pending (the service fails closed).
    if (baseline.get("session_revocation_pending") == "present"
            and current.get("session_revocation_pending") not in ("present", "invalid")):
        audited = set(current.get("session_revocation_audit") or ()) - set(
            baseline.get("session_revocation_audit") or ())
        now = current.get("sessions_invalidated")
        revoked = (bool(audited) and _int(before) and _int(after) and after > before
                   and now is not None
                   and all(now[key] for key in (baseline.get("sessions_invalidated") or {})
                           if key in now))
        if not revoked:
            failed.append({"id": "session_revocation_pending",
                           "reason": "cleared_without_revocation"})
    return {"status": "failed" if failed else "preserved", "failed": failed}


_PAIRING_ENROLLMENT_STATES = frozenset({"pending", "expired", "consumed", "activated", "revoked"})


def _staged_certificate_valid(row) -> bool:
    """Migration 21 (#136): NULL (staged before it) or exactly the PEM text
    stage_renewal() stores, one certificate whose DER SHA-256 is the staged
    serial digest (pairing._certificate_pem(), which a same-key retry also
    applies before resending it)."""
    if "certificate_pem" not in row.keys() or row["certificate_pem"] is None:
        return True
    value = row["certificate_pem"]
    if not isinstance(value, str):
        return False
    try:
        return _certificate_pem(value.encode("ascii"), row["credential_serial_digest"]) == value
    except (UnicodeError, PairingValidationError):
        return False


def _pairing_row_errors(connection, tables) -> list:
    """Pairing ledger rows as PairingLedger writes them (``_identity``,
    ``_digest`` and ``_expiry``); raw key digests never appear in the report."""
    errors = []

    def expiry(value, optional) -> bool:
        return ((optional and value is None)
                or (type(value) in (int, float) and value > 0 and math.isfinite(value)))

    def bad(table, item):
        errors.append(("security_state", f"{table}:{item}"))
    if "pairing_enrollments" in tables:
        for row in connection.execute("SELECT * FROM pairing_enrollments"):
            if not (_canonical_uuid(row["id"]) and _canonical_uuid(row["node_id"])
                    and _hex_digest(row["public_key_digest"]) and _hex_digest(row["code_digest"])
                    and _canonical_uuid(row["process_epoch"]) and expiry(row["expires_at"], False)
                    and row["state"] in _PAIRING_ENROLLMENT_STATES):
                bad("pairing_enrollments", row["id"])
    if "pairing_node_credentials" in tables:
        for row in connection.execute("SELECT * FROM pairing_node_credentials"):
            if not (_canonical_uuid(row["node_id"]) and _hex_digest(row["public_key_digest"])
                    and _hex_digest(row["credential_serial_digest"])
                    and row["state"] in ("active", "revoked")
                    and expiry(row["not_after"] if "not_after" in row.keys() else None, True)):
                bad("pairing_node_credentials", row["node_id"])
    if "pairing_node_renewals" in tables:
        for row in connection.execute("SELECT * FROM pairing_node_renewals"):
            if not (_canonical_uuid(row["node_id"]) and _hex_digest(row["public_key_digest"])
                    and _hex_digest(row["credential_serial_digest"])
                    and expiry(row["not_after"], False)
                    and _staged_certificate_valid(row)):
                bad("pairing_node_renewals", row["node_id"])
    if "pairing_key_bindings" in tables:
        for row in connection.execute("SELECT * FROM pairing_key_bindings"):
            if not (_hex_digest(row["public_key_digest"]) and _canonical_uuid(row["node_id"])
                    and row["revoked"] in (0, 1)):
                bad("pairing_key_bindings", row["node_id"])
    return errors
