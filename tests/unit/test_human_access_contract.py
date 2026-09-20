"""Exercise ADR-0003's proposed policy algebra, not deployed authentication."""

from dataclasses import replace
import itertools
import unittest

from tests.models.human_access import (
    Capability, Evidence, Identity, OriginEvidence, Policy, Principal,
    change_grants, enroll_credential, fresh_session, permits, recover,
    revoke_credential,
)


class HumanAccessContractTests(unittest.TestCase):
    def setUp(self):
        self.identity = Identity("synthetic-issuer", "viewer@example.invalid")
        self.principal = Principal(self.identity,
                                   permissions=frozenset({"live:view"}),
                                   credentials=frozenset({"credential-1"}))
        self.policy = Policy(approved_and_implemented=True, exclusive_origin=True)
        self.evidence = Evidence(self.identity)
        self.session = fresh_session(self.principal, self.policy, 100)

    def allowed(self, capability=Capability.LIVE, **changes):
        inputs = dict(policy=self.policy, evidence=self.evidence,
                      principal=self.principal, session=self.session,
                      capability=capability, now=100)
        inputs.update(changes)
        return permits(**inputs)

    def test_unapproved_or_unimplemented_boundary_is_closed_for_all_routes(self):
        for capability in Capability:
            for owner in (False, True):
                with self.subTest(capability=capability, owner=owner):
                    self.assertFalse(self.allowed(
                        capability, policy=Policy(),
                        principal=replace(self.principal, owner=owner)))

    def test_a_shared_browser_origin_closes_every_route(self):
        # Without a reserved scheme/host/port, a co-hosted application shares
        # this cookie scope and origin, so no exact-Origin or CSRF check helps.
        closed = replace(self.policy, exclusive_origin=False)
        for capability in Capability:
            for owner in (False, True):
                with self.subTest(capability=capability, owner=owner):
                    self.assertFalse(self.allowed(
                        capability, policy=closed,
                        principal=replace(self.principal, owner=owner)))
                    self.assertFalse(self.allowed(
                        capability, policy=closed, mutation=True,
                        principal=replace(self.principal, owner=owner)))

    def test_origin_evidence_required_per_request_kind(self):
        expected = {
            OriginEvidence.MATCHING: (True, True, True),
            # Browsers omit Origin for same-origin read navigation only.
            OriginEvidence.ABSENT: (True, False, False),
            OriginEvidence.FOREIGN: (False, False, False),
        }
        owner = replace(self.principal, owner=True)
        for origin, (read, mutate, handshake) in expected.items():
            evidence = replace(self.evidence, origin=origin)
            with self.subTest(origin=origin):
                self.assertEqual(self.allowed(evidence=evidence), read)
                self.assertEqual(self.allowed(evidence=evidence, handshake=True),
                                 handshake)
                self.assertEqual(self.allowed(
                    Capability.OWNER, principal=owner, evidence=evidence,
                    mutation=True), mutate)

    def test_every_gate_is_required_in_all_evidence_combinations(self):
        gates = ("trusted_transport", "human_listener", "identity_valid")
        for bits in itertools.product((False, True), repeat=len(gates)):
            with self.subTest(bits=bits):
                evidence = replace(self.evidence, **dict(zip(gates, bits)))
                self.assertEqual(self.allowed(evidence=evidence), all(bits))

    def test_verified_identity_without_a_credential_session_is_refused(self):
        # A shared Tailscale login never authorizes on its own: the session must
        # be bound to a per-person credential the principal still holds.
        for capability in Capability:
            with self.subTest(capability=capability):
                self.assertFalse(self.allowed(
                    capability,
                    principal=replace(self.principal, credentials=frozenset())))
        other = fresh_session(
            enroll_credential(self.principal, "credential-2"), self.policy, 100,
            credential="credential-2")
        self.assertFalse(self.allowed(session=other))

    def test_credential_revocation_ends_only_its_own_sessions(self):
        two = enroll_credential(self.principal, "credential-2")
        first = fresh_session(two, self.policy, 100, credential="credential-1")
        second = fresh_session(two, self.policy, 100, credential="credential-2")
        for session in (first, second):
            self.assertTrue(self.allowed(principal=two, session=session))
        remaining = revoke_credential(two, "credential-1")
        self.assertFalse(self.allowed(principal=remaining, session=first))
        self.assertTrue(self.allowed(principal=remaining, session=second))

    def test_network_membership_never_creates_an_invitation(self):
        self.assertFalse(self.allowed(principal=None))
        self.assertFalse(self.allowed(principal=replace(self.principal, active=False)))
        self.assertFalse(self.allowed(session=None))
        self.assertFalse(self.allowed(evidence=replace(self.evidence, identity=None)))

    def test_identity_is_exact_and_issuer_scoped_even_with_copied_session(self):
        for identity in (
            Identity("other-issuer", self.identity.login),
            Identity(self.identity.issuer, "other@example.invalid"),
            Identity(self.identity.issuer, "Viewer@example.invalid"),
            Identity(self.identity.issuer, self.identity.login + " "),
        ):
            with self.subTest(identity=identity):
                self.assertFalse(self.allowed(evidence=Evidence(identity)))
                self.assertFalse(self.allowed(session=replace(self.session, identity=identity)))

    def test_permission_matrix_and_history_mapping_exhaustively(self):
        for live, recordings, owner in itertools.product((False, True), repeat=3):
            grants = frozenset(p for p, granted in (
                ("live:view", live), ("recordings:view", recordings)) if granted)
            principal = replace(self.principal, permissions=grants, owner=owner)
            expected = {
                Capability.LIVE: live or owner,
                Capability.RECORDINGS: recordings or owner,
                Capability.TIMELINE: recordings or owner,
                Capability.OWNER: owner,
                Capability.NONOWNER_EXPORT: False,
                Capability.UNKNOWN: False,
            }
            for capability, allowed in expected.items():
                with self.subTest(grants=grants, owner=owner, capability=capability):
                    self.assertEqual(self.allowed(capability, principal=principal), allowed)

    def test_permission_reduction_invalidates_old_session(self):
        changed = change_grants(self.principal, {"recordings:view"})
        self.assertFalse(self.allowed(principal=changed))
        self.assertFalse(self.allowed(Capability.RECORDINGS, principal=changed))
        session = fresh_session(changed, self.policy, 100)
        self.assertTrue(self.allowed(Capability.RECORDINGS, principal=changed, session=session))
        self.assertFalse(self.allowed(principal=changed, session=session))

    def test_reinvitation_needs_a_new_credential_and_session(self):
        revoked = change_grants(self.principal, (), active=False)
        self.assertEqual(revoked.credentials, frozenset())
        reinvited = enroll_credential(change_grants(revoked, {"live:view"}),
                                      "credential-2")
        for principal in (revoked, reinvited):
            self.assertFalse(self.allowed(principal=principal))
        self.assertTrue(self.allowed(principal=reinvited,
                                    session=fresh_session(reinvited, self.policy, 100)))

    def test_logout_does_not_revoke_invitation_but_old_session_is_invalid(self):
        self.assertFalse(self.allowed(session=replace(self.session, valid=False)))
        self.assertTrue(self.allowed(session=fresh_session(self.principal, self.policy, 100)))

    def test_idle_and_absolute_expiry_boundaries(self):
        self.assertTrue(self.allowed(now=100 + self.policy.idle_limit - 1))
        self.assertFalse(self.allowed(now=100 + self.policy.idle_limit))
        end = 100 + self.policy.absolute_limit
        active = replace(self.session, last_use=end - 1)
        self.assertTrue(self.allowed(now=end - 1, session=active))
        self.assertFalse(self.allowed(now=end, session=active))

    def test_backward_clock_and_invalid_order_fail_closed(self):
        self.assertFalse(self.allowed(now=99))
        self.assertFalse(self.allowed(session=replace(self.session, last_use=99)))
        self.assertFalse(self.allowed(session=replace(self.session, last_use=101)))

    def test_unavailable_state_denies_owner_and_viewers(self):
        for owner in (False, True):
            self.assertFalse(self.allowed(
                policy=replace(self.policy, state_available=False),
                principal=replace(self.principal, owner=owner)))

    def test_cross_origin_and_missing_csrf_deny_mutation(self):
        owner = replace(self.principal, owner=True)
        for origin, csrf in itertools.product(
                (OriginEvidence.FOREIGN, OriginEvidence.MATCHING), (False, True)):
            self.assertEqual(self.allowed(
                Capability.OWNER, principal=owner, mutation=True,
                evidence=replace(self.evidence, origin=origin, csrf_valid=csrf)),
                origin is OriginEvidence.MATCHING and csrf)

    def test_owner_operations_need_a_fresh_user_verification(self):
        owner = replace(self.principal, owner=True)
        stale = replace(self.session,
                        verified=100 - self.policy.owner_step_up_limit)
        fresh = replace(stale, verified=101 - self.policy.owner_step_up_limit)
        self.assertFalse(self.allowed(Capability.OWNER, principal=owner,
                                      session=stale, mutation=True))
        self.assertTrue(self.allowed(Capability.OWNER, principal=owner,
                                     session=fresh, mutation=True))
        # Freshness gates the AUTH-008 operation, not ordinary viewing.
        self.assertTrue(self.allowed(principal=owner, session=stale))

    def test_recovery_requires_local_admin_evidence_and_invalidates_every_session(self):
        owner = replace(self.principal, owner=True)
        replacement = Identity("synthetic-issuer", "new-owner@example.invalid")
        with self.assertRaises(PermissionError):
            recover(self.policy, owner, replacement, local_admin_confirmed=False)
        policy, new_owner = recover(self.policy, owner, replacement, local_admin_confirmed=True)
        self.assertEqual(new_owner.credentials, frozenset())
        self.assertFalse(self.allowed(policy=policy))
        self.assertFalse(self.allowed(policy=policy, principal=new_owner,
                                      evidence=Evidence(replacement)))
        enrolled = enroll_credential(new_owner, "credential-owner-2")
        self.assertTrue(self.allowed(Capability.OWNER, policy=policy, principal=enrolled,
                                     evidence=Evidence(replacement),
                                     session=fresh_session(enrolled, policy, 100)))

    def test_long_lived_delivery_rechecks_current_permission_for_each_emission(self):
        # Each call represents an admission check, not a real socket/watchdog.
        self.assertTrue(self.allowed())
        revoked = change_grants(self.principal, (), active=False)
        for capability in (Capability.LIVE, Capability.RECORDINGS, Capability.TIMELINE):
            self.assertFalse(self.allowed(capability, principal=revoked))


if __name__ == "__main__":
    unittest.main()
