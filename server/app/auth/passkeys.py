"""Per-person WebAuthn/passkey ceremonies for Issue #10 (ADR-0004, ADR-0003).

``PasskeyCeremonies`` composes the pure verifier in ``webauthn.py`` with the
transactional state in ``AccessStore``. It registers no HTTP route: human route
mounting stays closed until the remaining Issue #10 gates pass. A future route
passes in the request body, the trusted-proxy identity (supplementary only) and
the session cookie value, and maps the results to responses.

Invariants enforced here:

- user presence and user verification are required at registration and at
  every authentication and step-up;
- a challenge is server-issued, stored only as a digest, single use, bound to
  its ceremony (and to its invitation or session), and expires;
- client data type, challenge and exact origin, the relying-party id hash and
  the signature are always verified — none of them is skipped as
  "minimization";
- a credential is bound to exactly one invited principal through that
  principal's single-use invitation, and a session to the credential that
  created it;
- the trusted-proxy identity is supplementary (ADR-0004 §1): it must be
  present, but it never selects or authorizes a principal, and several
  invited people behind one shared Tailscale login each register and sign in
  with their own passkey. A session keeps only its keyed HMAC binding, and a
  later request whose identity does not reproduce it is refused;
- every refusal before success is the same ``CeremonyDenied`` with one fixed
  message. The only distinct outcomes are ``StepUpRequired`` (an already
  authenticated Owner session that must re-verify) and
  ``DeviceBoundCredentialRequired`` (a holder of a valid invitation whose
  verified authenticator is backup eligible in a deployment that requires
  device-bound credentials).

Every ``finish_*`` step that redeems an invitation, establishes a session or
updates a session's user-verification time first takes
``session_gate.epoch()`` (in production the ``HostnameReservationCheck``),
before it consumes the challenge or verifies anything, and commits inside
``session_gate.admit(epoch)``, which re-checks under the gate lock that human
access is open and has not closed since that epoch (Issue #144, PR #174
review). A reservation check that closes access and revokes sessions can
therefore neither interleave with the commit nor complete a whole close ->
revoke -> reopen cycle while the request is verifying. Every ``begin_*``
step stores its challenge the same way (epoch at its start, insert inside
``admit(epoch)``), so a challenge either committed before a close, and the
revocation that follows deletes every pending challenge, or is never stored
(PR #174 review); one issued before a revocation cannot be used afterwards. Only the local
commit runs inside the gate. A step that finds access already closed
(``epoch()`` is ``None``) refuses at once, before it consumes a challenge or
verifies or records anything; the final ``admit(epoch)`` check still runs.
A gate refusal is the same generic denial.

Revocation is credential-scoped: revoking a credential disables it wherever a
synced passkey exists, not on one device. Nothing here receives or stores a
fingerprint or face template; user verification happens on the viewer's
authenticator and reaches the server only as the UV flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import secrets
from typing import Callable, ContextManager, Mapping, Protocol
from uuid import UUID

from . import webauthn
from .model import AccessValidationError, Credential, CredentialStatus, Principal, PrincipalStatus, utc_time
from .store import AccessStore, MAX_CHALLENGE_LIFETIME, StepUpRequired


DEFAULT_CHALLENGE_LIFETIME = timedelta(minutes=5)
SESSION_TOKEN_BYTES = 32


class CeremonyDenied(AccessValidationError):
    """The single generic denial for every failed pre-session ceremony step."""

    def __init__(self) -> None:
        super().__init__("access is unavailable")


class DeviceBoundCredentialRequired(AccessValidationError):
    """A verified backup-eligible registration refused by deployment policy.

    Reached only by someone who holds a valid invitation and completed a
    verified ceremony, so the Web client may show an actionable message. The
    invitation stays unredeemed.
    """

    def __init__(self) -> None:
        super().__init__("device_bound_credential_required")


class CredentialFinding(str, Enum):
    SIGN_COUNT_REGRESSION = "sign_count_regression"
    BACKUP_ELIGIBILITY_CHANGED = "backup_eligibility_changed"


class SessionGate(Protocol):
    def epoch(self) -> int | None:
        """The gate epoch at the start of a request; ``None`` while closed."""

    def admit(self, epoch: int | None) -> ContextManager[None]:
        """Hold the gate; raise unless access is open and unchanged since ``epoch``."""


class CredentialFindingSink(Protocol):
    def credential_finding(self, kind: CredentialFinding, principal_id: UUID) -> None:
        """Deliver an Owner notification; receives no credential material."""


@dataclass(frozen=True)
class SessionGrant:
    """A new session. ``token`` goes into the ``__Host-`` cookie and nowhere else."""

    principal_id: UUID
    session_id: UUID
    token: bytes

    def __repr__(self) -> str:
        return f"SessionGrant(principal_id={self.principal_id}, session_id={self.session_id})"


def _digest(challenge: bytes) -> bytes:
    return hashlib.sha256(challenge).digest()


class PasskeyCeremonies:
    def __init__(self, store: AccessStore, relying_party: webauthn.RelyingParty, *,
                 session_gate: SessionGate,
                 clock: Callable[[], datetime] | None = None,
                 challenge_lifetime: timedelta = DEFAULT_CHALLENGE_LIFETIME,
                 require_device_bound: bool = False,
                 allowed_algorithms: tuple[int, ...] = webauthn.SUPPORTED_ALGORITHMS,
                 findings: CredentialFindingSink | None = None,
                 random_bytes: Callable[[int], bytes] = secrets.token_bytes):
        if not isinstance(store, AccessStore) or store.audit is None:
            raise ValueError("an audited access store is required")
        if not store.session_binding_configured:
            raise ValueError("a session binding key is required")
        if not isinstance(relying_party, webauthn.RelyingParty):
            raise ValueError("relying party is required")
        if not callable(getattr(session_gate, "admit", None)) or not callable(getattr(session_gate, "epoch", None)):
            # Mandatory: without it a commit could land after a reservation
            # check closed access and revoked every session (Issue #144).
            raise ValueError("a session gate is required")
        if (not isinstance(challenge_lifetime, timedelta)
                or not timedelta(0) < challenge_lifetime <= MAX_CHALLENGE_LIFETIME):
            raise ValueError("challenge lifetime is invalid")
        if type(require_device_bound) is not bool:
            raise ValueError("device-bound policy is invalid")
        if (not allowed_algorithms or len(set(allowed_algorithms)) != len(allowed_algorithms)
                or any(alg not in webauthn.SUPPORTED_ALGORITHMS for alg in allowed_algorithms)):
            raise ValueError("algorithm policy is invalid")
        self.store = store
        self.rp = relying_party
        self.session_gate = session_gate
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.challenge_lifetime = challenge_lifetime
        self.require_device_bound = require_device_bound
        self.allowed_algorithms = tuple(allowed_algorithms)
        self.findings = findings
        self._random = random_bytes
        # Bounded health only: an Owner finding that could not be delivered.
        self.finding_delivery_failed = 0

    def _now(self) -> datetime:
        return utc_time(self._clock())

    def _challenge(self) -> bytes:
        challenge = self._random(webauthn.CHALLENGE_BYTES)
        if not isinstance(challenge, bytes) or len(challenge) != webauthn.CHALLENGE_BYTES:
            raise CeremonyDenied()
        return challenge

    def _timeout_ms(self) -> int:
        return int(self.challenge_lifetime.total_seconds() * 1000)

    def _report(self, kind: CredentialFinding, principal_id: UUID) -> None:
        if self.findings is None:
            return
        try:
            self.findings.credential_finding(kind, principal_id)
        except Exception:
            self.finding_delivery_failed += 1

    # --- Registration (invitation redemption) ---

    def begin_registration(self, enrollment_secret: bytes, proxy_identity: str) -> dict:
        """Return creation options for a valid invitation; generic denial otherwise.

        The options carry only what the browser ceremony needs: the reserved
        relying-party id (also used as its display name, so no product string
        is disclosed), the invitee's own display name, the challenge and the
        policy. No camera, recording, timeline or deployment data.
        """
        try:
            # First: the challenge is stored only if access stays open from
            # here to its commit (PR #174 review).
            epoch = self.session_gate.epoch()
            if epoch is None:
                # Closed: refuse before consuming or verifying anything.
                raise CeremonyDenied()
            challenge = self._challenge()
            with self.session_gate.admit(epoch):
                subject = self.store.begin_registration(
                    enrollment_secret, proxy_identity, _digest(challenge),
                    at=self._now(), lifetime=self.challenge_lifetime)
        except Exception:
            raise CeremonyDenied() from None
        return {
            "rp": {"id": self.rp.rp_id, "name": self.rp.rp_id},
            "user": {"id": webauthn.b64url_encode(subject.principal_id.bytes),
                     "name": subject.display_name, "displayName": subject.display_name},
            "challenge": webauthn.b64url_encode(challenge),
            "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in self.allowed_algorithms],
            "timeout": self._timeout_ms(),
            "excludeCredentials": [{"type": "public-key", "id": webauthn.b64url_encode(item)}
                                   for item in subject.excluded_credential_ids],
            "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True,
                                       "userVerification": "required"},
            "attestation": "none",
        }

    def finish_registration(self, enrollment_secret: bytes, proxy_identity: str,
                            credential: Mapping, *, label: str | None = None) -> Credential:
        """Verify a registration and redeem the invitation its challenge was bound to."""
        try:
            # First: a close after this point refuses the commit (Issue #144).
            epoch = self.session_gate.epoch()
            if epoch is None:
                # Closed: refuse before consuming or verifying anything.
                raise CeremonyDenied()
            at = self._now()
            challenge = webauthn.registration_challenge(credential, self.rp)
            consumed = self.store.consume_challenge(_digest(challenge), "registration", at=at)
            verified = webauthn.verify_registration(credential, self.rp, challenge,
                                                    allowed_algorithms=self.allowed_algorithms)
        except Exception:
            raise CeremonyDenied() from None
        if self.require_device_bound and verified.backup_eligible:
            raise DeviceBoundCredentialRequired()
        try:
            with self.session_gate.admit(epoch):
                return self.store.enroll_credential(
                    enrollment_secret, proxy_identity, verified.credential_id, verified.public_key,
                    verified.algorithm, verified.sign_count, now=at,
                    backup_eligible=verified.backup_eligible, backup_state=verified.backup_state,
                    label=label, invitation_id=consumed.invitation_id)
        except Exception:
            raise CeremonyDenied() from None

    # --- Authentication (sign-in) ---

    def begin_authentication(self) -> dict:
        """Issue an unbound challenge for a discoverable credential.

        No credential list is returned, so the response does not reveal
        whether any identity is invited.
        """
        try:
            epoch = self.session_gate.epoch()
            if epoch is None:
                # Closed: refuse before consuming or verifying anything.
                raise CeremonyDenied()
            challenge = self._challenge()
            with self.session_gate.admit(epoch):
                self.store.issue_authentication_challenge(_digest(challenge), at=self._now(),
                                                          lifetime=self.challenge_lifetime)
        except Exception:
            raise CeremonyDenied() from None
        return {"challenge": webauthn.b64url_encode(challenge), "rpId": self.rp.rp_id,
                "timeout": self._timeout_ms(), "userVerification": "required",
                "allowCredentials": []}

    def _verified_assertion(self, credential: Mapping, claims: webauthn.AssertionClaims,
                            *, require_user_handle: bool) -> tuple[Principal, Credential, webauthn.VerifiedAssertion]:
        subject = self.store.assertion_subject(claims.credential_id)
        if subject is None:
            raise CeremonyDenied()
        principal, stored = subject
        if principal.status is not PrincipalStatus.ACTIVE or stored.status is not CredentialStatus.ACTIVE:
            raise CeremonyDenied()
        if claims.user_handle is None:
            if require_user_handle:
                raise CeremonyDenied()
        elif claims.user_handle != principal.id.bytes:
            raise CeremonyDenied()
        verified = webauthn.verify_assertion(credential, self.rp, claims.challenge,
                                             stored.public_key, stored.algorithm)
        at = self._now()
        if verified.backup_eligible != stored.backup_eligible:
            self.store.mark_credential_inconsistent(stored.credential_id, principal.id, at=at)
            self._report(CredentialFinding.BACKUP_ELIGIBILITY_CHANGED, principal.id)
            raise CeremonyDenied()
        if not webauthn.sign_count_advances(stored.sign_count, verified.sign_count):
            self.store.record_sign_count_regression(principal.id)
            self._report(CredentialFinding.SIGN_COUNT_REGRESSION, principal.id)
            raise CeremonyDenied()
        return principal, stored, verified

    def finish_authentication(self, proxy_identity: str, credential: Mapping) -> SessionGrant:
        """Verify an assertion and establish a credential-bound session.

        The discoverable credential alone selects the principal. The verified
        proxy identity must be present; it is recorded as the principal's last
        observed value and bound into the new session as a keyed HMAC, but it
        is never compared with the principal: people sharing one Tailscale
        login each sign in with their own passkey.
        """
        try:
            # First: a close after this point refuses the commit (Issue #144).
            epoch = self.session_gate.epoch()
            if epoch is None:
                # Closed: refuse before consuming or verifying anything.
                raise CeremonyDenied()
            at = self._now()
            claims = webauthn.assertion_claims(credential, self.rp)
            self.store.consume_challenge(_digest(claims.challenge), "authentication", at=at)
            principal, stored, verified = self._verified_assertion(credential, claims, require_user_handle=True)
            token = self._random(SESSION_TOKEN_BYTES)
            if not isinstance(token, bytes) or len(token) != SESSION_TOKEN_BYTES:
                raise CeremonyDenied()
            with self.session_gate.admit(epoch):
                session_id = self.store.accept_assertion(
                    stored.credential_id, principal.id, proxy_identity,
                    expected_sign_count=stored.sign_count, sign_count=verified.sign_count,
                    backup_state=verified.backup_state, at=self._now(), token=token)
        except Exception:
            raise CeremonyDenied() from None
        return SessionGrant(principal.id, session_id, token)

    # --- Owner step-up (AUTH-008) ---

    def authorize_owner_operation(self, token: bytes, proxy_identity: str) -> Principal:
        """Generic denial, ``StepUpRequired`` for a stale Owner session, or the Owner."""
        try:
            return self.store.authorize_owner(token, proxy_identity, now=self._now())
        except StepUpRequired:
            raise
        except Exception:
            raise CeremonyDenied() from None

    def begin_step_up(self, token: bytes, proxy_identity: str) -> dict:
        """Issue a challenge bound to this Owner session and its own credential only."""
        try:
            epoch = self.session_gate.epoch()
            if epoch is None:
                # Closed: refuse before consuming or verifying anything.
                raise CeremonyDenied()
            challenge = self._challenge()
            with self.session_gate.admit(epoch):
                credential_id = self.store.begin_step_up(token, proxy_identity, _digest(challenge),
                                                         at=self._now(), lifetime=self.challenge_lifetime)
        except Exception:
            raise CeremonyDenied() from None
        return {"challenge": webauthn.b64url_encode(challenge), "rpId": self.rp.rp_id,
                "timeout": self._timeout_ms(), "userVerification": "required",
                "allowCredentials": [{"type": "public-key", "id": webauthn.b64url_encode(credential_id)}]}

    def finish_step_up(self, token: bytes, proxy_identity: str, credential: Mapping) -> None:
        """Refresh the session's verification time, or change nothing and deny.

        The assertion must come from the credential that created this session.
        A valid assertion by any other credential — including someone else's
        passkey at the same workstation — is refused and leaves the session's
        verification time untouched.
        """
        try:
            # First: a close after this point refuses the commit (Issue #144).
            epoch = self.session_gate.epoch()
            if epoch is None:
                # Closed: refuse before consuming or verifying anything.
                raise CeremonyDenied()
            at = self._now()
            claims = webauthn.assertion_claims(credential, self.rp)
            consumed = self.store.consume_challenge(_digest(claims.challenge), "step_up", at=at)
            session = self.store.current_session(token, proxy_identity, at=at)
            if (session is None or consumed.session_id != session.session_id
                    or claims.credential_id != session.credential_id):
                raise CeremonyDenied()
            principal, stored, verified = self._verified_assertion(credential, claims, require_user_handle=False)
            if principal.id != session.principal_id:
                raise CeremonyDenied()
            with self.session_gate.admit(epoch):
                self.store.accept_assertion(
                    stored.credential_id, principal.id, proxy_identity,
                    expected_sign_count=stored.sign_count, sign_count=verified.sign_count,
                    backup_state=verified.backup_state, at=self._now(),
                    step_up_session_id=session.session_id)
        except Exception:
            raise CeremonyDenied() from None
