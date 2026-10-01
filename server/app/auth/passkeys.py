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
- every refusal before success is the same ``CeremonyDenied`` with one fixed
  message. The only distinct outcomes are ``StepUpRequired`` (an already
  authenticated Owner session that must re-verify) and
  ``DeviceBoundCredentialRequired`` (a holder of a valid invitation whose
  verified authenticator is backup eligible in a deployment that requires
  device-bound credentials).

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
from typing import Callable, Mapping, Protocol
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
                 clock: Callable[[], datetime] | None = None,
                 challenge_lifetime: timedelta = DEFAULT_CHALLENGE_LIFETIME,
                 require_device_bound: bool = False,
                 allowed_algorithms: tuple[int, ...] = webauthn.SUPPORTED_ALGORITHMS,
                 findings: CredentialFindingSink | None = None,
                 random_bytes: Callable[[int], bytes] = secrets.token_bytes):
        if not isinstance(store, AccessStore) or store.audit is None:
            raise ValueError("an audited access store is required")
        if not isinstance(relying_party, webauthn.RelyingParty):
            raise ValueError("relying party is required")
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

    def begin_registration(self, enrollment_secret: bytes, external_identity: str) -> dict:
        """Return creation options for a valid invitation; generic denial otherwise.

        The options carry only what the browser ceremony needs: the reserved
        relying-party id (also used as its display name, so no product string
        is disclosed), the invitee's own display name, the challenge and the
        policy. No camera, recording, timeline or deployment data.
        """
        try:
            challenge = self._challenge()
            subject = self.store.begin_registration(
                enrollment_secret, external_identity, _digest(challenge),
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

    def finish_registration(self, enrollment_secret: bytes, external_identity: str,
                            credential: Mapping, *, label: str | None = None) -> Credential:
        """Verify a registration and redeem the invitation its challenge was bound to."""
        try:
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
            return self.store.enroll_credential(
                enrollment_secret, external_identity, verified.credential_id, verified.public_key,
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
            challenge = self._challenge()
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

    def finish_authentication(self, external_identity: str, credential: Mapping) -> SessionGrant:
        """Verify an assertion and establish a credential-bound session.

        The verified proxy identity must still match the principal's recorded
        identity (a supplementary check); it never authenticates on its own.
        """
        try:
            at = self._now()
            claims = webauthn.assertion_claims(credential, self.rp)
            self.store.consume_challenge(_digest(claims.challenge), "authentication", at=at)
            principal, stored, verified = self._verified_assertion(credential, claims, require_user_handle=True)
            token = self._random(SESSION_TOKEN_BYTES)
            if not isinstance(token, bytes) or len(token) != SESSION_TOKEN_BYTES:
                raise CeremonyDenied()
            session_id = self.store.accept_assertion(
                stored.credential_id, principal.id, external_identity,
                expected_sign_count=stored.sign_count, sign_count=verified.sign_count,
                backup_state=verified.backup_state, at=self._now(), token=token)
        except Exception:
            raise CeremonyDenied() from None
        return SessionGrant(principal.id, session_id, token)

    # --- Owner step-up (AUTH-008) ---

    def authorize_owner_operation(self, token: bytes, external_identity: str) -> Principal:
        """Generic denial, ``StepUpRequired`` for a stale Owner session, or the Owner."""
        try:
            return self.store.authorize_owner(token, external_identity, now=self._now())
        except StepUpRequired:
            raise
        except Exception:
            raise CeremonyDenied() from None

    def begin_step_up(self, token: bytes, external_identity: str) -> dict:
        """Issue a challenge bound to this Owner session and its own credential only."""
        try:
            challenge = self._challenge()
            credential_id = self.store.begin_step_up(token, external_identity, _digest(challenge),
                                                     at=self._now(), lifetime=self.challenge_lifetime)
        except Exception:
            raise CeremonyDenied() from None
        return {"challenge": webauthn.b64url_encode(challenge), "rpId": self.rp.rp_id,
                "timeout": self._timeout_ms(), "userVerification": "required",
                "allowCredentials": [{"type": "public-key", "id": webauthn.b64url_encode(credential_id)}]}

    def finish_step_up(self, token: bytes, external_identity: str, credential: Mapping) -> None:
        """Refresh the session's verification time, or change nothing and deny.

        The assertion must come from the credential that created this session.
        A valid assertion by any other credential — including someone else's
        passkey at the same workstation — is refused and leaves the session's
        verification time untouched.
        """
        try:
            at = self._now()
            claims = webauthn.assertion_claims(credential, self.rp)
            consumed = self.store.consume_challenge(_digest(claims.challenge), "step_up", at=at)
            session = self.store.current_session(token, external_identity, at=at)
            if (session is None or consumed.session_id != session.session_id
                    or claims.credential_id != session.credential_id):
                raise CeremonyDenied()
            principal, stored, verified = self._verified_assertion(credential, claims, require_user_handle=False)
            if principal.id != session.principal_id:
                raise CeremonyDenied()
            self.store.accept_assertion(
                stored.credential_id, principal.id, external_identity,
                expected_sign_count=stored.sign_count, sign_count=verified.sign_count,
                backup_state=verified.backup_state, at=self._now(),
                step_up_session_id=session.session_id)
        except Exception:
            raise CeremonyDenied() from None
