"""ADR-0003 policy model, not a proxy, session manager, or runtime auth module.

Transport trust, origin exclusivity, identity validity, credential assertion,
and CSRF/origin evidence are supplied by the caller. This model cannot establish
them: it never inspects proxy configuration, verifies an authenticator, or reads
a request. Times and handles are synthetic; no real tokens, sockets, databases,
cryptography, or production APIs exist here.
"""

from dataclasses import dataclass, replace
from enum import Enum


class OriginEvidence(Enum):
    """What the request carried about the reserved ServerSentinel origin."""

    # Exactly the configured scheme/host/port.
    MATCHING = "matching"
    # No origin indicator, as browsers omit for same-origin read navigation.
    ABSENT = "absent"
    # Any other value, including a co-hosted name merged onto this origin.
    FOREIGN = "foreign"


class Capability(Enum):
    LIVE = "live:view"
    RECORDINGS = "recordings:view"
    TIMELINE = "timeline"
    OWNER = "owner"
    NONOWNER_EXPORT = "nonowner-export"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Identity:
    issuer: str
    login: str


@dataclass(frozen=True)
class Principal:
    identity: Identity
    active: bool = True
    owner: bool = False
    permissions: frozenset = frozenset()
    # Handles of the principal's currently active per-person credentials.
    credentials: frozenset = frozenset()
    generation: int = 0


@dataclass(frozen=True)
class Session:
    identity: Identity
    # The credential whose assertion established this session.
    credential: str
    principal_generation: int
    deployment_generation: int
    issued: int
    last_use: int
    # When the credential's user verification last happened.
    verified: int
    valid: bool = True


@dataclass(frozen=True)
class Evidence:
    identity: Identity | None
    trusted_transport: bool = True
    human_listener: bool = True
    identity_valid: bool = True
    origin: OriginEvidence = OriginEvidence.MATCHING
    csrf_valid: bool = True


@dataclass(frozen=True)
class Policy:
    # Proposed values are test parameters, not accepted product defaults.
    idle_limit: int = 30 * 60
    absolute_limit: int = 12 * 60 * 60
    owner_step_up_limit: int = 5 * 60
    deployment_generation: int = 0
    state_available: bool = True
    # Deployment/startup verification found a dedicated scheme/host/port with no
    # other application routed on it. Unverified exclusivity keeps access closed.
    exclusive_origin: bool = False
    # Production routes remain closed until approval AND implementation.
    approved_and_implemented: bool = False


def permits(policy, evidence, principal, session, capability, now,
            mutation=False, handshake=False):
    """Evaluate the conjunction of gates on already-verified synthetic evidence."""
    if not (policy.approved_and_implemented and policy.state_available
            and policy.exclusive_origin
            and evidence.trusted_transport and evidence.human_listener
            and evidence.identity_valid):
        return False
    # A foreign origin is refused everywhere; an absent one only reads, because
    # establishment, mutations, and handshakes must carry the reserved origin.
    if evidence.origin is OriginEvidence.FOREIGN:
        return False
    if (mutation or handshake) and evidence.origin is not OriginEvidence.MATCHING:
        return False
    if principal is None or session is None or evidence.identity is None:
        return False
    if not principal.active or not session.valid:
        return False
    if not (evidence.identity == principal.identity == session.identity):
        return False
    # Revoking one credential ends its sessions without revoking the principal.
    if session.credential not in principal.credentials:
        return False
    if (session.principal_generation != principal.generation
            or session.deployment_generation != policy.deployment_generation):
        return False
    if not (session.issued <= session.last_use <= now
            and now - session.issued < policy.absolute_limit
            and now - session.last_use < policy.idle_limit):
        return False
    if mutation and not evidence.csrf_valid:
        return False
    # AUTH-008 Owner operations need a recent user verification. Admit/deny is
    # all this model returns; the stale-session response belongs to the
    # shared-Tailnet-account ADR and its main-to-Web contract.
    if (mutation and capability is Capability.OWNER
            and now - session.verified >= policy.owner_step_up_limit):
        return False
    if capability in (Capability.UNKNOWN, Capability.NONOWNER_EXPORT):
        return False
    if principal.owner:
        return True
    if capability is Capability.OWNER:
        return False
    permission = (Capability.RECORDINGS.value if capability is Capability.TIMELINE
                  else capability.value)
    return permission in principal.permissions


def change_grants(principal, permissions, active=True):
    """Model a committed Owner-authorized mutation, not its transaction/authority.

    Full revocation also revokes every credential enrolled for the principal.
    """
    return replace(principal, permissions=frozenset(permissions), active=active,
                   credentials=principal.credentials if active else frozenset(),
                   generation=principal.generation + 1)


def enroll_credential(principal, credential):
    """Model a redeemed Owner invitation adding one per-person credential."""
    return replace(principal, credentials=principal.credentials | {credential})


def revoke_credential(principal, credential):
    """Model per-credential revocation; the principal and its grants survive."""
    return replace(principal, credentials=principal.credentials - {credential})


def fresh_session(principal, policy, now, credential=None):
    """Model established state; callers already supplied establishment evidence."""
    if credential is None:
        credential = min(principal.credentials)
    return Session(principal.identity, credential, principal.generation,
                   policy.deployment_generation, now, now, now)


def recover(policy, owner, new_identity, local_admin_confirmed):
    """Model an atomic, already-authorized local recovery outcome."""
    if not local_admin_confirmed or not owner.owner:
        raise PermissionError("local administration required")
    return (replace(policy, deployment_generation=policy.deployment_generation + 1),
            replace(owner, identity=new_identity, credentials=frozenset(),
                    generation=owner.generation + 1))
