"""ADR-0003 policy model, not a proxy, session manager, or runtime auth module.

Transport trust, identity validity, and CSRF/origin evidence are supplied by the
caller. This model cannot establish them. Times and handles are synthetic; no
real tokens, sockets, databases, cryptography, or production APIs exist here.
"""

from dataclasses import dataclass, replace
from enum import Enum


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
    generation: int = 0


@dataclass(frozen=True)
class Session:
    identity: Identity
    principal_generation: int
    deployment_generation: int
    issued: int
    last_use: int
    valid: bool = True


@dataclass(frozen=True)
class Evidence:
    identity: Identity | None
    trusted_transport: bool = True
    human_listener: bool = True
    identity_valid: bool = True
    origin_valid: bool = True
    csrf_valid: bool = True


@dataclass(frozen=True)
class Policy:
    # Proposed values are test parameters, not accepted product defaults.
    idle_limit: int = 30 * 60
    absolute_limit: int = 12 * 60 * 60
    deployment_generation: int = 0
    state_available: bool = True
    # Production routes remain closed until approval AND implementation.
    approved_and_implemented: bool = False


def permits(policy, evidence, principal, session, capability, now, mutation=False):
    """Evaluate the conjunction of gates on already-verified synthetic evidence."""
    if not (policy.approved_and_implemented and policy.state_available
            and evidence.trusted_transport and evidence.human_listener
            and evidence.identity_valid and evidence.origin_valid):
        return False
    if principal is None or session is None or evidence.identity is None:
        return False
    if not principal.active or not session.valid:
        return False
    if not (evidence.identity == principal.identity == session.identity):
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
    """Model a committed Owner-authorized mutation, not its transaction/authority."""
    return replace(principal, permissions=frozenset(permissions), active=active,
                   generation=principal.generation + 1)


def fresh_session(principal, policy, now):
    """Model established state; callers already supplied establishment evidence."""
    return Session(principal.identity, principal.generation,
                   policy.deployment_generation, now, now)


def recover(policy, owner, new_identity, local_admin_confirmed):
    """Model an atomic, already-authorized local recovery outcome."""
    if not local_admin_confirmed or not owner.owner:
        raise PermissionError("local administration required")
    return (replace(policy, deployment_generation=policy.deployment_generation + 1),
            replace(owner, identity=new_identity, generation=owner.generation + 1))
