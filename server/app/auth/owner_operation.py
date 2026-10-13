"""The Owner authorizer of human-access administration (Issue #10 phase 2 S4).

``HumanOwnerAuthorizer`` is the ``OwnerAuthorizer`` that
``HumanAccess.administration`` runs every Owner mutation through. It accepts
exactly one kind of actor context: an ``OwnerOperationContext``, which the
human surface creates only after ``AccessStore.authorize_request(...,
Requirement.OWNER_OP)`` has accepted the request inside ``admit(epoch)`` (a
current, credential-backed Owner session with a fresh user verification, the
proxy-identity binding and the CSRF token checked). Anything else, a raw
session token, a principal, a Tailscale login or a capture-node credential
included, is denied.

The context is a claim about one request, not a capability: the
administration re-reads the session inside the mutation's own SQLite
transaction (``AccessStore.require_owner_session_on``), because the local
``recover`` / revocation commands commit outside the session gate (D6). A
context built by hand for a session that is not, at that commit, the fresh
session of the active Owner changes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.audit.model import ActorCategory
from app.audit.service import OwnerAuthorizationError
from .model import PrincipalRole
from .store import SessionView


@dataclass(frozen=True)
class OwnerOperationContext:
    """One ``OWNER_OP`` request as its gated authorization saw it.

    ``session`` is the ``SessionView`` that authorization returned (its
    credential id stays out of ``repr``) and ``epoch`` the gate epoch it was
    authorized under; the mutation commits inside ``admit(epoch)``.
    """

    session: SessionView
    epoch: int

    def __post_init__(self) -> None:
        if not isinstance(self.session, SessionView) or isinstance(self.epoch, bool) \
                or not isinstance(self.epoch, int):
            raise ValueError("owner operation context is invalid")


class HumanOwnerAuthorizer:
    """Accept only an ``OwnerOperationContext`` of an Owner session.

    A context of a non-Owner session is denied as ``invited_user``; every
    other value as ``unauthenticated``. The authorizer never reads or stores
    anything about the context beyond that, so no identity, token or
    credential id reaches the denial or its audit record.
    """

    def require_owner(self, actor_context: object) -> None:
        if not isinstance(actor_context, OwnerOperationContext):
            raise OwnerAuthorizationError()
        if actor_context.session.role is not PrincipalRole.OWNER:
            raise OwnerAuthorizationError(ActorCategory.INVITED_USER)
