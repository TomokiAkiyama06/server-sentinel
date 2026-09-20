"""Owner-only execution boundary that records success, denial, and failure."""

from typing import Callable, Protocol, TypeVar
from uuid import UUID

from .model import (
    ActorCategory, AuditAction, AuditOutcome, AuditValidationError, TargetKind,
    validate_action_target,
)
from .store import AuditStore


Result = TypeVar("Result")


class OwnerAuthorizationError(PermissionError):
    """The supplied application principal is not an authorized Owner."""

    def __init__(self, actor_category: ActorCategory = ActorCategory.UNAUTHENTICATED):
        if not isinstance(actor_category, ActorCategory) or actor_category is ActorCategory.OWNER:
            raise AuditValidationError("invalid denied actor category")
        self.actor_category = actor_category
        super().__init__("owner authorization required")


class OwnerAuthorizer(Protocol):
    def require_owner(self, actor_context: object) -> None:
        """Return only for the current deployment Owner; otherwise raise."""


class OwnerAuditService:
    """Run an Owner-only mutation and persist its bounded audit outcome.

    ``actor_context`` is forwarded only to the injected authorizer. It is never
    inspected, represented, or stored by this subsystem.
    """

    def __init__(self, store: AuditStore, authorizer: OwnerAuthorizer):
        self.store = store
        self.authorizer = authorizer

    def execute(self, actor_context: object, *, action: AuditAction,
                target_kind: TargetKind, target_logical_id: UUID,
                operation: Callable[[], Result]) -> Result:
        # Validate before authorization or mutation; append() validates again.
        validate_action_target(action, target_kind, target_logical_id)
        try:
            self.authorizer.require_owner(actor_context)
        except OwnerAuthorizationError as error:
            self.store.append(
                actor_category=error.actor_category, action=action,
                target_kind=target_kind, target_logical_id=target_logical_id,
                outcome=AuditOutcome.DENIED,
            )
            raise
        try:
            result = operation()
        except Exception:
            self.store.append(
                actor_category=ActorCategory.OWNER, action=action,
                target_kind=target_kind, target_logical_id=target_logical_id,
                outcome=AuditOutcome.FAILED,
            )
            raise
        self.store.append(
            actor_category=ActorCategory.OWNER, action=action,
            target_kind=target_kind, target_logical_id=target_logical_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return result
