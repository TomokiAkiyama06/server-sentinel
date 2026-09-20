"""Owner-only execution boundary with atomic domain mutation plus audit."""

import sqlite3
from typing import Callable, Protocol, TypeVar
from uuid import UUID

from .model import (
    ActorCategory, AuditAction, AuditOutcome, AuditValidationError, TargetKind,
    validate_action_target,
)
from .store import AuditStorageError, AuditStore


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


class DenyAllOwners:
    def require_owner(self, actor_context: object) -> None:
        raise OwnerAuthorizationError()


class OwnerAuditService:
    """Run an Owner-only mutation and persist its bounded audit outcome.

    ``actor_context`` is forwarded only to the injected authorizer. It is never
    inspected, represented, or stored by this subsystem.
    """

    def __init__(self, store: AuditStore, authorizer: OwnerAuthorizer):
        self.store = store
        self.authorizer = authorizer

    @staticmethod
    def _denied_category(error: PermissionError) -> ActorCategory:
        if isinstance(error, OwnerAuthorizationError):
            return error.actor_category
        # Foreign authorizers commonly raise plain PermissionError. Never read
        # or persist its message/attributes because they may contain identity.
        return ActorCategory.UNAUTHENTICATED

    def _authorize(self, actor_context, action, target_kind, target_logical_id,
                   *, connection=None):
        try:
            self.authorizer.require_owner(actor_context)
        except PermissionError as error:
            category = self._denied_category(error)
            if connection is None:
                self.store.append(
                    actor_category=category, action=action, target_kind=target_kind,
                    target_logical_id=target_logical_id, outcome=AuditOutcome.DENIED,
                )
            else:
                if connection.in_transaction:
                    raise AuditStorageError("audit transaction is unavailable")
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self.store.append_on(
                        connection, actor_category=category, action=action,
                        target_kind=target_kind, target_logical_id=target_logical_id,
                        outcome=AuditOutcome.DENIED,
                    )
                    connection.execute("COMMIT")
                except BaseException:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
            raise OwnerAuthorizationError(category) from None

    def execute_transactional(self, actor_context: object, *, action: AuditAction,
                              target_kind: TargetKind, target_logical_id: UUID,
                              operation: Callable[[sqlite3.Connection], Result],
                              connection: sqlite3.Connection | None = None) -> Result:
        """Commit the mutation and success audit in one SQLite transaction.

        On mutation/audit failure the shared transaction rolls back, then a
        separate bounded failure record is attempted. An audit append failure
        can therefore never leave only the sensitive mutation committed.
        """
        validate_action_target(action, target_kind, target_logical_id)
        self._authorize(actor_context, action, target_kind, target_logical_id,
                        connection=connection)

        def run(active):
            result = operation(active)
            self.store.append_on(
                active, actor_category=ActorCategory.OWNER, action=action,
                target_kind=target_kind, target_logical_id=target_logical_id,
                outcome=AuditOutcome.SUCCEEDED,
            )
            return result

        try:
            if connection is None:
                with self.store.transaction(write=True) as active:
                    return run(active)
            if connection.in_transaction:
                raise AuditStorageError("audit transaction is unavailable")
            connection.execute("BEGIN IMMEDIATE")
            try:
                result = run(connection)
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        except Exception:
            # A failed success-append may also prevent this best-effort failure
            # append. The mutation has already rolled back either way.
            try:
                self.store.append(
                    actor_category=ActorCategory.OWNER, action=action,
                    target_kind=target_kind, target_logical_id=target_logical_id,
                    outcome=AuditOutcome.FAILED,
                )
            except Exception:
                pass
            raise

    def record_owner_post_commit_failure(self, *, action: AuditAction,
                                         target_kind: TargetKind,
                                         target_logical_id: UUID):
        """Record a bounded failure after an authorized durable journal commit."""
        validate_action_target(action, target_kind, target_logical_id)
        return self.store.append(
            actor_category=ActorCategory.OWNER, action=action,
            target_kind=target_kind, target_logical_id=target_logical_id,
            outcome=AuditOutcome.FAILED,
        )
