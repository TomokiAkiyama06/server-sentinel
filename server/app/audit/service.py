"""Owner-only execution boundary with atomic domain mutation plus audit."""

import sqlite3
from contextlib import nullcontext
from typing import Callable, ContextManager, Protocol, TypeVar
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
        """Return only for the current deployment Owner; otherwise raise.

        This subsystem defines no authentication of its own. An implementation
        must come from the Issue #6 human-access boundary and satisfy its
        contract, including verified identity, current grants rechecked for
        this operation, and the Owner-operation verification freshness window
        proposed in ADR-0003. Network reachability, a Tailnet membership or a
        capture-node credential never satisfies it.
        """


class DenyAllOwners:
    """The default until a deployment supplies that boundary: deny everything."""

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
        # Bounded health only. A storage admission or append failure must stay
        # visible here instead of silently dropping an audit outcome.
        self.audit_delivery_failed = False
        self.undelivered_audit_records = 0

    def _delivery_failed(self) -> None:
        self.audit_delivery_failed = True
        self.undelivered_audit_records += 1

    @staticmethod
    def _denied_category(error: PermissionError) -> ActorCategory:
        if isinstance(error, OwnerAuthorizationError):
            return error.actor_category
        # Foreign authorizers commonly raise plain PermissionError. Never read
        # or persist its message/attributes because they may contain identity.
        return ActorCategory.UNAUTHENTICATED

    def _authorize(self, actor_context, action, target_kind, target_logical_id,
                   *, connection=None, reservation=None):
        try:
            self.authorizer.require_owner(actor_context)
        except PermissionError as error:
            category = self._denied_category(error)
            try:
                if connection is None:
                    # The store admits this write through its own reservation.
                    self.store.append(
                        actor_category=category, action=action, target_kind=target_kind,
                        target_logical_id=target_logical_id, outcome=AuditOutcome.DENIED,
                    )
                else:
                    # A caller-owned connection carries the caller's admission.
                    with reservation() if reservation is not None else nullcontext():
                        if connection.in_transaction:
                            raise AuditStorageError("audit transaction is unavailable")
                        connection.execute("BEGIN IMMEDIATE")
                        try:
                            self.store.append_on(
                                connection, actor_category=category, action=action,
                                target_kind=target_kind,
                                target_logical_id=target_logical_id,
                                outcome=AuditOutcome.DENIED,
                            )
                            connection.execute("COMMIT")
                        except BaseException:
                            if connection.in_transaction:
                                connection.execute("ROLLBACK")
                            raise
            except BaseException:
                # Denied work never ran, so keep the denial as the caller's
                # result and expose the undelivered record through health.
                self._delivery_failed()
                raise
            raise OwnerAuthorizationError(category) from None

    def execute_transactional(self, actor_context: object, *, action: AuditAction,
                              target_kind: TargetKind, target_logical_id: UUID,
                              operation: Callable[..., Result],
                              prepare: Callable[[], object] | None = None,
                              connection: sqlite3.Connection | None = None,
                              reservation: Callable[[], ContextManager] | None = None) -> Result:
        """Commit the mutation and success audit in one SQLite transaction.

        An optional reservation is acquired after authorization and remains
        active until the shared transaction commits or rolls back.
        On mutation/audit failure the shared transaction rolls back, then a
        separate bounded failure record is attempted. An audit append failure
        can therefore never leave only the sensitive mutation committed.

        ``prepare`` runs after authorization and before the transaction opens,
        for validation that must not hold a database write lock, such as
        blocking device discovery. It is not run for a denied actor, its result
        is passed to ``operation``, and its failure is audited like any other.
        """
        validate_action_target(action, target_kind, target_logical_id)
        if reservation is not None and not callable(reservation):
            raise AuditValidationError("invalid audit storage reservation")
        if prepare is not None and not callable(prepare):
            raise AuditValidationError("invalid audit operation preparation")
        self._authorize(actor_context, action, target_kind, target_logical_id,
                        connection=connection, reservation=reservation)

        def run(active):
            result = operation(active) if prepare is None else operation(active, prepared)
            self.store.append_on(
                active, actor_category=ActorCategory.OWNER, action=action,
                target_kind=target_kind, target_logical_id=target_logical_id,
                outcome=AuditOutcome.SUCCEEDED,
            )
            return result

        try:
            # Preparation stays outside the transaction so slow validation
            # cannot hold the database write lock against other writers.
            prepared = prepare() if prepare is not None else None
            boundary = reservation() if reservation is not None else nullcontext()
            with boundary:
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
            # The mutation has already rolled back. This bounded failure record
            # is appended through the store's own storage admission, so a hard
            # filesystem reserve is never spent to report the failure. When
            # even that write is refused, the loss becomes visible health
            # instead of a silently dropped outcome.
            try:
                self.store.append(
                    actor_category=ActorCategory.OWNER, action=action,
                    target_kind=target_kind, target_logical_id=target_logical_id,
                    outcome=AuditOutcome.FAILED,
                )
            except Exception:
                self._delivery_failed()
            raise

    def record_owner_post_commit_failure(self, *, action: AuditAction,
                                         target_kind: TargetKind,
                                         target_logical_id: UUID):
        """Record a bounded failure after an authorized durable journal commit.

        This runs while the operation's own failure is propagating, so it never
        replaces that failure with a storage/admission error of its own. An
        undeliverable record becomes visible health instead.
        """
        validate_action_target(action, target_kind, target_logical_id)
        try:
            return self.store.append(
                actor_category=ActorCategory.OWNER, action=action,
                target_kind=target_kind, target_logical_id=target_logical_id,
                outcome=AuditOutcome.FAILED,
            )
        except Exception:
            self._delivery_failed()
            return None

    def list_records(self, actor_context: object, *, limit: int = 100,
                     before=None) -> tuple:
        """Read audit history for the deployment Owner only.

        Audit reading is a privileged security operation: no invited principal
        and no capture-node credential may reach it, and the underlying store
        is never exposed as a readable API to them. Reads are not themselves
        audited, so an unauthorized caller cannot grow the audit table.
        """
        self.authorizer.require_owner(actor_context)
        return self.store.list_records(limit=limit, before=before)
