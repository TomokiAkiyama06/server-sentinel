"""Runtime integration for Owner-authorized administrative mutations."""

from functools import partial
from uuid import UUID, uuid4

from app.auth.reservation import HostnameReservationCheck
from app.auth.reservation_store import ListenerExceptionStore
from app.cameras.registry import NodeHealthState
from .model import AuditAction, TargetKind


ACTIVE_SOURCE_LIMIT_ID = UUID("ed83d8b4-ec44-4e27-b197-8603c03d8fd2")
# The Main Server holds one approved hardware baseline; this fixed logical ID
# names it without exposing any hardware serial or device identifier.
HARDWARE_BASELINE_ID = UUID("6f5f5a2e-3f0e-4a3a-9a4c-2b0f1c7d5e41")
# Fixed logical ID for the Owner's hostname-reservation listener exceptions;
# no port, address or service name reaches the audit log.
RESERVATION_LISTENER_EXCEPTIONS_ID = UUID("1c18dba3-1e38-4e1d-9d2f-70e078205a41")


class OwnerAdministration:
    """The only runtime-facing facade for registry administrative mutations."""

    def __init__(self, service, registry):
        self.service = service
        self.registry = registry

    def list_audit_records(self, actor_context, *, limit=100, before=None):
        """Owner-only audit reading through the same authorization boundary."""
        return self.service.list_records(actor_context, limit=limit, before=before)

    def set_active_source_limit(self, actor_context, limit):
        return self.service.execute_transactional(
            actor_context, action=AuditAction.CHANGE_ADMIN_SETTING,
            target_kind=TargetKind.ADMIN_SETTINGS,
            target_logical_id=ACTIVE_SOURCE_LIMIT_ID,
            operation=lambda connection: self.registry.set_active_limit_on(connection, limit),
        )

    def create_capture_node(self, actor_context, name):
        target = uuid4()
        return self.service.execute_transactional(
            actor_context, action=AuditAction.CREATE_CAPTURE_NODE,
            target_kind=TargetKind.CAPTURE_NODE, target_logical_id=target,
            operation=lambda connection: self.registry.create_capture_node_on(
                connection, target, name,
            ),
        )

    def update_capture_node(self, actor_context, node_id, **changes):
        return self.service.execute_transactional(
            actor_context, action=AuditAction.UPDATE_CAPTURE_NODE,
            target_kind=TargetKind.CAPTURE_NODE, target_logical_id=node_id,
            operation=lambda connection: self.registry.update_capture_node_on(
                connection, node_id, **changes,
            ),
        )

    def revoke_capture_node(self, actor_context, node_id):
        return self.service.execute_transactional(
            actor_context, action=AuditAction.REVOKE_CAPTURE_NODE,
            target_kind=TargetKind.CAPTURE_NODE, target_logical_id=node_id,
            operation=lambda connection: self.registry.update_capture_node_on(
                connection, node_id, health_state=NodeHealthState.REVOKED,
            ),
        )

    def create_source(self, actor_context, **configuration):
        target = uuid4()
        return self.service.execute_transactional(
            actor_context, action=AuditAction.CREATE_SOURCE,
            target_kind=TargetKind.SOURCE, target_logical_id=target,
            operation=lambda connection: self.registry.create_source_on(
                connection, target, **configuration,
            ),
        )

    def update_source(self, actor_context, source_id, **changes):
        return self.service.execute_transactional(
            actor_context, action=AuditAction.UPDATE_SOURCE,
            target_kind=TargetKind.SOURCE, target_logical_id=source_id,
            operation=lambda connection: self.registry.update_source_on(
                connection, source_id, **changes,
            ),
        )

    def revoke_source(self, actor_context, source_id):
        return self.service.execute_transactional(
            actor_context, action=AuditAction.REVOKE_SOURCE,
            target_kind=TargetKind.SOURCE, target_logical_id=source_id,
            operation=lambda connection: self.registry.update_source_on(
                connection, source_id, enabled=False,
            ),
        )

    def approve_uvc(self, actor_context, adapter, source_id, candidate):
        """Approve through the adapter; its transaction-aware hook is required.

        Device discovery and candidate validation run after authorization and
        before the audited transaction, so no denied actor triggers a scan and
        no hardware I/O holds the database write lock.
        """
        approved = self.service.execute_transactional(
            actor_context, action=AuditAction.APPROVE_CAMERA,
            target_kind=TargetKind.CAMERA, target_logical_id=source_id,
            prepare=lambda: adapter.prepare_approval(source_id, candidate),
            operation=lambda connection, prepared: adapter.approve_source_on(
                connection, prepared,
            ),
        )
        adapter.accept_committed_approval(source_id, approved)
        return approved

    def approve_hardware_baseline(self, actor_context, baseline_id, approve_on,
                                  *, connection=None, reservation=None):
        """Commit a baseline mutation and its audit record in one transaction.

        The callback mutates its baseline on the supplied transaction. A store
        that owns the database connection passes it with its storage
        reservation so both writes share one admitted transaction.
        """
        if not callable(approve_on):
            raise TypeError("baseline approval operation is required")
        return self.service.execute_transactional(
            actor_context, action=AuditAction.APPROVE_HARDWARE_BASELINE,
            target_kind=TargetKind.HARDWARE_BASELINE,
            target_logical_id=baseline_id,
            connection=connection, reservation=reservation,
            operation=lambda active: approve_on(active, baseline_id),
        )

    def approve_integrity_baseline(self, actor_context, integrity_store, inventory, *,
                                   expected_revision, at):
        """Approve the Main Server hardware baseline through this boundary.

        The new baseline, the integrity store's own approval record and the
        `approve_hardware_baseline` security audit record commit together on
        the integrity store's connection, inside its storage admission.
        """
        return self.approve_hardware_baseline(
            actor_context, HARDWARE_BASELINE_ID,
            lambda connection, _target: integrity_store.approve_on(
                connection, inventory, expected_revision=expected_revision, at=at,
            ),
            connection=integrity_store.db,
            reservation=integrity_store.control_reservation,
        )

    def set_recording_starred(self, actor_context, recording_store,
                              recording_id, starred):
        return self.service.execute_transactional(
            actor_context, action=AuditAction.UPDATE_RECORDING,
            target_kind=TargetKind.RECORDING, target_logical_id=recording_id,
            connection=recording_store.db,
            reservation=recording_store.control_reservation,
            operation=lambda connection: recording_store.set_starred_on(
                connection, recording_id, starred,
            ),
        )

    def delete_recording(self, actor_context, recording_store, recording_id):
        """Commit Owner deletion journal and audit, then finish recoverable cleanup."""
        before = self.service.execute_transactional(
            actor_context, action=AuditAction.DELETE_RECORDING,
            target_kind=TargetKind.RECORDING, target_logical_id=recording_id,
            connection=recording_store.db,
            reservation=recording_store.control_reservation,
            operation=lambda connection: recording_store.prepare_delete_on(
                connection, recording_id, owner_requested=True,
            ),
        )
        try:
            return recording_store.finish_prepared_delete(recording_id, before)
        except Exception:
            # The deletion journal and its success audit are already durable.
            # Preserve that history and append the distinct cleanup failure;
            # never rewrite an existing security audit record.
            self.service.record_owner_post_commit_failure(
                action=AuditAction.DELETE_RECORDING_CLEANUP,
                target_kind=TargetKind.RECORDING,
                target_logical_id=recording_id,
            )
            raise


class AccessAdministration:
    """Owner-only human-access mutations with their security audit records.

    Each operation runs through ``OwnerAuditService.execute_transactional``:
    the Owner authorizer runs first, a refused actor gets a bounded ``denied``
    record and no mutation, and a permitted mutation commits in the same SQLite
    transaction as its ``succeeded`` record. Only the principal's application
    logical UUID reaches the audit log; external identities, display names,
    invitation secrets, credential identifiers and public keys never do.
    This class registers no route.

    ``session_gate`` must be stated. Wiring reached from a human route passes
    the ``HostnameReservationCheck``: issuing an enrollment authorization
    takes the gate epoch before Owner authorization and commits inside
    ``admit(epoch)`` before the write transaction opens, so it cannot land
    after a reservation check has closed access, even if access has reopened
    since, and so cannot rest on an Owner authorization that such a check
    revoked (Issue #144, PR #174 review); a closed gate is a failed operation
    with its ``failed`` record. ``None`` is only for a caller
    that no human route reaches.
    """

    def __init__(self, service, access_store, *, session_gate):
        if getattr(service.store, "database", None) != access_store.database:
            raise ValueError("access audit must share the access database")
        if session_gate is not None and not (callable(getattr(session_gate, "admit", None))
                                             and callable(getattr(session_gate, "epoch", None))):
            raise ValueError("session gate is invalid")
        self.service = service
        self.access = access_store
        self.session_gate = session_gate

    def _execute(self, actor_context, action, principal_id, operation, *, gated=False):
        reservation = None
        if gated and self.session_gate is not None:
            # The epoch is taken before authorization; the gate is entered
            # after it and held until the commit: gate lock before the SQLite
            # write lock (the check's lock order).
            reservation = partial(self.session_gate.admit, self.session_gate.epoch())
        return self.service.execute_transactional(
            actor_context, action=action, target_kind=TargetKind.PRINCIPAL,
            target_logical_id=principal_id,
            operation=lambda connection: operation(connection, self.access.now()),
            reservation=reservation,
        )

    def invite(self, actor_context, display_name, permissions):
        """Invite one person; the invitation, not a proxy login, identifies them."""
        target = uuid4()
        return self._execute(
            actor_context, AuditAction.INVITE_PRINCIPAL, target,
            lambda connection, at: self.access.invite_on(
                connection, target, display_name, permissions, at=at,
            ),
        )

    def issue_invitation(self, actor_context, principal_id, secret, expires_at):
        return self._execute(
            actor_context, AuditAction.ISSUE_PRINCIPAL_INVITATION, principal_id,
            lambda connection, at: self.access.issue_enrollment_on(
                connection, principal_id, secret, expires_at, at=at,
            ),
            gated=True,
        )

    def set_permissions(self, actor_context, principal_id, permissions):
        return self._execute(
            actor_context, AuditAction.CHANGE_PRINCIPAL_PERMISSIONS, principal_id,
            lambda connection, at: self.access.set_permissions_on(
                connection, principal_id, permissions, at=at,
            ),
        )

    def revoke_principal(self, actor_context, principal_id):
        return self._execute(
            actor_context, AuditAction.REVOKE_PRINCIPAL, principal_id,
            lambda connection, at: self.access.revoke_principal_on(
                connection, principal_id, at=at,
            ),
        )

    def revoke_credential(self, actor_context, principal_id, credential_id):
        return self._execute(
            actor_context, AuditAction.REVOKE_PRINCIPAL_CREDENTIAL, principal_id,
            lambda connection, at: self.access.revoke_credential_on(
                connection, principal_id, credential_id, at=at,
            ),
        )


class ReservationAdministration:
    """Owner-only change of the hostname-reservation listener exceptions.

    Validation runs after Owner authorization. The persisted set
    (``ListenerExceptionStore.write_on``) and the ``change_security_setting``
    audit record commit in one SQLite transaction; only after that commit is
    the set applied to the in-memory check, which immediately re-checks; the
    check's ``exception_change_lock`` serializes that whole sequence with
    every other change and with the check's own startup/daily/retry runs, so
    a verdict based on a superseded set is never published after the
    durable commit. A
    refused actor gets a bounded ``denied`` record and changes nothing; an
    invalid set or a failed write/append gets a ``failed`` record, rolls back,
    and changes nothing. This class registers no route.
    """

    def __init__(self, service, check):
        if not isinstance(check, HostnameReservationCheck):
            raise ValueError("reservation check is required")
        store = check.exception_store
        if not isinstance(store, ListenerExceptionStore) or \
                getattr(service.store, "database", None) != store.database:
            raise ValueError("listener exceptions must persist with their audit record")
        self.service = service
        self.check = check
        self.store = store

    def set_listener_exceptions(self, actor_context, exceptions):
        def persist(connection, staged):
            self.store.write_on(connection, staged.exceptions)
            return staged

        # One change at a time from stage to apply: otherwise an older, wider
        # set could be applied after a newer, narrower one had committed.
        with self.check.exception_change_lock:
            change = self.service.execute_transactional(
                actor_context, action=AuditAction.CHANGE_SECURITY_SETTING,
                target_kind=TargetKind.SECURITY_SETTINGS,
                target_logical_id=RESERVATION_LISTENER_EXCEPTIONS_ID,
                prepare=lambda: self.check.stage_listener_exceptions(exceptions),
                operation=persist,
            )
            return self.check.apply_audited_listener_exceptions(change)
