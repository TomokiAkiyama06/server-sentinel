"""Runtime integration for Owner-authorized administrative mutations."""

from datetime import datetime
from typing import Callable
from uuid import UUID, uuid4

from app.auth.invitation_code import new_invitation_code
from app.auth.model import AccessValidationError
from app.auth.owner_operation import OwnerOperationContext
from app.auth.reservation import HostnameReservationCheck
from app.auth.reservation_store import ListenerExceptionStore
from app.auth.serving_gate import ServingGate
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
    transaction as its ``succeeded`` record(s). Only the principal's
    application logical UUID reaches the audit log; external identities,
    display names, invitation codes, credential identifiers or handles and
    public keys never do. This class registers no route.

    ``session_gate`` must be the human composition's ``ServingGate``
    (``HumanAccess.gate``; Issue #181, Issue #232 item 1): anything else, a
    raw ``HostnameReservationCheck`` included, is refused at construction,
    because only the ``ServingGate`` also refuses a commit after
    ``HumanAccess.stop()`` or a failed check tick (Issue #228 item 1).

    Every method takes the ``epoch`` the request's ``OWNER_OP``
    authorization was made under (``_Authorized.epoch``), never a fresh one,
    and commits inside ``admit(epoch)`` before the write transaction opens
    (lock order: gate -> storage admission -> SQLite). A close, reopen,
    ``stop()`` or failed tick since that authorization is a failed operation
    with its ``failed`` record and changes nothing (Issue #144, D6). The
    actor context must be the ``OwnerOperationContext`` of that same
    authorization (same epoch), and inside the mutation's transaction its
    session is read again (``AccessStore.require_owner_session_on``): a local
    ``recover`` or revocation that committed outside the gate in between, an
    expired session or a verification no longer fresh (``StepUpRequired``)
    is a failed operation that changes nothing. Every time the mutation
    depends on (an invitation's expiry included) is read inside that
    transaction. While human access is closed, an emergency revocation is
    done over SSH with the local command instead (D6).

    Owner decisions applied (S4, 2026-10-13): the Owner principal is never a
    target (S4-3); grants change as a delta and only a real change ends the
    principal's sessions, its pending code staying valid (S4-5); a principal
    has at most one pending code and re-issuing revokes the others, for an
    invited or an active principal (S4-4, S4-8); at most ``MAX_PRINCIPALS``
    principals are not revoked (S4-8).
    """

    def __init__(self, service, access_store, *, session_gate, new_code=new_invitation_code):
        if getattr(service.store, "database", None) != access_store.database:
            raise ValueError("access audit must share the access database")
        if not isinstance(session_gate, ServingGate):
            # Issue #181 / #232 item 1: ``None``, a raw reservation check or
            # any other gate would let an Owner mutation commit after
            # ``HumanAccess.stop()``.
            raise ValueError("session gate is invalid")
        if not callable(new_code):
            raise ValueError("invitation code source is invalid")
        self.service = service
        self.access = access_store
        self.session_gate = session_gate
        self._new_code = new_code
        # Optional observer of committed grant/revocation changes (the S7
        # interim live service re-checks or ends that principal's live
        # sessions at once). Called after the commit, best effort: it can
        # neither refuse nor undo the committed change.
        self.principal_changed: Callable[[UUID], None] | None = None

    def _changed(self, principal_id, result):
        observer = self.principal_changed
        if observer is not None:
            try:
                observer(principal_id)
            except Exception:
                pass
        return result

    def _execute(self, actor_context, action, principal_id, operation, *, epoch, followed_by=()):
        def run(connection):
            # Read inside the transaction, after the gate, the storage
            # admission and BEGIN IMMEDIATE (PR #234 rule).
            at = self.access.now()
            if (not isinstance(actor_context, OwnerOperationContext) or isinstance(epoch, bool)
                    or not isinstance(epoch, int) or actor_context.epoch != epoch):
                raise AccessValidationError("access is unavailable")
            self.access.require_owner_session_on(connection, actor_context.session, at)
            return operation(connection, at)

        return self.service.execute_transactional(
            actor_context, action=action, target_kind=TargetKind.PRINCIPAL,
            target_logical_id=principal_id, operation=run,
            reservation=lambda: self.session_gate.admit(epoch),
            followed_by=followed_by,
        )

    @staticmethod
    def _expiry(value):
        """An invitation expiry checked inside the mutation's transaction.

        The human A2/A3 routes format it into their response after the
        commit (PR #242 review): an expiry that is not an aware ``datetime``
        is refused here, before the commit, so that formatting cannot fail
        and no refusal is ever returned for a change that was committed.
        """
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise AccessValidationError("invitation is unavailable")
        return value

    def _code(self) -> tuple[bytes, str]:
        secret, code = self._new_code()
        if not isinstance(secret, bytes) or not isinstance(code, str):
            raise AccessValidationError("invitation is unavailable")
        return secret, code

    def invite(self, actor_context, display_name, permissions, *, epoch):
        """Invite one person with their grants and one code; ``(principal id, code, expiry)``.

        The principal, its grants and its invitation commit in one
        transaction with the ``invite_principal`` and
        ``issue_principal_invitation`` records
        (``AccessStore.invite_with_invitation_on``). The code is returned for
        the Owner to hand over once; only its digest and lookup key are stored.
        """
        target = uuid4()
        secret, code = self._code()
        expires_at = self._execute(
            actor_context, AuditAction.INVITE_PRINCIPAL, target,
            lambda connection, at: self._expiry(self.access.invite_with_invitation_on(
                connection, target, display_name, permissions, secret, at=at,
            )),
            epoch=epoch, followed_by=(AuditAction.ISSUE_PRINCIPAL_INVITATION,),
        )
        return target, code, expires_at

    def reissue_invitation(self, actor_context, principal_id, *, epoch):
        """Revoke the principal's unused codes and issue one new code; ``(code, expiry)``."""
        secret, code = self._code()
        expires_at = self._execute(
            actor_context, AuditAction.ISSUE_PRINCIPAL_INVITATION, principal_id,
            lambda connection, at: self._expiry(self.access.reissue_invitation_on(
                connection, principal_id, secret, at=at,
            )),
            epoch=epoch,
        )
        return code, expires_at

    def set_permissions(self, actor_context, principal_id, permissions, *, epoch):
        """Set the grants; ``True`` when they changed (a no-op ends no session)."""
        return self._changed(principal_id, self._execute(
            actor_context, AuditAction.CHANGE_PRINCIPAL_PERMISSIONS, principal_id,
            lambda connection, at: self.access.set_permissions_on(
                connection, principal_id, permissions, at=at,
            ),
            epoch=epoch,
        ))

    def change_permission(self, actor_context, principal_id, permission, granted, *, epoch):
        """Grant or withdraw one permission as a delta; ``True`` when the grants changed.

        A request that changes nothing still commits its one ``succeeded``
        record, read as "requested, no change" (Issue #240 item 4).
        """
        return self._changed(principal_id, self._execute(
            actor_context, AuditAction.CHANGE_PRINCIPAL_PERMISSIONS, principal_id,
            lambda connection, at: self.access.change_permission_on(
                connection, principal_id, permission, granted, at=at,
            ),
            epoch=epoch,
        ))

    def revoke_principal(self, actor_context, principal_id, *, epoch):
        return self._changed(principal_id, self._execute(
            actor_context, AuditAction.REVOKE_PRINCIPAL, principal_id,
            lambda connection, at: self.access.revoke_principal_on(
                connection, principal_id, at=at,
            ),
            epoch=epoch,
        ))

    def revoke_credential(self, actor_context, principal_id, handle, *, epoch):
        """Credential-scoped, by handle: a synced passkey is revoked on every device it exists on."""
        return self._changed(principal_id, self._execute(
            actor_context, AuditAction.REVOKE_PRINCIPAL_CREDENTIAL, principal_id,
            lambda connection, at: self.access.revoke_credential_on(
                connection, principal_id, handle, at=at,
            ),
            epoch=epoch,
        ))


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
