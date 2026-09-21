"""Runtime integration for Owner-authorized administrative mutations."""

from uuid import UUID, uuid4

from app.cameras.registry import NodeHealthState
from .model import AuditAction, TargetKind


ACTIVE_SOURCE_LIMIT_ID = UUID("ed83d8b4-ec44-4e27-b197-8603c03d8fd2")
# The Main Server holds one approved hardware baseline; this fixed logical ID
# names it without exposing any hardware serial or device identifier.
HARDWARE_BASELINE_ID = UUID("6f5f5a2e-3f0e-4a3a-9a4c-2b0f1c7d5e41")


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
