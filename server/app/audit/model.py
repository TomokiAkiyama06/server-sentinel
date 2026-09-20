"""Bounded security/admin audit vocabulary with no arbitrary payload field."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID


class AuditValidationError(ValueError):
    """An audit record was invalid; messages never include submitted values."""


class ActorCategory(StrEnum):
    OWNER = "owner"
    SYSTEM = "system"
    INVITED_USER = "invited_user"
    CAPTURE_NODE = "capture_node"
    UNAUTHENTICATED = "unauthenticated"


class AuditOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"


class TargetKind(StrEnum):
    HARDWARE_BASELINE = "hardware_baseline"
    SECURITY_SETTINGS = "security_settings"
    ADMIN_SETTINGS = "admin_settings"
    OWNER_BIOMETRIC = "owner_biometric"
    CAMERA = "camera"
    SOURCE = "source"
    CAPTURE_NODE = "capture_node"
    PRINCIPAL = "principal"
    RECORDING = "recording"


class AuditAction(StrEnum):
    APPROVE_HARDWARE_BASELINE = "approve_hardware_baseline"
    CHANGE_SECURITY_SETTING = "change_security_setting"
    CHANGE_ADMIN_SETTING = "change_admin_setting"
    ENROLL_OWNER_BIOMETRIC = "enroll_owner_biometric"
    REPLACE_OWNER_BIOMETRIC = "replace_owner_biometric"
    DELETE_OWNER_BIOMETRIC = "delete_owner_biometric"
    CREATE_CAMERA = "create_camera"
    UPDATE_CAMERA = "update_camera"
    APPROVE_CAMERA = "approve_camera"
    REVOKE_CAMERA = "revoke_camera"
    CREATE_SOURCE = "create_source"
    UPDATE_SOURCE = "update_source"
    REVOKE_SOURCE = "revoke_source"
    CREATE_CAPTURE_NODE = "create_capture_node"
    UPDATE_CAPTURE_NODE = "update_capture_node"
    REVOKE_CAPTURE_NODE = "revoke_capture_node"
    CHANGE_PRINCIPAL_PERMISSIONS = "change_principal_permissions"
    REVOKE_PRINCIPAL = "revoke_principal"
    DELETE_RECORDING = "delete_recording"
    UPDATE_RECORDING = "update_recording"


ACTION_TARGETS = {
    AuditAction.APPROVE_HARDWARE_BASELINE: TargetKind.HARDWARE_BASELINE,
    AuditAction.CHANGE_SECURITY_SETTING: TargetKind.SECURITY_SETTINGS,
    AuditAction.CHANGE_ADMIN_SETTING: TargetKind.ADMIN_SETTINGS,
    AuditAction.ENROLL_OWNER_BIOMETRIC: TargetKind.OWNER_BIOMETRIC,
    AuditAction.REPLACE_OWNER_BIOMETRIC: TargetKind.OWNER_BIOMETRIC,
    AuditAction.DELETE_OWNER_BIOMETRIC: TargetKind.OWNER_BIOMETRIC,
    AuditAction.CREATE_CAMERA: TargetKind.CAMERA,
    AuditAction.UPDATE_CAMERA: TargetKind.CAMERA,
    AuditAction.APPROVE_CAMERA: TargetKind.CAMERA,
    AuditAction.REVOKE_CAMERA: TargetKind.CAMERA,
    AuditAction.CREATE_SOURCE: TargetKind.SOURCE,
    AuditAction.UPDATE_SOURCE: TargetKind.SOURCE,
    AuditAction.REVOKE_SOURCE: TargetKind.SOURCE,
    AuditAction.CREATE_CAPTURE_NODE: TargetKind.CAPTURE_NODE,
    AuditAction.UPDATE_CAPTURE_NODE: TargetKind.CAPTURE_NODE,
    AuditAction.REVOKE_CAPTURE_NODE: TargetKind.CAPTURE_NODE,
    AuditAction.CHANGE_PRINCIPAL_PERMISSIONS: TargetKind.PRINCIPAL,
    AuditAction.REVOKE_PRINCIPAL: TargetKind.PRINCIPAL,
    AuditAction.DELETE_RECORDING: TargetKind.RECORDING,
    AuditAction.UPDATE_RECORDING: TargetKind.RECORDING,
}


def utc_timestamp(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise AuditValidationError("audit timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def validate_action_target(action: AuditAction, target_kind: TargetKind,
                           target_logical_id: UUID) -> None:
    if not isinstance(target_logical_id, UUID):
        raise AuditValidationError("audit target identity must be a logical UUID")
    if not isinstance(action, AuditAction) or not isinstance(target_kind, TargetKind):
        raise AuditValidationError("invalid audit action or target")
    if ACTION_TARGETS[action] is not target_kind:
        raise AuditValidationError("audit action and target do not match")


@dataclass(frozen=True)
class AuditRecord:
    id: UUID
    actor_category: ActorCategory
    action: AuditAction
    target_kind: TargetKind
    target_logical_id: UUID
    occurred_at: datetime
    outcome: AuditOutcome

    def __post_init__(self):
        if not isinstance(self.id, UUID):
            raise AuditValidationError("invalid audit record identity")
        if not isinstance(self.actor_category, ActorCategory):
            raise AuditValidationError("invalid actor category")
        validate_action_target(self.action, self.target_kind, self.target_logical_id)
        if not isinstance(self.outcome, AuditOutcome):
            raise AuditValidationError("invalid audit outcome")
        object.__setattr__(self, "occurred_at", utc_timestamp(self.occurred_at))
