"""Human-access domain values without HTTP, headers, cookies, or WebAuthn parsing."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID


class AccessValidationError(ValueError):
    pass


class PrincipalRole(str, Enum):
    OWNER = "owner"
    INVITED_USER = "invited_user"


class PrincipalStatus(str, Enum):
    INVITED = "invited"
    ACTIVE = "active"
    REVOKED = "revoked"


class Permission(str, Enum):
    LIVE_VIEW = "live:view"
    RECORDINGS_VIEW = "recordings:view"


def utc_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AccessValidationError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class Principal:
    id: UUID
    external_identity: str
    display_name: str
    role: PrincipalRole
    status: PrincipalStatus
    authorization_revision: int
    created_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self):
        if not isinstance(self.id, UUID):
            raise AccessValidationError("principal identity is invalid")
        if not isinstance(self.external_identity, str) or not self.external_identity:
            raise AccessValidationError("external identity is invalid")
        if not isinstance(self.display_name, str) or not self.display_name:
            raise AccessValidationError("display name is invalid")
        if type(self.authorization_revision) is not int or self.authorization_revision < 0:
            raise AccessValidationError("authorization revision is invalid")
        object.__setattr__(self, "created_at", utc_time(self.created_at))
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", utc_time(self.revoked_at))


@dataclass(frozen=True)
class Credential:
    credential_id: bytes
    principal_id: UUID
    public_key: bytes
    algorithm: int
    sign_count: int
    enrolled_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self):
        if not isinstance(self.credential_id, bytes) or not 1 <= len(self.credential_id) <= 1024:
            raise AccessValidationError("credential identifier is invalid")
        if not isinstance(self.principal_id, UUID) or not isinstance(self.public_key, bytes) or not 1 <= len(self.public_key) <= 8192:
            raise AccessValidationError("credential is invalid")
        if type(self.algorithm) is not int or type(self.sign_count) is not int or self.sign_count < 0:
            raise AccessValidationError("credential metadata is invalid")
        object.__setattr__(self, "enrolled_at", utc_time(self.enrolled_at))
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", utc_time(self.revoked_at))
