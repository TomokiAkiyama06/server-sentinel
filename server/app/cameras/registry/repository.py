"""Transactional configuration registry, deliberately without HTTP endpoints."""

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import json
import sqlite3
from typing import Callable
from uuid import UUID, uuid4

from app.storage.database import Database
from .models import (
    CameraSource, CaptureNode, CaptureProfile, DetectionBinding, DetectionKind,
    NodeHealthState, SourceHealthState, SourceType, ValidationError, json_object, positive_integer,
    text_value, timestamp,
)


class RegistryError(RuntimeError):
    """Storage operation failed, with no submitted values or paths disclosed."""


class NotFoundError(LookupError):
    """Requested source or node does not exist."""


class ActiveSourceLimitError(ValidationError):
    """Admission would exceed the configured active-source limit."""


_UNSET = object()


def _identity(value: UUID) -> str:
    if not isinstance(value, UUID):
        raise ValidationError("invalid registry identity")
    return str(value)


def _profile(value: CaptureProfile | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, CaptureProfile):
        raise ValidationError("invalid capture profile")
    return _json(asdict(CaptureProfile(**asdict(value))))


def _json(value) -> str:
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _bindings(values) -> tuple[DetectionBinding, ...]:
    if not isinstance(values, (tuple, list)) or len(values) > 256:
        raise ValidationError("invalid detection bindings")
    result = []
    ids = set()
    for value in values:
        if not isinstance(value, DetectionBinding) or value.binding_id in ids:
            raise ValidationError("invalid or duplicate detection binding")
        ids.add(value.binding_id)
        result.append(DetectionBinding(**asdict(value)))
    return tuple(result)


def _time(value: datetime | None) -> str | None:
    return None if value is None else timestamp(value).isoformat()


def _parsed_time(value: str | None) -> datetime | None:
    return None if value is None else timestamp(datetime.fromisoformat(value))


class CameraRegistry:
    """The database must have all application migrations applied before use.

    Each operation owns a fresh connection. Mutations serialize before reading
    admission state. Enabled sources reserve capacity even while offline; health
    never silently removes a source from the configured active collection.
    """

    def __init__(self, database: Database, *, clock: Callable[[], datetime] | None = None):
        self.database = database
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @contextmanager
    def _transaction(self, *, write=False):
        connection = None
        try:
            connection = self.database.connect()
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except sqlite3.Error:
            if connection is not None:
                connection.rollback()
            raise RegistryError("camera registry storage operation failed") from None
        except BaseException:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _limit(connection):
        row = connection.execute(
            "SELECT max_active_video_sources FROM camera_registry_settings WHERE id = 1"
        ).fetchone()
        if row is None:
            raise RegistryError("camera registry settings are unavailable")
        return row[0]

    @property
    def max_active_video_sources(self) -> int:
        with self._transaction() as connection:
            return self._limit(connection)

    def set_active_limit(self, limit: int) -> None:
        positive_integer(limit, "active source limit")
        with self._transaction(write=True) as connection:
            self.set_active_limit_on(connection, limit)

    # Transactional integration hooks. These are process-internal primitives
    # with no authorization of their own and no route exposure. A runtime
    # security/admin change must reach them only through the audited Owner
    # boundary (`app.audit.integration.OwnerAdministration`), which commits the
    # mutation together with its audit record; calling one directly would
    # change privileged configuration without that durable record.
    def set_active_limit_on(self, connection, limit: int) -> None:
        """Apply the limit on a caller-owned audited Owner transaction."""
        positive_integer(limit, "active source limit")
        active = connection.execute(
            "SELECT COUNT(*) FROM camera_sources WHERE enabled = 1"
        ).fetchone()[0]
        if active > limit:
            raise ActiveSourceLimitError("active sources exceed requested limit")
        connection.execute(
            "UPDATE camera_registry_settings SET max_active_video_sources = ? WHERE id = 1",
            (limit,),
        )

    def create_capture_node(self, name: str) -> CaptureNode:
        """Record an independent node identity; this does not pair or authorize it."""
        text_value(name, "node name")
        with self._transaction(write=True) as connection:
            return self.create_capture_node_on(connection, uuid4(), name)

    def create_capture_node_on(self, connection, node_id: UUID, name: str) -> CaptureNode:
        """Create a node on a caller-owned audited Owner transaction.

        The application logical ID is chosen by that boundary so the audit
        record and the created row identify the same target.
        """
        identity = _identity(node_id)
        text_value(name, "node name")
        now = _time(self._clock())
        connection.execute(
            "INSERT INTO capture_nodes VALUES (?, ?, 'offline', NULL, ?, ?)",
            (identity, name, now, now),
        )
        return self._node(connection, identity)

    @staticmethod
    def _node(connection, node_id: str) -> CaptureNode:
        row = connection.execute("SELECT * FROM capture_nodes WHERE id = ?", (node_id,)).fetchone()
        if row is None:
            raise NotFoundError("capture node does not exist")
        return CaptureNode(
            UUID(row["id"]), row["name"], NodeHealthState(row["health_state"]),
            _parsed_time(row["last_seen_at"]), _parsed_time(row["created_at"]),
            _parsed_time(row["updated_at"]),
        )

    def get_capture_node(self, node_id: UUID) -> CaptureNode:
        identity = _identity(node_id)
        with self._transaction() as connection:
            return self._node(connection, identity)

    def update_capture_node(self, node_id: UUID, *, name=_UNSET,
                            health_state=_UNSET, last_seen_at=_UNSET) -> CaptureNode:
        with self._transaction(write=True) as connection:
            return self.update_capture_node_on(
                connection, node_id, name=name, health_state=health_state,
                last_seen_at=last_seen_at,
            )

    def update_capture_node_on(self, connection, node_id: UUID, *, name=_UNSET,
                               health_state=_UNSET, last_seen_at=_UNSET) -> CaptureNode:
        """Update a node on a caller-owned audited Owner transaction."""
        identity = _identity(node_id)
        old = self._node(connection, identity)
        name = old.name if name is _UNSET else text_value(name, "node name")
        health = old.health_state if health_state is _UNSET else health_state
        if not isinstance(health, NodeHealthState):
            raise ValidationError("invalid node health")
        seen = old.last_seen_at if last_seen_at is _UNSET else last_seen_at
        connection.execute(
            "UPDATE capture_nodes SET name = ?, health_state = ?, last_seen_at = ?, "
            "updated_at = ? WHERE id = ?",
            (name, health.value, _time(seen), _time(self._clock()), identity),
        )
        return self._node(connection, identity)

    @staticmethod
    def _admit(connection, limit: int):
        active = connection.execute(
            "SELECT COUNT(*) FROM camera_sources WHERE enabled = 1"
        ).fetchone()[0]
        if active >= limit:
            raise ActiveSourceLimitError("active source limit would be exceeded")

    @staticmethod
    def _config(name, role, enabled, capabilities, desired, bindings):
        text_value(name, "source name")
        if role is not None:
            text_value(role, "role label")
        if type(enabled) is not bool:
            raise ValidationError("invalid source enabled state")
        return (_json(json_object(capabilities)), _profile(desired), _bindings(bindings))

    @staticmethod
    def _write_bindings(connection, identity, bindings):
        connection.execute("DELETE FROM detection_bindings WHERE source_id = ?", (identity,))
        connection.executemany(
            "INSERT INTO detection_bindings VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(identity, str(binding.binding_id), binding.kind.value, binding.version,
              int(binding.enabled), _json(binding.thresholds), _json(binding.config))
             for binding in bindings],
        )

    def create_source(self, *, source_type: SourceType, name: str,
                      capture_node_id: UUID | None = None, role_label: str | None = None,
                      enabled: bool = False, capabilities: dict | None = None,
                      desired_capture_profile: CaptureProfile | None = None,
                      detection_bindings: tuple[DetectionBinding, ...] = ()) -> CameraSource:
        with self._transaction(write=True) as connection:
            return self.create_source_on(
                connection, uuid4(), source_type=source_type, name=name,
                capture_node_id=capture_node_id, role_label=role_label, enabled=enabled,
                capabilities=capabilities, desired_capture_profile=desired_capture_profile,
                detection_bindings=detection_bindings,
            )

    def create_source_on(self, connection, source_id: UUID, *, source_type: SourceType,
                         name: str, capture_node_id: UUID | None = None,
                         role_label: str | None = None, enabled: bool = False,
                         capabilities: dict | None = None,
                         desired_capture_profile: CaptureProfile | None = None,
                         detection_bindings: tuple[DetectionBinding, ...] = ()) -> CameraSource:
        """Create a source on a caller-owned audited Owner transaction."""
        identity = _identity(source_id)
        if not isinstance(source_type, SourceType):
            raise ValidationError("invalid source type")
        if ((source_type is SourceType.LOCAL_UVC and capture_node_id is not None)
                or (source_type is SourceType.REMOTE_AGENT and capture_node_id is None)):
            raise ValidationError("source type and capture node relationship is invalid")
        node_id = None if capture_node_id is None else _identity(capture_node_id)
        caps, desired, bindings = self._config(
            name, role_label, enabled, {} if capabilities is None else capabilities,
            desired_capture_profile, detection_bindings,
        )
        now = _time(self._clock())
        if node_id is not None:
            self._node(connection, node_id)
        if enabled:
            self._admit(connection, self._limit(connection))
        connection.execute(
            "INSERT INTO camera_sources VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, NULL, 'offline', 'unknown', NULL, ?, ?)",
            (identity, node_id, source_type.value, name, role_label, int(enabled),
             caps, desired, now, now),
        )
        self._write_bindings(connection, identity, bindings)
        return self._source(connection, identity)

    @staticmethod
    def _source(connection, identity) -> CameraSource:
        row = connection.execute("SELECT * FROM camera_sources WHERE id = ?", (identity,)).fetchone()
        if row is None:
            raise NotFoundError("camera source does not exist")
        bindings = tuple(DetectionBinding(
            UUID(binding["binding_id"]), DetectionKind(binding["kind"]), binding["version"],
            bool(binding["enabled"]), json.loads(binding["thresholds"]), json.loads(binding["config"]),
        ) for binding in connection.execute(
            "SELECT * FROM detection_bindings WHERE source_id = ? ORDER BY binding_id", (identity,)
        ))
        desired = row["desired_capture_profile"]
        negotiated = row["negotiated_capture_profile"]
        return CameraSource(
            UUID(row["id"]), UUID(row["capture_node_id"]) if row["capture_node_id"] else None,
            SourceType(row["source_type"]), row["name"], row["role_label"], bool(row["enabled"]),
            json.loads(row["capabilities"]), CaptureProfile(**json.loads(desired)) if desired else None,
            CaptureProfile(**json.loads(negotiated)) if negotiated else None,
            SourceHealthState(row["health_state"]), row["image_quality_state"],
            _parsed_time(row["last_seen_at"]), _parsed_time(row["created_at"]),
            _parsed_time(row["updated_at"]), bindings,
        )

    def get_source(self, source_id: UUID) -> CameraSource:
        identity = _identity(source_id)
        with self._transaction() as connection:
            return self._source(connection, identity)

    def list_sources(self) -> tuple[CameraSource, ...]:
        with self._transaction() as connection:
            identities = connection.execute("SELECT id FROM camera_sources ORDER BY created_at, id")
            return tuple(self._source(connection, row[0]) for row in identities.fetchall())

    def update_source(self, source_id: UUID, *, name=_UNSET, role_label=_UNSET,
                      enabled=_UNSET, capabilities=_UNSET, desired_capture_profile=_UNSET,
                      detection_bindings=_UNSET) -> CameraSource:
        """Update metadata/configuration without changing source or node identities."""
        with self._transaction(write=True) as connection:
            return self.update_source_on(
                connection, source_id, name=name, role_label=role_label, enabled=enabled,
                capabilities=capabilities, desired_capture_profile=desired_capture_profile,
                detection_bindings=detection_bindings,
            )

    def update_source_on(self, connection, source_id: UUID, *, name=_UNSET,
                         role_label=_UNSET, enabled=_UNSET, capabilities=_UNSET,
                         desired_capture_profile=_UNSET,
                         detection_bindings=_UNSET) -> CameraSource:
        """Update a source on a caller-owned audited Owner transaction."""
        identity = _identity(source_id)
        old = self._source(connection, identity)
        name = old.name if name is _UNSET else name
        role = old.role_label if role_label is _UNSET else role_label
        active = old.enabled if enabled is _UNSET else enabled
        caps = old.capabilities if capabilities is _UNSET else capabilities
        desired = (old.desired_capture_profile if desired_capture_profile is _UNSET
                   else desired_capture_profile)
        bindings = old.detection_bindings if detection_bindings is _UNSET else detection_bindings
        caps, desired, bindings = self._config(name, role, active, caps, desired, bindings)
        if active and not old.enabled:
            self._admit(connection, self._limit(connection))
        connection.execute(
            "UPDATE camera_sources SET name = ?, role_label = ?, enabled = ?, capabilities = ?, "
            "desired_capture_profile = ?, updated_at = ? WHERE id = ?",
            (name, role, int(active), caps, desired, _time(self._clock()), identity),
        )
        self._write_bindings(connection, identity, bindings)
        return self._source(connection, identity)

    def update_source_health(self, source_id: UUID, *, health_state: SourceHealthState,
                             negotiated_capture_profile=_UNSET, image_quality_state=_UNSET,
                             last_seen_at=_UNSET) -> CameraSource:
        """Persist adapter observations, independently of node liveness.

        This method performs no identity matching or automatic reconnect. The
        UVC adapter must obtain owner re-approval before resolving ambiguity.
        Quality is descriptive; unknown quality never means a negative detection.
        """
        identity = _identity(source_id)
        if not isinstance(health_state, SourceHealthState):
            raise ValidationError("invalid source health")
        with self._transaction(write=True) as connection:
            old = self._source(connection, identity)
            negotiated = (old.negotiated_capture_profile if negotiated_capture_profile is _UNSET
                          else negotiated_capture_profile)
            quality = (old.image_quality_state if image_quality_state is _UNSET
                       else text_value(image_quality_state, "image quality state", 64))
            seen = old.last_seen_at if last_seen_at is _UNSET else last_seen_at
            connection.execute(
                "UPDATE camera_sources SET health_state = ?, negotiated_capture_profile = ?, "
                "image_quality_state = ?, last_seen_at = ?, updated_at = ? WHERE id = ?",
                (health_state.value, _profile(negotiated), quality, _time(seen),
                 _time(self._clock()), identity),
            )
            return self._source(connection, identity)
