"""Synthetic security/admin audit tests; no real people, devices, or secrets."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.audit import (
    ActorCategory, AuditAction, AuditOutcome, AuditStorageError, AuditStore,
    AuditValidationError,
    OwnerAuditService, OwnerAuthorizationError, TargetKind,
)
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry, NodeHealthState, SourceType
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


class SyntheticOwnerAuthorizer:
    def require_owner(self, actor_context):
        if actor_context != "synthetic-owner-session":
            category = (ActorCategory.INVITED_USER if isinstance(actor_context, dict)
                        else ActorCategory.UNAUTHENTICATED)
            raise OwnerAuthorizationError(category)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Database(Path(self.temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
            # These stand in for lifecycles owned by other subsystems.
            connection.execute("CREATE TABLE synthetic_timeline (id TEXT PRIMARY KEY)")
            connection.execute("CREATE TABLE synthetic_protected_incident (id TEXT PRIMARY KEY)")
            connection.execute("INSERT INTO synthetic_timeline VALUES ('timeline-kept')")
            connection.execute(
                "INSERT INTO synthetic_protected_incident VALUES ('incident-kept')"
            )
        self.now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        self.store = AuditStore(self.database, clock=lambda: self.now)
        self.service = OwnerAuditService(self.store, SyntheticOwnerAuthorizer())
        self.registry = CameraRegistry(self.database, clock=lambda: self.now)
        self.admin = OwnerAdministration(self.service, self.registry)

    def execute(self, *, action=AuditAction.APPROVE_HARDWARE_BASELINE,
                target_kind=TargetKind.HARDWARE_BASELINE, target_id=None,
                actor="synthetic-owner-session", operation=lambda: "done"):
        return self.service.execute_transactional(
            actor, action=action, target_kind=target_kind,
            target_logical_id=target_id or uuid4(),
            operation=lambda connection: operation(),
        )

    def test_owner_baseline_approval_records_bounded_success(self):
        target = uuid4()
        self.assertEqual("approved", self.execute(target_id=target, operation=lambda: "approved"))
        self.assertEqual(1, len(self.store.list_records()))
        record = self.store.list_records()[0]
        self.assertEqual(ActorCategory.OWNER, record.actor_category)
        self.assertEqual(AuditAction.APPROVE_HARDWARE_BASELINE, record.action)
        self.assertEqual(TargetKind.HARDWARE_BASELINE, record.target_kind)
        self.assertEqual(target, record.target_logical_id)
        self.assertEqual(self.now, record.occurred_at)
        self.assertEqual(AuditOutcome.SUCCEEDED, record.outcome)

    def test_owner_security_failure_is_recorded_without_exception_details(self):
        private_value = "synthetic-private-setting-value-never-store"

        def fail():
            raise RuntimeError(private_value)

        with self.assertRaisesRegex(RuntimeError, private_value):
            self.execute(
                action=AuditAction.CHANGE_SECURITY_SETTING,
                target_kind=TargetKind.SECURITY_SETTINGS, operation=fail,
            )
        record = self.store.list_records()[0]
        self.assertEqual(AuditOutcome.FAILED, record.outcome)
        self.assertEqual(ActorCategory.OWNER, record.actor_category)
        self.assertNotIn(private_value.encode(), self.database.path.read_bytes())

    def test_denied_owner_action_does_not_run_and_is_audited(self):
        calls = []
        with self.assertRaises(OwnerAuthorizationError):
            self.execute(actor={"synthetic_bearer_secret": "must-not-persist"},
                         operation=lambda: calls.append(True))
        self.assertEqual([], calls)
        record = self.store.list_records()[0]
        self.assertEqual(ActorCategory.INVITED_USER, record.actor_category)
        self.assertEqual(AuditOutcome.DENIED, record.outcome)
        self.assertNotIn(b"synthetic_bearer_secret", self.database.path.read_bytes())
        self.assertNotIn(b"must-not-persist", self.database.path.read_bytes())

    def test_camera_source_node_and_admin_actions_are_supported(self):
        cases = (
            (AuditAction.UPDATE_CAMERA, TargetKind.CAMERA),
            (AuditAction.REVOKE_SOURCE, TargetKind.SOURCE),
            (AuditAction.REVOKE_CAPTURE_NODE, TargetKind.CAPTURE_NODE),
            (AuditAction.CHANGE_ADMIN_SETTING, TargetKind.ADMIN_SETTINGS),
            (AuditAction.REPLACE_OWNER_BIOMETRIC, TargetKind.OWNER_BIOMETRIC),
            (AuditAction.CHANGE_PRINCIPAL_PERMISSIONS, TargetKind.PRINCIPAL),
        )
        for action, target in cases:
            self.execute(action=action, target_kind=target)
        self.assertEqual(
            {action for action, _ in cases},
            {record.action for record in self.store.list_records()},
        )

    def test_sensitive_values_have_no_storage_field_and_raw_identifier_is_rejected(self):
        with self.assertRaises(TypeError):
            self.store.append(
                actor_category=ActorCategory.OWNER,
                action=AuditAction.UPDATE_SOURCE,
                target_kind=TargetKind.SOURCE,
                target_logical_id=uuid4(),
                outcome=AuditOutcome.SUCCEEDED,
                details={"raw_serial": "synthetic-serial"},
            )
        with self.assertRaises(AuditValidationError):
            self.store.append(
                actor_category=ActorCategory.OWNER,
                action=AuditAction.UPDATE_SOURCE,
                target_kind=TargetKind.SOURCE,
                target_logical_id="synthetic-raw-device-serial",
                outcome=AuditOutcome.SUCCEEDED,
            )
        with self.assertRaises(AuditValidationError):
            self.execute(action=AuditAction.UPDATE_CAMERA, target_kind=TargetKind.CAPTURE_NODE)
        self.assertEqual((), self.store.list_records())

    def test_default_ninety_day_cleanup_only_deletes_expired_audit_rows(self):
        old_id, boundary_id, fresh_id = uuid4(), uuid4(), uuid4()
        self.now -= timedelta(days=90, microseconds=1)
        self.execute(target_id=old_id)
        self.now += timedelta(microseconds=1)
        self.execute(target_id=boundary_id)
        self.now += timedelta(days=90)
        self.execute(target_id=fresh_id)

        self.assertEqual(1, self.store.cleanup_expired())
        self.assertEqual(
            {fresh_id, boundary_id},
            {record.target_logical_id for record in self.store.list_records()},
        )
        with closing(self.database.connect()) as connection:
            self.assertEqual(1, connection.execute(
                "SELECT count(*) FROM synthetic_timeline"
            ).fetchone()[0])
            self.assertEqual(1, connection.execute(
                "SELECT count(*) FROM synthetic_protected_incident"
            ).fetchone()[0])

    def test_records_are_immutable_and_timeline_storage_is_separate(self):
        self.execute()
        with closing(self.database.connect()) as connection:
            names = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )}
            self.assertIn("security_admin_audit_records", names)
            self.assertIn("synthetic_timeline", names)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE security_admin_audit_records SET outcome = 'failed'"
                )

    def test_audit_migration_upgrades_existing_application_without_data_loss(self):
        other = Database(Path(self.temporary.name) / "upgrade.sqlite3")
        with closing(other.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS[:-1])
            connection.execute(
                "INSERT INTO application_metadata VALUES ('synthetic-kept', 'yes')"
            )
            migrate(connection, APPLICATION_MIGRATIONS)
            self.assertEqual("yes", connection.execute(
                "SELECT value FROM application_metadata WHERE key = 'synthetic-kept'"
            ).fetchone()[0])
            self.assertIsNotNone(connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name = 'security_admin_audit_records'"
            ).fetchone())

    def test_paging_and_retention_inputs_fail_closed(self):
        for limit in (0, -1, True, 1001, "10"):
            with self.subTest(limit=limit), self.assertRaises(AuditValidationError):
                self.store.list_records(limit=limit)
        for retention in (timedelta(0), timedelta(days=-1), 90, None):
            with self.subTest(retention=retention), self.assertRaises(AuditValidationError):
                AuditStore(self.database, retention=retention)

    def test_runtime_admin_integrates_node_source_success_and_failure(self):
        node = self.admin.create_capture_node("synthetic-owner-session", "Synthetic node")
        source = self.admin.create_source(
            "synthetic-owner-session", source_type=SourceType.REMOTE_AGENT,
            capture_node_id=node.id, name="Synthetic source", enabled=True,
        )
        self.admin.revoke_source("synthetic-owner-session", source.id)
        self.admin.revoke_capture_node("synthetic-owner-session", node.id)
        self.assertFalse(self.registry.get_source(source.id).enabled)
        self.assertEqual(NodeHealthState.REVOKED,
                         self.registry.get_capture_node(node.id).health_state)
        with self.assertRaises(Exception):
            self.admin.create_source(
                "synthetic-owner-session", source_type=SourceType.REMOTE_AGENT,
                capture_node_id=uuid4(), name="Missing node",
            )
        records = self.store.list_records()
        self.assertEqual(
            {AuditAction.CREATE_CAPTURE_NODE, AuditAction.CREATE_SOURCE,
             AuditAction.REVOKE_SOURCE, AuditAction.REVOKE_CAPTURE_NODE},
            {record.action for record in records if record.outcome is AuditOutcome.SUCCEEDED},
        )
        self.assertIn(AuditOutcome.FAILED, {record.outcome for record in records})

    def test_success_audit_failure_rolls_back_sensitive_mutation(self):
        with patch.object(self.store, "append_on",
                          side_effect=AuditStorageError("synthetic unavailable")):
            with self.assertRaises(AuditStorageError):
                self.admin.create_source(
                    "synthetic-owner-session", source_type=SourceType.LOCAL_UVC,
                    name="Must roll back", enabled=True,
                )
        self.assertEqual((), self.registry.list_sources())

    def test_plain_permission_denial_is_safely_classified_and_audited(self):
        private_value = "synthetic-private-denial-detail"

        class GenericDeny:
            def require_owner(self, actor_context):
                raise PermissionError(private_value)

        admin = OwnerAdministration(
            OwnerAuditService(self.store, GenericDeny()), self.registry,
        )
        with self.assertRaisesRegex(OwnerAuthorizationError, "owner authorization required"):
            admin.create_capture_node({"secret": private_value}, "Denied node")
        self.assertEqual((), self.registry.list_sources())
        record = self.store.list_records()[0]
        self.assertEqual(AuditOutcome.DENIED, record.outcome)
        self.assertEqual(ActorCategory.UNAUTHENTICATED, record.actor_category)
        self.assertNotIn(private_value.encode(), self.database.path.read_bytes())
