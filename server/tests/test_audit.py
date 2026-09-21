"""Synthetic security/admin audit tests; no real people, devices, or secrets."""

from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.audit import (
    ActorCategory, AuditAction, AuditCursor, AuditOutcome, AuditStorageError, AuditStore,
    AuditValidationError,
    OwnerAuditService, OwnerAuthorizationError, TargetKind,
)
from app.audit.integration import OwnerAdministration
from app.cameras.registry import (
    CameraRegistry, NodeHealthState, SourceHealthState, SourceType, UnauditedWriteError,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


class SyntheticStorageDenied(RuntimeError):
    """Stands in for the Main Server storage hard-stop/pressure refusal."""


class SyntheticReservation:
    """Stands in for the deployment storage admission reservation."""

    def __init__(self):
        self.denial = None
        self.acquired = 0
        self.active = False

    @contextmanager
    def __call__(self):
        if self.denial is not None:
            raise SyntheticStorageDenied(self.denial)
        if self.active:
            raise AssertionError("overlapping reservation")
        self.acquired += 1
        self.active = True
        try:
            yield
        finally:
            self.active = False


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
            migrate(connection, APPLICATION_MIGRATIONS[:-2])
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

    def test_compound_cursor_does_not_skip_equal_timestamp_records(self):
        targets = [uuid4() for _ in range(7)]
        for target in targets:
            self.execute(target_id=target)
        seen = []
        cursor = None
        while True:
            page = self.store.list_records(limit=2, before=cursor)
            if not page:
                break
            seen.extend(record.id for record in page)
            cursor = AuditCursor.after(page[-1])
        self.assertEqual(7, len(seen))
        self.assertEqual(7, len(set(seen)))
        with self.assertRaises(AuditValidationError):
            self.store.list_records(before=self.now)

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

    def reserved_store(self, reservation, **kwargs):
        return AuditStore(self.database, clock=lambda: self.now,
                          reservation=reservation, **kwargs)

    def expired_rows(self, count, store=None):
        store = store or self.store
        for _ in range(count):
            store.append(
                actor_category=ActorCategory.SYSTEM,
                action=AuditAction.CHANGE_ADMIN_SETTING,
                target_kind=TargetKind.ADMIN_SETTINGS,
                target_logical_id=uuid4(), outcome=AuditOutcome.SUCCEEDED,
            )

    def remaining(self, table="security_admin_audit_records"):
        with closing(self.database.connect()) as connection:
            return connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]

    def test_retention_cleanup_runs_bounded_admitted_batches_and_is_idempotent(self):
        reservation = SyntheticReservation()
        store = self.reserved_store(reservation, cleanup_batch_size=2)
        self.now -= timedelta(days=91)
        self.expired_rows(7, store)
        self.now += timedelta(days=91)
        self.expired_rows(1, store)
        reservation.acquired = 0

        self.assertEqual(7, store.cleanup_expired())
        # Seven expired rows drain as bounded two-row transactions, and every
        # delete transaction holds the storage reservation.
        self.assertEqual(4, reservation.acquired)
        self.assertFalse(reservation.active)
        self.assertEqual(1, self.remaining())
        self.assertEqual(0, store.cleanup_expired())
        self.assertEqual(1, self.remaining())

    def test_retention_also_expires_integrity_approval_audit_only(self):
        store = self.reserved_store(SyntheticReservation(), cleanup_batch_size=2)
        old = (self.now - timedelta(days=90, microseconds=1)).isoformat()
        boundary = (self.now - timedelta(days=90)).isoformat()
        with closing(self.database.connect()) as connection:
            connection.execute(
                "INSERT INTO integrity_baseline VALUES(1,1,'synthetic-baseline')"
            )
            connection.execute(
                "INSERT INTO integrity_audit(at,actor,revision) VALUES(?,?,?)",
                (old, str(uuid4()), 1),
            )
            connection.execute(
                "INSERT INTO integrity_audit(at,actor,revision) VALUES(?,?,?)",
                (boundary, str(uuid4()), 1),
            )
        self.assertEqual(1, store.cleanup_expired())
        with closing(self.database.connect()) as connection:
            rows = connection.execute(
                "SELECT at FROM integrity_audit ORDER BY at"
            ).fetchall()
            self.assertEqual([boundary], [row["at"] for row in rows])
            self.assertEqual(1, connection.execute(
                "SELECT revision FROM integrity_baseline WHERE singleton=1"
            ).fetchone()[0])

    def test_interrupted_cleanup_keeps_committed_batches_and_unexpired_rows(self):
        store = self.reserved_store(SyntheticReservation(), cleanup_batch_size=2)
        self.now -= timedelta(days=91)
        self.expired_rows(5, store)
        self.now += timedelta(days=91)
        self.expired_rows(2, store)
        original = store.transaction
        attempts = []

        def interrupt(*args, **kwargs):
            attempts.append(True)
            if len(attempts) == 2:
                raise AuditStorageError("synthetic interruption")
            return original(*args, **kwargs)

        with patch.object(store, "transaction", side_effect=interrupt):
            with self.assertRaises(AuditStorageError):
                store.cleanup_expired()
        self.assertEqual(5, self.remaining())

        self.assertEqual(3, store.cleanup_expired())
        self.assertEqual(2, self.remaining())
        self.assertEqual(0, store.cleanup_expired())

    def test_audit_writes_are_refused_instead_of_spending_the_hard_reserve(self):
        reservation = SyntheticReservation()
        store = self.reserved_store(reservation)
        self.expired_rows(1, store)
        reservation.denial = "STORAGE_HARD_STOP"
        with self.assertRaises(SyntheticStorageDenied):
            self.expired_rows(1, store)
        with self.assertRaises(SyntheticStorageDenied):
            store.cleanup_expired()
        self.assertEqual(1, self.remaining())
        # Owner reading remains available while writes are refused.
        self.assertEqual(1, len(store.list_records()))

    def test_registry_mutation_audit_is_admitted_by_storage_reservation(self):
        reservation = SyntheticReservation()
        service = OwnerAuditService(self.reserved_store(reservation),
                                    SyntheticOwnerAuthorizer())
        admin = OwnerAdministration(service, self.registry)
        admin.create_capture_node("synthetic-owner-session", "Synthetic node")
        self.assertEqual(1, reservation.acquired)
        self.assertFalse(reservation.active)

        reservation.denial = "STORAGE_HARD_STOP"
        with self.assertRaises(SyntheticStorageDenied):
            admin.create_capture_node("synthetic-owner-session", "Refused node")
        # Neither the mutation nor any unadmitted audit row was written, and
        # the undelivered outcome stays visible as bounded health.
        self.assertEqual(1, self.remaining())
        self.assertEqual(1, self.remaining("capture_nodes"))
        self.assertTrue(service.audit_delivery_failed)
        self.assertEqual(1, service.undelivered_audit_records)

    def test_denied_action_audit_is_admitted_and_never_silently_dropped(self):
        reservation = SyntheticReservation()
        service = OwnerAuditService(self.reserved_store(reservation),
                                    SyntheticOwnerAuthorizer())
        admin = OwnerAdministration(service, self.registry)
        with self.assertRaises(OwnerAuthorizationError):
            admin.create_capture_node({"synthetic": "not-owner"}, "Denied node")
        self.assertEqual(1, reservation.acquired)
        self.assertEqual(AuditOutcome.DENIED, service.store.list_records()[0].outcome)
        self.assertFalse(service.audit_delivery_failed)

        reservation.denial = "STORAGE_HARD_STOP"
        # A refused denial record still denies: the caller never receives a
        # storage error that discloses deployment state or invites a retry.
        with self.assertRaises(OwnerAuthorizationError):
            admin.create_capture_node({"synthetic": "not-owner"}, "Denied node")
        self.assertEqual(1, self.remaining())
        self.assertEqual(0, self.remaining("capture_nodes"))
        self.assertTrue(service.audit_delivery_failed)
        self.assertEqual(1, service.undelivered_audit_records)

    def test_invalid_storage_reservation_and_batch_inputs_fail_closed(self):
        for reservation in ("reservation", 5):
            with self.subTest(reservation=reservation):
                with self.assertRaises(AuditValidationError):
                    AuditStore(self.database, reservation=reservation)
        for batch in (0, -1, True, 1001, "10"):
            with self.subTest(batch=batch), self.assertRaises(AuditValidationError):
                AuditStore(self.database, cleanup_batch_size=batch)
        with self.assertRaises(AuditValidationError):
            self.service.execute_transactional(
                "synthetic-owner-session", action=AuditAction.CHANGE_ADMIN_SETTING,
                target_kind=TargetKind.ADMIN_SETTINGS, target_logical_id=uuid4(),
                operation=lambda connection: None, reservation="reservation",
            )

    def test_audit_reading_requires_owner_authorization(self):
        target = uuid4()
        self.execute(target_id=target)
        records = self.admin.list_audit_records("synthetic-owner-session")
        self.assertEqual([target], [record.target_logical_id for record in records])

        for actor in ({"invited": "recordings:view"}, "synthetic-capture-node", None):
            with self.subTest(actor=actor):
                with self.assertRaises(OwnerAuthorizationError):
                    self.admin.list_audit_records(actor)
                with self.assertRaises(OwnerAuthorizationError):
                    self.service.list_records(actor, limit=1)
        # A refused read never records a row, so it cannot grow the table.
        self.assertEqual(1, self.remaining())
        self.assertEqual(
            1, len(self.admin.list_audit_records("synthetic-owner-session", limit=1)),
        )

        private_value = "synthetic-private-read-denial-detail"

        class GenericDeny:
            def require_owner(self, actor_context):
                raise PermissionError(private_value)

        denied = OwnerAdministration(
            OwnerAuditService(self.store, GenericDeny()), self.registry,
        )
        # A denied reader receives the same bounded denial, never the injected
        # authorizer's message, which may carry identity.
        with self.assertRaisesRegex(OwnerAuthorizationError,
                                    "^owner authorization required$") as denial:
            denied.list_audit_records({"secret": private_value})
        self.assertEqual(ActorCategory.UNAUTHENTICATED, denial.exception.actor_category)
        self.assertNotIn(private_value, str(denial.exception))

    def test_post_commit_failure_record_never_masks_the_original_failure(self):
        reservation = SyntheticReservation()
        service = OwnerAuditService(self.reserved_store(reservation),
                                    SyntheticOwnerAuthorizer())
        reservation.denial = "STORAGE_HARD_STOP"
        self.assertIsNone(service.record_owner_post_commit_failure(
            action=AuditAction.DELETE_RECORDING_CLEANUP,
            target_kind=TargetKind.RECORDING, target_logical_id=uuid4(),
        ))
        self.assertTrue(service.audit_delivery_failed)
        self.assertEqual(1, service.undelivered_audit_records)
        self.assertEqual(0, self.remaining())
        with self.assertRaises(AuditValidationError):
            service.record_owner_post_commit_failure(
                action=AuditAction.DELETE_RECORDING_CLEANUP,
                target_kind=TargetKind.SOURCE, target_logical_id=uuid4(),
            )

    def test_audit_transactions_close_with_python_sqlite_autocommit(self):
        class AutocommitDatabase:
            """A deployment connection factory running in autocommit mode."""

            def __init__(self, database):
                self.database = database

            def connect(self):
                connection = self.database.connect()
                if not hasattr(connection, "autocommit"):
                    connection.close()
                    raise unittest.SkipTest("Python sqlite3 has no autocommit mode")
                connection.autocommit = True
                return connection

        store = AuditStore(AutocommitDatabase(self.database), clock=lambda: self.now)
        store.append(
            actor_category=ActorCategory.OWNER,
            action=AuditAction.CHANGE_SECURITY_SETTING,
            target_kind=TargetKind.SECURITY_SETTINGS,
            target_logical_id=uuid4(), outcome=AuditOutcome.SUCCEEDED,
        )
        # A no-op Connection.commit() would discard the record when its
        # connection closed; the row must be durable for other readers.
        self.assertEqual(1, self.remaining())
        self.now += timedelta(days=91)
        self.assertEqual(1, store.cleanup_expired())
        self.assertEqual(0, self.remaining())

    def test_privileged_registry_writes_require_the_audited_boundary(self):
        runtime = CameraRegistry(self.database, clock=lambda: self.now)
        node = self.admin.create_capture_node("synthetic-owner-session", "Synthetic node")
        source = self.admin.create_source(
            "synthetic-owner-session", source_type=SourceType.REMOTE_AGENT,
            capture_node_id=node.id, name="Synthetic source", enabled=True,
        )
        for operation in (
            lambda: runtime.set_active_limit(2),
            lambda: runtime.create_capture_node("Bypass node"),
            lambda: runtime.update_capture_node(node.id, name="Bypass"),
            lambda: runtime.create_source(source_type=SourceType.LOCAL_UVC, name="Bypass"),
            lambda: runtime.update_source(source.id, name="Bypass"),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(UnauditedWriteError):
                    operation()
        # No privileged change happened outside the audited boundary.
        self.assertEqual(4, runtime.max_active_video_sources)
        self.assertEqual("Synthetic node", runtime.get_capture_node(node.id).name)
        self.assertEqual((source.id,), tuple(row.id for row in runtime.list_sources()))
        self.assertEqual("Synthetic source", runtime.get_source(source.id).name)
        self.assertEqual(
            {AuditAction.CREATE_CAPTURE_NODE, AuditAction.CREATE_SOURCE},
            {record.action for record in self.store.list_records()},
        )

        # Runtime health observation is not an Owner decision and still works,
        # and the audited boundary performs the same privileged change.
        runtime.update_source_health(source.id, health_state=SourceHealthState.OFFLINE)
        self.admin.update_source("synthetic-owner-session", source.id, name="Renamed")
        self.admin.set_active_source_limit("synthetic-owner-session", 2)
        self.assertEqual("Renamed", runtime.get_source(source.id).name)
        self.assertEqual(2, runtime.max_active_video_sources)
        self.assertEqual(
            {AuditOutcome.SUCCEEDED},
            {record.outcome for record in self.store.list_records()},
        )

        # Fixture and bootstrap tooling may opt in explicitly.
        fixtures = CameraRegistry(self.database, clock=lambda: self.now,
                                  unaudited_writes=True)
        self.assertEqual("Fixture", fixtures.update_source(source.id, name="Fixture").name)
        with self.assertRaises(ValueError):
            CameraRegistry(self.database, unaudited_writes="yes")

    def test_plan23_baseline_approval_contract_uses_fixed_atomic_action(self):
        baseline_id = uuid4()
        with closing(self.database.connect()) as connection:
            connection.execute(
                "CREATE TABLE synthetic_hardware_baselines "
                "(id TEXT PRIMARY KEY, approved INTEGER NOT NULL)"
            )

        def approve_on(connection, target):
            connection.execute(
                "INSERT INTO synthetic_hardware_baselines VALUES (?, 1)",
                (str(target),),
            )

        self.admin.approve_hardware_baseline(
            "synthetic-owner-session", baseline_id, approve_on,
        )
        with closing(self.database.connect()) as connection:
            self.assertEqual(1, connection.execute(
                "SELECT approved FROM synthetic_hardware_baselines WHERE id=?",
                (str(baseline_id),),
            ).fetchone()[0])
        record = self.store.list_records()[0]
        self.assertEqual(AuditAction.APPROVE_HARDWARE_BASELINE, record.action)
        self.assertEqual(TargetKind.HARDWARE_BASELINE, record.target_kind)
        self.assertEqual(AuditOutcome.SUCCEEDED, record.outcome)
