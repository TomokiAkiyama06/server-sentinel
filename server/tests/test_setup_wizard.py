"""Synthetic tests for transport-neutral first-run wizard state."""

from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from itertools import count
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import UUID

from app.audit import (
    ActorCategory, AuditAction, AuditOutcome, AuditStorageError, AuditStore,
    OwnerAuditService,
    OwnerAuthorizationError, TargetKind,
)
from app.setup_wizard import (
    STEP_CATALOG,
    WIZARD_STEP_TARGETS,
    SetupWizardService,
    UnauditedWizardWriteError,
    WizardStateStore,
    WizardStatus,
    WizardStep,
    WizardStorageError,
    WizardValidationError,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from app.setup_wizard.schema import wizard_state_migration


class SetupWizardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Database(Path(self.temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.store = WizardStateStore(self.database, unaudited_writes=True)

    def transition(self, step, status):
        revision = self.store.snapshot().state_for(step).revision
        return self.store.transition(step, status, expected_revision=revision)

    def test_fresh_state_uses_documented_order_and_survives_restart(self):
        snapshot = self.store.snapshot()
        self.assertEqual(
            tuple(definition.step for definition in STEP_CATALOG),
            tuple(state.step for state in snapshot.states),
        )
        self.assertTrue(all(state.status is WizardStatus.PENDING
                            for state in snapshot.states))
        self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED)
        restarted = WizardStateStore(self.database).snapshot()
        self.assertEqual(WizardStatus.COMPLETED,
                         restarted.state_for(WizardStep.WELCOME).status)
        self.assertEqual(WizardStep.DEPLOYMENT_OWNER, restarted.current_step)

    def test_order_is_enforced_but_unavailable_integration_does_not_block_shell(self):
        with self.assertRaisesRegex(WizardValidationError, "earlier"):
            self.transition(WizardStep.STORAGE, WizardStatus.COMPLETED)

        for definition in STEP_CATALOG[:5]:
            self.transition(definition.step, WizardStatus.COMPLETED)
        self.transition(WizardStep.CAMERA_SOURCES, WizardStatus.UNAVAILABLE)
        after = self.transition(WizardStep.DETECTION_PROFILES, WizardStatus.UNAVAILABLE)
        self.assertFalse(after.deployment_ready)
        self.assertEqual(WizardStep.OWNER_VERIFICATION, after.current_step)
        self.assertFalse(all(state.status is WizardStatus.COMPLETED
                             for state in after.states))

    def test_required_steps_cannot_be_skipped_but_optional_steps_can(self):
        with self.assertRaisesRegex(WizardValidationError, "required"):
            self.transition(WizardStep.WELCOME, WizardStatus.SKIPPED)
        for definition in STEP_CATALOG[:7]:
            self.transition(definition.step, WizardStatus.COMPLETED)
        after = self.transition(WizardStep.OWNER_VERIFICATION, WizardStatus.SKIPPED)
        self.assertEqual(WizardStatus.SKIPPED,
                         after.state_for(WizardStep.OWNER_VERIFICATION).status)

    def test_camera_and_profile_steps_require_completion_for_readiness(self):
        for definition in STEP_CATALOG[:5]:
            self.transition(definition.step, WizardStatus.COMPLETED)
        for step in (WizardStep.CAMERA_SOURCES, WizardStep.DETECTION_PROFILES):
            with self.subTest(step=step), self.assertRaisesRegex(
                    WizardValidationError, "required"):
                self.transition(step, WizardStatus.SKIPPED)

        self.transition(WizardStep.CAMERA_SOURCES, WizardStatus.COMPLETED)
        self.assertFalse(self.store.snapshot().deployment_ready)
        self.transition(WizardStep.DETECTION_PROFILES, WizardStatus.UNAVAILABLE)
        self.assertFalse(self.store.snapshot().deployment_ready)
        self.transition(WizardStep.DETECTION_PROFILES, WizardStatus.PENDING)
        after = self.transition(WizardStep.DETECTION_PROFILES, WizardStatus.COMPLETED)
        self.assertTrue(after.deployment_ready)

    def test_published_wizard_migration_is_frozen(self):
        self.assertEqual(
            "2dd6c7282b60db67e4ba8659d83c3e2b35fb6204878bfff6f0311e9c86481c50",
            wizard_state_migration(13).checksum,
        )

    def test_unavailable_and_skipped_steps_must_be_retried_before_completion(self):
        self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED)
        self.transition(WizardStep.DEPLOYMENT_OWNER, WizardStatus.UNAVAILABLE)
        with self.assertRaisesRegex(WizardValidationError, "retried"):
            self.transition(WizardStep.DEPLOYMENT_OWNER, WizardStatus.COMPLETED)
        self.transition(WizardStep.DEPLOYMENT_OWNER, WizardStatus.PENDING)
        self.transition(WizardStep.DEPLOYMENT_OWNER, WizardStatus.COMPLETED)

    def test_compare_and_swap_rejects_stale_writer_without_losing_state(self):
        first = self.store.snapshot().state_for(WizardStep.WELCOME)
        self.store.transition(
            WizardStep.WELCOME, WizardStatus.COMPLETED,
            expected_revision=first.revision,
        )
        with self.assertRaisesRegex(WizardValidationError, "changed"):
            self.store.transition(
                WizardStep.WELCOME, WizardStatus.COMPLETED,
                expected_revision=first.revision,
            )
        self.assertEqual(WizardStatus.COMPLETED,
                         self.store.snapshot().state_for(WizardStep.WELCOME).status)

    def test_completed_step_cannot_be_downgraded(self):
        self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED)
        for target in (WizardStatus.PENDING, WizardStatus.UNAVAILABLE,
                       WizardStatus.SKIPPED):
            with self.subTest(target=target), self.assertRaisesRegex(
                    WizardValidationError, "immutable"):
                self.transition(WizardStep.WELCOME, target)

    def test_migration_preserves_existing_application_state(self):
        other = Database(Path(self.temporary.name) / "upgrade.sqlite3")
        with closing(other.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS[:-1])
            connection.execute(
                "INSERT INTO application_metadata VALUES ('synthetic-kept', 'yes')"
            )
            migrate(connection, APPLICATION_MIGRATIONS)
            self.assertEqual("yes", connection.execute(
                "SELECT value FROM application_metadata WHERE key='synthetic-kept'"
            ).fetchone()[0])
            self.assertEqual(len(STEP_CATALOG), connection.execute(
                "SELECT count(*) FROM setup_wizard_steps"
            ).fetchone()[0])

    def test_state_contract_cannot_store_sensitive_or_arbitrary_values(self):
        marker = "SYNTHETIC_SECRET_BIOMETRIC_RAW_SERIAL"
        with self.assertRaises(TypeError):
            self.store.transition(  # type: ignore[call-arg]
                WizardStep.WELCOME, WizardStatus.COMPLETED,
                expected_revision=0, details={"secret": marker},
            )
        self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED)
        self.assertNotIn(marker.encode(), self.database.path.read_bytes())
        self.assertNotIn(marker, repr(self.store.snapshot()))

    def test_invalid_types_and_corrupt_catalog_fail_closed_without_values(self):
        marker = "SYNTHETIC_PRIVATE_STEP"
        for step, status, revision in (
            (marker, WizardStatus.COMPLETED, 0),
            (WizardStep.WELCOME, marker, 0),
            (WizardStep.WELCOME, WizardStatus.COMPLETED, True),
        ):
            with self.subTest(step=type(step), status=type(status)), self.assertRaises(
                    WizardValidationError) as caught:
                self.store.transition(step, status, expected_revision=revision)
            self.assertNotIn(marker, str(caught.exception))

        with closing(self.database.connect()) as connection:
            connection.execute(
                "DELETE FROM setup_wizard_steps WHERE step=?", (WizardStep.SLACK.value,)
            )
        with self.assertRaisesRegex(WizardValidationError, "catalog"):
            self.store.snapshot()

    def test_plain_transition_is_refused_outside_fixtures(self):
        runtime = WizardStateStore(self.database)
        with self.assertRaises(UnauditedWizardWriteError):
            runtime.transition(WizardStep.WELCOME, WizardStatus.COMPLETED,
                               expected_revision=0)
        self.assertEqual(WizardStatus.PENDING,
                         runtime.snapshot().state_for(WizardStep.WELCOME).status)
        with self.assertRaises(WizardValidationError):
            WizardStateStore(self.database, unaudited_writes=1)  # type: ignore[arg-type]

    def test_transition_on_requires_a_caller_owned_transaction(self):
        with closing(self.database.connect()) as connection:
            with self.assertRaises(WizardStorageError):
                self.store.transition_on(connection, WizardStep.WELCOME,
                                         WizardStatus.COMPLETED, expected_revision=0)
        self.assertEqual(WizardStatus.PENDING,
                         self.store.snapshot().state_for(WizardStep.WELCOME).status)


NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)
OWNER_CONTEXT = "synthetic-owner-session"
VIEWER_CONTEXT = "synthetic-viewer-session"
NODE_CONTEXT = "synthetic-capture-node-credential"


class SyntheticOwnerAuthorizer:
    """Only the synthetic Owner context passes; others fail with their category."""

    def require_owner(self, actor_context):
        if actor_context == OWNER_CONTEXT:
            return
        if actor_context == VIEWER_CONTEXT:
            raise OwnerAuthorizationError(ActorCategory.INVITED_USER)
        if actor_context == NODE_CONTEXT:
            raise OwnerAuthorizationError(ActorCategory.CAPTURE_NODE)
        raise OwnerAuthorizationError()


class PlainDenial:
    def require_owner(self, actor_context):
        raise PermissionError("synthetic detail synthetic-viewer@example.invalid")


class SyntheticReservation:
    def __init__(self):
        self.refuse = False

    @contextmanager
    def __call__(self):
        if self.refuse:
            raise RuntimeError("synthetic storage refusal")
        yield


class SetupWizardServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Database(Path(self.temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.reservation = SyntheticReservation()
        ticks = count()
        self.audit = AuditStore(self.database, reservation=self.reservation,
                                clock=lambda: NOW + timedelta(microseconds=next(ticks)))
        self.audit_service = OwnerAuditService(self.audit, SyntheticOwnerAuthorizer())
        self.store = WizardStateStore(self.database)
        self.wizard = SetupWizardService(self.audit_service, self.store)

    def transition(self, step, status, actor=OWNER_CONTEXT):
        revision = self.store.snapshot().state_for(step).revision
        return self.wizard.transition(actor, step, status, expected_revision=revision)

    def summary(self):
        return [(record.actor_category, record.action, record.target_kind,
                 record.target_logical_id, record.outcome)
                for record in reversed(self.audit.list_records(limit=1000))]

    def audit_text(self):
        with closing(self.database.connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM security_admin_audit_records").fetchall()
        return " ".join(str(value) for row in rows for value in row)

    def record(self, step, outcome, actor=ActorCategory.OWNER):
        return (actor, AuditAction.TRANSITION_SETUP_WIZARD_STEP,
                TargetKind.SETUP_WIZARD_STEP, WIZARD_STEP_TARGETS[step], outcome)

    def statuses(self):
        return tuple(state.status for state in self.store.snapshot().states)

    def test_owner_transition_commits_with_one_bounded_success_record(self):
        after = self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED)
        self.assertEqual(WizardStatus.COMPLETED, after.state_for(WizardStep.WELCOME).status)
        self.assertEqual(WizardStep.DEPLOYMENT_OWNER, after.current_step)
        self.assertEqual([self.record(WizardStep.WELCOME, AuditOutcome.SUCCEEDED)],
                         self.summary())
        # The record names the step only; the requested status is not stored.
        text = self.audit_text()
        for status in WizardStatus:
            self.assertNotIn(status.value, text)
        self.assertNotIn(WizardStep.WELCOME.value, text)

    def test_step_targets_are_fixed_distinct_logical_ids(self):
        self.assertEqual({definition.step for definition in STEP_CATALOG},
                         set(WIZARD_STEP_TARGETS))
        self.assertEqual(len(STEP_CATALOG), len(set(WIZARD_STEP_TARGETS.values())))
        self.assertEqual(UUID("f627abac-2bcf-5f96-b58d-5ff3f8941933"),
                         WIZARD_STEP_TARGETS[WizardStep.WELCOME])
        self.assertEqual(AuditAction.TRANSITION_SETUP_WIZARD_STEP.value,
                         "transition_setup_wizard_step")

    def test_step_order_is_enforced_and_audited_as_failed(self):
        with self.assertRaisesRegex(WizardValidationError, "earlier"):
            self.transition(WizardStep.STORAGE, WizardStatus.COMPLETED)
        self.assertTrue(all(status is WizardStatus.PENDING for status in self.statuses()))
        self.assertEqual([self.record(WizardStep.STORAGE, AuditOutcome.FAILED)],
                         self.summary())
        for definition in STEP_CATALOG:
            if definition.skippable:
                break
            self.transition(definition.step, WizardStatus.COMPLETED)
        snapshot = self.wizard.snapshot(OWNER_CONTEXT)
        self.assertTrue(snapshot.deployment_ready)
        self.assertEqual(WizardStep.OWNER_VERIFICATION, snapshot.current_step)

    def test_only_optional_steps_can_be_skipped(self):
        for definition in STEP_CATALOG:
            if definition.skippable:
                continue
            with self.subTest(step=definition.step):
                before = self.statuses()
                with self.assertRaisesRegex(WizardValidationError, "required"):
                    self.transition(definition.step, WizardStatus.SKIPPED)
                self.assertEqual(before, self.statuses())
                self.transition(definition.step, WizardStatus.COMPLETED)
        for definition in STEP_CATALOG:
            if definition.skippable:
                with self.subTest(step=definition.step):
                    after = self.transition(definition.step, WizardStatus.SKIPPED)
                    self.assertEqual(WizardStatus.SKIPPED,
                                     after.state_for(definition.step).status)
        final = self.store.snapshot()
        self.assertIsNone(final.current_step)
        self.assertTrue(final.deployment_ready)

    def test_pending_and_unavailable_are_never_reported_as_completed(self):
        for definition in STEP_CATALOG[:5]:
            self.transition(definition.step, WizardStatus.COMPLETED)
        self.transition(WizardStep.CAMERA_SOURCES, WizardStatus.UNAVAILABLE)
        after = self.transition(WizardStep.DETECTION_PROFILES, WizardStatus.UNAVAILABLE)
        self.assertFalse(after.deployment_ready)
        for step in (WizardStep.CAMERA_SOURCES, WizardStep.DETECTION_PROFILES):
            self.assertIs(WizardStatus.UNAVAILABLE, after.state_for(step).status)
            with self.subTest(step=step), self.assertRaisesRegex(
                    WizardValidationError, "retried"):
                self.transition(step, WizardStatus.COMPLETED)
            self.assertIs(WizardStatus.UNAVAILABLE,
                          self.store.snapshot().state_for(step).status)
        for state in after.states[7:]:
            self.assertIs(WizardStatus.PENDING, state.status)

    def test_stale_revision_is_rejected_without_changing_state(self):
        first = self.store.snapshot().state_for(WizardStep.WELCOME)
        self.wizard.transition(OWNER_CONTEXT, WizardStep.WELCOME, WizardStatus.COMPLETED,
                               expected_revision=first.revision)
        before = self.store.snapshot()
        with self.assertRaisesRegex(WizardValidationError, "changed"):
            self.wizard.transition(OWNER_CONTEXT, WizardStep.WELCOME,
                                   WizardStatus.COMPLETED,
                                   expected_revision=first.revision)
        self.assertEqual(before, self.store.snapshot())
        self.assertEqual([self.record(WizardStep.WELCOME, AuditOutcome.SUCCEEDED),
                          self.record(WizardStep.WELCOME, AuditOutcome.FAILED)],
                         self.summary())

    def test_non_owner_is_denied_audited_and_changes_nothing(self):
        before = self.store.snapshot()
        for actor, category in ((VIEWER_CONTEXT, ActorCategory.INVITED_USER),
                                (NODE_CONTEXT, ActorCategory.CAPTURE_NODE),
                                ("synthetic-unknown", ActorCategory.UNAUTHENTICATED)):
            with self.subTest(actor=category):
                with self.assertRaises(OwnerAuthorizationError) as caught:
                    self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED, actor)
                self.assertIs(category, caught.exception.actor_category)
                with self.assertRaises(OwnerAuthorizationError):
                    self.wizard.snapshot(actor)
        self.assertEqual(before, self.store.snapshot())
        # Refused reads write nothing; each refused transition writes one denial.
        self.assertEqual(
            [self.record(WizardStep.WELCOME, AuditOutcome.DENIED, category)
             for category in (ActorCategory.INVITED_USER, ActorCategory.CAPTURE_NODE,
                              ActorCategory.UNAUTHENTICATED)],
            self.summary(),
        )

    def test_plain_permission_error_is_classified_without_its_detail(self):
        wizard = SetupWizardService(OwnerAuditService(self.audit, PlainDenial()), self.store)
        for call in (lambda: wizard.transition("synthetic", WizardStep.WELCOME,
                                               WizardStatus.COMPLETED, expected_revision=0),
                     lambda: wizard.snapshot("synthetic")):
            with self.assertRaises(OwnerAuthorizationError) as caught:
                call()
            self.assertIs(ActorCategory.UNAUTHENTICATED, caught.exception.actor_category)
            self.assertNotIn("example.invalid", str(caught.exception))
        self.assertNotIn("example.invalid", self.audit_text())
        self.assertEqual(WizardStatus.PENDING,
                         self.store.snapshot().state_for(WizardStep.WELCOME).status)

    def test_audit_failure_rolls_back_the_transition(self):
        with closing(self.database.connect()) as connection:
            connection.execute(
                "CREATE TRIGGER synthetic_audit_fault BEFORE INSERT ON "
                "security_admin_audit_records BEGIN "
                "SELECT RAISE(ABORT, 'synthetic audit fault'); END")
        with self.assertRaises(AuditStorageError):
            self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED)
        self.assertEqual(WizardStatus.PENDING,
                         self.store.snapshot().state_for(WizardStep.WELCOME).status)
        self.assertEqual(0, self.store.snapshot().state_for(WizardStep.WELCOME).revision)
        # The separate failure record could not be written either; the loss is
        # visible as bounded health rather than silently dropped.
        self.assertTrue(self.audit_service.audit_delivery_failed)

    def test_refused_storage_admission_changes_nothing(self):
        self.reservation.refuse = True
        with self.assertRaises(RuntimeError):
            self.transition(WizardStep.WELCOME, WizardStatus.COMPLETED)
        self.assertEqual(WizardStatus.PENDING,
                         self.store.snapshot().state_for(WizardStep.WELCOME).status)
        self.assertEqual([], self.summary())
        self.assertTrue(self.audit_service.audit_delivery_failed)

    def test_invalid_step_is_refused_before_authorization_without_a_record(self):
        marker = "SYNTHETIC_PRIVATE_STEP"
        with self.assertRaises(WizardValidationError) as caught:
            self.wizard.transition(VIEWER_CONTEXT, marker, WizardStatus.COMPLETED,  # type: ignore[arg-type]
                                   expected_revision=0)
        self.assertNotIn(marker, str(caught.exception))
        self.assertEqual([], self.summary())

    def test_service_requires_the_audit_store_on_the_wizard_database(self):
        other = Database(Path(self.temporary.name) / "other.sqlite3")
        with self.assertRaises(ValueError):
            SetupWizardService(self.audit_service, WizardStateStore(other))
        with self.assertRaises(TypeError):
            SetupWizardService(object(), self.store)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
