"""Synthetic tests for transport-neutral first-run wizard state."""

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.setup_wizard import (
    STEP_CATALOG,
    WizardStateStore,
    WizardStatus,
    WizardStep,
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
        self.store = WizardStateStore(self.database)

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
            "5e093df62583d85f20c2d15ae6b285c3b9c0c2e2d78d7701a77cc09bb41b5730",
            wizard_state_migration(11).checksum,
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


if __name__ == "__main__":
    unittest.main()
