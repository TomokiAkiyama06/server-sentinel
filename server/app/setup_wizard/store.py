"""Transactional persistence for ordered first-run wizard progress."""

import sqlite3
from contextlib import closing

from app.storage.database import Database

from .model import (
    STEP_CATALOG,
    WizardSnapshot,
    WizardState,
    WizardStatus,
    WizardStep,
    WizardValidationError,
)


class WizardStorageError(RuntimeError):
    """Wizard persistence failed without exposing submitted data."""


_INDEX = {definition.step: index for index, definition in enumerate(STEP_CATALOG)}
_SKIPPABLE = {definition.step for definition in STEP_CATALOG if definition.skippable}


class WizardStateStore:
    """Persist bounded progress only; configuration belongs to feature owners."""

    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _validate_step(step: WizardStep) -> None:
        if not isinstance(step, WizardStep):
            raise WizardValidationError("invalid wizard step")

    @staticmethod
    def _validate_status(status: WizardStatus) -> None:
        if not isinstance(status, WizardStatus):
            raise WizardValidationError("invalid wizard status")

    @staticmethod
    def _validate_revision(revision: int) -> None:
        if type(revision) is not int or revision < 0:
            raise WizardValidationError("invalid expected revision")

    @staticmethod
    def _snapshot_on(connection: sqlite3.Connection) -> WizardSnapshot:
        rows = connection.execute(
            "SELECT step,status,revision FROM setup_wizard_steps"
        ).fetchall()
        try:
            by_step = {
                WizardStep(row["step"]): WizardState(
                    WizardStep(row["step"]), WizardStatus(row["status"]), row["revision"]
                )
                for row in rows
            }
            if len(rows) != len(STEP_CATALOG) or len(by_step) != len(STEP_CATALOG):
                raise WizardValidationError("wizard state catalog does not match")
            return WizardSnapshot(tuple(by_step[item.step] for item in STEP_CATALOG))
        except (KeyError, TypeError, ValueError) as error:
            if isinstance(error, WizardValidationError):
                raise
            raise WizardValidationError("wizard state catalog does not match") from None

    def snapshot(self) -> WizardSnapshot:
        try:
            with closing(self.database.connect()) as connection:
                return self._snapshot_on(connection)
        except WizardValidationError:
            raise
        except sqlite3.Error:
            raise WizardStorageError("wizard state is unavailable") from None

    def transition(self, step: WizardStep, status: WizardStatus, *,
                   expected_revision: int) -> WizardSnapshot:
        """Apply one compare-and-swap transition and return committed state.

        ``UNAVAILABLE`` resolves navigation without claiming completion. It can
        be retried through ``PENDING``. Completed states are immutable so a
        stale client cannot silently erase already accepted setup progress.
        """
        self._validate_step(step)
        self._validate_status(status)
        self._validate_revision(expected_revision)
        try:
            with closing(self.database.connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    before = self._snapshot_on(connection)
                    current = before.state_for(step)
                    if current.revision != expected_revision:
                        raise WizardValidationError("wizard state changed")
                    self._validate_transition(before, current, status)
                    if status is current.status:
                        connection.commit()
                        return before
                    cursor = connection.execute(
                        "UPDATE setup_wizard_steps SET status=?, revision=revision+1 "
                        "WHERE step=? AND revision=?",
                        (status.value, step.value, expected_revision),
                    )
                    if cursor.rowcount != 1:
                        raise WizardValidationError("wizard state changed")
                    after = self._snapshot_on(connection)
                    connection.commit()
                    return after
                except BaseException:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
        except WizardValidationError:
            raise
        except sqlite3.Error:
            raise WizardStorageError("wizard state update failed") from None

    @staticmethod
    def _validate_transition(snapshot: WizardSnapshot, current: WizardState,
                             target: WizardStatus) -> None:
        if current.status is WizardStatus.COMPLETED and target is not current.status:
            raise WizardValidationError("completed wizard step is immutable")
        if target is WizardStatus.SKIPPED and current.step not in _SKIPPABLE:
            raise WizardValidationError("required wizard step cannot be skipped")
        if target is WizardStatus.PENDING:
            if current.status not in (WizardStatus.UNAVAILABLE, WizardStatus.SKIPPED,
                                      WizardStatus.PENDING):
                raise WizardValidationError("wizard step cannot return to pending")
            return
        if current.status is WizardStatus.UNAVAILABLE and target is not WizardStatus.UNAVAILABLE:
            raise WizardValidationError("unavailable wizard step must be retried first")
        if current.status is WizardStatus.SKIPPED and target is not WizardStatus.SKIPPED:
            raise WizardValidationError("skipped wizard step must be retried first")
        for state in snapshot.states[:_INDEX[current.step]]:
            if state.status is WizardStatus.PENDING:
                raise WizardValidationError("earlier wizard step is still pending")
