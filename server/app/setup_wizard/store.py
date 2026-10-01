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


class UnauditedWizardWriteError(RuntimeError):
    """A wizard transition was attempted outside the audited Owner boundary."""


_INDEX = {definition.step: index for index, definition in enumerate(STEP_CATALOG)}
_SKIPPABLE = {definition.step for definition in STEP_CATALOG if definition.skippable}


class WizardStateStore:
    """Persist bounded progress only; configuration belongs to feature owners.

    Reads are process-internal and perform no authorization. Runtime writes go
    through ``SetupWizardService`` and ``transition_on``; the plain
    ``transition`` wrapper is reserved for explicit non-runtime fixtures.
    """

    def __init__(self, database: Database, *, unaudited_writes: bool = False):
        if type(unaudited_writes) is not bool:
            raise WizardValidationError("unaudited write mode is invalid")
        self.database = database
        self.unaudited_writes = unaudited_writes

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
        """Apply one unaudited compare-and-swap transition (fixtures only).

        Runtime Owner transitions go through ``SetupWizardService``, which
        commits ``transition_on`` together with its security audit record.
        This wrapper refuses with ``UnauditedWizardWriteError`` unless the store
        was explicitly constructed with ``unaudited_writes=True``.
        """
        if not self.unaudited_writes:
            raise UnauditedWizardWriteError("wizard transition requires the audited boundary")
        self._validate_request(step, status, expected_revision)
        try:
            with closing(self.database.connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    after = self.transition_on(
                        connection, step, status, expected_revision=expected_revision,
                    )
                    connection.execute("COMMIT")
                    return after
                except BaseException:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
        except (WizardValidationError, WizardStorageError):
            raise
        except sqlite3.Error:
            raise WizardStorageError("wizard state update failed") from None

    def transition_on(self, connection: sqlite3.Connection, step: WizardStep,
                      status: WizardStatus, *, expected_revision: int) -> WizardSnapshot:
        """Apply one compare-and-swap transition on a caller-owned transaction.

        The caller owns ``BEGIN IMMEDIATE`` / ``COMMIT`` / ``ROLLBACK`` so the
        progress change can commit atomically with another write, such as its
        security audit record. A raised error leaves the rollback to the caller.

        ``UNAVAILABLE`` resolves navigation without claiming completion. It can
        be retried through ``PENDING``. Completed states are immutable so a
        stale client cannot silently erase already accepted setup progress.
        Requesting the current status at the current revision changes nothing.
        """
        self._validate_request(step, status, expected_revision)
        if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
            raise WizardStorageError("wizard transaction is unavailable")
        try:
            before = self._snapshot_on(connection)
            current = before.state_for(step)
            if current.revision != expected_revision:
                raise WizardValidationError("wizard state changed")
            self._validate_transition(before, current, status)
            if status is current.status:
                return before
            cursor = connection.execute(
                "UPDATE setup_wizard_steps SET status=?, revision=revision+1 "
                "WHERE step=? AND revision=?",
                (status.value, step.value, expected_revision),
            )
            if cursor.rowcount != 1:
                raise WizardValidationError("wizard state changed")
            return self._snapshot_on(connection)
        except sqlite3.Error:
            raise WizardStorageError("wizard state update failed") from None

    def _validate_request(self, step: WizardStep, status: WizardStatus,
                          expected_revision: int) -> None:
        self._validate_step(step)
        self._validate_status(status)
        self._validate_revision(expected_revision)

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
