"""SQLite schema for restart-safe, payload-free wizard progress."""

from app.storage.migrations import Migration

from .model import STEP_CATALOG, WizardStatus


def wizard_state_migration(version: int) -> Migration:
    steps = ",".join(f"'{definition.step.value}'" for definition in STEP_CATALOG)
    statuses = ",".join(f"'{status.value}'" for status in WizardStatus)
    inserts = tuple(
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        f"VALUES ('{definition.step.value}','pending',0)"
        for definition in STEP_CATALOG
    )
    return Migration(version, "setup_wizard_state", (
        "CREATE TABLE setup_wizard_steps ("
        f"step TEXT PRIMARY KEY CHECK (step IN ({steps})), "
        f"status TEXT NOT NULL CHECK (status IN ({statuses})), "
        "revision INTEGER NOT NULL CHECK (revision >= 0))",
        *inserts,
    ))
