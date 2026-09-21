"""SQLite schema for restart-safe, payload-free wizard progress."""

from app.storage.migrations import Migration


def wizard_state_migration(version: int) -> Migration:
    """Return the immutable schema published as application migration 11."""
    return Migration(version, "setup_wizard_state", (
        "CREATE TABLE setup_wizard_steps ("
        "step TEXT PRIMARY KEY CHECK (step IN ('welcome','deployment_owner','storage',"
        "'hardware_and_recorder','locale_and_time','camera_sources',"
        "'detection_profiles','owner_verification','slack','human_remote_access')), "
        "status TEXT NOT NULL CHECK (status IN "
        "('pending','unavailable','skipped','completed')), "
        "revision INTEGER NOT NULL CHECK (revision >= 0))",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('welcome','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('deployment_owner','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('storage','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('hardware_and_recorder','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('locale_and_time','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('camera_sources','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('detection_profiles','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('owner_verification','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('slack','pending',0)",
        "INSERT INTO setup_wizard_steps(step,status,revision) "
        "VALUES ('human_remote_access','pending',0)",
    ))
