"""Synthetic hardware-baseline drift path under the shared smoke audit hook."""

from contextlib import nullcontext
from datetime import datetime, timezone
from uuid import UUID

from app.audit import AuditAction, AuditOutcome, AuditStore, OwnerAuditService
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry
from app.integrity.model import Component, Inventory, Kind, State
from app.integrity.service import IntegrityService
from app.integrity.store import IntegrityStore
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


class _SyntheticOwner:
    def require_owner(self, actor_context):
        if actor_context != "synthetic-owner":
            raise PermissionError("not the deployment owner")


class _ApprovedOwner:
    def require_owner(self):
        return UUID("00000000-0000-4000-8000-000000000001")


def _storage(serial):
    return Component(
        Kind.STORAGE, "synthetic-slot", (("capacity_bytes", "1024"),),
        (("serial", serial),),
    )


def run_integrity_smoke(root):
    """A drift fault remains visible and retryable without host probing."""
    database = Database(root / "synthetic-integrity.sqlite3")
    connection = database.connect()
    try:
        migrate(connection, APPLICATION_MIGRATIONS)
        store = IntegrityStore(connection, reservation=nullcontext, max_pending_events=8)
        store.approval = _ApprovedOwner()
        audit = AuditStore(database, reservation=store.control_reservation)
        administration = OwnerAdministration(OwnerAuditService(audit, _SyntheticOwner()),
                                              CameraRegistry(database))
        approved = Inventory((_storage("synthetic-approved"),))
        assert administration.approve_integrity_baseline(
            "synthetic-owner", store, approved, expected_revision=0,
            at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ) == 1

        class Probe:
            current = approved

            def collect(self):
                return self.current

        probe = Probe()
        clock = [0.0]
        delivered = []

        def unavailable(*_event):
            raise OSError("synthetic-private-delivery-error")

        service = IntegrityService(
            store, probe, unavailable, monotonic=lambda: clock[0],
            utcnow=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        assert {finding.state for finding in service.startup()} == {State.OK}

        # Startup always checks: a replacement must be immediately faulted,
        # while a notification failure cannot rewrite the approved baseline.
        probe.current = Inventory((_storage("synthetic-replacement"),))
        findings = service.startup()
        assert {finding.state for finding in findings} == {State.CHANGED}
        assert store.baseline() == (1, approved)
        assert connection.execute(
            "SELECT delivered FROM integrity_outbox"
        ).fetchone()[0] == 0

        # The next worker tick retries the durable event before any daily
        # probe.  Its notification data contains no raw hardware identity.
        clock[0] = 1.0
        service.sink = lambda *event: delivered.append(event)
        assert service.tick() is None
        assert len(delivered) == 1
        assert delivered[0][2] is True
        assert {finding["state"] for finding in delivered[0][3]} == {"CHANGED"}
        assert connection.execute("SELECT COUNT(*) FROM integrity_outbox").fetchone()[0] == 0
        assert "synthetic-approved" not in str(delivered)
        assert "synthetic-replacement" not in str(delivered)
        records = audit.list_records()
        assert [(record.action, record.outcome) for record in records] == [
            (AuditAction.APPROVE_HARDWARE_BASELINE, AuditOutcome.SUCCEEDED),
        ]
    finally:
        connection.close()
