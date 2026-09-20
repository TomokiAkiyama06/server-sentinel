"""Synthetic persisted presence/history with explicit mock permission/storage ports."""

import asyncio
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.main import create_app
from app.settings import Settings
from tests.asgi import request
import unittest
from uuid import UUID

from app.presence.access import AccessDenied
from app.presence.delivery import ActionResult, NotificationAdapter
from app.presence.models import (InvalidObservation, Kind, Observation, PresenceState,
                                 Quality, Value, timestamp)
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

CRITICAL_PATHS = ("critical_detection", "critical_persistence",
                  "critical_evidence", "critical_notifications")

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE, NODE, OWNER = UUID(int=1), UUID(int=2), UUID(int=3)


class MockAccess:
    """Test fixture only, not an authentication/session implementation."""
    def __init__(self):
        self.revoked = False

    def require_owner(self, context):
        if self.revoked or context != "owner":
            raise AccessDenied()
        return OWNER

    def require_recordings(self, context):
        if self.revoked or context not in {"owner", "recordings", "both"}:
            raise AccessDenied()


def observation(kind=Kind.OWNER_ENTRY, *, at=NOW, received=None, **fields):
    values = dict(source_id=SOURCE, confidence=0.98, quality=Quality.SUFFICIENT,
                  clock_trusted=True, confirmed=True)
    values.update(fields)
    return Observation(kind, at, received or at, **values)


class PresenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as db:
            # The production catalog, so the ordinary startup path is exercised.
            migrate(db, APPLICATION_MIGRATIONS)
        self.access = MockAccess()
        self.evidence, self.notifications = [], []
        self.service = self.make_service()

    def make_service(self, **changes):
        def evidence(item, complete):
            self.evidence.append(item)
            return ActionResult.DELIVERED
        def notifications(item, complete):
            self.notifications.append(item)
            return ActionResult.DELIVERED
        ports = dict(access=self.access, evidence=evidence, notifications=notifications,
                     write_guard=lambda: None, detection=lambda: True)
        ports.update(changes)
        return PresenceService(self.database, **ports)

    def status(self, *, now=NOW):
        return self.service.snapshot(now=now, clock_trusted=True)

    def history(self, context="recordings", **changes):
        query = dict(received_from=NOW - timedelta(days=1), received_to=NOW + timedelta(days=1))
        query.update(changes)
        return self.service.history(context, **query)

    def test_default_storage_and_permission_boundaries_refuse(self):
        closed = PresenceService(self.database)
        with self.assertRaisesRegex(AccessDenied, "Not Found"):
            closed.override("owner", PresenceState.PRESENT, now=NOW, clock_trusted=True)
        with self.assertRaises(AccessDenied):
            closed.history("recordings", received_from=NOW, received_to=NOW + timedelta(hours=1))
        with self.assertRaisesRegex(RuntimeError, "storage admission required"):
            closed.record(observation())

    def test_four_states_only_explicit_present_suppresses_ordinary(self):
        for state in PresenceState:
            result = self.service.override("owner", state, now=NOW, clock_trusted=True)
            self.assertEqual(result["state"], state.value)
            self.assertEqual(result["suppress_ordinary"], state == PresenceState.PRESENT)
            # No presence state, including a manual override, disarms a path.
            self.assertEqual([result[key] for key in CRITICAL_PATHS], ["armed"] * 4)
            self.assertFalse(result["critical_paths_degraded"])

    def test_manual_override_precedes_inference_and_hint_until_expired(self):
        self.service.set_hint("owner", PresenceState.ABSENT, now=NOW, valid_until=NOW + timedelta(hours=3), clock_trusted=True)
        self.service.override("owner", PresenceState.ABSENT, now=NOW, expires_at=NOW + timedelta(hours=1), clock_trusted=True)
        self.service.record(observation(), presence_valid_until=NOW + timedelta(hours=2))
        self.assertEqual(self.status()["basis"], "manual_override")
        self.assertEqual(self.status()["state"], "ABSENT")
        current = self.status(now=NOW + timedelta(hours=1))
        self.assertEqual((current["state"], current["basis"]), ("PRESENT", "owner_observation"))
        audit = self.service.audit("owner")
        self.assertEqual([row["action"] for row in audit], ["hint_set", "override_set", "override_expired"])
        self.assertEqual(audit[1]["actor"], str(OWNER))
        self.status(now=NOW + timedelta(hours=1))
        self.assertEqual(len(self.service.audit("owner")), 3)

    def test_cancellation_restores_current_inference_and_is_audited(self):
        self.service.record(observation(), presence_valid_until=NOW + timedelta(hours=2))
        self.service.override("owner", PresenceState.ABSENT, now=NOW, clock_trusted=True)
        result = self.service.cancel_override("owner", now=NOW, clock_trusted=True)
        self.assertEqual(result["state"], "PRESENT")
        self.assertEqual(self.service.audit("owner")[-1]["action"], "override_cancelled")
        self.assertEqual(self.service.audit("owner")[-1]["actor"], str(OWNER))

    def test_hints_cannot_silently_suppress_and_stale_inference_expires(self):
        self.service.set_hint("owner", PresenceState.PRESENT, now=NOW, valid_until=NOW + timedelta(hours=2), clock_trusted=True)
        self.assertEqual(self.status()["state"], "PROBABLY_PRESENT")
        self.assertFalse(self.status()["suppress_ordinary"])
        self.service.record(observation(), presence_valid_until=NOW + timedelta(hours=1))
        self.assertTrue(self.status()["suppress_ordinary"])
        self.assertEqual(self.status(now=NOW + timedelta(hours=1))["state"], "PROBABLY_PRESENT")
        self.assertEqual(self.status(now=NOW + timedelta(hours=2))["state"], "UNKNOWN")

    def test_owner_observation_requires_confirmation_quality_clock_and_explicit_validity(self):
        for changes in ({"confirmed": False}, {"confirmed": False, "quality": Quality.INSUFFICIENT}, {"clock_trusted": False}):
            self.service.record(observation(**changes), presence_valid_until=NOW + timedelta(hours=1))
            self.assertEqual(self.status()["state"], "UNKNOWN")
            self.assertFalse(self.status()["suppress_ordinary"])
        self.service.record(observation())
        self.assertEqual(self.status()["state"], "UNKNOWN")

    def test_critical_detector_evidence_notification_run_in_every_manual_state(self):
        calls = []
        for state in PresenceState:
            self.service.override("owner", state, now=NOW, clock_trusted=True)
            for kind in (Kind.SERVER_MOVEMENT, Kind.CAMERA_TAMPER):
                def detector():
                    calls.append(kind)
                    return observation(kind)
                result = self.service.process_critical(detector)
                self.service.dispatch_pending()
                self.assertEqual(self.evidence[-1].identifier, result.identifier)
                self.assertEqual(self.notifications[-1].identifier, result.identifier)
        self.assertEqual((len(calls), len(self.evidence), len(self.notifications)), (8, 8, 8))
        self.assertEqual(self.status()["pending_critical_actions"], 0)

    def test_evidence_failure_never_skips_notification_and_uncertainty_is_durable(self):
        def failed(_, complete):
            raise OSError("synthetic private detail")
        self.service.evidence = failed
        result = self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.service.dispatch_pending()
        self.assertEqual(len(self.notifications), 1)
        self.assertEqual(self.status()["pending_critical_actions"], 1)
        restarted = self.make_service()
        restarted.dispatch_pending()
        self.assertEqual(self.evidence, [])  # Do not retry an uncertain side effect.
        restarted.complete_action(result.identifier, "evidence", ActionResult.DELIVERED)
        self.assertEqual(len(self.notifications), 1)
        self.assertEqual(restarted.snapshot(now=NOW, clock_trusted=True)["pending_critical_actions"], 0)

    def test_unconfigured_ports_visible_unconfirmed_events_do_not_dispatch(self):
        self.service = self.make_service(evidence=None, notifications=None)
        self.service.record(observation(Kind.SERVER_MOVEMENT, confirmed=False))
        status = self.status()
        self.assertEqual(status["pending_critical_actions"], 0)
        # An unconfigured preservation/notification path is never called armed.
        self.assertEqual(status["critical_evidence"], "unavailable")
        self.assertEqual(status["critical_notifications"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])
        self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.assertEqual(self.status()["pending_critical_actions"], 2)

    def test_critical_paths_reported_from_configuration_and_known_health(self):
        closed = PresenceService(self.database)
        status = closed.snapshot(now=NOW, clock_trusted=True)
        self.assertEqual([status[key] for key in CRITICAL_PATHS],
                         ["unknown", "unavailable", "unavailable", "unavailable"])
        self.assertTrue(status["critical_paths_degraded"])
        stopped = self.make_service(detection=lambda: False)
        self.assertEqual(stopped.snapshot(now=NOW, clock_trusted=True)["critical_detection"], "unavailable")

        def broken():
            raise OSError("synthetic private probe failure")

        for probe in (None, broken, lambda: "armed", lambda: 1):
            unclear = self.make_service(detection=probe)
            snapshot = unclear.snapshot(now=NOW, clock_trusted=True)
            self.assertEqual(snapshot["critical_detection"], "unknown")
            self.assertTrue(snapshot["critical_paths_degraded"])

    def test_status_stays_readable_and_honest_when_storage_admission_refuses(self):
        self.service.override("owner", PresenceState.PRESENT, now=NOW,
                              expires_at=NOW + timedelta(hours=1), clock_trusted=True)
        self.service.record(observation(Kind.SERVER_MOVEMENT))

        def full():
            raise RuntimeError("storage admission refused")

        self.service.write_guard = full
        status = self.status(now=NOW + timedelta(hours=2))
        # Reading status must not need a durable write, and the expired override
        # must stop applying even while its retirement cannot be persisted.
        self.assertEqual((status["state"], status["basis"]), ("UNKNOWN", "unknown"))
        self.assertTrue(status["override_expiry_pending"])
        self.assertEqual(status["critical_persistence"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])
        self.assertEqual(status["pending_critical_actions"], 2)
        self.assertEqual([row["action"] for row in self.service.audit("owner")], ["override_set"])
        self.service.write_guard = lambda: None
        recovered = self.status(now=NOW + timedelta(hours=2))
        self.assertFalse(recovered["override_expiry_pending"])
        self.assertEqual(recovered["critical_persistence"], "armed")
        self.status(now=NOW + timedelta(hours=2))
        self.assertEqual([row["action"] for row in self.service.audit("owner")],
                         ["override_set", "override_expired"])

    def test_application_startup_migration_creates_presence_storage(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        settings = Settings(Path(directory.name))
        application = create_app(settings)

        async def start():
            async with application.router.lifespan_context(application):
                pass

        asyncio.run(start())
        service = PresenceService(Database(settings.database_path), access=self.access,
                                  write_guard=lambda: None)
        service.record(observation())
        window = dict(received_from=NOW - timedelta(days=1), received_to=NOW + timedelta(days=1))
        self.assertEqual(len(service.history("recordings", **window)["items"]), 1)

    def test_duplicate_event_does_not_repeat_completed_side_effects(self):
        value = observation(Kind.CAMERA_TAMPER)
        self.service.record(value)
        self.service.dispatch_pending()
        self.service.record(value)
        self.service.dispatch_pending()
        self.assertEqual((len(self.evidence), len(self.notifications)), (1, 1))
        with self.assertRaisesRegex(ValueError, "identity conflict"):
            self.service.record(replace(value, kind=Kind.SERVER_MOVEMENT))

    def test_entry_movement_camera_offline_neutral_attributed_history(self):
        self.service.record(observation(), presence_valid_until=NOW + timedelta(hours=1))
        self.service.record(observation(Kind.SERVER_MOVEMENT, at=NOW + timedelta(seconds=1)))
        self.service.record(observation(Kind.CAMERA_HEALTH, at=NOW + timedelta(seconds=2), value=Value.OFFLINE, confirmed=False))
        history = self.history()
        self.assertEqual([row["kind"] for row in history["items"]], ["owner_entry", "server_movement", "camera_health"])
        for row in history["items"]:
            self.assertEqual(row["source_id"], str(SOURCE))
            self.assertIn("confidence", row)
            self.assertIn("quality", row)
            self.assertNotIn("culprit", row["label"].lower())
            self.assertNotIn("attacker", row["label"].lower())
        self.assertEqual(history["causality"], "not_inferred")

    def test_recordings_permission_independent_and_rechecked_after_revocation(self):
        self.service.record(observation())
        self.assertEqual(len(self.history("recordings")["items"]), 1)
        for context in ("live", "uninvited", None):
            with self.assertRaises(AccessDenied):
                self.history(context)
        self.access.revoked = True
        for context in ("recordings", "both", "owner"):
            with self.assertRaises(AccessDenied):
                self.history(context)

    def test_clock_discontinuity_uses_receive_order_and_never_forces_presence(self):
        self.service.record(observation(), presence_valid_until=NOW + timedelta(hours=1))
        skewed = observation(Kind.OWNER_EXIT, at=NOW - timedelta(hours=1), received=NOW + timedelta(seconds=1))
        stored = self.service.record(skewed, presence_valid_until=NOW + timedelta(hours=1))
        self.assertFalse(stored.clock_trusted)
        self.assertEqual(self.status(now=NOW + timedelta(seconds=1))["state"], "UNKNOWN")
        result = self.history()
        self.assertTrue(result["ordering_degraded"])
        self.assertEqual(result["ordering_basis"], "received_at")
        self.assertEqual(result["items"][-1]["id"], str(skewed.identifier))

    def test_uncertain_clock_keeps_override_visible_without_suppression_or_expiry(self):
        self.service.override("owner", PresenceState.PRESENT, now=NOW, expires_at=NOW + timedelta(hours=1), clock_trusted=True)
        status = self.service.snapshot(now=NOW + timedelta(hours=2), clock_trusted=False)
        self.assertEqual(status["state"], "PRESENT")
        self.assertTrue(status["clock_degraded"])
        self.assertFalse(status["suppress_ordinary"])
        self.assertEqual(len(self.service.audit("owner")), 1)
        self.assertEqual(self.status(now=NOW + timedelta(hours=2))["state"], "UNKNOWN")

    def test_low_quality_person_absence_invalid_unknown_retained(self):
        with self.assertRaises(InvalidObservation):
            observation(Kind.PERSON, value=Value.NOT_OBSERVED, quality=Quality.INSUFFICIENT, confirmed=False)
        self.service.record(observation(Kind.PERSON, value=Value.UNKNOWN, quality=Quality.INSUFFICIENT, confirmed=False))
        self.assertEqual(self.history()["items"][0]["value"], "unknown")
        self.assertEqual(self.status()["state"], "UNKNOWN")

    def test_invalid_values_and_unattributed_observations_rejected(self):
        for values in ({"source_id": None}, {"confidence": float("nan")}, {"confidence": True}, {"uncertainty_us": -1}, {"clock_trusted": 1}):
            with self.assertRaises(InvalidObservation):
                observation(**values)
        with self.assertRaises(InvalidObservation):
            observation(at=NOW.replace(tzinfo=None))
        for kind in (Kind.NODE_HEALTH, Kind.STORAGE, Kind.RECORDING, Kind.CONFIGURATION):
            self.service.record(Observation(kind, NOW, NOW, node_id=NODE, value=Value.CHANGED))
        self.assertEqual(len(self.history()["items"]), 4)

    def test_restart_preserves_override_audit_and_history(self):
        self.service.override("owner", PresenceState.ABSENT, now=NOW, clock_trusted=True)
        self.service.record(observation())
        self.service = self.make_service()
        self.assertEqual(self.status()["state"], "ABSENT")
        self.assertEqual(len(self.service.audit("owner")), 1)
        self.assertEqual(len(self.history()["items"]), 2)

    def test_history_bounded_cursor_prevents_duplicate_rows(self):
        for _ in range(3):
            self.service.record(observation(Kind.PERSON, confirmed=False))
        first = self.history(limit=2)
        second = self.history(after=first["next_cursor"])
        self.assertEqual((len(first["items"]), len(second["items"])), (2, 1))
        self.assertTrue(set(row["id"] for row in first["items"]).isdisjoint(row["id"] for row in second["items"]))
        self.assertEqual(self.history(after=second["next_cursor"])["items"], [])
        for limit in (0, 501, True):
            with self.assertRaises(ValueError):
                self.history(limit=limit)
        for cursor in ("cursor", {"sequence": 1}, {"received_at": 1, "sequence": 1},
                       {"received_at": timestamp(NOW), "sequence": True},
                       {"received_at": timestamp(NOW), "sequence": -1},
                       {"received_at": timestamp(NOW), "sequence": 1, "kind": "person"}):
            with self.assertRaises(ValueError):
                self.history(after=cursor)

    def test_history_pages_share_one_ordering_key_when_occurrence_is_out_of_order(self):
        late = self.service.record(observation(Kind.PERSON, at=NOW + timedelta(hours=5),
                                               received=NOW + timedelta(seconds=1), confirmed=False))
        early = self.service.record(observation(Kind.PERSON, at=NOW, source_id=UUID(int=9),
                                                received=NOW + timedelta(seconds=2), confirmed=False))
        page = self.history(limit=1)
        self.assertEqual(page["ordering_basis"], "received_at")
        self.assertFalse(page["ordering_degraded"])
        rest = self.history(after=page["next_cursor"])
        # Concatenated pages follow the advertised order and drop no row, even
        # though the second source reported an earlier occurrence time.
        self.assertEqual([row["id"] for row in page["items"] + rest["items"]],
                         [str(late.identifier), str(early.identifier)])
        self.assertEqual([row["occurred_at"] for row in self.history()["items"]],
                         [timestamp(NOW + timedelta(hours=5)), timestamp(NOW)])

    def test_storage_guard_failure_prevents_mutation(self):
        def full():
            raise RuntimeError("storage admission refused")
        self.service.write_guard = full
        with self.assertRaisesRegex(RuntimeError, "storage admission refused"):
            self.service.override("owner", PresenceState.PRESENT, now=NOW, clock_trusted=True)
        self.assertEqual(self.service.audit("owner"), [])
        self.assertEqual(self.history()["items"], [])

    def test_interrupted_mutation_rolls_back_without_locking_next_request(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.service._transaction() as db:
                db.execute("INSERT INTO presence_audit(action,at) VALUES ('synthetic',?)", (NOW.isoformat(),))
                raise KeyboardInterrupt()
        self.assertEqual(self.service.audit("owner"), [])
        self.assertEqual(self.status()["state"], "UNKNOWN")


    def test_async_notification_stays_pending_until_polled_completion(self):
        class NotificationMock:
            callback = None
            def record(inner, kind, **fields):
                inner.identifier = fields["event_id"]
                inner.callback = fields["on_complete"]
                return type("Result", (), {"value": "pending"})()
        notifications = NotificationMock()
        self.service.notifications = NotificationAdapter(notifications, lambda kind: kind)
        value = self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.service.dispatch_pending()
        self.assertEqual(notifications.identifier, value.identifier)
        self.assertEqual(self.status()["pending_critical_actions"], 1)
        notifications.callback(type("Result", (), {"value": "sent"})())
        self.assertEqual(self.status()["pending_critical_actions"], 0)

    def test_delivery_ports_run_outside_database_write_lock(self):
        def port(item, complete):
            self.service.override("owner", PresenceState.PRESENT, now=NOW, clock_trusted=True)
            complete(ActionResult.DELIVERED)
            return ActionResult.QUEUED
        self.service.evidence = port
        self.service.record(observation(Kind.CAMERA_TAMPER))
        self.service.dispatch_pending()
        self.assertEqual(self.status()["state"], "PRESENT")
        self.assertEqual(self.status()["pending_critical_actions"], 0)

    def test_crash_during_submission_stays_visible_without_duplicate_retry(self):
        calls = []
        def interrupted(item, complete):
            calls.append(item.identifier)
            raise SystemExit()
        self.service.evidence = interrupted
        self.service.record(observation(Kind.SERVER_MOVEMENT))
        with self.assertRaises(SystemExit):
            self.service.dispatch_pending()
        self.service = self.make_service()
        self.service.dispatch_pending()
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.evidence, [])
        self.assertEqual(self.status()["pending_critical_actions"], 1)


    def test_mock_api_permissions_and_production_route_stays_closed(self):
        self.service.record(observation())
        application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        @application.get("/api/mock/timeline")
        async def history_route(request: Request):
            # This synthetic header exists only in this in-process test app.
            try:
                return self.history(request.headers.get("x-synthetic-identity"))
            except AccessDenied:
                return JSONResponse({"detail": "Not Found"}, status_code=404)
        for context, status in (("recordings", 200), ("live", 404), ("uninvited", 404)):
            response = asyncio.run(request(application, "/api/mock/timeline", headers=[(b"x-synthetic-identity", context.encode())]))
            self.assertEqual(response[0]["status"], status)
            if status == 404:
                self.assertEqual(response[1]["body"], b'{"detail":"Not Found"}')
        self.access.revoked = True
        response = asyncio.run(request(application, "/api/mock/timeline", headers=[(b"x-synthetic-identity", b"recordings")]))
        self.assertEqual(response[0]["status"], 404)
        production = create_app(Settings(self.database.path.parent))
        response = asyncio.run(request(production, "/api/timeline"))
        self.assertEqual(response[0]["status"], 404)
        self.assertEqual(response[1]["body"], b'{"detail":"Not Found"}')
