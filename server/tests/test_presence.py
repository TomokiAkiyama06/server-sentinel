"""Synthetic persisted presence/history with explicit mock permission/storage ports."""

import asyncio
from contextlib import closing, nullcontext
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
from app.storage.policy import FilesystemSpace, MainStoragePolicy, StorageLimits
from app.storage.retention import RetentionPeriods
from app.storage.schema import APPLICATION_MIGRATIONS

CRITICAL_PATHS = ("critical_detection", "critical_persistence",
                  "critical_evidence", "critical_notifications")

# Synthetic main-host storage limits; no deployment value is implied.
STORAGE_LIMITS = StorageLimits(recording_limit_bytes=100_000, critical_allowance_bytes=10_000,
                               hard_reserve_bytes=4_096, pressure_free_bytes=8_192,
                               recovery_free_bytes=16_384, recovery_allocation_bytes=90_000,
                               write_overhead_bytes=4_096, max_request_bytes=50_000,
                               cleanup_batch_size=10)

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
                     reservation=nullcontext, detection=lambda: True)
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

    def test_bounded_dispatch_never_starves_newly_queued_critical_work(self):
        unconfigured = self.make_service(evidence=None, notifications=None)
        for index in range(3):
            unconfigured.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=index + 1)))
        unconfigured.dispatch_pending()
        self.assertEqual(self.status()["pending_critical_actions"], 6)
        fresh = self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=UUID(int=2 ** 128 - 1)))
        # A bounded batch reaches the newly queued work instead of repeating
        # the stuck backlog that happens to sort first by identity.
        self.service.dispatch_pending(limit=2)
        self.assertEqual([item.identifier for item in self.evidence], [fresh.identifier])
        self.assertEqual([item.identifier for item in self.notifications], [fresh.identifier])
        self.service.dispatch_pending()
        self.assertEqual(self.status()["pending_critical_actions"], 0)

    def test_recovered_action_dispatches_its_unavailable_backlog_fairly(self):
        unavailable = self.make_service(evidence=None, notifications=None)
        for index in range(3):
            unavailable.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=index + 1)))
        unavailable.dispatch_pending()
        recovered = self.make_service(evidence=None)
        recovered.dispatch_pending(limit=2)
        self.assertEqual([item.identifier for item in self.notifications], [UUID(int=1), UUID(int=2)])
        recovered.dispatch_pending()
        self.assertEqual([item.identifier for item in self.notifications], [UUID(int=1), UUID(int=2), UUID(int=3)])

    def test_fresh_arrivals_do_not_starve_recovered_delivery(self):
        unavailable = self.make_service(evidence=None, notifications=None)
        old = unavailable.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=1)))
        unavailable.dispatch_pending()
        recovered = self.make_service(notifications=None)
        fresh = recovered.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=2)))
        recovered.dispatch_pending(limit=1)
        recovered.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=3)))
        recovered.dispatch_pending(limit=1)
        self.assertEqual([fresh.identifier, old.identifier], [item.identifier for item in self.evidence])

    def test_disabled_critical_action_stays_visible_as_degraded(self):
        event = self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.service.complete_action(event.identifier, "notification", ActionResult.DISABLED)
        self.service.dispatch_pending()
        status = self.status()
        self.assertEqual(status["pending_critical_actions"], 0)
        self.assertEqual(status["critical_notifications"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])

    def test_unavailable_critical_action_stays_visible_as_degraded(self):
        event = self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.service.complete_action(event.identifier, "evidence", ActionResult.UNAVAILABLE)
        status = self.status()
        self.assertEqual(status["critical_evidence"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])

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

        self.service.reservation = full
        # No expiring override is needed for status to prove current storage
        # admission. A configured but refusing guard never looks armed.
        self.assertEqual(self.status()["critical_persistence"], "unavailable")
        status = self.status(now=NOW + timedelta(hours=2))
        # Reading status must not need a durable write, and the expired override
        # must stop applying even while its retirement cannot be persisted.
        self.assertEqual((status["state"], status["basis"]), ("UNKNOWN", "unknown"))
        self.assertTrue(status["override_expiry_pending"])
        self.assertEqual(status["critical_persistence"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])
        self.assertEqual(status["pending_critical_actions"], 2)
        self.assertEqual([row["action"] for row in self.service.audit("owner")], ["override_set"])
        self.service.reservation = nullcontext
        recovered = self.status(now=NOW + timedelta(hours=2))
        self.assertFalse(recovered["override_expiry_pending"])
        self.assertEqual(recovered["critical_persistence"], "armed")
        self.status(now=NOW + timedelta(hours=2))
        self.assertEqual([row["action"] for row in self.service.audit("owner")],
                         ["override_set", "override_expired"])

    def test_storage_reservation_is_held_and_released_around_every_write(self):
        policy = MainStoragePolicy(STORAGE_LIMITS, lambda: FilesystemSpace(50_000, 100_000),
                                   lambda: 0, lambda transition: None)
        service = self.make_service(reservation=policy.control)
        held = []
        with service._transaction() as db:
            # The reservation is entered for the whole write, not merely built.
            held.append(policy._reservation)
            db.execute("INSERT INTO presence_audit(action,at) VALUES ('synthetic',?)", (timestamp(NOW),))
        self.assertEqual(held, [True])
        self.assertFalse(policy._reservation)
        service.override("owner", PresenceState.ABSENT, now=NOW, clock_trusted=True)
        # An admit-only port would hold this reservation forever and refuse
        # every later presence write with STORAGE_INVALID_RESERVATION.
        self.assertFalse(policy._reservation)
        event = service.record(observation(Kind.SERVER_MOVEMENT))
        self.assertFalse(policy._reservation)
        service.dispatch_pending()
        self.assertEqual(self.evidence[-1].identifier, event.identifier)
        status = service.snapshot(now=NOW, clock_trusted=True)
        self.assertEqual(status["critical_persistence"], "armed")
        self.assertFalse(policy._reservation)
        with self.assertRaises(KeyboardInterrupt):
            with service._transaction() as db:
                db.execute("INSERT INTO presence_audit(action,at) VALUES ('synthetic',?)", (timestamp(NOW),))
                raise KeyboardInterrupt()
        self.assertFalse(policy._reservation)
        service.override("owner", PresenceState.PRESENT, now=NOW, clock_trusted=True)

    def test_storage_admission_port_must_supply_a_reservation_context(self):
        policy = MainStoragePolicy(STORAGE_LIMITS, lambda: FilesystemSpace(50_000, 100_000),
                                   lambda: 0, lambda transition: None)
        # An admit-only port reserves without ever releasing, so it is refused
        # instead of silently leaking the deployment's metadata reserve.
        for port in (lambda: None, policy.admit_control):
            service = self.make_service(reservation=port)
            with self.assertRaisesRegex(RuntimeError, "storage admission reservation required"):
                service.record(observation())
            self.assertEqual(service.snapshot(now=NOW, clock_trusted=True)["critical_persistence"],
                             "unavailable")
        self.assertEqual(self.history()["items"], [])

    def test_failed_or_uncertain_delivery_keeps_its_path_degraded(self):
        def failing(item, complete):
            raise OSError("synthetic private failure")

        service = self.make_service(evidence=failing)
        service.record(observation(Kind.SERVER_MOVEMENT, identifier=UUID(int=11)))
        service.dispatch_pending()
        status = service.snapshot(now=NOW, clock_trusted=True)
        # An uncertain evidence submission is known unfinished critical work.
        self.assertEqual(status["critical_evidence"], "unavailable")
        self.assertEqual(status["critical_notifications"], "armed")
        self.assertTrue(status["critical_paths_degraded"])
        second = service.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=12)))
        service.complete_action(second.identifier, "notification", ActionResult.FAILED)
        status = service.snapshot(now=NOW, clock_trusted=True)
        self.assertEqual(status["critical_notifications"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])

    def test_unusable_owner_observation_never_masks_a_valid_hint(self):
        self.service.set_hint("owner", PresenceState.ABSENT, now=NOW,
                              valid_until=NOW + timedelta(hours=3), clock_trusted=True)
        self.service.record(observation(confirmed=False, quality=Quality.INSUFFICIENT),
                            presence_valid_until=NOW + timedelta(hours=2))
        status = self.status()
        # Only a high-confidence owner observation outranks a configured hint.
        self.assertEqual((status["state"], status["basis"]), ("ABSENT", "hint"))
        self.assertFalse(status["suppress_ordinary"])
        self.service.record(observation(identifier=UUID(int=21)),
                            presence_valid_until=NOW + timedelta(hours=2))
        status = self.status()
        self.assertEqual((status["state"], status["basis"]), ("PRESENT", "owner_observation"))
        # A later unusable observation invalidates that inference without
        # claiming presence and without hiding the still valid hint.
        self.service.record(observation(Kind.OWNER_EXIT, confirmed=False, identifier=UUID(int=22)),
                            presence_valid_until=NOW + timedelta(hours=2))
        status = self.status()
        self.assertEqual((status["state"], status["basis"]), ("ABSENT", "hint"))
        self.assertFalse(status["suppress_ordinary"])

    def test_expired_disabled_delivery_keeps_its_path_degraded(self):
        event = self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.service.complete_action(event.identifier, "notification", ActionResult.DISABLED)
        self.service.complete_action(event.identifier, "evidence", ActionResult.DELIVERED)
        self.assertEqual(self.status()["critical_notifications"], "unavailable")
        later = NOW + timedelta(days=RetentionPeriods().recording_days + 1)
        self.assertEqual(self.service.expire_history(now=later), 1)
        self.assertEqual(self.history()["items"], [])
        status = self.status(now=later)
        # The notification never happened, so expiring its row must not report
        # the path as armed again; a replay cannot repair it either.
        self.assertEqual(status["critical_notifications"], "unavailable")
        self.assertEqual(status["critical_evidence"], "armed")
        self.assertTrue(status["critical_paths_degraded"])
        self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=event.identifier,
                                        at=later, received=later))
        self.assertEqual(self.status(now=later)["critical_notifications"], "unavailable")

    def test_expired_critical_identity_is_not_replayed_into_new_side_effects(self):
        event = self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.service.dispatch_pending()
        self.assertEqual((len(self.evidence), len(self.notifications)), (1, 1))
        later = NOW + timedelta(days=RetentionPeriods().recording_days + 1)
        self.assertEqual(self.service.expire_history(now=later), 1)
        self.assertEqual(self.history()["items"], [])
        # A delayed source reconnect replays the same event identity.
        replay = self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=event.identifier,
                                                 at=later, received=later))
        self.service.dispatch_pending()
        self.assertEqual(replay.identifier, event.identifier)
        self.assertEqual((len(self.evidence), len(self.notifications)), (1, 1))
        self.assertEqual(self.status(now=later)["pending_critical_actions"], 0)
        window = dict(received_from=later - timedelta(hours=1), received_to=later + timedelta(hours=1))
        self.assertEqual(self.history(**window)["items"], [])

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
                                  reservation=nullcontext)
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

    def test_source_high_water_never_restores_trust_for_late_intermediate_event(self):
        high = self.service.record(observation(at=NOW + timedelta(hours=10), received=NOW),
                                   presence_valid_until=NOW + timedelta(hours=12))
        low = self.service.record(observation(Kind.OWNER_EXIT, at=NOW + timedelta(hours=5),
                                  received=NOW + timedelta(seconds=1)),
                                  presence_valid_until=NOW + timedelta(hours=12))
        middle = self.service.record(observation(at=NOW + timedelta(hours=7),
                                     received=NOW + timedelta(seconds=2)),
                                     presence_valid_until=NOW + timedelta(hours=12))
        self.assertTrue(high.clock_trusted)
        self.assertFalse(low.clock_trusted)
        self.assertFalse(middle.clock_trusted)
        self.assertEqual(self.status(now=NOW + timedelta(seconds=2))["state"], "UNKNOWN")

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

    def test_presence_audit_retention_is_bounded_and_oldest_first(self):
        self.service.override("owner", PresenceState.ABSENT, now=NOW, clock_trusted=True)
        self.service.set_hint("owner", PresenceState.PRESENT, now=NOW + timedelta(days=1),
                              valid_until=NOW + timedelta(days=2), clock_trusted=True)
        self.service.cancel_override("owner", now=NOW + timedelta(days=2), clock_trusted=True)
        self.assertEqual(1, self.service.expire_audit(now=NOW + timedelta(days=92), limit=1))
        self.assertEqual(["hint_set", "override_cancelled"],
                         [row["action"] for row in self.service.audit("owner")])
        # The cutoff is exclusive, so the audit record exactly 90 days old is retained.
        self.assertEqual(1, self.service.expire_audit(now=NOW + timedelta(days=92)))
        self.assertEqual(["override_cancelled"], [row["action"] for row in self.service.audit("owner")])
        with self.assertRaisesRegex(ValueError, "audit retention"):
            self.service.expire_audit(now=NOW + timedelta(days=92), limit=1001)

    def test_timeline_retention_is_bounded_and_preserves_unfinished_critical_work(self):
        completed = self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=UUID(int=1)))
        unfinished = self.service.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=2)))
        self.service.complete_action(completed.identifier, "evidence", ActionResult.DELIVERED)
        self.service.complete_action(completed.identifier, "notification", ActionResult.DELIVERED)
        self.assertEqual(1, self.service.expire_history(now=NOW + timedelta(days=21), limit=1))
        self.assertEqual([str(unfinished.identifier)], [item["id"] for item in self.history()["items"]])
        with self.assertRaisesRegex(ValueError, "timeline retention"):
            self.service.expire_history(now=NOW + timedelta(days=21), limit=1001)

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
        self.service.reservation = full
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
        queued = self.status()
        self.assertEqual(queued["pending_critical_actions"], 1)
        # Accepted work is not a completed critical action, and a lost callback
        # would strand it, so the path stays degraded until completion.
        self.assertEqual(queued["critical_notifications"], "unavailable")
        self.assertTrue(queued["critical_paths_degraded"])
        notifications.callback(type("Result", (), {"value": "sent"})())
        completed = self.status()
        self.assertEqual(completed["pending_critical_actions"], 0)
        self.assertEqual(completed["critical_notifications"], "armed")

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
        event = self.service.record(observation(Kind.SERVER_MOVEMENT))
        with self.assertRaises(SystemExit):
            self.service.dispatch_pending()
        stranded = self.status()
        # An interrupted submission is unfinished critical work, so the path is
        # never reported as healthy while it stays stranded.
        self.assertEqual(stranded["critical_evidence"], "unavailable")
        self.assertTrue(stranded["critical_paths_degraded"])
        # The interrupted evidence submission plus the notification it never
        # reached are both still unfinished at this point.
        self.assertEqual(stranded["pending_critical_actions"], 2)
        self.service = self.make_service()
        self.service.dispatch_pending()
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.evidence, [])
        status = self.status()
        self.assertEqual(status["pending_critical_actions"], 1)
        self.assertEqual(status["critical_evidence"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])
        # Only an explicit Owner decision accepts the duplicate risk and puts
        # the stranded action back in the queue.
        self.service.requeue_action("owner", event.identifier, "evidence",
                                    now=NOW, clock_trusted=True)
        self.service.dispatch_pending()
        self.assertEqual([item.identifier for item in self.evidence], [event.identifier])
        recovered = self.status()
        self.assertEqual(recovered["pending_critical_actions"], 0)
        self.assertEqual(recovered["critical_evidence"], "armed")
        self.assertFalse(recovered["critical_paths_degraded"])
        self.assertEqual(self.service.audit("owner")[-1]["action"], "critical_action_requeued")

    def test_requeue_requires_owner_and_an_unresolved_action(self):
        event = self.service.record(observation(Kind.CAMERA_TAMPER))
        for context in ("recordings", "live", None):
            with self.assertRaises(AccessDenied):
                self.service.requeue_action(context, event.identifier, "evidence",
                                            now=NOW, clock_trusted=True)
        # Queued and completed work is not resubmitted through this route.
        with self.assertRaisesRegex(ValueError, "no unresolved critical action"):
            self.service.requeue_action("owner", event.identifier, "evidence", now=NOW, clock_trusted=True)
        self.service.dispatch_pending()
        with self.assertRaisesRegex(ValueError, "no unresolved critical action"):
            self.service.requeue_action("owner", event.identifier, "evidence", now=NOW, clock_trusted=True)
        with self.assertRaises(ValueError):
            self.service.requeue_action("owner", event.identifier, "owner_alert", now=NOW, clock_trusted=True)
        self.assertEqual(self.service.audit("owner"), [])

    def test_unresolved_critical_history_is_bounded_by_the_audit_horizon(self):
        event = self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=UUID(int=91)))
        self.service.complete_action(event.identifier, "evidence", ActionResult.FAILED)
        periods = RetentionPeriods()
        recording = NOW + timedelta(days=periods.recording_days + 1)
        # Unfinished critical work keeps its payload past ordinary retention.
        self.assertEqual(self.service.expire_history(now=recording), 0)
        self.assertEqual(len(self.history()["items"]), 1)
        audit = NOW + timedelta(days=periods.audit_days + 1)
        # The exception is bounded, so the payload cannot accumulate forever.
        self.assertEqual(self.service.expire_history(now=audit), 1)
        self.assertEqual(self.history()["items"], [])
        status = self.status(now=audit)
        self.assertEqual(status["critical_evidence"], "unavailable")
        self.assertEqual(status["critical_notifications"], "unavailable")
        self.assertTrue(status["critical_paths_degraded"])
        # The identity stays a duplicate, so a replay cannot re-queue the work.
        self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=event.identifier,
                                        at=audit, received=audit))
        self.assertEqual(self.status(now=audit)["pending_critical_actions"], 0)

    def test_owner_clears_an_expired_critical_degradation(self):
        event = self.service.record(observation(Kind.SERVER_MOVEMENT))
        self.service.complete_action(event.identifier, "notification", ActionResult.DISABLED)
        self.service.complete_action(event.identifier, "evidence", ActionResult.DELIVERED)
        later = NOW + timedelta(days=RetentionPeriods().recording_days + 1)
        self.service.expire_history(now=later)
        self.assertEqual(self.status(now=later)["critical_notifications"], "unavailable")
        with self.assertRaises(AccessDenied):
            self.service.clear_expired_degradation("recordings", "notification",
                                                   now=later, clock_trusted=True)
        self.service.clear_expired_degradation("owner", "notification", now=later, clock_trusted=True)
        status = self.status(now=later)
        self.assertEqual(status["critical_notifications"], "armed")
        self.assertFalse(status["critical_paths_degraded"])
        cleared = self.service.audit("owner")[-1]
        self.assertEqual((cleared["action"], cleared["target"]),
                         ("critical_degradation_cleared", "notification"))
        with self.assertRaisesRegex(ValueError, "no expired critical degradation"):
            self.service.clear_expired_degradation("owner", "notification", now=later, clock_trusted=True)

    def test_future_observation_timestamp_cannot_lock_out_owner_control(self):
        far = NOW + timedelta(days=365)
        self.service.record(observation(Kind.PERSON, at=far, received=far, confirmed=False))
        # Owner control keeps its own monotonic marker, so a single source
        # timestamp cannot refuse every later override, cancellation and hint.
        result = self.service.override("owner", PresenceState.PRESENT, now=NOW, clock_trusted=True)
        self.assertEqual((result["state"], result["basis"]), ("PRESENT", "manual_override"))
        # The accepted override keeps its documented precedence: a source
        # timestamp neither withholds its suppression nor hides its own skew.
        self.assertTrue(result["suppress_ordinary"])
        self.assertFalse(result["clock_degraded"])
        self.assertTrue(result["observation_clock_degraded"])
        self.service.cancel_override("owner", now=NOW, clock_trusted=True)
        self.service.set_hint("owner", PresenceState.ABSENT, now=NOW,
                              valid_until=NOW + timedelta(hours=1), clock_trusted=True)
        self.assertEqual([row["action"] for row in self.service.audit("owner")],
                         ["override_set", "override_cancelled", "hint_set"])
        # The Owner-configured hint also survives the skewed observation clock.
        status = self.status()
        self.assertEqual((status["state"], status["basis"]), ("ABSENT", "hint"))
        self.assertFalse(status["suppress_ordinary"])
        self.assertTrue(status["observation_clock_degraded"])
        # Observation-derived inference still needs observation-clock trust.
        self.service.record(observation(identifier=UUID(int=41)),
                            presence_valid_until=NOW + timedelta(hours=1))
        self.assertEqual(self.status()["basis"], "hint")

    def test_stale_callback_cannot_cancel_an_owner_requeued_attempt(self):
        callbacks = []

        def queueing(item, complete):
            callbacks.append(complete)
            return ActionResult.QUEUED

        service = self.make_service(evidence=queueing, notifications=None)
        event = service.record(observation(Kind.SERVER_MOVEMENT, identifier=UUID(int=71)))
        service.dispatch_pending()
        self.assertEqual(len(callbacks), 1)
        service.requeue_action("owner", event.identifier, "evidence", now=NOW, clock_trusted=True)
        # The first attempt's callback arrives after the Owner requeue and must
        # not cancel the approved resubmission.
        callbacks[0](ActionResult.FAILED)
        service.dispatch_pending()
        self.assertEqual(len(callbacks), 2)
        # A stale callback also cannot overwrite the newer attempt's outcome.
        callbacks[0](ActionResult.FAILED)
        callbacks[1](ActionResult.DELIVERED)
        status = service.snapshot(now=NOW, clock_trusted=True)
        self.assertEqual(status["critical_evidence"], "armed")
        self.assertEqual(status["pending_critical_actions"], 1)  # notification port absent

    def test_owner_recovery_audit_names_the_recovered_target(self):
        first = self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=UUID(int=81)))
        second = self.service.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=82)))
        for event in (first, second):
            self.service.complete_action(event.identifier, "notification", ActionResult.FAILED)
            self.service.requeue_action("owner", event.identifier, "notification",
                                        now=NOW, clock_trusted=True)
        entries = [row for row in self.service.audit("owner")
                   if row["action"] == "critical_action_requeued"]
        # The audit distinguishes which duplicate-risk resubmission was approved.
        self.assertEqual([row["target"] for row in entries],
                         [f"notification:{first.identifier}", f"notification:{second.identifier}"])
        self.assertTrue(all(row["actor"] == str(OWNER) for row in entries))

    def test_owner_requeued_action_leads_fresh_zero_attempt_work(self):
        def failing(item, complete):
            raise OSError("synthetic private failure")

        def healthy(item, complete):
            self.evidence.append(item)
            return ActionResult.DELIVERED

        self.service.evidence = failing
        stranded = self.service.record(observation(Kind.SERVER_MOVEMENT, identifier=UUID(int=51)))
        self.service.dispatch_pending()
        self.assertEqual(self.evidence, [])
        self.service.evidence = healthy
        for index in range(3):
            self.service.record(observation(Kind.CAMERA_TAMPER, identifier=UUID(int=60 + index)))
        self.service.requeue_action("owner", stranded.identifier, "evidence", now=NOW, clock_trusted=True)
        # The recovered action retains its attempt count, so ordering by
        # attempts alone would let fresh work starve an Owner decision.
        self.service.dispatch_pending(limit=1)
        self.assertEqual([item.identifier for item in self.evidence], [stranded.identifier])


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
