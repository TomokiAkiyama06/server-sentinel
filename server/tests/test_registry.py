"""Synthetic SQLite integration tests; no physical devices or media."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from uuid import UUID, uuid4

from app.cameras.registry import (
    ActiveSourceLimitError, CameraRegistry, CaptureProfile, DetectionBinding,
    DetectionKind, NodeHealthState, SourceHealthState, NotFoundError, RegistryError, SourceType, ValidationError,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Database(Path(self.directory.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.registry = CameraRegistry(self.database, clock=lambda: self.now)

    def source(self, **overrides):
        arguments = {"source_type": SourceType.LOCAL_UVC, "name": "Synthetic source"}
        arguments.update(overrides)
        return self.registry.create_source(**arguments)

    def binding(self, **overrides):
        arguments = dict(binding_id=uuid4(), kind=DetectionKind.MOTION, version=1,
                         enabled=True, thresholds={"synthetic_threshold": 0.25},
                         config={"synthetic_region": [0, 0, 1, 1]})
        arguments.update(overrides)
        return DetectionBinding(**arguments)

    def test_one_through_four_mixed_sources(self):
        node = self.registry.create_capture_node("Synthetic node")
        for count in range(1, 5):
            local = count % 2
            source = self.source(
                source_type=SourceType.LOCAL_UVC if local else SourceType.REMOTE_AGENT,
                capture_node_id=None if local else node.id, enabled=True,
                role_label=f"custom role {count}",
            )
            self.assertIsInstance(source.id, UUID)
            self.assertEqual(count, len(self.registry.list_sources()))
            self.assertEqual(count, sum(item.enabled for item in self.registry.list_sources()))
            self.assertNotEqual(source.id, node.id)
            self.assertEqual(source.capture_node_id, None if local else node.id)

    def test_fifth_active_creation_preserves_all_sources(self):
        for _ in range(4):
            self.source(enabled=True)
        before = self.registry.list_sources()
        with self.assertRaises(ActiveSourceLimitError):
            self.source(enabled=True)
        self.assertEqual(before, self.registry.list_sources())
        fifth = self.source(enabled=False)
        self.assertFalse(fifth.enabled)
        self.assertEqual(5, len(self.registry.list_sources()))

    def test_fifth_activation_rolls_back_other_requested_edits(self):
        for _ in range(4):
            self.source(enabled=True)
        fifth = self.source(enabled=False, detection_bindings=(self.binding(),))
        before = self.registry.list_sources()
        self.now += timedelta(seconds=1)
        with self.assertRaises(ActiveSourceLimitError):
            self.registry.update_source(fifth.id, enabled=True, name="Changed", detection_bindings=())
        self.assertEqual(before, self.registry.list_sources())

    def test_offline_and_ambiguous_sources_still_reserve_capacity(self):
        for health in SourceHealthState:
            source = self.source(enabled=True)
            self.registry.update_source_health(source.id, health_state=health)
        with self.assertRaises(ActiveSourceLimitError):
            self.source(enabled=True)
        self.assertTrue(all(source.enabled for source in self.registry.list_sources()))

    def test_disabling_releases_only_requested_source(self):
        sources = [self.source(enabled=True) for _ in range(4)]
        self.registry.update_source(sources[1].id, enabled=False)
        replacement = self.source(enabled=True)
        self.assertTrue(replacement.enabled)
        self.assertEqual(4, sum(source.enabled for source in self.registry.list_sources()))
        for source in (sources[0], sources[2], sources[3]):
            self.assertEqual(source, self.registry.get_source(source.id))

    def test_existing_enabled_source_update_allowed_at_limit(self):
        sources = [self.source(enabled=True) for _ in range(4)]
        updated = self.registry.update_source(sources[0].id, enabled=True, name="New name")
        self.assertEqual("New name", updated.name)
        self.assertEqual(sources[0].id, updated.id)

    def test_limit_is_configurable_durable_and_shared_between_instances(self):
        self.assertEqual(4, self.registry.max_active_video_sources)
        self.registry.set_active_limit(5)
        other = CameraRegistry(self.database)
        self.assertEqual(5, other.max_active_video_sources)
        for _ in range(5):
            self.source(enabled=True)
        before = self.registry.list_sources()
        with self.assertRaises(ActiveSourceLimitError):
            other.set_active_limit(4)
        self.assertEqual(5, self.registry.max_active_video_sources)
        self.assertEqual(before, self.registry.list_sources())

    def test_invalid_limits_have_no_effect(self):
        for value in (0, -1, True, 4.0, "4", None, 2**40):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.registry.set_active_limit(value)
        self.assertEqual(4, self.registry.max_active_video_sources)

    def test_concurrent_activation_cannot_overbook(self):
        sources = [self.source() for _ in range(8)]
        barrier = Barrier(len(sources))

        def activate(source):
            registry = CameraRegistry(self.database)
            barrier.wait(timeout=10)
            try:
                registry.update_source(source.id, enabled=True, name="Admitted")
                return True
            except ActiveSourceLimitError:
                return False

        with ThreadPoolExecutor(max_workers=len(sources)) as pool:
            results = list(pool.map(activate, sources))
        self.assertEqual(4, sum(results))
        self.assertEqual(4, sum(source.enabled for source in self.registry.list_sources()))
        for source, admitted in zip(sources, results):
            if not admitted:
                self.assertEqual(source, self.registry.get_source(source.id))

    def test_concurrent_creation_cannot_overbook(self):
        barrier = Barrier(8)

        def create(_):
            barrier.wait(timeout=10)
            try:
                CameraRegistry(self.database).create_source(
                    source_type=SourceType.LOCAL_UVC, name="Synthetic concurrent", enabled=True,
                )
                return True
            except ActiveSourceLimitError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(create, range(8)))
        self.assertEqual(4, sum(results))
        self.assertEqual(4, len(self.registry.list_sources()))

    def test_source_node_and_role_identity_are_separate(self):
        node = self.registry.create_capture_node("Synthetic node")
        first = self.source(source_type=SourceType.REMOTE_AGENT, capture_node_id=node.id,
                            role_label="custom role")
        second = self.source(source_type=SourceType.REMOTE_AGENT, capture_node_id=node.id)
        updated = self.registry.update_source(first.id, role_label="another custom role", name="Edited")
        for state in SourceHealthState:
            updated = self.registry.update_source_health(first.id, health_state=state)
            self.assertEqual(first.id, updated.id)
            self.assertEqual(node.id, updated.capture_node_id)
            self.assertEqual(SourceType.REMOTE_AGENT, updated.source_type)
        self.assertNotEqual(first.id, second.id)
        self.assertNotEqual(first.id, node.id)
        self.assertEqual(second, self.registry.get_source(second.id))
        self.assertIsNone(self.source(role_label="another custom role").capture_node_id)

    def test_rejects_invalid_source_type_node_relationship(self):
        node = self.registry.create_capture_node("Synthetic node")
        for arguments in (
            dict(capture_node_id=node.id),
            dict(source_type=SourceType.REMOTE_AGENT),
            dict(source_type="local_uvc"),
            dict(source_type=SourceType.REMOTE_AGENT, capture_node_id=str(node.id)),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValidationError):
                self.source(**arguments)
        with self.assertRaises(NotFoundError):
            self.source(source_type=SourceType.REMOTE_AGENT, capture_node_id=uuid4())
        self.assertEqual((), self.registry.list_sources())

    def test_node_online_does_not_make_camera_online(self):
        node = self.registry.create_capture_node("Synthetic node")
        source = self.source(source_type=SourceType.REMOTE_AGENT, capture_node_id=node.id)
        self.registry.update_capture_node(node.id, health_state=NodeHealthState.ONLINE, last_seen_at=self.now)
        self.assertEqual(SourceHealthState.OFFLINE, self.registry.get_source(source.id).health_state)
        self.assertEqual(NodeHealthState.ONLINE, self.registry.get_capture_node(node.id).health_state)
        self.registry.update_source_health(source.id, health_state=SourceHealthState.MANUAL_INTERVENTION_REQUIRED)
        self.assertEqual(NodeHealthState.ONLINE, self.registry.get_capture_node(node.id).health_state)

    def test_node_health_has_distinct_revocation_state_and_round_trips(self):
        node = self.registry.create_capture_node("Synthetic node")
        source = self.source(source_type=SourceType.REMOTE_AGENT, capture_node_id=node.id)
        for state in NodeHealthState:
            changed = self.registry.update_capture_node(node.id, health_state=state)
            self.assertIsInstance(changed.health_state, NodeHealthState)
            self.assertEqual(state, changed.health_state)
            self.assertEqual(source, self.registry.get_source(source.id))
        restarted = CameraRegistry(self.database)
        self.assertEqual(NodeHealthState.REVOKED, restarted.get_capture_node(node.id).health_state)
        self.assertEqual(node.id, restarted.get_capture_node(node.id).id)

    def test_node_and_source_health_types_cannot_be_interchanged(self):
        node = self.registry.create_capture_node("Synthetic node")
        source = self.source(source_type=SourceType.REMOTE_AGENT, capture_node_id=node.id)
        for state in SourceHealthState:
            with self.assertRaises(ValidationError):
                self.registry.update_capture_node(node.id, health_state=state)
        for state in NodeHealthState:
            with self.assertRaises(ValidationError):
                self.registry.update_source_health(source.id, health_state=state)
        self.assertEqual(node, self.registry.get_capture_node(node.id))
        self.assertEqual(source, self.registry.get_source(source.id))
        with closing(self.database.connect()) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE capture_nodes SET health_state = 'manual_intervention_required' WHERE id = ?",
                    (str(node.id),),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE camera_sources SET health_state = 'revoked' WHERE id = ?",
                                   (str(source.id),))
        self.assertEqual(node, self.registry.get_capture_node(node.id))
        self.assertEqual(source, self.registry.get_source(source.id))

    def test_desired_and_negotiated_profiles_are_independent(self):
        desired = CaptureProfile(width=1920, height=1080, fps=15, codec="synthetic")
        negotiated = CaptureProfile(width=1280, height=720, fps=10, pixel_format="synthetic")
        source = self.source(desired_capture_profile=desired, capabilities={"synthetic_modes": [1, 2]})
        self.assertIsNone(source.negotiated_capture_profile)
        self.assertEqual("unknown", source.image_quality_state)
        observed = self.now.astimezone(timezone(timedelta(hours=9)))
        updated = self.registry.update_source_health(
            source.id, health_state=SourceHealthState.DEGRADED, negotiated_capture_profile=negotiated,
            image_quality_state="synthetic_low_quality", last_seen_at=observed,
        )
        self.assertEqual(desired, updated.desired_capture_profile)
        self.assertEqual(negotiated, updated.negotiated_capture_profile)
        self.assertEqual(self.now, updated.last_seen_at)
        self.assertEqual(timezone.utc, updated.last_seen_at.tzinfo)
        self.assertEqual({"synthetic_modes": [1, 2]}, updated.capabilities)
        updated = self.registry.update_source(source.id, desired_capture_profile=None, role_label=None)
        self.assertIsNone(updated.desired_capture_profile)
        self.assertEqual(negotiated, updated.negotiated_capture_profile)
        updated = self.registry.update_source_health(
            source.id, health_state=SourceHealthState.OFFLINE, negotiated_capture_profile=None, last_seen_at=None,
        )
        self.assertIsNone(updated.negotiated_capture_profile)
        self.assertIsNone(updated.last_seen_at)

    def test_multiple_versioned_bindings_round_trip_and_replace(self):
        bindings = (self.binding(), self.binding(version=2, enabled=False),
                    self.binding(kind=DetectionKind.PERSON, config={"synthetic": {"values": [1, None]}}))
        source = self.source(detection_bindings=bindings)
        actual = {item.binding_id: item for item in source.detection_bindings}
        self.assertEqual({item.binding_id: item for item in bindings}, actual)
        changed = self.binding(binding_id=bindings[0].binding_id, version=3, thresholds={"delta": -0.1})
        updated = self.registry.update_source(source.id, detection_bindings=(changed,))
        self.assertEqual((changed,), updated.detection_bindings)
        self.assertEqual((), self.registry.update_source(source.id, detection_bindings=()).detection_bindings)

    def test_input_and_output_mutation_do_not_change_persisted_config(self):
        capabilities = {"synthetic": [1]}
        config = {"synthetic": [2]}
        binding = self.binding(config=config)
        config["synthetic"].append(3)
        source = self.source(capabilities=capabilities, detection_bindings=(binding,))
        capabilities["synthetic"].append(4)
        source.capabilities["synthetic"].append(5)
        source.detection_bindings[0].config["synthetic"].append(6)
        reloaded = self.registry.get_source(source.id)
        self.assertEqual({"synthetic": [1]}, reloaded.capabilities)
        self.assertEqual({"synthetic": [2]}, reloaded.detection_bindings[0].config)

    def test_bad_profile_config_or_binding_rolls_back_update(self):
        source = self.source(detection_bindings=(self.binding(),))
        invalid_binding = self.binding()
        invalid_binding.thresholds["mutated"] = float("nan")
        for changes in (
            {"capabilities": {"bad": float("inf")}},
            {"capabilities": {"nested": {1: "bad"}}},
            {"capabilities": {"huge": "a" * 65536}},
            {"desired_capture_profile": {}},
            {"enabled": 1},
            {"role_label": ""},
            {"name": "\n"},
            {"detection_bindings": (invalid_binding,)},
            {"detection_bindings": (source.detection_bindings[0],) * 2},
        ):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValidationError):
                self.registry.update_source(source.id, **changes)
            self.assertEqual(source, self.registry.get_source(source.id))

    def test_profile_and_binding_validation(self):
        for kwargs in ({"width": 0}, {"height": True}, {"fps": float("nan")},
                       {"fps": True}, {"fps": 10**1000}, {"fps": 0}, {"bitrate_bps": -1}, {"codec": ""}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                CaptureProfile(**kwargs)
        for kwargs in ({"version": True}, {"version": 0}, {"enabled": 1},
                       {"kind": "motion"}, {"thresholds": {"bad": True}},
                       {"thresholds": {"bad": float("inf")}},
                       {"thresholds": {"bad": 10**1000}}, {"binding_id": "bad"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                self.binding(**kwargs)

    def test_health_validation_and_naive_times_leave_state_unchanged(self):
        source = self.source()
        for changes in ({"health_state": "online"}, {"last_seen_at": datetime(2026, 1, 1)},
                        {"image_quality_state": ""}, {"negotiated_capture_profile": {}}):
            arguments = {"health_state": SourceHealthState.ONLINE}
            arguments.update(changes)
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValidationError):
                self.registry.update_source_health(source.id, **arguments)
            self.assertEqual(source, self.registry.get_source(source.id))
        node = self.registry.create_capture_node("Synthetic node")
        with self.assertRaises(ValidationError):
            self.registry.update_capture_node(node.id, last_seen_at=datetime(2026, 1, 1))
        self.assertEqual(node, self.registry.get_capture_node(node.id))

    def test_missing_identity_is_explicit_without_creating_records(self):
        for method in (self.registry.get_source, self.registry.update_source,
                       self.registry.get_capture_node, self.registry.update_capture_node):
            with self.assertRaises(NotFoundError):
                method(uuid4())
            with self.assertRaises(ValidationError):
                method("bad")
        self.assertEqual((), self.registry.list_sources())

    def test_binding_storage_failure_rolls_back_metadata_and_previous_bindings(self):
        source = self.source(detection_bindings=(self.binding(),))
        with closing(self.database.connect()) as connection:
            connection.execute(
                "CREATE TRIGGER synthetic_failure BEFORE INSERT ON detection_bindings "
                "BEGIN SELECT RAISE(ABORT, 'synthetic internal detail'); END"
            )
        with self.assertRaisesRegex(RegistryError, "^camera registry storage operation failed$"):
            self.registry.update_source(source.id, name="Edited", detection_bindings=(self.binding(),))
        self.assertEqual(source, self.registry.get_source(source.id))
        with self.assertRaises(RegistryError):
            self.source(detection_bindings=(self.binding(),))
        self.assertEqual((source,), self.registry.list_sources())

    def test_restart_and_migration_preserve_sources_and_limits(self):
        node = self.registry.create_capture_node("Synthetic node")
        source = self.source(source_type=SourceType.REMOTE_AGENT, capture_node_id=node.id,
                             enabled=True, detection_bindings=(self.binding(),))
        self.registry.set_active_limit(2)
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        restarted = CameraRegistry(Database(self.database.path))
        self.assertEqual(source, restarted.get_source(source.id))
        self.assertEqual(node, restarted.get_capture_node(node.id))
        self.assertEqual(2, restarted.max_active_video_sources)

    def test_registry_migration_upgrades_existing_foundation_without_data_loss(self):
        database = Database(Path(self.directory.name) / "upgrade.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection)
            connection.execute("INSERT INTO application_metadata VALUES ('synthetic', 'preserved')")
            migrate(connection, APPLICATION_MIGRATIONS)
            self.assertEqual("preserved", connection.execute(
                "SELECT value FROM application_metadata WHERE key = 'synthetic'"
            ).fetchone()[0])
        self.assertEqual(4, CameraRegistry(database).max_active_video_sources)

    def test_concurrent_limit_decrease_and_activation_preserve_invariant(self):
        for _ in range(3):
            self.source(enabled=True)
        candidate = self.source()
        barrier = Barrier(2)

        def activate():
            barrier.wait(timeout=10)
            try:
                self.registry.update_source(candidate.id, enabled=True)
            except ActiveSourceLimitError:
                pass

        def lower_limit():
            barrier.wait(timeout=10)
            try:
                CameraRegistry(self.database).set_active_limit(3)
            except ActiveSourceLimitError:
                pass

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(activate), pool.submit(lower_limit)]
            for future in futures:
                future.result(timeout=10)
        active = sum(source.enabled for source in self.registry.list_sources())
        self.assertLessEqual(active, self.registry.max_active_video_sources)
        self.assertGreaterEqual(active, 3)

    def test_json_cycles_and_excessive_structure_are_rejected(self):
        cyclic = {"synthetic": []}
        cyclic["synthetic"].append(cyclic)
        for capabilities in (cyclic, {"synthetic": [0] * 8192}):
            with self.assertRaises(ValidationError):
                self.source(capabilities=capabilities)
        self.assertEqual((), self.registry.list_sources())

    def test_database_constraints_preserve_node_relationships(self):
        source = self.source()
        with closing(self.database.connect()) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE camera_sources SET source_type = 'remote_agent' WHERE id = ?",
                                   (str(source.id),))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE camera_sources SET source_type = 'remote_agent', capture_node_id = ? WHERE id = ?",
                    (str(uuid4()), str(source.id)),
                )
        self.assertEqual(source, self.registry.get_source(source.id))


if __name__ == "__main__":
    unittest.main()
