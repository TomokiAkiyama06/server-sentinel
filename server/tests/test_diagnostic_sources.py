"""Issue #49 production diagnostic producers over synthetic deployment data.

Every value seeded here is a generated canary: no real camera, serial, Slack
workspace, pairing code, biometric template or monitoring media is used.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4
from zipfile import ZipFile
from zoneinfo import ZoneInfo
import zlib

from app.audit import AuditStore, DenyAllOwners, OwnerAuditService
from app.audit.runtime import AuditRetentionHealth
from app.auth.store import AccessStore
from app.cameras.registry import CameraRegistry
from app.cameras.registry.models import NodeHealthState, SourceHealthState, SourceType
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.detection.owner.contracts import Operation
from app.detection.owner.store import OwnerTemplateStore
from app.diagnostics import (
    DiagnosticCategory,
    DiagnosticExportAction,
    DiagnosticExportError,
    DiagnosticExportService,
    DiagnosticField,
    DiagnosticFieldKind,
    SafeDiagnosticFieldName,
)
from app.diagnostics.export import _COUNT_FIELDS, _REASON_FIELDS, _STATE_FIELDS
from app.diagnostics.sources import (
    AuditDeliveryAdapter,
    CameraRegistryAdapter,
    CompositeDiagnosticSource,
    DiagnosticSourceUnavailable,
    IntegrityAdapter,
    MonitoringRuntimeAdapter,
    OwnerWorkerCalls,
    RecordingHealthAdapter,
    RecordingSegmentMediaSource,
    StorageAdapter,
    VersionAdapter,
    compose_diagnostic_sources,
    segment_media_id,
)
from app.integrity.model import Component, Finding, Inventory, Kind, State
from app.media.health.service import HealthState
from app.media.recording import Segment
from app.media.recording.model import Limits
from app.media.recording.store import RootIdentity
from app.monitoring.config import MonitoringConfiguration, RecordingFilesystem
from app.monitoring.runtime import (
    MonitoringDependencies, MonitoringRuntime, MonitoringStatus, RuntimeState,
)
from app.settings import Settings
from app.storage.database import Database
from app.storage.policy import StorageLimits, StorageState
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.test_owner_verification import PROVENANCE
from tests.test_recording import SyntheticValidator
from tests.test_storage_notifications import Transport, endpoint


CANARY_CAMERA_NAME = "CANARY-camera-name-backdoor-lab"
CANARY_ROLE = "CANARY-role-label-server-rack"
CANARY_NODE_NAME = "CANARY-capture-node-hostname"
CANARY_SERIAL = "CANARY-UVC-SERIAL-0000-1111"
CANARY_DEVICE_PATH = "/dev/v4l/by-id/CANARY-device-path"
CANARY_HARDWARE_SERIAL = "CANARY-HW-DISK-SERIAL-9999"
CANARY_TEMPLATE = b"CANARY-OWNER-BIOMETRIC-TEMPLATE-BYTES"
CANARY_FINDING_REASON = "CANARY_FREEFORM_FINDING_REASON"
KEY_DIGEST = "a" * 64
PAYLOAD = b"generated geometric test payload" * 4


def values(documents):
    return {document.category.value: {field.name: str(field.value)
                                      for field in document.fields}
            for document in documents}


def states(documents):
    return {name: value for fields in values(documents).values()
            for name, value in fields.items()
            if name in _STATE_FIELDS}


@dataclass
class FakeMonitoring:
    status: MonitoringStatus
    integrity_store: object = None
    recordings: object = None


class StoreFindings:
    def __init__(self, latest):
        self._latest = latest

    def latest(self):
        return self._latest


class ProducerMappingTests(unittest.TestCase):
    def test_every_new_field_name_is_bound_to_exactly_one_reviewed_value_type(self):
        typed = (_STATE_FIELDS, _REASON_FIELDS, _COUNT_FIELDS)
        for name in SafeDiagnosticFieldName:
            memberships = sum(name in group for group in typed)
            if name in {SafeDiagnosticFieldName.VERSION, SafeDiagnosticFieldName.COMPONENT,
                        SafeDiagnosticFieldName.ENABLED}:
                self.assertEqual(memberships, 0, name)
            else:
                self.assertEqual(memberships, 1, name)
        # Typed names cannot carry a free-form string even when allowlisted.
        for name in (SafeDiagnosticFieldName.CAMERA_REGISTRY_STATE,
                     SafeDiagnosticFieldName.INTEGRITY_CPU_REASON_CODE,
                     SafeDiagnosticFieldName.CAMERA_SOURCES_TOTAL):
            with self.assertRaises((TypeError, ValueError)):
                DiagnosticField(name.value, CANARY_CAMERA_NAME)

    def test_absent_subsystems_report_unavailable_and_never_ok(self):
        composition = compose_diagnostic_sources()
        documents = composition.source.collect()
        reported = states(documents)
        self.assertTrue(reported)
        self.assertEqual(set(reported.values()), {"unavailable"})
        by_category = values(documents)
        self.assertEqual(by_category["runtime"]["monitoring.reason_code"], "not_configured")
        self.assertEqual(by_category["camera_health"]["camera_registry.reason_code"],
                         "not_configured")
        # No counts are invented for an absent subsystem.
        self.assertFalse(any(name in _COUNT_FIELDS for fields in by_category.values()
                             for name in fields))
        self.assertIsNone(composition.media_source)

    def test_raising_subsystem_is_unavailable_and_its_message_is_never_relayed(self):
        class BrokenRegistry:
            def list_sources(self):
                raise RuntimeError(CANARY_CAMERA_NAME)

        class BrokenMonitoring:
            @property
            def status(self):
                raise RuntimeError(CANARY_NODE_NAME)

        class BrokenAudit:
            @property
            def undelivered_audit_records(self):
                raise RuntimeError(CANARY_SERIAL)

        source = compose_diagnostic_sources(
            registry=BrokenRegistry(), monitoring=BrokenMonitoring(),
            owner_audit=BrokenAudit()).source
        documents = source.collect()
        reported = states(documents)
        self.assertNotIn("ok", reported.values())
        self.assertEqual(reported["camera_registry.state"], "unavailable")
        self.assertEqual(reported["monitoring.state"], "unavailable")
        self.assertEqual(reported["audit.owner.state"], "unavailable")
        self.assertEqual(values(documents)["camera_health"]["camera_registry.reason_code"],
                         "dependency_unavailable")
        text = json.dumps(values(documents))
        for canary in (CANARY_CAMERA_NAME, CANARY_NODE_NAME, CANARY_SERIAL):
            self.assertNotIn(canary, text)

    def test_counter_that_is_not_a_bounded_integer_is_unavailable(self):
        class Recorder:
            audit_delivery_failed = False
            undelivered_audit_records = True

        documents = CompositeDiagnosticSource((AuditDeliveryAdapter(
            Recorder(), SafeDiagnosticFieldName.AUDIT_ACCESS_STATE,
            SafeDiagnosticFieldName.AUDIT_ACCESS_UNDELIVERED),)).collect()
        self.assertEqual(values(documents), {"security": {"audit.access.state": "unavailable"}})

    def test_undelivered_audit_records_degrade_security_health(self):
        class Recorder:
            audit_delivery_failed = True
            undelivered_audit_records = 3

        documents = compose_diagnostic_sources(pairing_audit=Recorder()).source.collect()
        security = values(documents)["security"]
        self.assertEqual(security["audit.pairing.state"], "degraded")
        self.assertEqual(security["audit.pairing.undelivered_records"], "3")

    def test_a_production_adapter_cannot_contribute_a_classified_field(self):
        class LeakyVersion(VersionAdapter):
            def read(self):
                return (DiagnosticField("hardware_identifier.camera_serial", CANARY_SERIAL),)

        documents = CompositeDiagnosticSource((LeakyVersion(),)).collect()
        self.assertEqual(documents, ())

    def test_monitoring_job_flags_are_healthy_only_while_the_runtime_runs(self):
        for runtime_state in (RuntimeState.STARTING, RuntimeState.FAILED,
                              RuntimeState.STOPPED):
            with self.subTest(runtime_state=runtime_state):
                monitoring = FakeMonitoring(MonitoringStatus(runtime_state))
                documents = CompositeDiagnosticSource((
                    MonitoringRuntimeAdapter(monitoring), StorageAdapter(monitoring),
                    RecordingHealthAdapter(monitoring),
                    IntegrityAdapter(monitoring, StoreFindings(None).latest),
                )).collect()
                self.assertNotIn("ok", states(documents).values())

        failed = FakeMonitoring(MonitoringStatus(
            RuntimeState.FAILED, recording_filesystem_ok=False,
            recording_health=HealthState.FAILED))
        documents = CompositeDiagnosticSource((
            StorageAdapter(failed), RecordingHealthAdapter(failed))).collect()
        reported = values(documents)
        self.assertEqual(reported["storage"]["recording_filesystem.state"], "failed")
        self.assertEqual(reported["recording_health"]["recording_health.state"], "failed")
        self.assertEqual(reported["recording_health"]["recording_health.reason_code"],
                         "self_test_failed")

    def test_running_monitoring_maps_storage_and_recording_health_verdicts(self):
        monitoring = FakeMonitoring(MonitoringStatus(
            RuntimeState.RUNNING, storage_state=StorageState.HARD_STOP,
            storage_audit_failed=True, recording_filesystem_ok=True,
            recording_health=HealthState.UNAVAILABLE, notification_delivery_failed=True))
        documents = CompositeDiagnosticSource((
            MonitoringRuntimeAdapter(monitoring), StorageAdapter(monitoring),
            RecordingHealthAdapter(monitoring))).collect()
        reported = values(documents)
        self.assertEqual(reported["runtime"]["monitoring.state"], "ok")
        self.assertEqual(reported["runtime"]["notification.delivery_state"], "degraded")
        self.assertEqual(reported["storage"]["storage.state"], "failed")
        self.assertEqual(reported["storage"]["storage.reason_code"], "storage_hard_stop")
        self.assertEqual(reported["storage"]["storage.audit_delivery_state"], "degraded")
        self.assertEqual(reported["recording_health"]["recording_health.state"], "unavailable")

        unobserved = FakeMonitoring(MonitoringStatus(RuntimeState.RUNNING))
        documents = CompositeDiagnosticSource((
            StorageAdapter(unobserved), RecordingHealthAdapter(unobserved))).collect()
        reported = values(documents)
        self.assertEqual(reported["storage"]["storage.state"], "unknown")
        self.assertEqual(reported["recording_health"]["recording_health.state"], "unknown")

    def test_integrity_verdicts_exclude_reasons_and_treat_unreported_kinds_as_unverifiable(self):
        monitoring = FakeMonitoring(MonitoringStatus(RuntimeState.RUNNING))
        findings = (Finding(Kind.CPU, State.OK, CANARY_FINDING_REASON),
                    Finding(Kind.MEMORY, State.OK, "OK"),
                    Finding(Kind.GPU, State.NEW_DEVICE, CANARY_FINDING_REASON))
        documents = CompositeDiagnosticSource((IntegrityAdapter(
            monitoring, StoreFindings((findings, True)).latest),)).collect()
        integrity = values(documents)["hardware_inventory"]
        self.assertEqual(integrity["integrity.cpu.reason_code"], "none")
        self.assertEqual(integrity["integrity.gpu.reason_code"], "hardware_new_device")
        # STORAGE was not reported: unverifiable storage is an immediate fault.
        self.assertEqual(integrity["integrity.storage.reason_code"], "hardware_unverifiable")
        self.assertEqual(integrity["integrity.state"], "failed")
        self.assertEqual(integrity["integrity.delivery_state"], "degraded")
        self.assertNotIn(CANARY_FINDING_REASON, json.dumps(integrity))

        missing = (Finding(Kind.CPU, State.MISSING, "x"), Finding(Kind.MEMORY, State.OK, "x"),
                   Finding(Kind.STORAGE, State.OK, "x"), Finding(Kind.GPU, State.OK, "x"))
        documents = CompositeDiagnosticSource((IntegrityAdapter(
            monitoring, StoreFindings((missing, False)).latest),)).collect()
        integrity = values(documents)["hardware_inventory"]
        self.assertEqual((integrity["integrity.state"], integrity["integrity.reason_code"]),
                         ("failed", "hardware_missing"))

        documents = CompositeDiagnosticSource((IntegrityAdapter(
            monitoring, StoreFindings(None).latest),)).collect()
        self.assertEqual(values(documents)["hardware_inventory"]["integrity.state"], "unknown")

    def test_malformed_version_is_omitted_rather_than_relayed(self):
        documents = CompositeDiagnosticSource((VersionAdapter(CANARY_NODE_NAME),)).collect()
        self.assertEqual(documents, ())


class RegistryCountTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sentinel-generated-registry-")
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "metadata.sqlite3")
        from app.storage.migrations import migrate
        connection = self.database.connect()
        try:
            migrate(connection, APPLICATION_MIGRATIONS)
        finally:
            connection.close()
        self.registry = CameraRegistry(self.database, unaudited_writes=True)

    def seed(self):
        node = self.registry.create_capture_node(CANARY_NODE_NAME)
        self.registry.update_capture_node(node.id, health_state=NodeHealthState.ONLINE)
        capabilities = {"serial": CANARY_SERIAL, "device_path": CANARY_DEVICE_PATH}
        local = self.registry.create_source(
            source_type=SourceType.LOCAL_UVC, name=CANARY_CAMERA_NAME, role_label=CANARY_ROLE,
            enabled=True, capabilities=capabilities)
        remote = self.registry.create_source(
            source_type=SourceType.REMOTE_AGENT, name=CANARY_CAMERA_NAME + "-2",
            capture_node_id=node.id, enabled=True, capabilities=capabilities)
        self.registry.create_source(
            source_type=SourceType.LOCAL_UVC, name=CANARY_CAMERA_NAME + "-3",
            enabled=False, capabilities=capabilities)
        self.registry.update_source_health(local.id, health_state=SourceHealthState.ONLINE)
        self.registry.update_source_health(
            remote.id, health_state=SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
            image_quality_state=CANARY_ROLE)

    def test_counts_by_type_and_enabled_health_without_names_serials_or_paths(self):
        self.seed()
        documents = CompositeDiagnosticSource((CameraRegistryAdapter(self.registry),)).collect()
        camera = values(documents)["camera_health"]
        self.assertEqual(camera, {
            "camera_registry.state": "degraded",
            "camera_registry.reason_code": "manual_intervention_required",
            "camera_sources.total": "3",
            "camera_sources.enabled": "2",
            "camera_sources.local_uvc": "2",
            "camera_sources.remote_agent": "1",
            "camera_sources.online": "1",
            "camera_sources.degraded": "0",
            "camera_sources.offline": "0",
            "camera_sources.manual_intervention_required": "1",
            "camera_sources.active_limit": "4",
        })
        text = json.dumps(camera)
        for canary in (CANARY_CAMERA_NAME, CANARY_ROLE, CANARY_NODE_NAME, CANARY_SERIAL,
                       CANARY_DEVICE_PATH, "/dev/video"):
            self.assertNotIn(canary, text)

    def test_no_enabled_source_is_unavailable_not_ok(self):
        documents = CompositeDiagnosticSource((CameraRegistryAdapter(self.registry),)).collect()
        camera = values(documents)["camera_health"]
        self.assertEqual(camera["camera_registry.state"], "unavailable")
        self.assertEqual(camera["camera_sources.total"], "0")


class MediaSelectionTests(unittest.TestCase):
    def setUp(self):
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.worker.shutdown)
        self.calls = OwnerWorkerCalls(self.worker, timeout_seconds=5)

        class Store:
            def __init__(inner_self):
                inner_self.requests = []

            def segment_length(inner_self, segment):
                inner_self.requests.append(segment)
                return 10

        self.store = Store()
        self.media = RecordingSegmentMediaSource(lambda: self.store, self.calls)

    def test_only_segment_ids_resolve_so_biometric_or_other_namespaces_cannot(self):
        for media_id in ("owner_biometric.template", "owner_biometric.embedding",
                         "owner-template.sqlite3", "raw_monitoring_media.face_crop",
                         "segment." + "A" * 32, "segment." + "0" * 31, "segment",
                         "self_test.artifact", "../segment." + "0" * 32):
            with self.subTest(media_id=media_id):
                with self.assertRaises(DiagnosticSourceUnavailable):
                    self.media.describe_selected(media_id)
        self.assertEqual(self.store.requests, [])

    def test_describe_runs_on_the_owning_worker_and_open_refuses_other_threads(self):
        segment = uuid4()
        observed = []
        self.store.segment_length = lambda item: (observed.append(threading.get_ident()), 7)[1]
        descriptor = self.media.describe_selected(segment_media_id(segment))
        self.assertEqual(descriptor.size_bytes, 7)
        worker_thread = self.worker.submit(threading.get_ident).result()
        self.assertEqual(observed, [worker_thread])
        with self.assertRaises(DiagnosticSourceUnavailable):
            with self.media.open_selected(segment_media_id(segment)):
                pass

    def test_owner_calls_refuse_a_worker_that_changes_threads(self):
        class DriftingWorker:
            def __init__(inner_self):
                inner_self.executors = [ThreadPoolExecutor(1), ThreadPoolExecutor(1)]

            def submit(inner_self, call):
                return inner_self.executors.pop(0).submit(call)

        calls = OwnerWorkerCalls(DriftingWorker(), timeout_seconds=5)
        self.assertEqual(calls.run(lambda: 1), 1)
        with self.assertRaises(DiagnosticSourceUnavailable):
            calls.run(lambda: 2)


class OwnerAuthorization:
    async def require_owner_caller(self, action):
        return None

    async def require_owner_export(self, action, confirmation):
        self.confirmation = confirmation


class PairingOwner:
    def require_owner(self, actor_context):
        return None


class TemplateOwner:
    def require_owner(self, operation):
        return UUID(int=123)


class CanaryProbe:
    """Generated inventory whose private identity must never be exported."""

    def collect(self):
        return Inventory((Component(
            Kind.STORAGE, CANARY_DEVICE_PATH, (("model", CANARY_ROLE),),
            (("serial", CANARY_HARDWARE_SERIAL),)),), frozenset())


class NetworkUsed(AssertionError):
    pass


class ComposedExportTests(unittest.IsolatedAsyncioTestCase):
    """The composed producers behind the real export service and runtime."""

    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sentinel-generated-diagnostics-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        self.base = base
        state, recordings, self.output, private = (
            base / "state", base / "recordings", base / "exports", base / "owner-private")
        for path in (state, recordings, self.output, private):
            path.mkdir(mode=0o700)
        device = recordings.stat().st_dev
        self.slack = endpoint()
        configuration = MonitoringConfiguration(
            time_zone=ZoneInfo("UTC"), slack=self.slack,
            storage_limits=StorageLimits(
                recording_limit_bytes=10_000_000, critical_allowance_bytes=100_000,
                hard_reserve_bytes=4096, pressure_free_bytes=8192,
                recovery_free_bytes=16_384, recovery_allocation_bytes=90_000,
                write_overhead_bytes=4096, max_request_bytes=1_000_000,
                cleanup_batch_size=10),
            recording_limits=Limits(
                pre_roll_bytes=4096, max_segment_bytes=512, max_segment_ms=30_000,
                max_active_recordings=8, max_spool_segments=16,
                max_segments_per_recording=100),
            recording_filesystem=RecordingFilesystem(
                recordings, "00000000-1111-2222-3333-444444444444",
                (os.major(device), os.minor(device)), recordings.parent,
                lambda uuid: device, lambda path: True),
        )
        self.transport = Transport()
        self.settings = Settings(state)
        self.database = Database(self.settings.database_path)
        self.runtime = MonitoringRuntime(
            configuration, self.database, MonitoringDependencies(
                integrity_probe=CanaryProbe(), segment_validator=SyntheticValidator(),
                slack_opener=self.transport, tick_seconds=3600.0),
            migrations=APPLICATION_MIGRATIONS)
        await self.runtime.start()
        self.addAsyncCleanup(self.runtime.stop)
        self.assertEqual(self.runtime.status.state, RuntimeState.RUNNING)

        runtime = self.runtime

        class RuntimeWorker:
            def submit(inner_self, call):
                return runtime._executor.submit(call)

        self.worker = RuntimeWorker()
        self.segment = await self.runtime.call(self.runtime.recordings.append, Segment(
            source_id=uuid4(), stream_id=uuid4(), sequence=0, start_ms=30_000,
            end_ms=40_000, codec="synthetic", container="deflate",
            data=zlib.compress(PAYLOAD)))

        registry = CameraRegistry(self.database, unaudited_writes=True)
        node = registry.create_capture_node(CANARY_NODE_NAME)
        registry.create_source(
            source_type=SourceType.REMOTE_AGENT, name=CANARY_CAMERA_NAME,
            capture_node_id=node.id, role_label=CANARY_ROLE, enabled=True,
            capabilities={"serial": CANARY_SERIAL, "device_path": CANARY_DEVICE_PATH})
        audit = AuditStore(self.database, reservation=self.runtime.reservation)
        self.pairing = PairingLedger(self.database, HmacCodeVerifier(b"g" * 32), audit=audit)
        _, code = self.pairing.approve(PairingOwner(), "synthetic-owner", node_id=node.id,
                                       public_key_digest=KEY_DIGEST)
        self.pairing_code = code.value

        template_store = OwnerTemplateStore(
            private, max_template_bytes=1024, reservation=self.runtime.reservation,
            authorizer=TemplateOwner())
        self.addCleanup(template_store.close)
        template_store._replace(
            CANARY_TEMPLATE, PROVENANCE, operation=Operation.ENROLL, actor=UUID(int=123),
            expected_generation=0, at=datetime(2026, 1, 1, tzinfo=timezone.utc))

        retention = type("Retention", (), {"health": AuditRetentionHealth.HEALTHY})()
        self.composition = compose_diagnostic_sources(
            monitoring=self.runtime, registry=registry,
            owner_audit=OwnerAuditService(audit, DenyAllOwners()),
            access_audit=AccessStore(self.database, audit=audit),
            pairing_audit=self.pairing, audit_retention=retention,
            owner_worker=self.worker, owner_call_timeout_seconds=10)
        info = recordings.stat()
        self.approved_filesystem = RootIdentity(info.st_dev, info.st_ino)
        self.service = DiagnosticExportService(
            OwnerAuthorization(), self.composition.source, self.runtime._policy,
            self.worker, self.approved_filesystem, self.composition.media_source)

    def canaries(self):
        return (CANARY_CAMERA_NAME, CANARY_ROLE, CANARY_NODE_NAME, CANARY_SERIAL,
                CANARY_DEVICE_PATH, CANARY_HARDWARE_SERIAL, self.pairing_code,
                self.slack.url,
                "hooks.slack.com", "generated_dummy_value", str(self.base),
                str(self.segment), self.segment.hex)

    async def export(self, selected=()):
        # Attempts are recorded, not only raised: a producer that swallowed the
        # error into an `unavailable` fallback must still fail the test.
        attempts = []

        def forbid_network(*args, **kwargs):
            attempts.append(True)
            raise NetworkUsed("diagnostic export attempted network use")

        try:
            with patch.object(socket.socket, "connect", forbid_network), \
                    patch.object(socket.socket, "connect_ex", forbid_network), \
                    patch.object(socket.socket, "sendto", forbid_network), \
                    patch.object(socket, "create_connection", forbid_network), \
                    patch.object(socket, "getaddrinfo", forbid_network):
                return await self.service.export(
                    DiagnosticExportAction(self.output, selected))
        finally:
            self.assertEqual(attempts, [])

    async def test_network_guard_detects_a_producer_that_swallows_network_errors(self):
        class Phoning(VersionAdapter):
            def read(self):
                socket.create_connection(("192.0.2.1", 443), timeout=0.01)
                return ()

        self.service = DiagnosticExportService(
            OwnerAuthorization(), CompositeDiagnosticSource((Phoning(),)),
            self.runtime._policy, self.worker, self.approved_filesystem)
        with self.assertRaises(AssertionError):
            await self.export()

    def assert_no_canary(self, raw: bytes):
        for canary in self.canaries():
            self.assertNotIn(canary.encode(), raw, canary)
        self.assertNotIn(CANARY_TEMPLATE, raw)
        self.assertNotIn(b"owner-template", raw)

    async def test_default_bundle_has_health_but_no_private_value_media_or_network(self):
        # Positive control: the canaries really exist in deployment storage.
        database = self.settings.database_path.read_bytes()
        self.assertIn(CANARY_CAMERA_NAME.encode(), database)
        self.assertIn(CANARY_SERIAL.encode(), database)
        self.assertIn(CANARY_TEMPLATE, (
            self.base / "owner-private" / "owner-template.sqlite3").read_bytes())
        sent_before = len(self.transport.requests)
        result = await self.export()
        raw = result.bundle_path.read_bytes()
        self.assert_no_canary(raw)
        with ZipFile(result.bundle_path) as archive:
            names = archive.namelist()
            manifest = json.loads(archive.read("manifest.json"))
            documents = {name: json.loads(archive.read(name)) for name in names
                         if name.startswith("diagnostics/")}
        self.assertFalse(any(name.startswith("media/") for name in names))
        self.assertIn({"category": "raw_monitoring_media", "reason": "not_owner_selected"},
                      manifest["exclusions"])
        self.assertEqual(set(documents), {
            f"diagnostics/{category.value}.json" for category in DiagnosticCategory})
        self.assertEqual(documents["diagnostics/runtime.json"]["monitoring.state"], "ok")
        self.assertEqual(documents["diagnostics/camera_health.json"]["camera_sources.total"], 1)
        self.assertEqual(documents["diagnostics/security.json"]["audit.retention.state"], "ok")
        self.assertIn(documents["diagnostics/hardware_inventory.json"]["integrity.state"],
                      {"ok", "degraded", "failed", "unknown"})
        # No automatic upload: nothing reached even the intercepted Slack opener.
        self.assertEqual(len(self.transport.requests), sent_before)
        self.assertEqual(result.included_media_count, 0)

    async def test_only_an_owner_selected_segment_is_copied(self):
        result = await self.export((segment_media_id(self.segment),))
        with ZipFile(result.bundle_path) as archive:
            media = [name for name in archive.namelist() if name.startswith("media/")]
            self.assertEqual(media, ["media/0001.bin"])
            self.assertEqual(archive.read("media/0001.bin"), zlib.compress(PAYLOAD))
            manifest = archive.read("manifest.json")
        self.assertNotIn(self.segment.hex.encode(), manifest)
        self.assertEqual(result.included_media_count, 1)
        self.assert_no_canary(manifest)

    async def test_biometric_or_unknown_media_selection_is_refused_without_a_bundle(self):
        for selected in (("owner_biometric.template",), ("owner_biometric.embedding",),
                         (segment_media_id(uuid4()),)):
            with self.subTest(selected=selected):
                with self.assertRaises(DiagnosticExportError):
                    await self.export(selected)
                self.assertEqual(list(self.output.iterdir()), [])

    async def test_a_replaced_or_linked_segment_file_is_not_copied(self):
        stored = self.base / "recordings" / (self.segment.hex + ".seg")
        os.link(stored, self.base / "linked-copy.seg")
        with self.assertRaises(DiagnosticExportError):
            await self.export((segment_media_id(self.segment),))
        self.assertEqual(list(self.output.iterdir()), [])
        os.unlink(self.base / "linked-copy.seg")
        original = stored.read_bytes()
        stored.unlink()
        os.symlink(self.base / "state", stored)
        with self.assertRaises(DiagnosticExportError):
            await self.export((segment_media_id(self.segment),))
        self.assertEqual(list(self.output.iterdir()), [])
        stored.unlink()
        stored.write_bytes(original)
        stored.chmod(0o600)
        result = await self.export((segment_media_id(self.segment),))
        self.assertEqual(result.included_media_count, 1)

    async def test_integrity_verdicts_are_read_on_the_owning_worker(self):
        latest = await self.runtime.call(self.runtime.integrity_store.latest)
        self.assertIsNotNone(latest)
        with self.assertRaises(RuntimeError):
            self.runtime.integrity_store.latest()

    def test_composed_fields_are_all_reviewed_safe_scalars(self):
        for document in self.composition.source.collect():
            for field in document.fields:
                self.assertIs(field.kind, DiagnosticFieldKind.SAFE)
                self.assertIn(field.name, {item.value for item in SafeDiagnosticFieldName})


if __name__ == "__main__":
    unittest.main()
