"""Issue #205: Owner scene calibration and the restart re-acquisition.

Owner decision 2026-10-22 (option A): after a Main restart the reference is
re-acquired from the camera and the Owner is notified; nothing derived from
an image is written to disk. Every pixel here is generated in memory; the
database is a disposable SQLite file. No camera, real scene or person is used.
"""

import asyncio
import hashlib
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path
from uuid import UUID, uuid4

from app.cameras.registry.models import SourceType
from app.cameras.uvc.capture import VideoFrame
from app.detection.roi import CalibrationArchive
from app.detection.roi.calibration import (
    append_on, calibration_metadata, decode_history_row, provenance, scrub_legacy_reference_digests,
)
from app.detection.roi.calibration_service import (
    REACQUIRED, REQUIRED, CalibrationOrigin, Notice, CalibrationPhase, CalibrationRefused,
    CalibrationTemplate, SceneCalibrationConfiguration, SceneCalibrationService, TransientReferences,
)
from app.detection.roi.mjpg import MjpgLumaLayout
from app.detection.roi.runtime import (
    ArchiveCalibrationProvider, PackedLumaLayout, ReferenceUnavailable, SceneMonitoringConfiguration,
    SceneMonitoringDependencies, SceneMonitoringRuntime, SceneRuntimeState, SceneSourceState, reader_identity,
)
from app.detection.roi.mjpg_worker import NUMPY_VERSION, SIMPLEJPEG_VERSION
from app.logging import Event
from app.main import create_app
from app.monitoring.runtime import MonitoringDependencies
from app.notifications.service import NotificationService
from app.notifications.slack import DeliveryResult
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_detector_roi import HEIGHT, POLYGON, WIDTH, frame_digests, near_dark, pixels, policy
from tests.test_scene_runtime import (
    INTERVAL, OTHER, SOURCE, Harness, Recorder, binding, calibration_for, quality, unattainable, yuyv,
)
from tests.test_monitoring_runtime import RuntimeFixture
from tests.test_scene_timeline import refuse_outbox_open, timeline_configuration
from tests.test_recording import SyntheticValidator
from tests.test_uvc_runtime import wait_for


RULES = policy(maximum_gap_ns=10_000_000_000, confirmation_ns=1)
REMOTE_READER = "decoded:remote_agent"


def template(source=OTHER, **changes):
    values = dict(width=WIDTH, height=HEIGHT, polygon=POLYGON, policy=RULES)
    values.update(changes)
    return CalibrationTemplate(source, **values)


def stored(source=OTHER, *, version=1, reader=REMOTE_READER, identifier=UUID(int=700),
           source_type=SourceType.REMOTE_AGENT):
    """A calibration as an earlier process stored it (provenance only)."""
    item = binding(source, source_type)
    calibration = replace(calibration_for(item, rules=RULES, version=version), reader=reader,
                          identifier=identifier)
    return calibration


class Feed:
    """Offers generated luma to a decoded-sample source from its own thread."""

    def __init__(self, runtime, source=OTHER, luma=None, period=0.005):
        self.runtime, self.source, self.period = runtime, source, period
        self.luma = luma or pixels()
        self.stream = uuid4()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.is_set():
            self.runtime.offer_luma(self.source, stream_id=self.stream, width=WIDTH, height=HEIGHT,
                                    pixels=self.luma)
            time.sleep(self.period)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *details):
        self.stop.set()
        self.thread.join(5)


class Database_:
    def __init__(self, test):
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)

    def store(self, calibration):
        with closing(self.database.connect()) as connection:
            CalibrationArchive(connection).append(calibration)

    def history(self, source=OTHER):
        with closing(self.database.connect()) as connection:
            return [decode_history_row(row) for row in connection.execute(
                "SELECT source_id, profile_id, version, identifier, metadata FROM roi_calibration_history "
                "WHERE source_id=? ORDER BY version", (str(source),))]

    def raw(self):
        return database_bytes(self.database.path)


def database_bytes(path):
    """The database file with any WAL or rollback journal beside it."""
    path = Path(path)
    return b"".join(candidate.read_bytes() for candidate in
                    (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-journal"))
                    if candidate.exists())


def store_legacy(path, calibration):
    """Store `calibration` as a pre-#205 build did: with its frame digest."""
    database = Database(Path(path))
    with closing(database.connect()) as connection:
        migrate(connection, APPLICATION_MIGRATIONS)
        connection.execute("BEGIN IMMEDIATE")
        append_on(connection, calibration)
        value = calibration_metadata(calibration)
        value["reference"]["sha256"] = hashlib.sha256(calibration.reference.pixels).hexdigest()
        connection.execute("UPDATE roi_calibration_history SET metadata=? WHERE source_id=? AND version=?",
                           (json.dumps(value, sort_keys=True), str(calibration.source_id),
                            calibration.version))
        connection.execute("COMMIT")


def assert_no_frame_trace(test, raw, luma=None):
    """Neither the reference pixels nor any digest of them reached the disk."""
    luma = pixels() if luma is None else luma
    test.assertNotIn(luma, raw)
    for trace in frame_digests(luma):
        test.assertNotIn(trace, raw)


def commit_with(database, log=None):
    """A synthetic audited commit: prepare, then persist in one transaction."""
    def commit(source_id, prepare, persist):
        calibration = prepare()
        with closing(database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                record = persist(connection, calibration)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        if log is not None:
            log.append(source_id)
        return record
    return commit


class Service:
    """A threaded runtime with one decoded-sample source and its service."""

    def __init__(self, test, database, *, templates=None, quality_policy=None, timeout=5.0,
                 reacquire_timeout=5.0, start=True):
        self.references = TransientReferences()
        movement = quality_policy or quality("server_roi")
        tamper = (quality_policy and replace(quality_policy, detector="camera_tamper")
                  or quality("camera_tamper"))
        remote = binding(OTHER, SourceType.REMOTE_AGENT, sample_interval_ns=1_000_000,
                         movement_quality=movement, tamper_quality=tamper)
        self.recorder = Recorder()
        self.runtime = SceneMonitoringRuntime(
            SceneMonitoringConfiguration((remote,)),
            SceneMonitoringDependencies(
                recorder=self.recorder, tick_seconds=0.01,
                calibrations=ArchiveCalibrationProvider(database.connect_read_only,
                                                        references=self.references)))
        configuration = SceneCalibrationConfiguration(
            (template(),) if templates is None else templates,
            acquisition_timeout_seconds=timeout, reacquire_timeout_seconds=reacquire_timeout)
        self.service = SceneCalibrationService(configuration, self.runtime, database.connect_read_only,
                                               references=self.references)
        if start:
            self.runtime.start()
        test.addCleanup(self.close)

    def close(self):
        self.service.close()
        self.runtime.stop()

    def status(self):
        (item,) = self.service.status()
        return item

    def source(self):
        (item,) = self.runtime.status().sources
        return item


class RuntimeAcquisitionTests(unittest.TestCase):
    """`SceneMonitoringRuntime.acquire_reference` on an unthreaded runtime."""

    def test_reference_is_a_later_frame_both_gates_report_sufficient(self):
        harness = Harness(calibrations=None)
        harness.runtime.start()
        harness.frame()
        future = harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=10 * INTERVAL)
        # Quality recovery needs two consecutive good samples captured after
        # the request; the sample before it is never used.
        harness.frame()
        self.assertFalse(future.done())
        harness.frame()
        frame = future.result(0)
        self.assertEqual((frame.source_id, frame.width, frame.height, frame.pixels),
                         (SOURCE, WIDTH, HEIGHT, pixels()))
        self.assertEqual(2, frame.sequence)
        # The source itself stays inactive: acquisition binds nothing.
        self.assertIs(SceneSourceState.INACTIVE, harness.source().state)

    def test_deadline_without_frames_is_no_frame_and_with_poor_frames_quality(self):
        harness = Harness(calibrations=None)
        harness.runtime.start()
        future = harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=3 * INTERVAL)
        harness.clock.value += 4 * INTERVAL
        harness.runtime.step()
        with self.assertRaises(ReferenceUnavailable) as raised:
            future.result(0)
        self.assertEqual("no_frame", raised.exception.reason)
        poor = Harness(binding(movement_quality=unattainable("server_roi")), calibrations=None)
        poor.runtime.start()
        future = poor.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=3 * INTERVAL)
        for _ in range(4):
            poor.frame()
        with self.assertRaises(ReferenceUnavailable) as raised:
            future.result(0)
        self.assertEqual("quality_insufficient", raised.exception.reason)

    def test_a_camera_loss_restarts_the_consecutive_good_samples(self):
        harness = Harness(calibrations=None)
        harness.runtime.start()
        future = harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=100 * INTERVAL)
        harness.frame()
        harness.runtime.source_unavailable(SOURCE, trusted=True)
        harness.frame()
        self.assertFalse(future.done())
        harness.frame()
        self.assertTrue(future.done())

    def held_sample(self, harness):
        """A sample offered to the slot but not yet handled by the worker."""
        harness.clock.value += INTERVAL
        number = harness.sequence.get(SOURCE, 0) + 1
        harness.sequence[SOURCE] = number
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(pixels()), number, 0.0))
        harness.clock.value += 1

    def test_a_sample_captured_before_the_request_is_never_used(self):
        # Claude review 5: still unprocessed in its slot when the request
        # arrives, so only the capture time can exclude it.
        harness = Harness(calibrations=None)
        harness.runtime.start()
        self.held_sample(harness)
        future = harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=100 * INTERVAL)
        harness.runtime.step()
        harness.frame()
        self.assertFalse(future.done())
        harness.frame()
        self.assertEqual(2, future.result(0).sequence)

    def test_a_sample_captured_before_a_loss_is_never_used(self):
        # Behaviour only, not a guard of one line: the runtime mints a new
        # stream for the first sample after every loss (even when the
        # producer keeps its stream id), and the quality gate restarts on a
        # stream change, so the pre-loss sample can never be followed by a
        # consecutive one. `_acquire`'s own pre-loss exclusion is therefore
        # a redundant second guard that no observable case distinguishes
        # (Claude re-review 1 on PR #330).
        harness = Harness(binding(OTHER, SourceType.REMOTE_AGENT), calibrations=None)
        harness.runtime.start()
        stream = uuid4()

        def offer(step=True):
            harness.clock.value += INTERVAL
            harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH, height=HEIGHT, pixels=pixels())
            if step:
                harness.runtime.step()

        future = harness.runtime.acquire_reference(OTHER, WIDTH, HEIGHT, timeout_ns=100 * INTERVAL)
        offer()
        # Captured after the request but before the camera loss handled in
        # the same pass: it starts no new count after the loss.
        offer(step=False)
        harness.clock.value += 1
        harness.runtime.source_unavailable(OTHER, trusted=True)
        harness.runtime.step()
        offer()
        self.assertFalse(future.done())
        offer()
        self.assertTrue(future.done())

    def test_refusals_busy_geometry_unavailable_cancel_and_stop(self):
        harness = Harness(calibrations=None)
        with self.assertRaises(ReferenceUnavailable) as raised:
            harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=INTERVAL)
        self.assertEqual("unavailable", raised.exception.reason)
        harness.runtime.start()
        for width, height in ((WIDTH + 1, HEIGHT), (0, HEIGHT), (128, 128)):
            with self.assertRaises(ReferenceUnavailable) as raised:
                harness.runtime.acquire_reference(SOURCE, width, height, timeout_ns=INTERVAL)
            self.assertEqual("geometry_unsupported", raised.exception.reason)
        with self.assertRaises(ReferenceUnavailable):
            harness.runtime.acquire_reference(uuid4(), WIDTH, HEIGHT, timeout_ns=INTERVAL)
        future = harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=INTERVAL)
        with self.assertRaises(ReferenceUnavailable) as raised:
            harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=INTERVAL)
        self.assertEqual("busy", raised.exception.reason)
        harness.runtime.cancel_acquisition(SOURCE, future)
        with self.assertRaises(ReferenceUnavailable) as raised:
            future.result(0)
        self.assertEqual("cancelled", raised.exception.reason)
        pending = harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=INTERVAL)
        harness.runtime.stop()
        with self.assertRaises(ReferenceUnavailable) as raised:
            pending.result(0)
        self.assertEqual("unavailable", raised.exception.reason)

    def test_acquisition_during_detection_keeps_evaluating(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        evaluated = harness.source().evaluated
        future = harness.runtime.acquire_reference(SOURCE, WIDTH, HEIGHT, timeout_ns=100 * INTERVAL)
        harness.frame()
        harness.frame()
        self.assertTrue(future.done())
        self.assertEqual(evaluated + 2, harness.source().evaluated)

    def test_reader_identity_names_the_layout_and_decoder_only(self):
        self.assertEqual("packed:yuyv:24x24", reader_identity(binding()))
        mjpg = binding(layout=MjpgLumaLayout(1920, 1080))
        self.assertEqual(f"mjpg:simplejpeg={SIMPLEJPEG_VERSION}:numpy={NUMPY_VERSION}:1920x1080",
                         reader_identity(mjpg))
        self.assertEqual(REMOTE_READER, reader_identity(binding(OTHER, SourceType.REMOTE_AGENT)))
        self.assertEqual("packed:grey:24x24",
                         reader_identity(binding(layout=PackedLumaLayout(WIDTH * 2, HEIGHT * 2, "GREY"))))


class HistoryTests(unittest.TestCase):
    def test_reader_is_recorded_and_an_older_record_reads_back_without_one(self):
        database = Database_(self)
        database.store(stored())
        (record,) = database.history()
        self.assertEqual(REMOTE_READER, record.reader)
        older = replace(stored(source=uuid4(), reader=None))
        database.store(older)
        (record,) = database.history(older.source_id)
        self.assertIsNone(record.reader)
        with self.assertRaises(ValueError):
            replace(stored(), reader="Packed/YUYV")

    def test_append_on_needs_the_callers_transaction_and_keeps_version_rules(self):
        database = Database_(self)
        with closing(database.database.connect()) as connection:
            with self.assertRaises(ValueError):
                append_on(connection, stored())
            connection.execute("BEGIN IMMEDIATE")
            append_on(connection, stored())
            with self.assertRaises(ValueError):
                append_on(connection, stored(version=3))
            connection.execute("ROLLBACK")
        self.assertEqual([], database.history())

    def test_history_holds_no_pixel_of_the_reference(self):
        database = Database_(self)
        database.store(stored())
        with closing(database.database.connect()) as connection:
            (metadata,) = connection.execute("SELECT metadata FROM roi_calibration_history").fetchone()
        self.assertEqual({"identifier", "source_id", "source_type", "profile_id", "version", "created_at",
                          "polygon", "policy", "reference", "reader"}, set(json.loads(metadata)))
        # Only geometry of the reference: no digest or other value computed
        # from its pixels (Owner decision 2026-10-22, option A).
        self.assertEqual({"stream_id", "sequence", "width", "height"},
                         set(json.loads(metadata)["reference"]))
        assert_no_frame_trace(self, database.raw())
        # The check itself sees a stored digest (the pre-#205 layout).
        legacy = database.raw() + hashlib.sha256(pixels()).hexdigest().encode()
        with self.assertRaises(AssertionError):
            assert_no_frame_trace(self, legacy)

    def test_a_pre_205_record_with_a_reference_digest_is_read_and_the_digest_ignored(self):
        database = Database_(self)
        with closing(database.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            append_on(connection, stored())
            (metadata,) = connection.execute("SELECT metadata FROM roi_calibration_history").fetchone()
            value = json.loads(metadata)
            value["reference"]["sha256"] = "0" * 64
            connection.execute("UPDATE roi_calibration_history SET metadata=?",
                               (json.dumps(value, sort_keys=True),))
            connection.commit()
        (record,) = database.history()
        self.assertNotIn("reference_sha256", vars(record))
        self.assertEqual(stored(), record.bind(stored()))


class LegacyDigestScrubTests(unittest.TestCase):
    def test_the_scrub_removes_the_digest_from_the_file_and_keeps_the_provenance(self):
        # Codex P1 (#330): a version a pre-#205 build stored still carries
        # its frame's SHA-256; the scrub removes it from the database file.
        database = Database_(self)
        store_legacy(database.database.path, stored())
        store_legacy(database.database.path, stored(source=SOURCE, source_type=SourceType.LOCAL_UVC))
        # Positive control: the digest is on disk before the scrub.
        with self.assertRaises(AssertionError):
            assert_no_frame_trace(self, database.raw())
        with closing(database.database.connect()) as connection:
            with self.assertRaises(ValueError):
                scrub_legacy_reference_digests(connection)
            connection.execute("BEGIN IMMEDIATE")
            self.assertEqual(2, scrub_legacy_reference_digests(connection))
            connection.execute("COMMIT")
            connection.execute("BEGIN IMMEDIATE")
            self.assertEqual(0, scrub_legacy_reference_digests(connection))
            connection.execute("COMMIT")
            rows = connection.execute("SELECT metadata FROM roi_calibration_history "
                                      "WHERE source_id=?", (str(OTHER),)).fetchall()
        assert_no_frame_trace(self, database.raw())
        # Exactly what the archive writes for such a version today.
        self.assertEqual([json.dumps(calibration_metadata(stored()), sort_keys=True)],
                         [row[0] for row in rows])
        (record,) = database.history()
        self.assertEqual(stored(), record.bind(stored()))

    def test_the_scrub_itself_turns_secure_delete_on(self):
        # Claude re-review proposal 1: with `secure_delete` explicitly off on
        # the connection (some SQLite builds default it on) and a thousand
        # versions in a DELETE-journal database, the rebuilt table's freed
        # pages would keep stale digests; the scrub's own pragma is what
        # zeroes them (the pragma-less mutant leaves copies here).
        database = Database_(self)
        with closing(database.database.connect()) as connection:
            self.assertEqual("delete", connection.execute("PRAGMA journal_mode").fetchone()[0].lower())
            # The legacy build's writes, with secure_delete off as well, and a
            # later in-place rewrite, so stale digest copies sit in the free
            # space (Claude re-review on b528106: the update-only mutant fails).
            connection.execute("PRAGMA secure_delete = OFF")
            connection.execute("BEGIN IMMEDIATE")
            digest = hashlib.sha256(pixels()).hexdigest()
            for version in range(1, 1001):
                calibration = stored(version=version)
                append_on(connection, calibration)
                value = calibration_metadata(calibration)
                value["reference"]["sha256"] = digest
                connection.execute("UPDATE roi_calibration_history SET metadata=? WHERE version=?",
                                   (json.dumps(value, sort_keys=True), version))
            connection.execute("UPDATE roi_calibration_history SET metadata=metadata")
            connection.execute("COMMIT")
        with self.assertRaises(AssertionError):
            assert_no_frame_trace(self, database.raw())
        with closing(database.database.connect()) as connection:
            connection.execute("PRAGMA secure_delete = OFF")
            connection.execute("BEGIN IMMEDIATE")
            self.assertEqual(1000, scrub_legacy_reference_digests(connection))
            connection.execute("COMMIT")
        assert_no_frame_trace(self, database.raw())
        self.assertEqual(list(range(1, 1001)), [item.version for item in database.history()])

    def test_only_rows_that_carried_the_digest_are_counted_and_rewritten(self):
        # Claude re-review on b528106: a row without the key, even one not in
        # the archive's own serialization, is inserted back byte-for-byte.
        database = Database_(self)
        store_legacy(database.database.path, stored())
        database.store(stored(source=SOURCE, source_type=SourceType.LOCAL_UVC))
        compact = json.dumps(calibration_metadata(stored(source=SOURCE, source_type=SourceType.LOCAL_UVC)),
                             sort_keys=True, separators=(",", ":"))
        with closing(database.database.connect()) as connection:
            connection.execute("UPDATE roi_calibration_history SET metadata=? WHERE source_id=?",
                               (compact, str(SOURCE)))
            connection.execute("BEGIN IMMEDIATE")
            self.assertEqual(1, scrub_legacy_reference_digests(connection))
            connection.execute("COMMIT")
            (kept,) = connection.execute("SELECT metadata FROM roi_calibration_history WHERE source_id=?",
                                         (str(SOURCE),)).fetchone()
        self.assertEqual(compact, kept)
        assert_no_frame_trace(self, database.raw())

    def test_without_the_table_or_a_digest_nothing_is_written(self):
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.assertEqual(0, scrub_legacy_reference_digests(connection))
            connection.execute("ROLLBACK")
        database = Database_(self)
        database.store(stored())
        before = database.raw()
        with closing(database.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.assertEqual(0, scrub_legacy_reference_digests(connection))
            connection.execute("COMMIT")
        self.assertEqual([1], [item.version for item in database.history()])
        self.assertEqual(len(before), len(database.raw()))


class TransientReferenceTests(unittest.TestCase):
    def test_a_record_is_served_only_its_own_in_memory_calibration(self):
        # Claude review 4: the in-memory binding itself, apart from bind().
        references = TransientReferences()
        calibration = stored()
        references.stage(calibration)
        self.assertIs(calibration, references(provenance(calibration)))
        later = calibration.created_at + timedelta(seconds=1)
        for other in (replace(calibration, created_at=later), replace(calibration, identifier=uuid4()),
                      replace(calibration, reader="packed:yuyv:24x24"),
                      replace(calibration, version=2)):
            with self.subTest(other=other.version):
                self.assertIsNone(references(provenance(other)))
        references.drop(calibration)
        self.assertIsNone(references(provenance(calibration)))


class TemplateTests(unittest.TestCase):
    def test_template_is_checked_against_its_own_geometry(self):
        for changes in (dict(width=0), dict(polygon=((0, 0), (WIDTH, 0), (0, 3))),
                        dict(polygon=((0, 0), (1, 1), (2, 2))), dict(polygon=((0, 0), (1, 0)))):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                template(**changes)
        with self.assertRaises(ValueError):
            SceneCalibrationConfiguration((template(), template()))
        with self.assertRaises(ValueError):
            SceneCalibrationConfiguration(acquisition_timeout_seconds=0)

    def test_service_requires_the_runtime_to_read_its_references(self):
        database = Database_(self)
        runtime = SceneMonitoringRuntime(SceneMonitoringConfiguration((binding(OTHER, SourceType.REMOTE_AGENT),)),
                                         SceneMonitoringDependencies(recorder=Recorder()))
        with self.assertRaises(ValueError):
            SceneCalibrationService(SceneCalibrationConfiguration(), runtime, database.database.connect_read_only,
                                    references=TransientReferences())
        references = TransientReferences()
        runtime = SceneMonitoringRuntime(
            SceneMonitoringConfiguration((binding(OTHER, SourceType.REMOTE_AGENT),)),
            SceneMonitoringDependencies(recorder=Recorder(), calibrations=ArchiveCalibrationProvider(
                database.database.connect_read_only, references=references)))
        with self.assertRaises(ValueError):
            SceneCalibrationService(SceneCalibrationConfiguration((template(uuid4()),)), runtime,
                                    database.database.connect_read_only, references=references)


class OwnerCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.database = Database_(self)
        self.harness = Service(self, self.database.database)

    def test_owner_calibration_stores_provenance_and_activates_detection(self):
        log = []
        with Feed(self.harness.runtime):
            record = self.harness.service.calibrate(OTHER, commit_with(self.database.database, log))
            self.assertTrue(wait_for(lambda: self.harness.source().state is SceneSourceState.ACTIVE))
        self.assertEqual([OTHER], log)
        self.assertEqual((1, REMOTE_READER, POLYGON), (record.version, record.reader, record.polygon))
        self.assertEqual(1, self.harness.source().calibration_version)
        status = self.harness.status()
        self.assertEqual((CalibrationOrigin.OWNER, 1, CalibrationPhase.IDLE, None, True),
                         (status.origin, status.version, status.phase, status.failure,
                          status.owner_calibration_available))
        # A second calibration is the next version under the same identifier.
        with Feed(self.harness.runtime):
            second = self.harness.service.calibrate(OTHER, commit_with(self.database.database))
            self.assertTrue(wait_for(lambda: self.harness.source().calibration_version == 2))
        self.assertEqual((2, record.identifier), (second.version, second.identifier))
        self.assertEqual([1, 2], [item.version for item in self.database.history()])
        assert_no_frame_trace(self, self.database.raw())
        # The Owner path produces no Owner notice: only the restart path does.
        self.assertEqual((), self.harness.service.take_notices())

    def test_refusals_store_nothing_and_are_reported(self):
        with self.assertRaises(CalibrationRefused) as raised:
            self.harness.service.calibrate(uuid4(), commit_with(self.database.database))
        self.assertEqual("unavailable", raised.exception.reason)
        empty = Service(self, self.database.database, templates=(), timeout=1.0)
        with self.assertRaises(CalibrationRefused) as raised:
            empty.service.calibrate(OTHER, commit_with(self.database.database))
        self.assertEqual("template_unconfigured", raised.exception.reason)
        quick = Service(self, self.database.database, timeout=1.0)
        with self.assertRaises(CalibrationRefused) as raised:
            quick.service.calibrate(OTHER, commit_with(self.database.database))
        self.assertEqual("no_frame", raised.exception.reason)
        self.assertEqual("no_frame", quick.status().failure)
        # A reference already at the obscured threshold is refused by the
        # detector: nothing is stored.
        with Feed(quick.runtime, luma=near_dark()):
            with self.assertRaises(CalibrationRefused) as raised:
                quick.service.calibrate(OTHER, commit_with(self.database.database))
        self.assertIn(raised.exception.reason, ("scene_unsuitable", "quality_insufficient"))
        self.assertEqual([], self.database.history())
        self.assertIs(SceneSourceState.INACTIVE, quick.source().state)

    def test_a_failed_commit_drops_the_staged_reference(self):
        def failing(source_id, prepare, persist):
            prepare()
            raise RuntimeError("synthetic gate closed")

        with Feed(self.harness.runtime):
            with self.assertRaises(RuntimeError):
                self.harness.service.calibrate(OTHER, failing)
        self.assertEqual("history_unavailable", self.harness.status().failure)
        self.assertEqual(CalibrationOrigin.NONE, self.harness.status().origin)
        self.assertEqual({}, self.harness.references._frames)

    def test_close_ends_an_acquisition_in_flight(self):
        slow = Service(self, self.database.database, timeout=30.0)
        errors = []

        def attempt():
            try:
                slow.service.calibrate(OTHER, commit_with(self.database.database))
            except CalibrationRefused as refused:
                errors.append(refused.reason)

        thread = threading.Thread(target=attempt)
        started = time.monotonic()
        thread.start()
        self.assertTrue(wait_for(lambda: slow.status().phase is CalibrationPhase.ACQUIRING))
        slow.service.close()
        thread.join(10)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(["cancelled"], errors)


class RestartReacquisitionTests(unittest.TestCase):
    """Owner decision 2026-10-22, option A, without the application."""

    def setUp(self):
        self.database = Database_(self)

    def test_a_stored_calibration_is_reacquired_and_the_owner_notified(self):
        self.database.store(stored())
        harness = Service(self, self.database.database)
        # Before re-acquisition the stored version cannot be bound: the
        # reference frame did not survive the restart.
        self.assertTrue(wait_for(lambda: harness.source().reason == "calibration_reference_unavailable"))
        harness.service.start()
        self.assertEqual((OTHER,), harness.service.pending_reacquisitions())
        self.assertEqual(CalibrationPhase.REACQUIRE_PENDING, harness.status().phase)
        log = []
        with Feed(harness.runtime):
            record = harness.service.reacquire(OTHER, commit_with(self.database.database, log))
            harness.runtime.request_calibration_refresh(OTHER)
            self.assertTrue(wait_for(lambda: harness.source().state is SceneSourceState.ACTIVE))
        self.assertEqual((2, UUID(int=700), POLYGON), (record.version, record.identifier, record.polygon))
        self.assertEqual([OTHER], log)
        status = harness.status()
        self.assertEqual((CalibrationOrigin.RESTART_REACQUIRED, 2, CalibrationPhase.IDLE),
                         (status.origin, status.version, status.phase))
        (notice,) = harness.service.take_notices()
        self.assertEqual(REACQUIRED, notice.kind)
        self.assertEqual((), harness.service.pending_reacquisitions())
        # Nothing more to do, and nothing notified twice.
        self.assertIsNone(harness.service.reacquire(OTHER, commit_with(self.database.database)))
        self.assertEqual((), harness.service.take_notices())
        assert_no_frame_trace(self, self.database.raw())

    def test_owner_calibration_replaces_a_pending_reacquisition_without_notice(self):
        self.database.store(stored())
        harness = Service(self, self.database.database)
        harness.service.start()
        with Feed(harness.runtime):
            harness.service.calibrate(OTHER, commit_with(self.database.database))
        self.assertEqual((), harness.service.pending_reacquisitions())
        self.assertEqual(CalibrationOrigin.OWNER, harness.status().origin)
        self.assertEqual((), harness.service.take_notices())

    def test_a_changed_or_unrecorded_reader_is_not_reused_and_notified_once(self):
        for reader in ("packed:yuyv:24x24", None):
            with self.subTest(reader=reader):
                database = Database_(self)
                database.store(stored(reader=reader))
                harness = Service(self, database.database, reacquire_timeout=1.0)
                harness.service.start()
                for _ in range(3):
                    self.assertIsNone(harness.service.reacquire(OTHER, commit_with(database.database)))
                self.assertEqual("reader_changed", harness.status().failure)
                self.assertEqual([REQUIRED], [item.kind for item in harness.service.take_notices()])
                self.assertEqual([1], [item.version for item in database.history()])
                self.assertIs(SceneSourceState.INACTIVE, harness.source().state)

    def test_no_frame_is_retried_and_notified_once_then_success_notified(self):
        self.database.store(stored())
        harness = Service(self, self.database.database, reacquire_timeout=1.0)
        harness.service.start()
        for _ in range(2):
            self.assertIsNone(harness.service.reacquire(OTHER, commit_with(self.database.database)))
        self.assertEqual("no_frame", harness.status().failure)
        self.assertEqual([REQUIRED], [item.kind for item in harness.service.take_notices()])
        self.assertEqual((OTHER,), harness.service.pending_reacquisitions())
        with Feed(harness.runtime):
            self.assertIsNotNone(harness.service.reacquire(OTHER, commit_with(self.database.database)))
        self.assertEqual([REACQUIRED], [item.kind for item in harness.service.take_notices()])

    def test_an_unavailable_runtime_is_notified_only_after_it_ran_and_not_at_shutdown(self):
        # Codex P1 (#330): "unavailable" has three causes. A runtime that has
        # not started yet may still start: no notice. One that started and
        # then stopped or failed leaves detection off with every retry refused
        # the same way: one `scene_calibration_required`. A shutdown of this
        # service is not a failure: no notice.
        self.database.store(stored())
        pending = Service(self, self.database.database, start=False)
        pending.service.start()
        self.assertIsNone(pending.service.reacquire(OTHER, commit_with(self.database.database)))
        self.assertEqual("unavailable", pending.status().failure)
        self.assertEqual((), pending.service.take_notices())

        ended = Service(self, self.database.database)
        ended.service.start()
        ended.runtime.stop()
        for _ in range(2):
            self.assertIsNone(ended.service.reacquire(OTHER, commit_with(self.database.database)))
        self.assertEqual([REQUIRED], [notice.kind for notice in ended.service.take_notices()])

        failed = Service(self, self.database.database)
        failed.service.start()
        with mock.patch.object(failed.runtime, "acquire_reference",
                               side_effect=ReferenceUnavailable("unavailable")), \
                mock.patch.object(failed.runtime, "status", return_value=SimpleNamespace(
                    state=SceneRuntimeState.UNAVAILABLE)):
            # The worker failed: the runtime reports itself unavailable.
            self.assertIsNone(failed.service.reacquire(OTHER, commit_with(self.database.database)))
        self.assertEqual([REQUIRED], [notice.kind for notice in failed.service.take_notices()])

        for state, notified in ((SceneRuntimeState.DEGRADED, False), (None, True)):
            # Claude re-review: a degraded runtime still runs (no notice); a
            # status that cannot be read counts as ended (notice).
            other = Service(self, self.database.database)
            other.service.start()
            status = (mock.patch.object(other.runtime, "status", side_effect=RuntimeError("unreadable"))
                      if state is None else
                      mock.patch.object(other.runtime, "status", return_value=SimpleNamespace(state=state)))
            with mock.patch.object(other.runtime, "acquire_reference",
                                   side_effect=ReferenceUnavailable("unavailable")), status:
                self.assertIsNone(other.service.reacquire(OTHER, commit_with(self.database.database)))
            self.assertEqual([REQUIRED] if notified else [],
                             [notice.kind for notice in other.service.take_notices()])

        closing_down = Service(self, self.database.database)
        closing_down.service.start()
        closing_down.service.close()
        closing_down.runtime.stop()
        self.assertIsNone(closing_down.service.reacquire(OTHER, commit_with(self.database.database)))
        self.assertEqual((), closing_down.service.take_notices())
        self.assertEqual([1], [item.version for item in self.database.history()])

    def test_marking_before_start_only_shows_the_pending_reacquisition(self):
        # Issue #341: `mark_stored()` reads the history before the runtime
        # runs; the status reports `reacquire_pending`, but nothing is
        # re-acquired, refused or notified until `start()`.
        self.database.store(stored())
        harness = Service(self, self.database.database, start=False)
        harness.service.mark_stored()
        status = harness.status()
        self.assertEqual((CalibrationOrigin.NONE, CalibrationPhase.REACQUIRE_PENDING, None),
                         (status.origin, status.phase, status.failure))
        self.assertEqual((), harness.service.pending_reacquisitions())
        log = []
        self.assertIsNone(harness.service.reacquire(OTHER, commit_with(self.database.database, log)))
        self.assertEqual(([], None, ()), (log, harness.status().failure, harness.service.take_notices()))
        harness.runtime.start()
        harness.service.start()
        self.assertEqual((OTHER,), harness.service.pending_reacquisitions())
        with Feed(harness.runtime):
            self.assertIsNotNone(harness.service.reacquire(OTHER, commit_with(self.database.database, log)))
        self.assertEqual([OTHER], log)
        self.assertEqual([REACQUIRED], [item.kind for item in harness.service.take_notices()])
        # Without a stored calibration, or after close(), nothing is marked.
        empty = Service(self, Database_(self).database, start=False)
        empty.service.mark_stored()
        self.assertIs(CalibrationPhase.IDLE, empty.status().phase)
        closed = Service(self, self.database.database, start=False)
        closed.service.close()
        closed.service.mark_stored()
        self.assertIs(CalibrationPhase.IDLE, closed.status().phase)

    def test_without_a_stored_calibration_nothing_is_reacquired_or_notified(self):
        harness = Service(self, self.database.database)
        harness.service.start()
        self.assertEqual((), harness.service.pending_reacquisitions())
        self.assertEqual((CalibrationOrigin.NONE, CalibrationPhase.IDLE),
                         (harness.status().origin, harness.status().phase))
        self.assertEqual((), harness.service.take_notices())

    def test_returned_notices_keep_their_order_and_event_ids(self):
        self.database.store(stored())
        harness = Service(self, self.database.database)
        harness.service.start()
        with Feed(harness.runtime):
            harness.service.reacquire(OTHER, commit_with(self.database.database))
        notices = harness.service.take_notices()
        harness.service.return_notices(notices)
        self.assertEqual(notices, harness.service.take_notices())


def Database_History(test, source):
    with closing(Database(test.settings.database_path).connect()) as connection:
        return [decode_history_row(row) for row in connection.execute(
            "SELECT source_id, profile_id, version, identifier, metadata FROM roi_calibration_history "
            "WHERE source_id=? ORDER BY version", (str(source),))]


class LifespanTests(RuntimeFixture):
    """Main lifespan: restart -> re-acquisition -> audited commit -> Owner alert."""

    def scene_application(self, sources=(OTHER,), recorder=True, timeline=None, **calibration):
        remotes = tuple(binding(source, SourceType.REMOTE_AGENT, sample_interval_ns=1_000_000)
                        for source in sources)
        values = dict(reacquire_timeout_seconds=5, reacquire_retry_seconds=1)
        values.update(calibration)
        return create_app(
            self.settings,
            monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=3600.0),
            scene_monitoring=SceneMonitoringConfiguration(remotes),
            scene_monitoring_dependencies=SceneMonitoringDependencies(
                tick_seconds=0.01, recorder=Recorder() if recorder else None),
            scene_calibration=SceneCalibrationConfiguration(
                tuple(template(source) for source in sources), **values),
            scene_timeline=timeline,
        )

    def deferred_application(self):
        """`scene_application` whose timeline outbox open is refused
        (storage not admitted) until the returned event is cleared; the
        scene runtime meanwhile stays `configured` (deferred start)."""
        application = self.scene_application(recorder=False, timeline=timeline_configuration())
        return application, refuse_outbox_open(application.state.scene_timeline)

    def store(self, calibration):
        database = Database(self.settings.database_path)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
            CalibrationArchive(connection).append(calibration)

    def rows(self, query):
        with closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute(query).fetchall()

    def versions(self):
        return [row[0] for row in self.rows("SELECT version FROM roi_calibration_history ORDER BY version")]

    def scene_texts(self):
        return [text for text in self.slack_texts() if "scene_" in text]

    def notified(self):
        return self.rows("SELECT kind, confirmed, delivery FROM notification_events "
                         "WHERE kind LIKE 'scene_%' ORDER BY at, kind")

    def reacquire_records(self):
        return self.rows("SELECT actor_category, outcome, target_logical_id FROM security_admin_audit_records "
                         "WHERE action='reacquire_scene_reference' ORDER BY occurred_at_us")

    async def until(self, predicate, timeout=20.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.02)
        return predicate()

    async def test_each_restart_reacquires_commits_audits_and_notifies(self):
        self.store(stored())
        for restart, version in ((1, 2), (2, 3)):
            with self.subTest(restart=restart):
                application = self.scene_application()
                service = application.state.scene_calibration
                runtime = application.state.scene_monitoring
                async with asyncio.timeout(60), application.router.lifespan_context(application):
                    with Feed(runtime):
                        self.assertTrue(await self.until(
                            lambda: service.status()[0].origin is CalibrationOrigin.RESTART_REACQUIRED))
                        self.assertTrue(await self.until(
                            lambda: runtime.status().sources[0].state is SceneSourceState.ACTIVE))
                        self.assertTrue(await self.until(lambda: len(self.scene_texts()) == restart))
                self.assertEqual(list(range(1, version + 1)), self.versions())
                self.assertEqual(restart, len(self.reacquire_records()))
                self.assertEqual(("system", "succeeded", str(OTHER)), self.reacquire_records()[-1])
                self.assertEqual(["ServerSentinel critical alert: scene_reference_reacquired"] * restart,
                                 self.scene_texts())
                self.assertEqual([("scene_reference_reacquired", 1, "sent")] * restart, self.notified())
        # The reference never reached the disk.
        assert_no_frame_trace(self, database_bytes(self.settings.database_path))

    async def test_startup_scrubs_a_legacy_reference_digest_and_logs_only_the_count(self):
        # Codex P1 (#330): an upgraded database loses the frame digest of a
        # pre-#205 version at the first start, before any re-acquisition.
        store_legacy(self.settings.database_path, stored())
        application = self.scene_application()
        with self.assertLogs("app.main", "WARNING") as logs:
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                assert_no_frame_trace(self, database_bytes(self.settings.database_path))
        scrubbed = [record for record in logs.records
                    if record.msg == Event.SCENE_REFERENCE_DIGESTS_SCRUBBED]
        self.assertEqual([1], [record.count for record in scrubbed])
        self.assertNotIn(hashlib.sha256(pixels()).hexdigest(), "\n".join(logs.output))
        assert_no_frame_trace(self, database_bytes(self.settings.database_path))

    async def test_a_refused_startup_scrub_is_retried_before_the_reacquisition(self):
        # Claude re-review proposal 2: the scrub refused at startup (storage
        # not yet admitted, for example) runs again before the restart
        # re-acquisition, so no re-acquired version sits beside the digest.
        store_legacy(self.settings.database_path, stored())
        application = self.scene_application()
        service = application.state.scene_calibration
        runtime = application.state.scene_monitoring
        from app import main as main_module
        real, calls = main_module.scrub_legacy_reference_digests, []

        def scrub(connection):
            calls.append(service.status()[0].origin)
            if len(calls) == 1:
                raise RuntimeError("synthetic refusal")
            return real(connection)

        with self.assertLogs("app.main", "WARNING") as logs, \
                mock.patch.object(main_module, "scrub_legacy_reference_digests", side_effect=scrub):
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                with Feed(runtime):
                    self.assertTrue(await self.until(
                        lambda: service.status()[0].origin is CalibrationOrigin.RESTART_REACQUIRED))
        events = [record.msg for record in logs.records]
        self.assertEqual(1, events.count(Event.SCENE_REFERENCE_DIGEST_SCRUB_FAILED))
        self.assertLess(events.index(Event.SCENE_REFERENCE_DIGEST_SCRUB_FAILED),
                        events.index(Event.SCENE_REFERENCE_DIGESTS_SCRUBBED))
        # Both attempts ran before the re-acquisition.
        self.assertEqual([CalibrationOrigin.NONE, CalibrationOrigin.NONE], calls)
        self.assertEqual([1, 2], self.versions())
        assert_no_frame_trace(self, database_bytes(self.settings.database_path))

    async def test_a_silent_camera_delays_neither_other_sources_nor_their_notices(self):
        # Claude review 1 / Codex P1 (PR #330): the sources are re-acquired
        # independently. The silent camera is first, so a serial pass would
        # hold the others for its whole timeout; four sources, the maximum.
        silent, healthy = uuid4(), (OTHER, uuid4(), uuid4())
        sources = (silent, *healthy)
        for source in sources:
            self.store(stored(source))
        application = self.scene_application(sources, reacquire_timeout_seconds=30)
        service = application.state.scene_calibration
        runtime = application.state.scene_monitoring

        def state(source):
            return next(item for item in runtime.status().sources if item.source_id == source).state

        def phase(source):
            return next(item for item in service.status() if item.source_id == source).phase

        async with asyncio.timeout(60), application.router.lifespan_context(application):
            feeds = [Feed(runtime, source) for source in healthy]
            for feed in feeds:
                feed.__enter__()
            try:
                started = time.monotonic()
                self.assertTrue(await self.until(
                    lambda: all(state(source) is SceneSourceState.ACTIVE for source in healthy)))
                # One immediate notice per re-acquired source, each well
                # before the silent camera's 30 s deadline.
                self.assertTrue(await self.until(lambda: len(self.scene_texts()) == len(healthy)))
                self.assertLess(time.monotonic() - started, 20)
                self.assertIs(CalibrationPhase.ACQUIRING, phase(silent))
                self.assertIs(SceneSourceState.INACTIVE, state(silent))
            finally:
                for feed in feeds:
                    feed.__exit__()
            closing_at = time.monotonic()
        # Shutdown ends the silent camera's acquisition at once (close())
        # instead of waiting for its deadline.
        self.assertLess(time.monotonic() - closing_at, 15)
        self.assertEqual(["ServerSentinel critical alert: scene_reference_reacquired"] * len(healthy),
                         self.scene_texts())
        self.assertEqual(sorted(str(source) for source in healthy),
                         sorted(row[2] for row in self.reacquire_records()))
        for source in healthy:
            self.assertEqual([1, 2], [item.version for item in Database_History(self, source)])
        self.assertEqual([1], [item.version for item in Database_History(self, silent)])

    async def test_a_stored_calibration_that_cannot_be_reacquired_notifies_once(self):
        self.store(stored(reader="packed:yuyv:24x24"))
        application = self.scene_application()
        service = application.state.scene_calibration
        runtime = application.state.scene_monitoring
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            with Feed(runtime):
                self.assertTrue(await self.until(lambda: len(self.scene_texts()) == 1))
                # Retried every second; notified only once per process.
                await asyncio.sleep(2.5)
            self.assertEqual("reader_changed", service.status()[0].failure)
            self.assertIs(SceneSourceState.INACTIVE, runtime.status().sources[0].state)
        self.assertEqual(["ServerSentinel critical alert: scene_calibration_required"], self.scene_texts())
        self.assertEqual([1], self.versions())
        self.assertEqual([], self.reacquire_records())

    async def test_a_deferred_start_shows_the_pending_reacquisition_and_attempts_nothing(self):
        # Issue #341 (Claude re-review of PR #330): while the timeline outbox
        # open is deferred, the runtime is `configured`. It is not treated as
        # ended (`scene_runtime_ended`): no scrub, start or re-acquisition
        # runs and nothing is notified. The stored calibration is still shown
        # as waiting for its re-acquisition, not as never calibrated.
        self.store(stored())
        application, refusing = self.deferred_application()
        service = application.state.scene_calibration
        runtime = application.state.scene_monitoring
        calls, original = [], service.reacquire

        def reacquire(source_id, commit):
            calls.append(source_id)
            return original(source_id, commit)

        service.reacquire = reacquire
        with self.assertLogs("app", "ERROR"):
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                with Feed(runtime):
                    self.assertTrue(await self.until(
                        lambda: service.status()[0].phase is CalibrationPhase.REACQUIRE_PENDING))
                    # Many passes of the calibration loop (it polls at the
                    # runtime's 10 ms tick until the runtime runs).
                    await asyncio.sleep(1.0)
                    self.assertIs(SceneRuntimeState.CONFIGURED, runtime.status().state)
                    self.assertIs(SceneRuntimeState.UNAVAILABLE,
                                  application.state.scene_monitoring_state)
                    status = service.status()[0]
                    self.assertEqual(
                        (CalibrationOrigin.NONE, None, None, CalibrationPhase.REACQUIRE_PENDING, None),
                        (status.origin, status.version, status.calibrated_at, status.phase,
                         status.failure))
                    self.assertEqual((), service.pending_reacquisitions())
                    self.assertEqual([], calls)
                    self.assertEqual([], self.scene_texts())
                    self.assertEqual([], self.reacquire_records())
                    self.assertEqual([1], self.versions())
                    # Once the open succeeds the runtime runs and the stored
                    # calibration is re-acquired and notified as before.
                    refusing.clear()
                    self.assertTrue(await self.until(
                        lambda: service.status()[0].origin is CalibrationOrigin.RESTART_REACQUIRED))
                    self.assertTrue(await self.until(lambda: len(self.scene_texts()) == 1))
        self.assertEqual([OTHER], calls)
        self.assertEqual(["ServerSentinel critical alert: scene_reference_reacquired"], self.scene_texts())
        self.assertEqual([1, 2], self.versions())

    async def test_an_unreadable_runtime_status_during_a_deferred_start_is_notified_once(self):
        # Issue #341: `scene_runtime_ended` counts a status it cannot read as
        # ended, so the stored calibration's re-acquisition is attempted,
        # refused `unavailable` and notified once, instead of waiting forever.
        self.store(stored())
        application, _ = self.deferred_application()
        runtime = application.state.scene_monitoring
        required = ["ServerSentinel critical alert: scene_calibration_required"]
        with self.assertLogs("app", "ERROR"):
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                self.assertTrue(await self.until(
                    lambda: application.state.scene_calibration.status()[0].phase
                    is CalibrationPhase.REACQUIRE_PENDING))
                with mock.patch.object(runtime, "status", side_effect=RuntimeError("unreadable")):
                    self.assertTrue(await self.until(lambda: self.scene_texts() == required))
                    # Retried every second; notified only once per process.
                    await asyncio.sleep(2.5)
                status = application.state.scene_calibration.status()[0]
                self.assertEqual((CalibrationPhase.REACQUIRE_PENDING, "unavailable"),
                                 (status.phase, status.failure))
        self.assertEqual(required, self.scene_texts())
        self.assertEqual([1], self.versions())

    async def test_never_calibrated_sources_are_left_alone(self):
        application = self.scene_application()
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            with Feed(application.state.scene_monitoring):
                await asyncio.sleep(1.5)
        self.assertEqual([], self.scene_texts())
        self.assertEqual([], self.versions())

    async def test_an_unexpected_failure_of_one_source_ends_neither_others_nor_the_retries(self):
        # Claude re-review 3: `gather(return_exceptions=True)`.
        bad = uuid4()
        sources = (bad, OTHER)
        for source in sources:
            self.store(stored(source))
        application = self.scene_application(sources)
        service = application.state.scene_calibration
        runtime = application.state.scene_monitoring
        original, calls = service.reacquire, []

        def reacquire(source_id, commit):
            calls.append(source_id)
            if source_id == bad and calls.count(bad) == 1:
                raise RuntimeError("synthetic unexpected failure")
            return original(source_id, commit)

        service.reacquire = reacquire
        with self.assertLogs("app.main", "ERROR") as logs:
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                with Feed(runtime, bad), Feed(runtime, OTHER):
                    # The failed source is retried on the next pass.
                    self.assertTrue(await self.until(lambda: all(
                        item.state is SceneSourceState.ACTIVE for item in runtime.status().sources)))
                    self.assertTrue(await self.until(lambda: len(self.scene_texts()) == 2))
        self.assertGreaterEqual(calls.count(bad), 2)
        self.assertIn("scene_reacquisition_failed", "\n".join(logs.output))
        self.assertNotIn("synthetic unexpected failure", "\n".join(logs.output))

    async def test_a_notice_queued_just_before_shutdown_is_still_submitted(self):
        # Claude re-review 2: shutdown submits what an attempt queued right
        # before close(), while the monitoring runtime still runs.
        application = self.scene_application()
        service = application.state.scene_calibration
        original = service.close

        def close():
            service._notices.append(Notice(REACQUIRED, self.clock.utcnow(), uuid4()))
            original()

        service.close = close
        async with asyncio.timeout(60), application.router.lifespan_context(application):
            await asyncio.sleep(0.2)
        self.assertEqual([("scene_reference_reacquired", 1, "sent")], self.notified())
        self.assertEqual(["ServerSentinel critical alert: scene_reference_reacquired"], self.scene_texts())

    async def test_a_delivery_cancelled_by_shutdown_keeps_its_unsubmitted_notice(self):
        # Claude re-review 3: `return_notices` in `finally`. The submission
        # fails while shutdown cancels the pass that runs it; the notice is
        # put back (and, still undeliverable, reported) instead of vanishing.
        self.store(stored())
        application = self.scene_application()
        service = application.state.scene_calibration
        runtime = application.state.scene_monitoring
        entered = threading.Event()
        returned = []
        original_return = service.return_notices

        def return_notices(notices):
            returned.extend(notices)
            original_return(notices)

        service.return_notices = return_notices

        real_record = NotificationService.record

        def refuse(notifications, kind, **options):
            if kind.value != REACQUIRED:
                return real_record(notifications, kind, **options)
            entered.set()
            time.sleep(3.0)
            raise RuntimeError("synthetic submission failure")

        with self.assertLogs("app.main", "ERROR") as logs, \
                mock.patch.object(NotificationService, "record", autospec=True, side_effect=refuse):
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                with Feed(runtime):
                    # Shutdown starts while the first submission is running.
                    self.assertTrue(await self.until(entered.is_set))
        self.assertTrue(returned)
        self.assertEqual([REACQUIRED], [item.kind for item in returned][:1])
        self.assertIn("scene_calibration_notice_undelivered", "\n".join(logs.output))
        self.assertEqual([], self.notified())

    async def test_a_notice_the_service_refuses_is_retried_and_sent_once(self):
        # Codex P1 (#330): a full or closed queue (`can_accept` false) and a
        # `failed` result the service does not retain kept nothing; the
        # notice is put back and later sent once under its event id.
        self.store(stored())
        application = self.scene_application()
        service = application.state.scene_calibration
        runtime = application.state.scene_monitoring
        real_accept, real_record = NotificationService.can_accept, NotificationService.record
        real_take = service.take_notices
        ours, full, log = set(), set(), []

        def take_notices():
            notices = real_take()
            ours.update(notice.event_id for notice in notices)
            return notices

        def can_accept(notifications, event_id):
            if event_id in ours and "refused" not in log:
                # The first ask for the notice finds the queue full.
                log.append("refused")
                full.add(event_id)
                return False
            full.discard(event_id)
            return real_accept(notifications, event_id)

        def record(notifications, kind, **options):
            event_id = options.get("event_id")
            if event_id not in ours:
                return real_record(notifications, kind, **options)
            if event_id in full:
                log.append("recorded while full")
            log.append("record")
            if log.count("record") == 1:
                return DeliveryResult.FAILED   # closed queue: nothing kept
            return real_record(notifications, kind, **options)

        service.take_notices = take_notices
        with mock.patch.object(NotificationService, "can_accept", autospec=True, side_effect=can_accept), \
                mock.patch.object(NotificationService, "record", autospec=True, side_effect=record):
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                with Feed(runtime):
                    self.assertTrue(await self.until(lambda: len(self.scene_texts()) == 1, timeout=30))
                    await asyncio.sleep(1.5)
        self.assertEqual(["refused", "record", "record"], log)
        self.assertEqual([("scene_reference_reacquired", 1, "sent")], self.notified())
        self.assertEqual(["ServerSentinel critical alert: scene_reference_reacquired"], self.scene_texts())

    def test_scene_calibration_requires_the_monitoring_notifications(self):
        # Codex P2 (#330): without them a re-acquisition notice could only
        # be logged and dropped.
        remote = binding(OTHER, SourceType.REMOTE_AGENT)
        with self.assertRaises(TypeError):
            create_app(self.settings, scene_monitoring=SceneMonitoringConfiguration((remote,)),
                       scene_monitoring_dependencies=SceneMonitoringDependencies(recorder=Recorder()),
                       scene_calibration=SceneCalibrationConfiguration((template(),)))

    def test_scene_calibration_requires_a_durable_critical_recorder(self):
        # Codex P1 (#330): without `scene_timeline` or an injected recorder
        # the scene runtime never starts and nothing could be re-acquired.
        with self.assertRaisesRegex(TypeError, "critical recorder"):
            self.scene_application(recorder=False)

    async def test_a_scene_runtime_that_cannot_start_is_notified_once_per_source(self):
        # Codex P1 (#330): a start that ends `unavailable` cannot be retried;
        # each source with a stored calibration is notified once instead of
        # the loop waiting forever.
        silent = uuid4()
        sources = (OTHER, silent)
        self.store(stored())
        application = self.scene_application(sources)
        runtime = application.state.scene_monitoring
        service = application.state.scene_calibration
        with mock.patch.object(runtime._pump, "start", side_effect=RuntimeError("synthetic start failure")):
            async with asyncio.timeout(60), application.router.lifespan_context(application):
                self.assertIs(SceneRuntimeState.UNAVAILABLE, runtime.status().state)
                self.assertTrue(await self.until(lambda: len(self.scene_texts()) == 1))
                # Retried every second; still one notice per stored source.
                await asyncio.sleep(2.5)
                (status,) = [item for item in service.status() if item.source_id == OTHER]
                self.assertEqual("unavailable", status.failure)
        self.assertEqual(["ServerSentinel critical alert: scene_calibration_required"], self.scene_texts())
        self.assertEqual([1], self.versions())

    def test_the_application_owns_the_calibration_provider(self):
        remote = binding(OTHER, SourceType.REMOTE_AGENT)
        with self.assertRaises(TypeError):
            create_app(self.settings, scene_calibration=SceneCalibrationConfiguration())
        with self.assertRaises(TypeError):
            create_app(self.settings, scene_monitoring=SceneMonitoringConfiguration((remote,)),
                       scene_monitoring_dependencies=SceneMonitoringDependencies(
                           calibrations=lambda value: None),
                       scene_calibration=SceneCalibrationConfiguration())
        with self.assertRaises(TypeError):
            create_app(self.settings, scene_monitoring=SceneMonitoringConfiguration((remote,)),
                       scene_calibration=object())


if __name__ == "__main__":
    unittest.main()
