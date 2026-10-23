"""Owner calibration and the restart re-acquisition of scene references (#205).

The scene detector needs a calibration whose reference frame it can bind
(`CalibrationRecord.bind`), and the private history keeps frame-free
provenance only: never pixels, nor a digest or other value derived from
them. A reference therefore exists only in this process's memory
(`TransientReferences`); nothing derived from an image is written to disk
(Owner decision 2026-10-22). Two paths produce one:

- **Owner calibration.** The Owner states that the camera and the monitored
  server are in their normal position and asks for a calibration (the
  `OWNER_OP` route in `app.auth.human_surface`, with step-up). The next good
  frames of that source are read through its own luma reader
  (`SceneMonitoringRuntime.acquire_reference`), the deployment's
  `CalibrationTemplate` supplies the polygon, geometry and policy, and the
  new version's provenance commits together with its audit record.
- **Restart re-acquisition** (Owner decision 2026-10-22, option A). After a
  Main restart the stored reference frame is gone, so for every source with
  a stored calibration the reference is taken again with the stored
  polygon, geometry and policy, committed as a new version with a `system`
  audit record, and the Owner is notified immediately
  (`scene_reference_reacquired`). Such a reference was not confirmed by the
  Owner: a camera or server moved while Main was down is not detected
  against it, which is why the Owner is told and the status keeps
  `restart_reacquired` until the Owner calibrates. A reference that cannot
  be re-acquired (no frame, insufficient quality, a changed reader, an
  unsuitable scene, an unavailable history) leaves the source inactive and
  `unknown`, notifies `scene_calibration_required` once per process and is
  retried.

Nothing here decides who may calibrate: the caller hands in an audited
`commit` (the Owner route's, or Main's system commit). Status is value-free:
no pixel, digest, polygon or policy value leaves this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import logging
import sqlite3
import threading
from contextlib import closing
from typing import Callable
from uuid import UUID, uuid4

from app.detection.foundation import GrayFrame
from app.logging import Event
from .calibration import CalibrationArchive, CalibrationRecord, append_on, provenance
from .contracts import Calibration, Policy
from .geometry import validate_polygon
from .runtime import (
    MAXIMUM_SOURCES, ArchiveCalibrationProvider, ReferenceUnavailable, SceneMonitoringRuntime,
    reader_identity,
)


NANOSECONDS = 1_000_000_000
DEFAULT_ACQUISITION_TIMEOUT_SECONDS = 10.0
# A restart re-acquisition waits longer: capture opens after the scene
# runtime starts, and a camera may need a few seconds to deliver.
DEFAULT_REACQUIRE_TIMEOUT_SECONDS = 60.0
DEFAULT_REACQUIRE_RETRY_SECONDS = 60.0
# The requester waits this much longer than the worker's deadline before it
# cancels the acquisition itself (the worker checks its deadline per pass).
WAIT_MARGIN_SECONDS = 5.0
REACQUIRED = "scene_reference_reacquired"
REQUIRED = "scene_calibration_required"


class CalibrationRefused(Exception):
    """A calibration attempt's fixed, value-free refusal."""

    REASONS = ReferenceUnavailable.REASONS | frozenset({
        # The detector refused the reference (no usable support, an already
        # obscured scene, a bounded search that cannot register it).
        "scene_unsuitable",
        # No deployment template for an Owner calibration of this source.
        "template_unconfigured",
        # The calibration history could not be read or written.
        "history_unavailable",
        # The stored calibration was recorded through another luma reader
        # (or before readers were recorded), so it is not re-used.
        "reader_changed",
        # Nothing stored to re-acquire.
        "calibration_missing",
    })

    def __init__(self, reason: str):
        if reason not in self.REASONS:
            reason = "unavailable"
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CalibrationTemplate:
    """The deployment's calibration setting of one source.

    The Owner selects the server ROI polygon and the scene policy in the
    deployment configuration (the same Owner-controlled file as the source
    list); the reference is the only part taken from the camera. Coordinates
    are in the reference geometry (`width` x `height`, the decimated luma
    the detector compares), never in the camera's own resolution.
    """

    source_id: UUID
    width: int
    height: int
    polygon: tuple[tuple[int, int], ...]
    policy: Policy

    def __post_init__(self):
        if not isinstance(self.source_id, UUID) or not isinstance(self.policy, Policy):
            raise ValueError("invalid calibration template")
        for value in (self.width, self.height):
            if type(value) is not int or not 1 <= value <= 16384:
                raise ValueError("invalid calibration template geometry")
        if self.width * self.height > self.policy.maximum_pixels:
            raise ValueError("calibration template exceeds its pixel budget")
        if type(self.polygon) is not tuple or not 3 <= len(self.polygon) <= 32:
            raise ValueError("invalid calibration template polygon")
        for point in self.polygon:
            if (type(point) is not tuple or len(point) != 2 or any(type(v) is not int for v in point)
                    or not 0 <= point[0] < self.width or not 0 <= point[1] < self.height):
                raise ValueError("calibration template polygon lies outside its geometry")
        validate_polygon(self.polygon)


def _seconds(value, low, high, name):
    if type(value) not in (int, float) or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return float(value)


@dataclass(frozen=True)
class SceneCalibrationConfiguration:
    templates: tuple[CalibrationTemplate, ...] = ()
    acquisition_timeout_seconds: float = DEFAULT_ACQUISITION_TIMEOUT_SECONDS
    reacquire_timeout_seconds: float = DEFAULT_REACQUIRE_TIMEOUT_SECONDS
    reacquire_retry_seconds: float = DEFAULT_REACQUIRE_RETRY_SECONDS

    def __post_init__(self):
        if (type(self.templates) is not tuple or len(self.templates) > MAXIMUM_SOURCES
                or any(not isinstance(item, CalibrationTemplate) for item in self.templates)
                or len({item.source_id for item in self.templates}) != len(self.templates)):
            raise ValueError("invalid calibration templates")
        _seconds(self.acquisition_timeout_seconds, 1, 30, "acquisition timeout")
        _seconds(self.reacquire_timeout_seconds, 1, 600, "re-acquisition timeout")
        _seconds(self.reacquire_retry_seconds, 1, 3600, "re-acquisition retry interval")


class TransientReferences:
    """The process-memory reference port of `ArchiveCalibrationProvider`.

    Holds the reference frame of the calibration in use (and of one being
    committed) per source; never written anywhere. A stored record is served
    its in-memory calibration only when that calibration's whole frame-free
    provenance is the record (identity, version, time, polygon, policy,
    reader, reference stream, sample and geometry), so a frame staged for a
    commit that then failed is never bound to the record that is actually
    stored. This in-memory object identity is the integrity binding; no
    digest of the frame is kept on disk.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._frames: dict[tuple[UUID, UUID, int], Calibration] = {}

    @staticmethod
    def _key(item):
        return item.source_id, item.profile_id, item.version

    def stage(self, calibration: Calibration) -> None:
        with self._lock:
            self._frames[self._key(calibration)] = calibration

    def drop(self, calibration: Calibration) -> None:
        with self._lock:
            if self._frames.get(self._key(calibration)) is calibration:
                del self._frames[self._key(calibration)]

    def promote(self, calibration: Calibration) -> None:
        """Keep `calibration` and forget every older frame of its source."""
        with self._lock:
            for key in [key for key in self._frames
                        if key[:2] == self._key(calibration)[:2] and key[2] < calibration.version]:
                del self._frames[key]

    def clear(self) -> None:
        with self._lock:
            self._frames.clear()

    def __call__(self, record: CalibrationRecord) -> Calibration | None:
        with self._lock:
            calibration = self._frames.get(self._key(record))
        if calibration is None or provenance(calibration) != record:
            return None
        return calibration


class CalibrationOrigin(StrEnum):
    # No calibration is in use in this process.
    NONE = "none"
    # The Owner calibrated it in this process.
    OWNER = "owner"
    # Re-acquired automatically after a restart, not confirmed by the Owner.
    RESTART_REACQUIRED = "restart_reacquired"


class CalibrationPhase(StrEnum):
    IDLE = "idle"
    # A reference is being read for this source.
    ACQUIRING = "acquiring"
    # A stored calibration still waits for its restart re-acquisition.
    REACQUIRE_PENDING = "reacquire_pending"


@dataclass(frozen=True)
class SourceCalibrationStatus:
    source_id: UUID
    origin: CalibrationOrigin
    version: int | None
    calibrated_at: datetime | None
    phase: CalibrationPhase
    # The last attempt's fixed refusal (`CalibrationRefused.REASONS`), or None.
    failure: str | None
    owner_calibration_available: bool
    # The scene runtime's own value-free source state and reason.
    detection: str
    detection_reason: str


@dataclass(frozen=True)
class Notice:
    """One Owner notification to submit (fixed kind, no identity or value)."""

    kind: str
    at: datetime
    event_id: UUID


Commit = Callable[[UUID, Callable[[], Calibration],
                   Callable[[sqlite3.Connection, Calibration], CalibrationRecord]], CalibrationRecord]


@dataclass
class _Source:
    origin: CalibrationOrigin = CalibrationOrigin.NONE
    version: int | None = None
    calibrated_at: datetime | None = None
    acquiring: bool = False
    reacquire: bool = False
    failure: str | None = None
    required_notified: bool = False


def _utcnow():
    return datetime.now(timezone.utc)


class SceneCalibrationService:
    """Owner calibration and restart re-acquisition for one scene runtime."""

    def __init__(self, configuration: SceneCalibrationConfiguration, runtime: SceneMonitoringRuntime,
                 connect: Callable[[], sqlite3.Connection], *,
                 references: "TransientReferences",
                 utcnow: Callable[[], datetime] = _utcnow):
        if not isinstance(configuration, SceneCalibrationConfiguration):
            raise TypeError("scene calibration configuration is required")
        if not isinstance(runtime, SceneMonitoringRuntime) or not callable(connect) or not callable(utcnow):
            raise TypeError("invalid scene calibration dependencies")
        unknown = {item.source_id for item in configuration.templates} - set(runtime.source_ids)
        if unknown:
            raise ValueError("calibration template for a source that is not monitored")
        provider = runtime.calibrations
        if (not isinstance(references, TransientReferences)
                or not isinstance(provider, ArchiveCalibrationProvider)
                or provider.references is not references):
            # The runtime must resolve its calibrations through exactly these
            # in-memory references, or a committed version would never bind.
            raise ValueError("scene runtime does not read these calibration references")
        self.configuration = configuration
        self.runtime = runtime
        self._connect = connect
        self._utcnow = utcnow
        self.references = references
        self._templates = {item.source_id: item for item in configuration.templates}
        self._lock = threading.Lock()
        self._sources = {source_id: _Source() for source_id in runtime.source_ids}
        self._notices: list[Notice] = []
        self._pending: dict[UUID, object] = {}
        self._closed = False
        self._started = False

    # -- status ----------------------------------------------------------
    def status(self) -> tuple[SourceCalibrationStatus, ...]:
        try:
            runtime = {item.source_id: item for item in self.runtime.status().sources}
        except Exception:
            runtime = {}
        with self._lock:
            result = []
            for source_id, state in self._sources.items():
                detection = runtime.get(source_id)
                phase = (CalibrationPhase.ACQUIRING if state.acquiring
                         else CalibrationPhase.REACQUIRE_PENDING if state.reacquire
                         else CalibrationPhase.IDLE)
                result.append(SourceCalibrationStatus(
                    source_id, state.origin, state.version, state.calibrated_at, phase, state.failure,
                    source_id in self._templates,
                    detection.state.value if detection is not None else "inactive",
                    detection.reason if detection is not None else "unavailable"))
            return tuple(result)

    def take_notices(self) -> tuple[Notice, ...]:
        with self._lock:
            notices, self._notices = tuple(self._notices), []
            return notices

    def return_notices(self, notices) -> None:
        """Put undelivered notices back (kept in order, same event ids)."""
        with self._lock:
            self._notices[:0] = list(notices)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        """Mark every source with a stored calibration for re-acquisition.

        Called once after the scene runtime started. A history that cannot
        be read marks the source as well (the attempt reports why), so a
        failure is never silent.
        """
        with self._lock:
            if self._started or self._closed:
                return
            self._started = True
        for source_id in self.runtime.source_ids:
            binding = self.runtime.binding(source_id)
            try:
                record = self._latest(binding)
            except CalibrationRefused:
                record = True
            if record is not None:
                with self._lock:
                    state = self._sources[source_id]
                    if state.origin is CalibrationOrigin.NONE:
                        state.reacquire = True

    def pending_reacquisitions(self) -> tuple[UUID, ...]:
        with self._lock:
            return tuple(source_id for source_id, state in self._sources.items()
                         if state.reacquire and not state.acquiring)

    def close(self) -> None:
        """Refuse further attempts and end the acquisitions in flight."""
        with self._lock:
            self._closed = True
            pending = list(self._pending.items())
        for source_id, future in pending:
            self.runtime.cancel_acquisition(source_id, future)

    # -- attempts ----------------------------------------------------------
    def calibrate(self, source_id: UUID, commit: Commit) -> CalibrationRecord:
        """An Owner calibration with the deployment template of `source_id`.

        `commit(source_id, prepare, persist)` is the audited Owner
        transaction: it runs `prepare()` (the acquisition, after its
        authorization) and then `persist(connection, calibration)` with its
        audit record in one transaction. Raises `CalibrationRefused` for a
        refused attempt and lets any other commit failure propagate (the
        change was not committed).
        """
        template = self._templates.get(source_id)
        binding = self.runtime.binding(source_id) if isinstance(source_id, UUID) else None
        if binding is None:
            raise CalibrationRefused("unavailable")
        if template is None:
            raise CalibrationRefused("template_unconfigured")

        def plan():
            record = self._latest(binding)
            identifier, version = ((record.identifier, record.version + 1) if record is not None
                                   else (uuid4(), 1))
            return (identifier, version, template.width, template.height, template.polygon,
                    template.policy)

        return self._attempt(source_id, binding, plan, commit, CalibrationOrigin.OWNER,
                             self.configuration.acquisition_timeout_seconds)

    def reacquire(self, source_id: UUID, commit: Commit) -> CalibrationRecord | None:
        """One restart re-acquisition attempt of `source_id` (Owner decision A).

        Returns the new record, or None when the source no longer needs one
        or the attempt failed (the failure is in `status()` and, for a
        refusal the Owner can act on, in one `scene_calibration_required`
        notice per process).
        """
        binding = self.runtime.binding(source_id) if isinstance(source_id, UUID) else None
        with self._lock:
            state = self._sources.get(source_id)
            if binding is None or state is None or not state.reacquire:
                return None

        def plan():
            record = self._latest(binding)
            if record is None:
                raise CalibrationRefused("calibration_missing")
            if record.reader is None or record.reader != reader_identity(binding):
                raise CalibrationRefused("reader_changed")
            return (record.identifier, record.version + 1, record.reference_width,
                    record.reference_height, record.polygon, record.policy)

        try:
            return self._attempt(source_id, binding, plan, commit, CalibrationOrigin.RESTART_REACQUIRED,
                                 self.configuration.reacquire_timeout_seconds)
        except CalibrationRefused as refused:
            if refused.reason == "calibration_missing":
                with self._lock:
                    self._sources[source_id].reacquire = False
            elif refused.reason not in ("unavailable", "busy", "cancelled"):
                self._required(source_id)
            return None
        except Exception:
            self._required(source_id)
            return None

    def _required(self, source_id):
        with self._lock:
            state = self._sources[source_id]
            if state.required_notified or not state.reacquire:
                return
            state.required_notified = True
            self._notices.append(Notice(REQUIRED, self._utcnow(), uuid4()))
        logging.getLogger(__name__).error(Event.SCENE_CALIBRATION_REQUIRED)

    def _latest(self, binding) -> CalibrationRecord | None:
        try:
            with closing(self._connect()) as connection:
                return CalibrationArchive(connection).load(binding.source_id, binding.profile_id)
        except Exception:
            raise CalibrationRefused("history_unavailable") from None

    def _attempt(self, source_id, binding, plan, commit, origin, timeout):
        with self._lock:
            state = self._sources[source_id]
            if self._closed:
                raise CalibrationRefused("unavailable")
            if state.acquiring:
                raise CalibrationRefused("busy")
            state.acquiring = True
        staged = []

        def prepare() -> Calibration:
            identifier, version, width, height, polygon, policy = plan()
            frame = self._read(source_id, width, height, timeout)
            try:
                calibration = Calibration(identifier, source_id, binding.source_type, binding.profile_id,
                                          version, self._utcnow(), polygon, frame, policy,
                                          reader_identity(binding))
            except ValueError:
                raise CalibrationRefused("scene_unsuitable") from None
            refusal = self.runtime.calibration_refusal(calibration)
            if refusal == "calibration_refused":
                raise CalibrationRefused("scene_unsuitable")
            if refusal is not None:
                raise CalibrationRefused("geometry_unsupported")
            # Staged before the commit, so the worker can bind the new
            # version as soon as it is stored; dropped if the commit fails.
            self.references.stage(calibration)
            staged.append(calibration)
            return calibration

        def persist(connection, calibration) -> CalibrationRecord:
            try:
                return append_on(connection, calibration)
            except RuntimeError:
                raise CalibrationRefused("history_unavailable") from None

        try:
            record = commit(source_id, prepare, persist)
        except CalibrationRefused as refused:
            self._finish(source_id, staged, failure=refused.reason)
            raise
        except BaseException:
            self._finish(source_id, staged, failure="history_unavailable")
            raise
        if not isinstance(record, CalibrationRecord) or not staged:
            self._finish(source_id, staged, failure="history_unavailable")
            raise CalibrationRefused("history_unavailable")
        calibration = staged[0]
        self.references.promote(calibration)
        with self._lock:
            state = self._sources[source_id]
            state.acquiring = False
            state.failure = None
            state.origin, state.version, state.calibrated_at = origin, record.version, record.created_at
            notify = origin is CalibrationOrigin.RESTART_REACQUIRED and state.reacquire
            state.reacquire = False
            if notify:
                self._notices.append(Notice(REACQUIRED, self._utcnow(), uuid4()))
        # The worker re-resolves the calibration: the stored version now has
        # its in-memory frame.
        self.runtime.request_calibration_refresh(source_id)
        if notify:
            logging.getLogger(__name__).warning(Event.SCENE_REFERENCE_REACQUIRED)
        return record

    def _finish(self, source_id, staged, *, failure):
        for calibration in staged:
            self.references.drop(calibration)
        with self._lock:
            state = self._sources[source_id]
            state.acquiring = False
            state.failure = failure

    def _read(self, source_id, width, height, timeout) -> GrayFrame:
        try:
            future = self.runtime.acquire_reference(source_id, width, height,
                                                    timeout_ns=int(timeout * NANOSECONDS))
        except ReferenceUnavailable as error:
            raise CalibrationRefused(error.reason) from None
        with self._lock:
            closed = self._closed
            self._pending[source_id] = future
        try:
            if closed:
                self.runtime.cancel_acquisition(source_id, future)
            try:
                return future.result(timeout + WAIT_MARGIN_SECONDS)
            except ReferenceUnavailable as error:
                raise CalibrationRefused(error.reason) from None
            except Exception:
                self.runtime.cancel_acquisition(source_id, future)
                raise CalibrationRefused("cancelled") from None
        finally:
            with self._lock:
                if self._pending.get(source_id) is future:
                    del self._pending[source_id]
