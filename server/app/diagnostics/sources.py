"""Production diagnostic producers over existing deployment-local subsystems.

Every adapter reads a bounded, already value-free health surface and maps it
onto the reviewed field names and enums in `export.py`. None of them reads a
camera name, role label, serial, device path, capability document, pairing
code or digest, Slack endpoint, credential, WebAuthn material or the Owner
template store. Only counts and fixed states leave an adapter.

A subsystem that is not composed reports `unavailable` with `not_configured`;
one that raises reports `unavailable` with `dependency_unavailable`. Neither is
ever reported as `ok`. Nothing here opens a socket, schedules work, or writes.
"""

from collections.abc import Callable, Iterable
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass
import math
import re
import threading
from typing import Iterator
from uuid import UUID

from app import __version__
from app.cameras.registry.models import SourceHealthState, SourceType
from app.integrity.model import Finding, Kind, State
from app.media.health.service import HealthState
from app.monitoring.runtime import RuntimeState
from app.storage.policy import StorageState

from .export import (
    DiagnosticCategory,
    DiagnosticDocument,
    DiagnosticField,
    DiagnosticFieldKind,
    DiagnosticSource,
    MediaAsset,
    MediaDescriptor,
    MediaSource,
    SafeDiagnosticFieldName as Name,
    SafeDiagnosticReasonCode as Reason,
    SafeDiagnosticState as Health,
    StorageWorker,
)


# Selected raw media is addressed only as one published recording segment.
# No other namespace (Owner template, face crop, self-test artifact, bundle)
# is resolvable, so biometric data can never be selected for export.
_SEGMENT_MEDIA_ID = re.compile(r"^segment\.([0-9a-f]{32})$")
SEGMENT_MEDIA_TYPE = "application/octet-stream"
_MAX_UNDELIVERED = 1_000_000_000


class DiagnosticSourceUnavailable(RuntimeError):
    """A value-free adapter failure; it is never relayed to a caller."""


def segment_media_id(segment_id: UUID) -> str:
    """The only media ID form the recording-backed source resolves."""
    if not isinstance(segment_id, UUID):
        raise TypeError("segment identity must be a UUID")
    return "segment." + segment_id.hex


def _segment_id(media_id: object) -> UUID:
    if type(media_id) is not str:
        raise DiagnosticSourceUnavailable
    matched = _SEGMENT_MEDIA_ID.fullmatch(media_id)
    if matched is None:
        raise DiagnosticSourceUnavailable
    return UUID(hex=matched.group(1))


def _field(name: Name, value) -> DiagnosticField:
    return DiagnosticField(name.value, value)


class OwnerWorkerCalls:
    """Run a read on the worker thread that owns the monitoring stores.

    `RecordingStore` and `IntegrityStore` refuse calls from any other thread.
    Collection runs on a separate thread, so reads are submitted to the owning
    worker and awaited with a bound. Once that worker's thread is observed, a
    call already running on it executes directly instead of queueing behind
    itself; a worker that later runs a call on another thread is refused.
    """

    def __init__(self, worker: StorageWorker, *, timeout_seconds: float = 10.0) -> None:
        if not callable(getattr(worker, "submit", None)):
            raise TypeError("owner worker must schedule owning-thread calls")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or timeout_seconds <= 0):
            raise ValueError("owner worker timeout is invalid")
        self._worker = worker
        self._timeout = float(timeout_seconds)
        self._lock = threading.Lock()
        self._thread: int | None = None

    def on_owner(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread == threading.get_ident()

    def _bound(self, call):
        identity = threading.get_ident()
        with self._lock:
            if self._thread is None:
                self._thread = identity
            elif self._thread != identity:
                raise DiagnosticSourceUnavailable
        return call()

    def run(self, call):
        if self.on_owner():
            return call()
        try:
            scheduled = self._worker.submit(lambda: self._bound(call))
        except Exception:
            raise DiagnosticSourceUnavailable from None
        if not isinstance(scheduled, Future):
            raise DiagnosticSourceUnavailable
        try:
            return scheduled.result(timeout=self._timeout)
        except Exception:
            raise DiagnosticSourceUnavailable from None


class _Adapter:
    """One subsystem's fields within one category, plus value-free fallbacks."""

    category: DiagnosticCategory
    state_fields: tuple[Name, ...] = ()
    reason_field: Name | None = None

    def read(self) -> Iterable[DiagnosticField]:
        raise NotImplementedError

    def unavailable(self, reason: Reason) -> tuple[DiagnosticField, ...]:
        fields = [_field(name, Health.UNAVAILABLE) for name in self.state_fields]
        if self.reason_field is not None:
            fields.append(_field(self.reason_field, reason))
        return tuple(fields)


def _flag_state(flag: object) -> Health:
    if type(flag) is not bool:
        raise DiagnosticSourceUnavailable
    return Health.DEGRADED if flag else Health.OK


def _running(monitoring) -> tuple[object, bool]:
    status = monitoring.status
    if not isinstance(status.state, RuntimeState):
        raise DiagnosticSourceUnavailable
    return status, status.state is RuntimeState.RUNNING


class VersionAdapter(_Adapter):
    category = DiagnosticCategory.RUNTIME

    def __init__(self, version: str = __version__) -> None:
        self._version = version

    def read(self):
        # A malformed version fails validation and is omitted, never relayed.
        return (_field(Name.VERSION, self._version),)


_RUNTIME_STATES = {
    RuntimeState.RUNNING: (Health.OK, Reason.NONE),
    RuntimeState.STARTING: (Health.UNKNOWN, Reason.NONE),
    RuntimeState.FAILED: (Health.FAILED, Reason.DEPENDENCY_UNAVAILABLE),
    RuntimeState.STOPPED: (Health.OFFLINE, Reason.NONE),
    RuntimeState.UNCONFIGURED: (Health.UNAVAILABLE, Reason.NOT_CONFIGURED),
}


class MonitoringRuntimeAdapter(_Adapter):
    """Main Server monitoring worker state and its background job health."""

    category = DiagnosticCategory.RUNTIME
    state_fields = (Name.MONITORING_STATE, Name.RETENTION_STATE, Name.DAILY_SUMMARY_STATE,
                    Name.NOTIFICATION_LOCAL_STATE, Name.NOTIFICATION_DELIVERY_STATE)
    reason_field = Name.MONITORING_REASON_CODE

    def __init__(self, monitoring) -> None:
        self._monitoring = monitoring

    def read(self):
        if self._monitoring is None:
            return self.unavailable(Reason.NOT_CONFIGURED)
        status, running = _running(self._monitoring)
        state, reason = _RUNTIME_STATES[status.state]
        fields = [_field(Name.MONITORING_STATE, state),
                  _field(Name.MONITORING_REASON_CODE, reason)]
        for name, flag in ((Name.RETENTION_STATE, status.retention_degraded),
                           (Name.DAILY_SUMMARY_STATE, status.summary_degraded),
                           (Name.NOTIFICATION_LOCAL_STATE, status.notification_local_failed),
                           (Name.NOTIFICATION_DELIVERY_STATE,
                            status.notification_delivery_failed)):
            # A job flag defaults to "not degraded" before the worker runs, so
            # it only means healthy while the runtime is actually running.
            fields.append(_field(name, _flag_state(flag) if running else Health.UNAVAILABLE))
        return tuple(fields)


_STORAGE_STATES = {
    StorageState.NORMAL: (Health.OK, Reason.NONE),
    StorageState.PRESSURE: (Health.DEGRADED, Reason.STORAGE_PRESSURE),
    StorageState.HARD_STOP: (Health.FAILED, Reason.STORAGE_HARD_STOP),
}


class StorageAdapter(_Adapter):
    category = DiagnosticCategory.STORAGE
    state_fields = (Name.STORAGE_STATE, Name.STORAGE_AUDIT_DELIVERY_STATE,
                    Name.RECORDING_FILESYSTEM_STATE)
    reason_field = Name.STORAGE_REASON_CODE

    def __init__(self, monitoring) -> None:
        self._monitoring = monitoring

    def read(self):
        if self._monitoring is None:
            return self.unavailable(Reason.NOT_CONFIGURED)
        status, running = _running(self._monitoring)
        filesystem = status.recording_filesystem_ok
        if filesystem is not None and type(filesystem) is not bool:
            raise DiagnosticSourceUnavailable
        if filesystem is False:
            filesystem_state = Health.FAILED
        elif filesystem is True and running:
            filesystem_state = Health.OK
        else:
            filesystem_state = Health.UNKNOWN if running else Health.UNAVAILABLE
        if not running:
            return (_field(Name.STORAGE_STATE, Health.UNAVAILABLE),
                    _field(Name.STORAGE_REASON_CODE, Reason.DEPENDENCY_UNAVAILABLE),
                    _field(Name.STORAGE_AUDIT_DELIVERY_STATE, Health.UNAVAILABLE),
                    _field(Name.RECORDING_FILESYSTEM_STATE, filesystem_state))
        if status.storage_state is None:
            state, reason = Health.UNKNOWN, Reason.DEPENDENCY_UNAVAILABLE
        else:
            state, reason = _STORAGE_STATES[StorageState(status.storage_state)]
        return (_field(Name.STORAGE_STATE, state),
                _field(Name.STORAGE_REASON_CODE, reason),
                _field(Name.STORAGE_AUDIT_DELIVERY_STATE,
                       _flag_state(status.storage_audit_failed)),
                _field(Name.RECORDING_FILESYSTEM_STATE, filesystem_state))


_RECORDING_HEALTH = {
    HealthState.OK: (Health.OK, Reason.NONE),
    HealthState.FAILED: (Health.FAILED, Reason.SELF_TEST_FAILED),
    HealthState.UNAVAILABLE: (Health.UNAVAILABLE, Reason.DEPENDENCY_UNAVAILABLE),
}


class RecordingHealthAdapter(_Adapter):
    """Latest daily recording self-test verdict; stages and media stay local."""

    category = DiagnosticCategory.RECORDING_HEALTH
    state_fields = (Name.RECORDING_HEALTH_STATE, Name.RECORDING_SELF_TEST_STATE)
    reason_field = Name.RECORDING_HEALTH_REASON_CODE

    def __init__(self, monitoring) -> None:
        self._monitoring = monitoring

    def read(self):
        if self._monitoring is None:
            return self.unavailable(Reason.NOT_CONFIGURED)
        status, running = _running(self._monitoring)
        verdict = status.recording_health
        if verdict is not None and not isinstance(verdict, HealthState):
            raise DiagnosticSourceUnavailable
        if verdict is HealthState.FAILED:
            # A failed verdict stays visible even after the worker stopped.
            state, reason = _RECORDING_HEALTH[verdict]
        elif not running:
            state, reason = Health.UNAVAILABLE, Reason.DEPENDENCY_UNAVAILABLE
        elif verdict is None:
            state, reason = Health.UNKNOWN, Reason.NONE
        else:
            state, reason = _RECORDING_HEALTH[verdict]
        self_test = (_flag_state(status.recording_health_degraded) if running
                     else Health.UNAVAILABLE)
        return (_field(Name.RECORDING_HEALTH_STATE, state),
                _field(Name.RECORDING_HEALTH_REASON_CODE, reason),
                _field(Name.RECORDING_SELF_TEST_STATE, self_test))


_KIND_FIELDS = {
    Kind.CPU: Name.INTEGRITY_CPU_REASON_CODE,
    Kind.MEMORY: Name.INTEGRITY_MEMORY_REASON_CODE,
    Kind.STORAGE: Name.INTEGRITY_STORAGE_REASON_CODE,
    Kind.GPU: Name.INTEGRITY_GPU_REASON_CODE,
}
_FINDING_REASONS = {
    State.OK: Reason.NONE,
    State.CHANGED: Reason.HARDWARE_CHANGED,
    State.MISSING: Reason.HARDWARE_MISSING,
    State.NEW_DEVICE: Reason.HARDWARE_NEW_DEVICE,
    State.UNVERIFIABLE: Reason.HARDWARE_UNVERIFIABLE,
}
# Most severe first: the aggregate reason names the worst category verdict.
_FINDING_SEVERITY = (State.MISSING, State.CHANGED, State.UNVERIFIABLE, State.NEW_DEVICE)


class IntegrityAdapter(_Adapter):
    """Hardware Integrity verdicts per category; never baseline observations."""

    category = DiagnosticCategory.HARDWARE_INVENTORY
    state_fields = (Name.INTEGRITY_STATE, Name.INTEGRITY_CHECK_STATE,
                    Name.INTEGRITY_DELIVERY_STATE)
    reason_field = Name.INTEGRITY_REASON_CODE

    def __init__(self, monitoring,
                 latest: Callable[[], tuple[tuple[Finding, ...], bool] | None] | None) -> None:
        self._monitoring = monitoring
        self._latest = latest

    def read(self):
        if self._monitoring is None:
            return self.unavailable(Reason.NOT_CONFIGURED)
        status, running = _running(self._monitoring)
        if not running or self._latest is None:
            return self.unavailable(Reason.DEPENDENCY_UNAVAILABLE)
        check_state = _flag_state(status.integrity_degraded)
        latest = self._latest()
        if latest is None:
            # No comparison has completed yet: unknown, never healthy.
            return (_field(Name.INTEGRITY_STATE, Health.UNKNOWN),
                    _field(Name.INTEGRITY_REASON_CODE, Reason.NONE),
                    _field(Name.INTEGRITY_CHECK_STATE, check_state),
                    _field(Name.INTEGRITY_DELIVERY_STATE, Health.UNKNOWN))
        findings, delivery_blocked = latest
        by_kind: dict[Kind, Finding] = {}
        for finding in findings:
            if not isinstance(finding, Finding) or finding.kind in by_kind:
                raise DiagnosticSourceUnavailable
            by_kind[finding.kind] = finding
        # A category the check did not report is unverifiable, not healthy.
        verdicts = {kind: by_kind.get(kind) or Finding(kind, State.UNVERIFIABLE, "NOT_REPORTED")
                    for kind in Kind}
        if any(item.state is not State.OK and item.immediate for item in verdicts.values()):
            state = Health.FAILED
        elif any(item.state is not State.OK for item in verdicts.values()):
            state = Health.DEGRADED
        else:
            state = Health.OK
        present = {item.state for item in verdicts.values()}
        worst = next((item for item in _FINDING_SEVERITY if item in present), State.OK)
        fields = [_field(Name.INTEGRITY_STATE, state),
                  _field(Name.INTEGRITY_REASON_CODE, _FINDING_REASONS[worst]),
                  _field(Name.INTEGRITY_CHECK_STATE, check_state),
                  _field(Name.INTEGRITY_DELIVERY_STATE, _flag_state(delivery_blocked))]
        fields.extend(_field(_KIND_FIELDS[kind], _FINDING_REASONS[verdicts[kind].state])
                      for kind in Kind)
        return tuple(fields)


class CameraRegistryAdapter(_Adapter):
    """Source counts by type and health; no name, role, serial or device path.

    Health counts cover enabled sources, the ones the deployment expects to
    be capturing. A disabled source is counted only in the totals.
    """

    category = DiagnosticCategory.CAMERA_HEALTH
    state_fields = (Name.CAMERA_REGISTRY_STATE,)
    reason_field = Name.CAMERA_REGISTRY_REASON_CODE

    def __init__(self, registry) -> None:
        self._registry = registry

    def read(self):
        if self._registry is None:
            return self.unavailable(Reason.NOT_CONFIGURED)
        sources = tuple(self._registry.list_sources())
        limit = self._registry.max_active_video_sources
        types = [SourceType(item.source_type) for item in sources]
        enabled = [item for item in sources if item.enabled is True]
        health = [SourceHealthState(item.health_state) for item in enabled]
        counts = {state: health.count(state) for state in SourceHealthState}
        if not enabled:
            state, reason = Health.UNAVAILABLE, Reason.NOT_CONFIGURED
        elif counts[SourceHealthState.MANUAL_INTERVENTION_REQUIRED]:
            state, reason = Health.DEGRADED, Reason.MANUAL_INTERVENTION_REQUIRED
        elif not counts[SourceHealthState.ONLINE]:
            state, reason = Health.FAILED, Reason.SOURCE_OFFLINE
        elif counts[SourceHealthState.OFFLINE]:
            state, reason = Health.DEGRADED, Reason.SOURCE_OFFLINE
        elif counts[SourceHealthState.DEGRADED]:
            state, reason = Health.DEGRADED, Reason.NONE
        else:
            state, reason = Health.OK, Reason.NONE
        return (
            _field(Name.CAMERA_REGISTRY_STATE, state),
            _field(Name.CAMERA_REGISTRY_REASON_CODE, reason),
            _field(Name.CAMERA_SOURCES_TOTAL, len(sources)),
            _field(Name.CAMERA_SOURCES_ENABLED, len(enabled)),
            _field(Name.CAMERA_SOURCES_LOCAL_UVC, types.count(SourceType.LOCAL_UVC)),
            _field(Name.CAMERA_SOURCES_REMOTE_AGENT, types.count(SourceType.REMOTE_AGENT)),
            _field(Name.CAMERA_SOURCES_ONLINE, counts[SourceHealthState.ONLINE]),
            _field(Name.CAMERA_SOURCES_DEGRADED, counts[SourceHealthState.DEGRADED]),
            _field(Name.CAMERA_SOURCES_OFFLINE, counts[SourceHealthState.OFFLINE]),
            _field(Name.CAMERA_SOURCES_MANUAL_INTERVENTION,
                   counts[SourceHealthState.MANUAL_INTERVENTION_REQUIRED]),
            _field(Name.CAMERA_SOURCES_ACTIVE_LIMIT, limit),
        )


class AuditDeliveryAdapter(_Adapter):
    """Undelivered audit-outcome health of one audited subsystem.

    Reads only the bounded `audit_delivery_failed` flag and the
    `undelivered_audit_records` counter every audited subsystem keeps; the
    subsystem's records, identities, codes and digests are never touched.
    """

    category = DiagnosticCategory.SECURITY

    def __init__(self, recorder, state_field: Name, count_field: Name) -> None:
        self._recorder = recorder
        self.state_fields = (state_field,)
        self._count_field = count_field

    def read(self):
        if self._recorder is None:
            return self.unavailable(Reason.NOT_CONFIGURED)
        count = self._recorder.undelivered_audit_records
        failed = self._recorder.audit_delivery_failed
        if (type(count) is not int or not 0 <= count <= _MAX_UNDELIVERED
                or type(failed) is not bool):
            raise DiagnosticSourceUnavailable
        state = Health.DEGRADED if failed or count else Health.OK
        return (_field(self.state_fields[0], state), _field(self._count_field, count))


_AUDIT_RETENTION = {"not_started": Health.UNKNOWN, "healthy": Health.OK,
                    "degraded": Health.DEGRADED}


class AuditRetentionAdapter(_Adapter):
    category = DiagnosticCategory.SECURITY
    state_fields = (Name.AUDIT_RETENTION_STATE,)

    def __init__(self, retention) -> None:
        self._retention = retention

    def read(self):
        if self._retention is None:
            return self.unavailable(Reason.NOT_CONFIGURED)
        health = self._retention.health
        if type(health) is not str or health not in _AUDIT_RETENTION:
            raise DiagnosticSourceUnavailable
        return (_field(Name.AUDIT_RETENTION_STATE, _AUDIT_RETENTION[health]),)


class CompositeDiagnosticSource:
    """Collect every adapter, isolating one failure to that adapter's fields.

    Only reviewed SAFE-kind fields are accepted from a production adapter:
    even a hashed hardware identifier or a classified exclusion is refused
    here, so this source never contributes a value the export must redact.
    """

    def __init__(self, adapters: Iterable[_Adapter]) -> None:
        self._adapters = tuple(adapters)
        if not all(isinstance(item, _Adapter) for item in self._adapters):
            raise TypeError("diagnostic adapters must be reviewed producers")

    def collect(self) -> tuple[DiagnosticDocument, ...]:
        grouped: dict[DiagnosticCategory, dict[str, DiagnosticField]] = {}
        for adapter in self._adapters:
            try:
                fields = tuple(adapter.read())
                if not all(isinstance(item, DiagnosticField)
                           and item.kind is DiagnosticFieldKind.SAFE for item in fields):
                    raise DiagnosticSourceUnavailable
            except Exception:
                fields = adapter.unavailable(Reason.DEPENDENCY_UNAVAILABLE)
            category = grouped.setdefault(adapter.category, {})
            for item in fields:
                if item.name in category:
                    raise DiagnosticSourceUnavailable
                category[item.name] = item
        return tuple(DiagnosticDocument(category, tuple(grouped[category].values()))
                     for category in DiagnosticCategory if grouped.get(category))


class RecordingSegmentMediaSource:
    """Owner-selected raw media resolved from one published recording segment.

    It cannot enumerate recordings. Only IDs of the form `segment.<hex>` are
    resolved, through the monitoring worker's `RecordingStore`, which opens
    the file relative to its pinned, verified root without following links.
    """

    def __init__(self, recordings: Callable[[], object], calls: OwnerWorkerCalls) -> None:
        if not callable(recordings) or not isinstance(calls, OwnerWorkerCalls):
            raise TypeError("recording media source is incomplete")
        self._recordings = recordings
        self._calls = calls

    def _store(self):
        store = self._recordings()
        if store is None:
            raise DiagnosticSourceUnavailable
        return store

    def describe_selected(self, media_id: str) -> MediaDescriptor:
        segment = _segment_id(media_id)
        size = self._calls.run(lambda: self._store().segment_length(segment))
        return MediaDescriptor(size, SEGMENT_MEDIA_TYPE)

    @contextmanager
    def open_selected(self, media_id: str) -> Iterator[MediaAsset]:
        segment = _segment_id(media_id)
        # The export copies on the owning worker. Opening from any other
        # thread would hand a descriptor across threads, so it is refused.
        if not self._calls.on_owner():
            raise DiagnosticSourceUnavailable
        reader = self._store().open_segment(segment)
        try:
            yield MediaAsset(reader, SEGMENT_MEDIA_TYPE)
        finally:
            reader.close()


@dataclass(frozen=True)
class DiagnosticComposition:
    source: DiagnosticSource
    media_source: MediaSource | None


def _integrity_latest(monitoring, calls: OwnerWorkerCalls):
    def read():
        store = monitoring.integrity_store
        if store is None:
            raise DiagnosticSourceUnavailable
        return store.latest()
    return lambda: calls.run(read)


def compose_diagnostic_sources(*, monitoring=None, registry=None, owner_audit=None,
                               access_audit=None, pairing_audit=None,
                               audit_retention=None,
                               owner_worker: StorageWorker | None = None,
                               owner_call_timeout_seconds: float = 10.0,
                               ) -> DiagnosticComposition:
    """Compose production producers from whichever subsystems a deployment has.

    `monitoring` is the Main Server `MonitoringRuntime`; `owner_worker` must be
    the worker that owns its stores (and therefore the storage policy the
    export admits through). Without that worker, per-category integrity
    verdicts report `unavailable` and no raw media can be selected. Any other
    omitted subsystem reports `unavailable`/`not_configured`.
    """
    calls = (OwnerWorkerCalls(owner_worker, timeout_seconds=owner_call_timeout_seconds)
             if owner_worker is not None else None)
    integrity_latest = (_integrity_latest(monitoring, calls)
                        if calls is not None and monitoring is not None else None)
    source = CompositeDiagnosticSource((
        VersionAdapter(),
        MonitoringRuntimeAdapter(monitoring),
        CameraRegistryAdapter(registry),
        RecordingHealthAdapter(monitoring),
        StorageAdapter(monitoring),
        IntegrityAdapter(monitoring, integrity_latest),
        AuditDeliveryAdapter(owner_audit, Name.AUDIT_OWNER_STATE, Name.AUDIT_OWNER_UNDELIVERED),
        AuditDeliveryAdapter(access_audit, Name.AUDIT_ACCESS_STATE,
                             Name.AUDIT_ACCESS_UNDELIVERED),
        AuditDeliveryAdapter(pairing_audit, Name.AUDIT_PAIRING_STATE,
                             Name.AUDIT_PAIRING_UNDELIVERED),
        AuditRetentionAdapter(audit_retention),
    ))
    media_source = (RecordingSegmentMediaSource(lambda: monitoring.recordings, calls)
                    if calls is not None and monitoring is not None else None)
    return DiagnosticComposition(source, media_source)
