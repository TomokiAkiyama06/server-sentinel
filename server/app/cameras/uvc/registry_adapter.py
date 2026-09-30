"""Internal registry integration; authorization belongs to the calling Owner boundary."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
import time
from uuid import UUID

from app.cameras.registry import CaptureProfile, SourceHealthState, SourceType
from .capture import MmapCapture, VideoProfile
from .discovery import LinuxDiscovery
from .identity import DeviceEvidence, ReconnectController
from .persistence import ApprovalStore
from .session import CaptureSession


def capture_profile(profile):
    """Require explicit camera settings; codec/bitrate controls are not guessed."""
    if profile is None:
        return None
    if any(value is None for value in (profile.width, profile.height, profile.fps, profile.pixel_format)):
        return None
    if profile.codec is not None or profile.bitrate_bps is not None:
        raise ValueError("UVC codec and bitrate controls are not supported")
    return VideoProfile(profile.width, profile.height, profile.fps, profile.pixel_format)


def _serial_shared(candidate, devices):
    """True when another connected camera reports the candidate's serial identity."""
    return candidate.strong_key is not None and sum(
        device.strong_key == candidate.strong_key for device in devices
    ) > 1


class _HealthWriter:
    """One source's health persistence, coalesced and serialized.

    Transitions stage their values in memory under the controller's
    transition lock, so staged values always follow transition order. A
    flush writes the merged latest values outside that lock; merging is
    equivalent to applying the partial updates in order. At most one write
    is in flight: a non-blocking flush that finds one running leaves its
    values to that writer, which re-reads the staged values after its write,
    and marks the source unpersisted meanwhile so the runtime reports the
    in-memory state instead of a stale durable row.
    """

    def __init__(self, write, mark):
        self._write = write
        self._mark = mark
        self._staged_lock = threading.Lock()
        self._io = threading.Lock()
        self._staged = None

    def stage(self, **values):
        with self._staged_lock:
            self._staged = {**(self._staged or {}), **values}

    def flush(self, *, blocking=True):
        while True:
            if not self._io.acquire(blocking=blocking):
                with self._staged_lock:
                    if self._staged is not None:
                        self._mark(True)
                return False
            try:
                with self._staged_lock:
                    values, self._staged = self._staged, None
                if values is None:
                    return True
                try:
                    self._write(**values)
                except BaseException:
                    with self._staged_lock:
                        # Keep the failed values under anything newer, so a
                        # later flush retries whatever was not superseded.
                        self._staged = {**values, **(self._staged or {})}
                        self._mark(True)
                    raise
                with self._staged_lock:
                    if self._staged is None:
                        self._mark(False)
                        return True
            finally:
                self._io.release()


@dataclass(frozen=True)
class PreparedApproval:
    """One Owner selection already validated against a current device scan."""

    source_id: UUID
    candidate: DeviceEvidence = field(repr=False)
    serial_ambiguous: bool


class LocalUvcAdapter:
    """Owns independent source sessions; provides no HTTP routes or network client.

    The only Owner approval entry point is the audited boundary
    `OwnerAdministration.approve_uvc()`, which commits the selection with its
    `approve_camera` record; this class exposes no unaudited public approval.
    poll_source() is driven by a per-source worker. Do not execute different
    operations on the same source concurrently; the runtime supervisor owns
    that serialization.
    """

    # A frame-rate registry write per source would turn 1-4 cameras into a
    # sustained SQLite write load. Health transitions are written immediately
    # by the controller; the last-seen timestamp is refreshed at most this often.
    LAST_SEEN_INTERVAL_SECONDS = 1.0
    # While capture is live, a conflicting approval of another enabled source
    # (a pre-existing duplicate re-enabled later) is rechecked at most this
    # often; before any capture opens it is checked on every poll.
    APPROVAL_CONFLICT_INTERVAL_SECONDS = 1.0

    def __init__(self, registry, *, emit_audit, on_frame,
                 discovery=None, capture_factory=MmapCapture, clock=None,
                 monotonic=time.monotonic, frame_stall_seconds=1.0,
                 frame_stall_reopen_seconds=5.0, presence_scan_seconds=1.0):
        self.registry = registry
        # Session-marker writes share the registry's storage admission, so no
        # capture-driven write bypasses the Main storage policy.
        self.store = ApprovalStore(registry.database,
                                   reservation=getattr(registry, "reservation", None))
        self.emit_audit = emit_audit
        self.on_frame = on_frame
        self.discovery = discovery or LinuxDiscovery()
        self.capture_factory = capture_factory
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.monotonic = monotonic
        self.session_timing = {
            "frame_stall_seconds": frame_stall_seconds,
            "frame_stall_reopen_seconds": frame_stall_reopen_seconds,
            "presence_scan_seconds": presence_scan_seconds,
        }
        self.sessions = {}
        self._approved_handoffs = {}
        self._conflict_checked = {}
        self.closed = False
        # Sources whose latest health observation could not be persisted
        # (storage admission refused, database fault). The registry may then
        # still show an earlier state, so the runtime reports these in memory.
        self._unpersisted_lock = threading.Lock()
        self._unpersisted = set()
        self._writers = {}
        self._writers_lock = threading.Lock()

    def _source(self, source_id):
        if self.closed:
            raise ValueError("UVC adapter is closed")
        source = self.registry.get_source(source_id)
        if source.source_type != SourceType.LOCAL_UVC:
            raise ValueError("source is not local UVC")
        return source

    def _writer(self, source_id):
        with self._writers_lock:
            writer = self._writers.get(source_id)
            if writer is None:
                def write(**values):
                    self.registry.update_source_health(source_id, **values)

                def mark(unpersisted):
                    with self._unpersisted_lock:
                        if unpersisted:
                            self._unpersisted.add(source_id)
                        else:
                            self._unpersisted.discard(source_id)

                writer = self._writers[source_id] = _HealthWriter(write, mark)
            return writer

    def _write_health(self, source_id, **values):
        """Persist one health observation and track whether it was durable."""
        writer = self._writer(source_id)
        writer.stage(**values)
        writer.flush()

    def health_unpersisted(self, source_id):
        """True while this source's latest health write was refused or failed."""
        with self._unpersisted_lock:
            return source_id in self._unpersisted

    def _event(self, event):
        """Controller callback under its transition lock: in-memory work only.

        The health values are staged here and written by the controller's
        flush after the lock is released. A transient frame stall keeps the
        descriptor and its negotiated profile, so only other non-online
        states clear the profile.
        """
        keep_profile = event.state == "online" or event.reason == "video_frame_stalled"
        self._writer(event.source_id).stage(
            health_state=SourceHealthState(event.state.value),
            image_quality_state="unknown",
            **({} if keep_profile else {"negotiated_capture_profile": None}),
        )
        # The in-memory transition (runtime health, preview invalidation) is
        # delivered even when persistence is refused or still in flight, so
        # capture loss is never represented only by a stale durable ONLINE row.
        self.emit_audit(event)

    def _session(self, source, approved, *, explicit_candidate=None):
        self._write_health(source.id, health_state=SourceHealthState.OFFLINE,
                           negotiated_capture_profile=None, image_quality_state="unknown")
        writer = self._writer(source.id)
        controller = ReconnectController(source.id, approved, self._event,
                                         enabled=source.enabled, store=self.store,
                                         explicit_candidate=explicit_candidate,
                                         flush=writer.flush)

        def profile_sink(negotiated):
            value = negotiated.profile
            # Stage with the state read under the transition lock (so an
            # off-worker stall report cannot be overwritten by a stale state);
            # write after releasing it.
            with controller.lock:
                writer.stage(
                    health_state=SourceHealthState(controller.state.value),
                    negotiated_capture_profile=CaptureProfile(
                        width=value.width, height=value.height, fps=value.fps,
                        pixel_format=value.pixel_format,
                    ),
                )
            writer.flush()

        last_seen = {"at": None, "state": None}

        def frame_sink(frame):
            now = self.monotonic()
            with controller.lock:
                state = SourceHealthState(controller.state.value)
                due = (last_seen["at"] is None or last_seen["state"] is not state
                       or now - last_seen["at"] >= self.LAST_SEEN_INTERVAL_SECONDS)
                if due:
                    writer.stage(health_state=state, last_seen_at=self.clock())
            if due:
                writer.flush()
                last_seen["at"], last_seen["state"] = now, state
            self.on_frame(source.id, frame)

        session = CaptureSession(
            controller, self.discovery, capture_profile(source.desired_capture_profile),
            on_frame=frame_sink, on_profile=profile_sink, capture_factory=self.capture_factory,
            clock=lambda: self.monotonic(), **self.session_timing,
        )
        self.sessions[source.id] = session
        return session

    def _approve_live_session(self, source_id, candidate):
        """Run the in-memory approval ceremony on an already live session.

        Internal only: it has no audit record, so it is not an Owner entry
        point. It exists for the offline session/reconnect fixtures that need
        the live-controller transition the audited idle path deliberately
        avoids, because an in-memory/physical transition cannot roll back with
        a SQLite transaction.
        """
        source = self._source(source_id)
        scan = self.discovery.scan()
        if (not source.enabled or scan.failures or scan.devices.count(candidate) != 1
                or self.store.approved_elsewhere(
                    source.id, candidate,
                    serial_ambiguous=_serial_shared(candidate, scan.devices))):
            raise ValueError("candidate is unavailable or ambiguous")
        self.registry.update_source(source.id, capabilities={
            **source.capabilities, "uvc_formats": list(candidate.formats), "video_only": True,
        })
        session = self.sessions.get(source_id)
        if session is None:
            session = self._session(source, candidate)
        else:
            session.close()
            session.configure(enabled=source.enabled,
                              profile=capture_profile(source.desired_capture_profile))
        session.controller.approve(candidate, scan.devices)

    def prepare_approval(self, source_id, candidate):
        """Validate an Owner selection against the current devices.

        Device discovery runs here, before the audited transaction opens, so a
        slow or blocking USB/UVC scan never holds the database write lock.
        A camera already approved for another enabled source is refused with
        the same generic reason; the transaction repeats that check.
        """
        source = self._source(source_id)
        scan = self.discovery.scan()
        session = self.sessions.get(source_id)
        ambiguous = _serial_shared(candidate, scan.devices)
        if ((session is not None and not session.stopped) or not source.enabled
                or scan.failures or scan.devices.count(candidate) != 1
                or self.store.approved_elsewhere(source.id, candidate,
                                                 serial_ambiguous=ambiguous)):
            raise ValueError("candidate is unavailable or approval session is active")
        return PreparedApproval(source.id, candidate, ambiguous)

    def approve_source_on(self, connection, prepared):
        """Atomically persist a prepared idle Owner selection with its audit.

        A live session must be stopped by its supervisor before reapproval. This
        avoids an in-memory/physical-camera transition escaping SQLite rollback.
        The next poll starts a fresh recovery-fenced session from this approval.
        No device discovery runs here, so the transaction holds no hardware I/O.
        """
        if not isinstance(prepared, PreparedApproval):
            raise ValueError("owner approval was not prepared")
        source = self._source(prepared.source_id)
        session = self.sessions.get(prepared.source_id)
        if (session is not None and not session.stopped) or not source.enabled:
            raise ValueError("candidate is unavailable or approval session is active")
        self.registry.update_source_on(connection, source.id, capabilities={
            **source.capabilities, "uvc_formats": list(prepared.candidate.formats),
            "video_only": True,
        })
        self.store.approve_on(
            connection, source.id, prepared.candidate,
            serial_ambiguous=prepared.serial_ambiguous,
        )
        if session is not None:
            # Runtime supervisor serializes this source. Discarding a stopped
            # cache is safe even if the transaction later rolls back: the next
            # poll reconstructs the prior durable approval and recovery latch.
            session.supersede_stopped_session()
            del self.sessions[prepared.source_id]
        return prepared.candidate

    def accept_committed_approval(self, source_id, candidate):
        """Hand one exact live selection to the next session after commit."""
        if not isinstance(candidate, DeviceEvidence):
            raise ValueError("invalid committed approval")
        # The transaction hook already validated this source and candidate.
        # Keep this post-commit handoff free of storage operations so a
        # transient read cannot turn a durable success into an apparent error.
        self._approved_handoffs[source_id] = candidate

    def _fail_session(self, source_id):
        """Close a live session and report capture loss; never masks the cause."""
        session = self.sessions.get(source_id)
        if session is None:
            return
        try:
            session.close()
        finally:
            session.controller.capture_failed()

    def poll_source(self, source_id, *, timeout=1.0):
        try:
            source = self._source(source_id)
        except BaseException:
            # A registry read failure (lost mount, SQLite fault) while a
            # camera is live is current capture loss: close it and deliver
            # the offline transition, exactly like a failed poll.
            try:
                self._fail_session(source_id)
            except BaseException:
                pass
            raise
        session = self.sessions.get(source_id)
        if session is None:
            approved = self.store.load(source_id)
            if approved is None:
                # Registry entries never automatically acquire a physical device.
                # The worker retries this every poll; write only a change so an
                # unapproved source does not become a steady SQLite write load.
                if (source.health_state is not SourceHealthState.OFFLINE
                        or source.negotiated_capture_profile is not None):
                    self._write_health(
                        source_id, health_state=SourceHealthState.OFFLINE,
                        negotiated_capture_profile=None,
                    )
                return False
            explicit = self._approved_handoffs.get(source_id)
            if explicit is not None and explicit != approved.approved:
                # A later durable approval superseded this handoff; it can no
                # longer prove which physical device the Owner selected.
                del self._approved_handoffs[source_id]
                explicit = None
            # Keep the handoff until a session actually owns it, so a transient
            # registry/store failure cannot force another Owner approval.
            session = self._session(source, approved.approved, explicit_candidate=explicit)
            self._approved_handoffs.pop(source_id, None)
        try:
            session.configure(enabled=source.enabled,
                              profile=capture_profile(source.desired_capture_profile))
            if self._approval_conflict(source, session):
                session.controller.approval_conflict()
                session.close()
                return False
            return session.step(timeout=timeout)
        except BaseException:
            # Downstream/store errors must not leave capture running as healthy.
            session.close()
            session.controller.capture_failed()
            raise

    def check_frame_progress(self, source_id):
        """Off-worker frame-progress check for one source.

        Called by the supervisor watchdog, not the source worker, so a worker
        blocked in a kernel or storage call cannot keep a stalled source
        ``online``. It only lowers an ``online`` claim to ``degraded``
        (``video_frame_stalled``); it never opens, closes or rebinds a device.
        """
        session = self.sessions.get(source_id)
        if session is None or self.closed:
            return False
        return session.check_frame_progress()

    def _approval_conflict(self, source, session):
        """True when another enabled source holds an approval for this camera.

        Such duplicates can only predate the approval-time check. Every
        conflicting source reports manual intervention, so which one captures
        never depends on startup or polling order and nothing is rebound.
        """
        controller = session.controller
        if not source.enabled or controller.requires_approval:
            self._conflict_checked.pop(source.id, None)
            return False
        now = self.monotonic()
        last = self._conflict_checked.get(source.id)
        if (session.capture is not None and last is not None
                and now - last < self.APPROVAL_CONFLICT_INTERVAL_SECONDS):
            return False
        self._conflict_checked[source.id] = now
        return self.store.approved_elsewhere(source.id, controller.approved,
                                             serial_ambiguous=controller.serial_ambiguous)

    def stop_source(self, source_id):
        """Stop one source on the same serialized worker that polls it.

        Removing the cached session releases its durable active-session marker
        only after capture has closed.  The runtime supervisor must never call
        this concurrently with ``poll_source`` for the same source.
        """
        if not isinstance(source_id, UUID):
            raise ValueError("invalid source identity")
        self._conflict_checked.pop(source_id, None)
        session = self.sessions.pop(source_id, None)
        if session is None:
            self._approved_handoffs.pop(source_id, None)
            return False
        failures = []
        try:
            session.close()
        except BaseException as error:
            failures.append(error)
        try:
            session.controller.shutdown()
        except BaseException as error:
            # A failed release deliberately leaves the recovery marker durable.
            failures.append(error)
        self._approved_handoffs.pop(source_id, None)
        if failures:
            raise failures[0]
        return True

    def close(self):
        if self.closed:
            return
        self.closed = True
        self._approved_handoffs.clear()
        failures = []
        for source_id in tuple(self.sessions):
            try:
                self.stop_source(source_id)
            except BaseException as error:
                # Close every source even when one database/health sink fails.
                # A failed release keeps the already durable recovery marker.
                failures.append(error)
        if failures:
            raise failures[0]
