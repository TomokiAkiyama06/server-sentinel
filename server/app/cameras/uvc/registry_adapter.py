"""Internal registry integration; authorization belongs to the calling Owner boundary."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
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


@dataclass(frozen=True)
class PreparedApproval:
    """One Owner selection already validated against a current device scan."""

    source_id: UUID
    candidate: DeviceEvidence = field(repr=False)
    serial_ambiguous: bool


class LocalUvcAdapter:
    """Owns independent source sessions; provides no HTTP routes or network client.

    approve_source() is only for an authenticated Owner operation after the
    human authorization boundary is implemented. poll_source() is driven by a
    per-source worker. Do not execute different operations on the same source
    concurrently; the runtime supervisor owns that serialization.
    """

    def __init__(self, registry, *, emit_audit, on_frame,
                 discovery=None, capture_factory=MmapCapture, clock=None):
        self.registry = registry
        self.store = ApprovalStore(registry.database)
        self.emit_audit = emit_audit
        self.on_frame = on_frame
        self.discovery = discovery or LinuxDiscovery()
        self.capture_factory = capture_factory
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sessions = {}
        self._approved_handoffs = {}
        self.closed = False

    def _source(self, source_id):
        if self.closed:
            raise ValueError("UVC adapter is closed")
        source = self.registry.get_source(source_id)
        if source.source_type != SourceType.LOCAL_UVC:
            raise ValueError("source is not local UVC")
        return source

    def _event(self, event):
        self.registry.update_source_health(
            event.source_id, health_state=SourceHealthState(event.state.value),
            image_quality_state="unknown",
            **({"negotiated_capture_profile": None} if event.state != "online" else {}),
        )
        self.emit_audit(event)

    def _session(self, source, approved, *, explicit_candidate=None):
        self.registry.update_source_health(source.id, health_state=SourceHealthState.OFFLINE,
                                           negotiated_capture_profile=None, image_quality_state="unknown")
        controller = ReconnectController(source.id, approved, self._event,
                                         enabled=source.enabled, store=self.store,
                                         explicit_candidate=explicit_candidate)

        def profile_sink(negotiated):
            value = negotiated.profile
            self.registry.update_source_health(
                source.id, health_state=SourceHealthState(controller.state.value),
                negotiated_capture_profile=CaptureProfile(
                    width=value.width, height=value.height, fps=value.fps,
                    pixel_format=value.pixel_format,
                ),
            )

        def frame_sink(frame):
            self.registry.update_source_health(source.id, health_state=SourceHealthState(controller.state.value),
                                               last_seen_at=self.clock())
            self.on_frame(source.id, frame)

        session = CaptureSession(
            controller, self.discovery, capture_profile(source.desired_capture_profile),
            on_frame=frame_sink, on_profile=profile_sink, capture_factory=self.capture_factory,
        )
        self.sessions[source.id] = session
        return session

    def approve_source(self, source_id, candidate):
        """Owner selects an exact current device; stale selections are rejected."""
        source = self._source(source_id)
        scan = self.discovery.scan()
        if not source.enabled or scan.failures or scan.devices.count(candidate) != 1:
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
        """
        source = self._source(source_id)
        scan = self.discovery.scan()
        session = self.sessions.get(source_id)
        if ((session is not None and not session.stopped) or not source.enabled
                or scan.failures or scan.devices.count(candidate) != 1):
            raise ValueError("candidate is unavailable or approval session is active")
        peers = sum(
            candidate.strong_key is not None and device.strong_key == candidate.strong_key
            for device in scan.devices
        )
        return PreparedApproval(source.id, candidate,
                                candidate.strong_key is not None and peers > 1)

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

    def poll_source(self, source_id, *, timeout=1.0):
        source = self._source(source_id)
        session = self.sessions.get(source_id)
        if session is None:
            approved = self.store.load(source_id)
            if approved is None:
                # Registry entries never automatically acquire a physical device.
                self.registry.update_source_health(source_id, health_state=SourceHealthState.OFFLINE,
                                                   negotiated_capture_profile=None)
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
            return session.step(timeout=timeout)
        except BaseException:
            # Downstream/store errors must not leave capture running as healthy.
            session.close()
            session.controller.capture_failed()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        self._approved_handoffs.clear()
        failures = []
        for session in self.sessions.values():
            try:
                session.close()
                session.controller.shutdown()
            except BaseException as error:
                # Close every source even when one database/health sink fails.
                # A failed release keeps the already durable recovery marker.
                failures.append(error)
        if failures:
            raise failures[0]
