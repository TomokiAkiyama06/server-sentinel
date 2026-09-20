"""Internal registry integration; authorization belongs to the calling Owner boundary."""

from datetime import datetime, timezone

from app.cameras.registry import CaptureProfile, SourceHealthState, SourceType
from .capture import MmapCapture, VideoProfile
from .discovery import LinuxDiscovery
from .identity import ReconnectController
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

    def _session(self, source, approved):
        self.registry.update_source_health(source.id, health_state=SourceHealthState.OFFLINE,
                                           negotiated_capture_profile=None, image_quality_state="unknown")
        controller = ReconnectController(source.id, approved, self._event,
                                         enabled=source.enabled, store=self.store)

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

    def approve_source_on(self, connection, source_id, candidate):
        """Atomically persist an idle Owner selection with its audit record.

        A live session must be stopped by its supervisor before reapproval. This
        avoids an in-memory/physical-camera transition escaping SQLite rollback.
        The next poll starts a fresh recovery-fenced session from this approval.
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
        self.registry.update_source_on(connection, source.id, capabilities={
            **source.capabilities, "uvc_formats": list(candidate.formats), "video_only": True,
        })
        self.store.approve_on(
            connection, source.id, candidate,
            serial_ambiguous=candidate.strong_key is not None and peers > 1,
        )
        if session is not None:
            # Runtime supervisor serializes this source. Discarding a stopped
            # cache is safe even if the transaction later rolls back: the next
            # poll reconstructs the prior durable approval and recovery latch.
            session.supersede_stopped_session()
            del self.sessions[source_id]

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
            session = self._session(source, approved.approved)
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
