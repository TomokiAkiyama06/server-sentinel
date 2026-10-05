"""One source's capture lifecycle, with injected frame and negotiated-profile sinks."""

from .capture import CaptureError, MmapCapture, profile_satisfies
from .discovery import ProbeError
from .identity import current_live_instance, same_live_instance


class CaptureSession:
    """A caller drives step() in its worker; failures do not exit the service.

    Frame delivery stays in memory and is video-only. There is no preview HTTP
    route here; the eventual authorized viewer pipeline consumes this sink.
    Each session has its own capture descriptor and controller.
    """

    def __init__(self, controller, discovery, profile, *, on_frame, on_profile,
                 capture_factory=MmapCapture):
        self.controller = controller
        self.discovery = discovery
        self.profile = profile
        self.on_frame, self.on_profile = on_frame, on_profile
        self.capture_factory = capture_factory
        self.capture = None

    def close(self):
        try:
            if self.capture is not None:
                self.capture.close()
        finally:
            self.capture = None
            self.controller.capture_closed()

    @property
    def stopped(self):
        return self.capture is None and self.controller.bound is None

    def supersede_stopped_session(self):
        if not self.stopped:
            raise ValueError("capture session must stop before reapproval")
        self.controller.supersede_stopped_session()

    def configure(self, *, enabled, profile):
        if enabled != self.controller.enabled or profile != self.profile:
            self.close()
            self.controller.set_enabled(enabled)
            self.profile = profile

    def _verify(self, candidate):
        current = self.discovery.scan()
        if current.failures:
            return False
        return same_live_instance(self.controller.reconcile(current.devices), candidate)

    def step(self, *, timeout=1.0):
        """Deliver at most one frame, returning False on offline/manual/failure."""
        if self.profile is None:
            self.close()
            if self.controller.requires_approval:
                # A missing profile must not hide a durable Owner action. This
                # needs no physical discovery and the transition is deduplicated.
                self.controller.reconcile(())
            return False
        if not self.controller.enabled or self.controller.requires_approval:
            # Neither state depends on physical discovery; skip the rescan.
            self.close()
            self.controller.reconcile(())
            return False
        try:
            scan = self.discovery.scan()
            if (self.capture is not None and (self.controller.bound is None or current_live_instance(
                    scan.devices, self.controller.bound) is None)):
                self.close()
                self.controller.disconnected()
                return False
            candidate = self.controller.reconcile(scan.devices)
            if candidate is None:
                if self.capture is not None or not self.controller.profile_unavailable:
                    self.close()
                return False
            if self.capture is None:
                self.capture = self.capture_factory(candidate, self.profile, verify_identity=self._verify)
                negotiated = self.capture.open()
                if not profile_satisfies(self.profile, negotiated.profile):
                    # The driver silently adjusted an unsupported request.
                    # Record what it negotiated, but never report the source
                    # online for a profile the Owner did not configure.
                    capture, self.capture = self.capture, None
                    try:
                        capture.close()
                    finally:
                        self.controller.capture_profile_unavailable(candidate)
                    self.on_profile(negotiated)
                    return False
                self.on_profile(negotiated)
            frame = self.capture.read_frame(timeout)
            self.controller.capture_ready(candidate)
            self.on_frame(frame)
            return True
        except (CaptureError, ProbeError, OSError):
            self.close()
            self.controller.capture_failed()
            return False
