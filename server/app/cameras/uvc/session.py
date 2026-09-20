"""One source's capture lifecycle, with injected frame and negotiated-profile sinks."""

from .capture import CaptureError, MmapCapture
from .discovery import ProbeError


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
        if self.capture is not None:
            self.capture.close()
            self.capture = None

    def configure(self, *, enabled, profile):
        if enabled != self.controller.enabled or profile != self.profile:
            self.close()
            self.controller.set_enabled(enabled)
            self.profile = profile

    def _verify(self, candidate):
        current = self.discovery.scan()
        if current.failures:
            return False
        return self.controller.reconcile(current.devices) == candidate

    def step(self, *, timeout=1.0):
        """Deliver at most one frame, returning False on offline/manual/failure."""
        try:
            scan = self.discovery.scan()
            if self.capture is not None and self.controller.bound not in scan.devices:
                self.close()
                self.controller.disconnected()
                return False
            candidate = self.controller.reconcile(scan.devices)
            if candidate is None or self.profile is None:
                self.close()
                return False
            if self.capture is None:
                self.capture = self.capture_factory(candidate, self.profile, verify_identity=self._verify)
                negotiated = self.capture.open()
                self.on_profile(negotiated)
            frame = self.capture.read_frame(timeout)
            self.controller.capture_ready(candidate)
            self.on_frame(frame)
            return True
        except (CaptureError, ProbeError, OSError):
            self.close()
            self.controller.capture_failed()
            return False
