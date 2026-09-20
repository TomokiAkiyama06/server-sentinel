"""Conservative UVC identity decisions; device paths never identify a camera."""

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID


class CameraState(StrEnum):
    OFFLINE = "offline"
    DEGRADED = "degraded"
    ONLINE = "online"
    MANUAL = "manual_intervention_required"


@dataclass(frozen=True)
class DeviceEvidence:
    """Internal device facts. Do not serialize these into public diagnostics."""

    device_path: str = field(repr=False)
    vendor: str = field(repr=False)
    product: str = field(repr=False)
    serial: str | None = field(default=None, repr=False)
    interface: str = field(default="0", repr=False)
    by_id: tuple[str, ...] = field(default=(), repr=False)
    topology: str | None = field(default=None, repr=False)
    formats: tuple[str, ...] = ()
    device_number: int | None = field(default=None, repr=False)
    instance_token: tuple[int, int, int] | None = field(default=None, repr=False)

    def __post_init__(self):
        for value in (self.device_path, self.vendor, self.product, self.interface):
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise ValueError("invalid device evidence")
        for value in (self.serial, self.topology):
            if value is not None and (not isinstance(value, str) or not value or len(value) > 4096):
                raise ValueError("invalid device evidence")
        if not isinstance(self.by_id, tuple) or not isinstance(self.formats, tuple):
            raise ValueError("invalid device evidence collection")
        if len(self.by_id) > 256 or len(self.formats) > 256:
            raise ValueError("device evidence exceeds bound")
        if any(not isinstance(value, str) or not value or len(value) > 4096 for value in self.by_id):
            raise ValueError("invalid device alias")
        if any(not isinstance(value, str) or len(value) != 4
               or any(ord(char) < 32 or ord(char) > 126 for char in value) for value in self.formats):
            raise ValueError("invalid video format evidence")
        if self.device_number is not None and (type(self.device_number) is not int or self.device_number < 0):
            raise ValueError("invalid device number")
        if self.instance_token is not None:
            if (not isinstance(self.instance_token, tuple) or len(self.instance_token) != 3
                    or any(type(value) is not int or value < 0 for value in self.instance_token)):
                raise ValueError("invalid device instance token")

    @property
    def strong_key(self):
        # A by-id name can be synthesized from non-unique product metadata.
        # Only a nonempty serial-backed physical identity is strong here.
        if not self.serial or not self.vendor or not self.product:
            return None
        return self.vendor, self.product, self.serial, self.interface

    @property
    def model_key(self):
        return self.vendor, self.product, self.interface


@dataclass(frozen=True)
class IdentityDecision:
    state: CameraState
    reason: str
    device: DeviceEvidence | None = field(default=None, repr=False)
    candidates: tuple[DeviceEvidence, ...] = field(default=(), repr=False)


def match_reconnect(approved: DeviceEvidence, devices: tuple[DeviceEvidence, ...]):
    """Return a unique serial match, or explicitly refuse to choose a device."""
    if approved.strong_key is not None:
        matches = tuple(d for d in devices if d.strong_key == approved.strong_key)
        if len(matches) == 1:
            return IdentityDecision(CameraState.DEGRADED, "identity_matched", matches[0])
        if len(matches) > 1:
            return IdentityDecision(CameraState.MANUAL, "duplicate_identity", candidates=matches)
        return IdentityDecision(CameraState.OFFLINE, "approved_device_absent")
    matches = tuple(d for d in devices if d.model_key == approved.model_key)
    if matches:
        # A reused USB port or /dev/videoN cannot prove that the old non-serial
        # camera returned, even if only one indistinguishable candidate remains.
        return IdentityDecision(CameraState.MANUAL, "identity_not_unique", candidates=matches)
    return IdentityDecision(CameraState.OFFLINE, "approved_device_absent")


@dataclass(frozen=True)
class HealthEvent:
    source_id: UUID
    state: CameraState
    reason: str


class ReconnectController:
    """One source's state machine; independent of other sources and node health.

    The enclosing service must authorize approve()/set_enabled() through the
    Owner boundary. This module provides no remotely callable management route.
    A successful identity match is degraded until video negotiation/capture
    succeeds; discovery alone is never reported as healthy monitoring.
    """

    def __init__(self, source_id, approved, emit, *, enabled=True, store=None):
        if not isinstance(source_id, UUID) or not isinstance(approved, DeviceEvidence):
            raise ValueError("invalid source identity")
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        self.source_id = source_id
        self.store = store
        saved = store.load(source_id) if store is not None else None
        self.approved = saved.approved if saved else approved
        self.emit = emit
        self.enabled = enabled
        self.state = CameraState.OFFLINE
        self.bound = None
        self.requires_approval = saved.requires_approval if saved else False
        self._reason = "not_started"
        if saved is None:
            self._persist()

    def _persist(self):
        if self.store is not None:
            self.store.save(self.source_id, self.approved, self.requires_approval)

    def _transition(self, state, reason):
        changed = (self.state, self._reason) != (state, reason)
        self.state, self._reason = state, reason
        if changed:
            self.emit(HealthEvent(self.source_id, state, reason))

    def disconnected(self):
        self.bound = None
        self._transition(CameraState.OFFLINE, "device_disconnected")

    def reconcile(self, devices):
        if not self.enabled:
            self.bound = None
            self._transition(CameraState.OFFLINE, "disabled")
            return None
        if self.requires_approval:
            self.bound = None
            self._transition(CameraState.MANUAL, "owner_approval_required")
            return None
        devices = tuple(devices)
        # A live open capture descriptor may keep its approved weak binding.
        # Losing that descriptor ends this allowance, including process restart.
        if self.bound is not None and devices.count(self.bound) == 1:
            peers = [d for d in devices if d.strong_key == self.bound.strong_key]
            if self.bound.strong_key is None or len(peers) == 1:
                return self.bound
        decision = match_reconnect(self.approved, devices)
        self.bound = decision.device
        if decision.state == CameraState.MANUAL:
            self.requires_approval = True
            self._persist()
        self._transition(decision.state, decision.reason)
        return self.bound

    def approve(self, candidate, current_devices):
        # Exact current candidate selection is required. A remembered device
        # path cannot approve a candidate that vanished during the ceremony.
        if not self.enabled or tuple(current_devices).count(candidate) != 1:
            raise ValueError("candidate is unavailable or ambiguous")
        if self.store is not None:
            self.store.save(self.source_id, candidate, False)
        self.approved = self.bound = candidate
        self.requires_approval = False
        self._transition(CameraState.DEGRADED, "owner_approved_pending_capture")

    def capture_ready(self, candidate):
        if not self.enabled or self.requires_approval or self.bound != candidate or candidate is None:
            raise ValueError("capture has no approved binding")
        self._transition(CameraState.ONLINE, "video_capture_ready")

    def capture_failed(self):
        self.bound = None
        self._transition(CameraState.OFFLINE, "video_capture_failed")

    def capture_closed(self):
        # Only a continuously open capture descriptor can retain a weak live
        # binding. Invalidate it even when a subsequent approval operation fails.
        self.bound = None
        if self.state in (CameraState.DEGRADED, CameraState.ONLINE):
            self._transition(CameraState.OFFLINE, "video_capture_closed")

    def set_enabled(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        self.enabled = enabled
        self.bound = None
        self._transition(CameraState.OFFLINE, "enabled_pending_capture" if enabled else "disabled")
