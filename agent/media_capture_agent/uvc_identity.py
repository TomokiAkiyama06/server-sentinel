"""Conservative Agent-side UVC identity decisions; device paths never identify a camera.

This is a standalone port of ``server/app/cameras/uvc/identity.py`` (the Agent
artifact never imports Main Server code). The decision rules are intentionally
identical: only a unique serial-backed identity may reconnect automatically;
duplicate serials and every non-serial model match require Owner re-approval.
Keep both copies in step when either rule changes.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID


MAX_TEXT = 4096
MAX_ALIASES = 256


class CameraState(StrEnum):
    OFFLINE = "offline"
    DEGRADED = "degraded"
    ONLINE = "online"
    MANUAL = "manual_intervention_required"


def _text(value, *, optional=False):
    if value is None and optional:
        return
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT:
        raise ValueError("invalid device evidence")


@dataclass(frozen=True)
class DeviceEvidence:
    """Private device facts. Never serialize these into heartbeats or logs."""

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
            _text(value)
        for value in (self.serial, self.topology):
            _text(value, optional=True)
        if not isinstance(self.by_id, tuple) or not isinstance(self.formats, tuple):
            raise ValueError("invalid device evidence collection")
        if len(self.by_id) > MAX_ALIASES or len(self.formats) > MAX_ALIASES:
            raise ValueError("device evidence exceeds bound")
        for value in self.by_id:
            _text(value)
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
        # A by-id name can be synthesized from non-unique product metadata and
        # a /dev/videoN or USB port can be reused. Only a serial is strong.
        if not self.serial:
            return None
        return self.vendor, self.product, self.serial, self.interface

    @property
    def model_key(self):
        return self.vendor, self.product, self.interface

    def to_record(self):
        return {
            "device_path": self.device_path, "vendor": self.vendor, "product": self.product,
            "serial": self.serial, "interface": self.interface, "by_id": list(self.by_id),
            "topology": self.topology, "formats": list(self.formats),
            "device_number": self.device_number,
            "instance_token": None if self.instance_token is None else list(self.instance_token),
        }

    @classmethod
    def from_record(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid device evidence record")
        if not isinstance(value["by_id"], list) or not isinstance(value["formats"], list):
            raise ValueError("invalid device evidence record")
        token = value["instance_token"]
        if token is not None and not isinstance(token, list):
            raise ValueError("invalid device evidence record")
        return cls(value["device_path"], value["vendor"], value["product"], value["serial"],
                   value["interface"], tuple(value["by_id"]), value["topology"],
                   tuple(value["formats"]), value["device_number"],
                   None if token is None else tuple(token))


@dataclass(frozen=True)
class IdentityDecision:
    state: CameraState
    reason: str
    device: DeviceEvidence | None = field(default=None, repr=False)
    candidates: tuple[DeviceEvidence, ...] = field(default=(), repr=False)


def match_reconnect(approved, devices, *, serial_ambiguous=False):
    """Return a unique serial match, or explicitly refuse to choose a device."""
    if approved.strong_key is not None and not serial_ambiguous:
        matches = tuple(d for d in devices if d.strong_key == approved.strong_key)
        if len(matches) == 1:
            return IdentityDecision(CameraState.DEGRADED, "identity_matched", matches[0])
        if len(matches) > 1:
            return IdentityDecision(CameraState.MANUAL, "duplicate_identity", candidates=matches)
        return IdentityDecision(CameraState.OFFLINE, "approved_device_absent")
    matches = tuple(d for d in devices if (
        d.strong_key == approved.strong_key if approved.strong_key is not None
        else d.model_key == approved.model_key
    ))
    if matches:
        # A reused USB port or /dev/videoN cannot prove that the old non-serial
        # camera returned, even if only one indistinguishable candidate remains.
        return IdentityDecision(CameraState.MANUAL, "identity_not_unique", candidates=matches)
    return IdentityDecision(CameraState.OFFLINE, "approved_device_absent")


class ReconnectController:
    """One source's identity state machine, independent of other sources and node health.

    ``approve`` must only be reached through an Owner-authorized boundary; this
    module exposes no remotely callable route. A successful identity match is
    degraded until frames actually arrive; discovery alone is never online.
    ``approved`` may be ``None`` for a source that has never been approved.
    """

    def __init__(self, source_id, store):
        if not isinstance(source_id, UUID):
            raise ValueError("invalid source identity")
        self.source_id = source_id
        self.store = store
        # The durable active-session marker is armed before any decision is
        # trusted, so an unclean exit requires Owner re-approval at restart.
        saved = store.start_session(source_id)
        self._session_token = saved.session_token
        self.approved = saved.approved
        self.serial_ambiguous = saved.serial_ambiguous
        self.requires_approval = saved.requires_approval or saved.approved is None
        self.state = CameraState.OFFLINE
        self.reason = "not_started"
        # Only an in-memory hand-off after a durable Owner approval is an exact
        # live selection; it ends with the capture descriptor that used it.
        self.bound = None
        self._explicit_binding = False
        self._finished = False

    def _persist(self):
        self.store.save(self.source_id, self.approved, self.requires_approval,
                        session_token=self._session_token, serial_ambiguous=self.serial_ambiguous)

    def _transition(self, state, reason):
        self.state, self.reason = state, reason

    def reconcile(self, devices):
        if self._finished:
            raise ValueError("identity controller is closed")
        devices = tuple(devices)
        if self.requires_approval:
            self.bound = None
            if self.state != CameraState.MANUAL:
                self._transition(CameraState.MANUAL, "owner_approval_required")
            return None
        # Only a continuously open capture keeps an approved weak binding.
        if self.bound is not None and devices.count(self.bound) == 1:
            peers = [d for d in devices if d.strong_key == self.bound.strong_key]
            if (self._explicit_binding or self.bound.strong_key is None
                    or not self.serial_ambiguous and len(peers) == 1):
                return self.bound
        decision = match_reconnect(self.approved, devices, serial_ambiguous=self.serial_ambiguous)
        self.bound = decision.device
        self._explicit_binding = False
        if decision.state == CameraState.MANUAL:
            self.requires_approval = True
            if decision.reason == "duplicate_identity":
                self.serial_ambiguous = True
            self._transition(CameraState.MANUAL, decision.reason)
            # Latch first in memory, then durably; a failed write still leaves
            # this controller refusing to bind and the session marker armed.
            self._persist()
            return None
        if decision.state != CameraState.DEGRADED or self.state != CameraState.ONLINE:
            self._transition(decision.state, decision.reason)
        return self.bound

    def approve(self, candidate, current_devices):
        """Persist an exact current Owner selection, then hand it off in memory."""
        current_devices = tuple(current_devices)
        if (self._finished or not isinstance(candidate, DeviceEvidence)
                or current_devices.count(candidate) != 1):
            raise ValueError("candidate is unavailable or ambiguous")
        ambiguous = (
            self.serial_ambiguous and self.approved is not None
            and candidate.strong_key == self.approved.strong_key
            or candidate.strong_key is not None
            and sum(device.strong_key == candidate.strong_key for device in current_devices) > 1
        )
        self.store.save(self.source_id, candidate, False, session_token=self._session_token,
                        serial_ambiguous=ambiguous)
        self.approved = self.bound = candidate
        self._explicit_binding = True
        self.serial_ambiguous = ambiguous
        self.requires_approval = False
        self._transition(CameraState.DEGRADED, "owner_approved_pending_capture")

    def require_approval(self, reason):
        """Latch Owner re-approval, e.g. when two sources resolve to one camera."""
        self.bound = None
        self._explicit_binding = False
        self.requires_approval = True
        self._transition(CameraState.MANUAL, reason)
        self._persist()

    def capture_ready(self, candidate):
        if self.requires_approval or candidate is None or self.bound != candidate:
            raise ValueError("capture has no approved binding")
        self._transition(CameraState.ONLINE, "video_capture_ready")

    def capture_failed(self):
        self.bound = None
        self._explicit_binding = False
        self._transition(CameraState.OFFLINE, "video_capture_failed")

    def capture_closed(self, reason="video_capture_closed"):
        self.bound = None
        self._explicit_binding = False
        if self.state in (CameraState.DEGRADED, CameraState.ONLINE):
            self._transition(CameraState.OFFLINE, reason)

    def shutdown(self):
        """Release the recovery marker only after capture is closed."""
        if self.bound is not None:
            raise ValueError("capture binding must close before shutdown")
        if self._finished:
            return
        if self._session_token is not None:
            self.store.save(self.source_id, self.approved, self.requires_approval,
                            session_token=self._session_token,
                            serial_ambiguous=self.serial_ambiguous, release=True)
            self._session_token = None
        self._finished = True
