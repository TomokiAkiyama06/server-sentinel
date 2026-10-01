"""Conservative UVC identity decisions; device paths never identify a camera."""

from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
import threading
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

    @property
    def live_instance_key(self):
        # Fields fixed for one connected device node. by-id aliases and the
        # advertised format list are mutable metadata a rescan may refresh
        # (e.g. a udev alias appearing later), so they never name an instance.
        return (self.vendor, self.product, self.serial, self.interface, self.topology,
                self.device_path, self.device_number, self.instance_token)


def same_physical_camera(first, second, *, serial_ambiguous=False):
    """True when two pieces of evidence may name the same physical camera.

    A serial-backed identity compares by its strong key, so a changed device
    node or port still names the same camera. Weak (non-serial) evidence can
    only be compared by its live-instance fields, including its ephemeral
    instance marker.

    ``serial_ambiguous`` means several connected cameras share the serial of
    ``first``. The serial then cannot tell them apart, and such an approval is
    an exact live-instance binding that is never rebound by serial, so only
    the same live instance names the same camera. Mutable metadata (by-id
    aliases, advertised formats) is ignored so a rescan cannot free a held
    camera for another source.
    """
    if serial_ambiguous:
        return first.live_instance_key == second.live_instance_key
    if first.strong_key is not None or second.strong_key is not None:
        return first.strong_key == second.strong_key
    return first.live_instance_key == second.live_instance_key


@dataclass(frozen=True)
class IdentityDecision:
    state: CameraState
    reason: str
    device: DeviceEvidence | None = field(default=None, repr=False)
    candidates: tuple[DeviceEvidence, ...] = field(default=(), repr=False)


def match_reconnect(approved: DeviceEvidence, devices: tuple[DeviceEvidence, ...], *, serial_ambiguous=False):
    """Return a unique serial match, or explicitly refuse to choose a device."""
    if approved.strong_key is not None and not serial_ambiguous:
        matches = tuple(d for d in devices if d.strong_key == approved.strong_key)
        if len(matches) == 1:
            return IdentityDecision(CameraState.DEGRADED, "identity_matched", matches[0])
        if len(matches) > 1:
            return IdentityDecision(CameraState.MANUAL, "duplicate_identity", candidates=matches)
        return IdentityDecision(CameraState.OFFLINE, "approved_device_absent")
    matches = tuple(d for d in devices if (
        d.strong_key == approved.strong_key if approved.strong_key is not None else d.model_key == approved.model_key
    ))
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

    def __init__(self, source_id, approved, emit, *, enabled=True, store=None,
                 explicit_candidate=None, flush=None, notify=None):
        if not isinstance(source_id, UUID) or not isinstance(approved, DeviceEvidence):
            raise ValueError("invalid source identity")
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        self.source_id = source_id
        self.store = store
        saved = store.start_session(source_id, approved) if store is not None else None
        self._session_token = saved.session_token if saved else None
        self.serial_ambiguous = saved.serial_ambiguous if saved else False
        self.approved = saved.approved if saved else approved
        if (explicit_candidate is not None
                and (not isinstance(explicit_candidate, DeviceEvidence)
                     or explicit_candidate != self.approved)):
            raise ValueError("explicit candidate does not match approval")
        self.emit = emit
        self.enabled = enabled
        self.state = CameraState.OFFLINE
        # Only a candidate handed off in memory after the audited approval
        # commit represents the exact live selection. Durable evidence alone
        # must go through reconnect matching after a process restart.
        self.bound = explicit_candidate
        self._explicit_binding = explicit_candidate is not None
        self.requires_approval = saved.requires_approval if saved else False
        # The exact candidate (and whether it was an explicit binding) whose
        # negotiated profile did not satisfy the requested profile. It keeps
        # the source visibly degraded without reopening the device on every
        # poll; it never authorizes capture by itself.
        self._profile_hold = None
        self._reason = "not_started"
        self._finished = False
        # Serializes health transitions between the source worker and the
        # off-worker frame-progress check. It is held only for in-memory work:
        # ``emit`` runs under it (so events and staged writes keep transition
        # order) and must not block; ``flush(blocking=...)`` persists what was
        # staged and ``notify`` delivers events to potentially blocking
        # downstream sinks, both after the lock is released, so a slow SQLite
        # write or health sink never holds the transition lock. All other
        # controller state is mutated only by the source worker.
        self.lock = threading.RLock()
        self.flush = flush
        self.notify = notify
        # Events emitted under the lock, delivered to ``notify`` in the same
        # order by one thread at a time.
        self._outbox = deque()
        self._delivery = threading.Lock()
        # A non-blocking caller (the supervisor watchdog) never runs
        # ``notify`` itself: a downstream sink may block indefinitely, and the
        # single watchdog thread must keep enforcing reopen deadlines and
        # checking other sources. At most one handoff thread per controller
        # drains the outbox for it.
        self._handoff_lock = threading.Lock()
        self._handoff_running = False
        self._handoff_pending = False
        self.delivery_failures = 0
        # A close transition recorded in memory by capture_closing() whose
        # persistence and notification capture_closed() still owes.
        self._close_pending = False

    def _persist(self):
        if self.store is not None:
            self.store.save(self.source_id, self.approved, self.requires_approval,
                            session_token=self._session_token, serial_ambiguous=self.serial_ambiguous)

    def _set_state(self, state, reason):
        """Change the in-memory state; the caller holds ``self.lock``."""
        changed = (self.state, self._reason) != (state, reason)
        self.state, self._reason = state, reason
        if changed:
            event = HealthEvent(self.source_id, state, reason)
            self.emit(event)
            if self.notify is not None:
                self._outbox.append(event)
        return changed

    def _deliver(self, blocking=True):
        """Hand queued events to ``notify`` outside the transition lock.

        A blocking caller delivers in its own thread, in queue order. A
        non-blocking caller never calls ``notify``: it hands the queue to a
        background delivery thread, so a blocking sink cannot hold it.
        """
        if self.notify is None:
            return
        if not blocking:
            self._handoff()
            return
        while self._outbox:
            if not self._delivery.acquire(blocking=blocking):
                return
            try:
                while True:
                    try:
                        event = self._outbox.popleft()
                    except IndexError:
                        break
                    self.notify(event)
            finally:
                self._delivery.release()

    def _handoff(self):
        with self._handoff_lock:
            if self._handoff_running:
                # The running thread re-checks the queue before it exits.
                self._handoff_pending = True
                return
            if not self._outbox:
                return
            self._handoff_running = True
            self._handoff_pending = False
        thread = threading.Thread(target=self._drain_handoff, daemon=True,
                                  name="serversentinel-local-uvc-health-delivery")
        try:
            thread.start()
        except BaseException:
            with self._handoff_lock:
                self._handoff_running = False
            raise

    def _drain_handoff(self):
        while True:
            while self._outbox:
                try:
                    self._deliver()
                except Exception:
                    # Counted only: exception text may carry private details.
                    # Each failed attempt consumed one event, so this ends.
                    self.delivery_failures += 1
            with self._handoff_lock:
                if not self._handoff_pending and not self._outbox:
                    self._handoff_running = False
                    return
                self._handoff_pending = False

    def _flush(self, blocking=True):
        if self.flush is not None:
            self.flush(blocking=blocking)

    def _transition(self, state, reason):
        with self.lock:
            changed = self._set_state(state, reason)
        try:
            if changed:
                self._flush()
        finally:
            # A refused or failed write must not suppress the in-memory
            # transition reaching downstream sinks (e.g. preview invalidation).
            self._deliver()

    def disconnected(self):
        self.bound = None
        self._transition(CameraState.OFFLINE, "device_disconnected")

    def reconcile(self, devices):
        if self._finished:
            raise ValueError("capture controller is closed")
        if not self.enabled:
            self.bound = None
            self._transition(CameraState.OFFLINE, "disabled")
            return None
        if self.requires_approval:
            self.bound = None
            self._transition(CameraState.MANUAL, "owner_approval_required")
            return None
        devices = tuple(devices)
        if self._profile_hold is not None:
            held, explicit = self._profile_hold
            peers = [d for d in devices if d.strong_key == held.strong_key]
            if devices.count(held) == 1 and (explicit or held.strong_key is None
                                               or not self.serial_ambiguous and len(peers) == 1):
                # Same conditions as a live binding below. Nothing is opened
                # until the profile or enablement changes (set_enabled) or
                # the device instance changes.
                self.bound = None
                self._transition(CameraState.DEGRADED, "capture_profile_unavailable")
                return None
            self._profile_hold = None
        # A live open capture descriptor may keep its approved weak binding.
        # Losing that descriptor ends this allowance, including process restart.
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
            self._persist()
        self._transition(decision.state, decision.reason)
        return self.bound

    def approve(self, candidate, current_devices):
        # Exact current candidate selection is required. A remembered device
        # path cannot approve a candidate that vanished during the ceremony.
        current_devices = tuple(current_devices)
        if (self._finished or not self.enabled or not isinstance(candidate, DeviceEvidence)
                or current_devices.count(candidate) != 1):
            raise ValueError("candidate is unavailable or ambiguous")
        ambiguous = (self.serial_ambiguous and candidate.strong_key == self.approved.strong_key
                     or candidate.strong_key is not None and sum(
                         device.strong_key == candidate.strong_key for device in current_devices
                     ) > 1)
        if self.store is not None:
            self.store.save(self.source_id, candidate, False, session_token=self._session_token,
                            serial_ambiguous=ambiguous)
        self.approved = self.bound = candidate
        self._explicit_binding = True
        self._profile_hold = None
        self.serial_ambiguous = ambiguous
        self.requires_approval = False
        self._transition(CameraState.DEGRADED, "owner_approved_pending_capture")

    def capture_ready(self, candidate):
        if not self.enabled or self.requires_approval or self.bound != candidate or candidate is None:
            raise ValueError("capture has no approved binding")
        self._transition(CameraState.ONLINE, "video_capture_ready")

    def frame_stalled(self, candidate, *, only_online=False, blocking=True,
                      confirm=None, capture_lost=False):
        """An open capture delivered no frame within its stall window.

        Reported ``degraded`` with a fixed reason: a camera that is not
        delivering video is never ``online``, and a stall is never evidence
        about the scene. Only a later delivered frame (``capture_ready``)
        returns the source to ``online``. Offline/manual states and a changed
        binding are never raised to ``degraded`` here. The off-worker check
        passes ``only_online`` and ``blocking=False``: it only lowers an
        ``online`` claim, skips a tick while the worker is transitioning, and
        leaves event delivery to a background thread (see ``_deliver``).
        ``confirm`` is re-evaluated under the transition lock, so frame
        progress recorded after the caller's snapshot wins. ``capture_lost``
        reports a stall past the reopen bound as ``offline``
        (``video_capture_failed``) without touching the descriptor, which the
        (possibly blocked) worker still owns and closes when it returns.
        Returns True when the stall is (now) the reported state.
        """
        if not self.lock.acquire(blocking=blocking):
            return False
        try:
            allowed = ((CameraState.ONLINE,) if only_online
                       else (CameraState.ONLINE, CameraState.DEGRADED))
            if (self._finished or candidate is None or self.bound != candidate
                    or self.state not in allowed):
                return False
            if confirm is not None and not confirm():
                return False
            if capture_lost:
                changed = self._set_state(CameraState.OFFLINE, "video_capture_failed")
            else:
                changed = self._set_state(CameraState.DEGRADED, "video_frame_stalled")
        finally:
            self.lock.release()
        try:
            if changed:
                self._flush(blocking)
        finally:
            self._deliver(blocking)
        return True

    @property
    def profile_unavailable(self):
        return self._profile_hold is not None and self._reason == "capture_profile_unavailable"

    def capture_profile_unavailable(self, candidate):
        """The driver negotiated a different profile than the requested one.

        The caller has already closed the capture descriptor. The source stays
        visibly degraded (never online) instead of silently accepting the
        driver-adjusted profile as if it had been requested.
        """
        if self.bound != candidate or candidate is None:
            raise ValueError("capture has no approved binding")
        self._profile_hold = (candidate, self._explicit_binding)
        self.bound = None
        self._explicit_binding = False
        self._transition(CameraState.DEGRADED, "capture_profile_unavailable")

    def approval_conflict(self):
        """Another enabled source holds an active approval for this camera.

        Reported as manual intervention without changing either durable
        approval, so every conflicting source sees the same state regardless
        of startup or polling order. The Owner resolves it by disabling or
        reapproving one of the sources.
        """
        if self._finished:
            raise ValueError("capture controller is closed")
        self.bound = None
        self._explicit_binding = False
        self._profile_hold = None
        self._transition(CameraState.MANUAL, "approval_conflict")

    def capture_failed(self):
        self.bound = None
        self._transition(CameraState.OFFLINE, "video_capture_failed")

    def capture_closing(self):
        """In-memory part of closing a capture, before the kernel teardown.

        Only a continuously open capture descriptor can retain a weak live
        binding, so it is invalidated here (even when a subsequent approval
        operation fails), and an ``online``/``degraded`` source is lowered to
        ``offline``. Nothing here persists or notifies: that I/O can hang and
        must not keep the descriptor open (see ``capture_closed``).
        """
        self.bound = None
        with self.lock:
            if self.state in (CameraState.DEGRADED, CameraState.ONLINE):
                self._close_pending |= self._set_state(CameraState.OFFLINE, "video_capture_closed")

    def capture_closed(self):
        """After the descriptor is closed: persist and notify, never blocking.

        Persistence goes to the background health writer and notification to
        the background delivery thread, so a hung registry write or health
        sink cannot keep a teardown (or a bounded shutdown) waiting.
        """
        self.bound = None
        with self.lock:
            changed = self._close_pending
            self._close_pending = False
            if self.state in (CameraState.DEGRADED, CameraState.ONLINE):
                changed |= self._set_state(CameraState.OFFLINE, "video_capture_closed")
        try:
            if changed:
                self._flush(blocking=False)
        finally:
            self._deliver(blocking=False)

    def shutdown(self):
        """Release recovery marker only after capture is closed and state durable."""
        if self.bound is not None:
            raise ValueError("capture binding must close before shutdown")
        # No transition lock around this storage write: with no binding the
        # off-worker check cannot report a stall for this controller anyway.
        if self.store is not None and self._session_token is not None:
            self.store.save(self.source_id, self.approved, self.requires_approval,
                            session_token=self._session_token, serial_ambiguous=self.serial_ambiguous, release=True)
            self._session_token = None
        with self.lock:
            self._finished = True

    def supersede_stopped_session(self):
        """Discard only in-memory state after an audited approval supersedes it."""
        if self.bound is not None:
            raise ValueError("capture binding must stop before reapproval")
        # The audited transaction replaces/fences the durable session token.
        # Never save this stale controller during disposal.
        with self.lock:
            self._session_token = None
            self._finished = True

    def set_enabled(self, enabled):
        if self._finished or type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        self.enabled = enabled
        self.bound = None
        self._profile_hold = None
        self._transition(CameraState.OFFLINE, "enabled_pending_capture" if enabled else "disabled")
