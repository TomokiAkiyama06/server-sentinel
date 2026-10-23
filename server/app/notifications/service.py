"""Sparse immediate alerts plus fixed, aggregate daily summary data."""

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Callable
from uuid import UUID, uuid4
import threading

from app.notifications.slack import DeliveryResult, SlackDelivery
from app.notifications.worker import DeliveryWorker
from app.storage.policy import StorageState


class NotificationKind(StrEnum):
    SERVER_MOVEMENT = "server_movement"
    CAMERA_TAMPER = "camera_tamper"
    HARDWARE_INTEGRITY_FAILURE = "hardware_integrity_failure"
    RECORDING_HEALTH_FAILURE = "recording_health_failure"
    # Human access faults (Issue #232 item 4, Owner decision 2026-10-16): a
    # failing hostname reservation check or human-access composition, its
    # recovery, and a committed WebAuthn credential finding. Immediate and
    # value-free: no hostname, identity, principal, credential or reason.
    HUMAN_ACCESS_FAULT = "human_access_fault"
    HUMAN_ACCESS_RECOVERED = "human_access_recovered"
    CREDENTIAL_FINDING = "credential_finding"
    # Issue #321: the recorded major/minor numbers of the recording/runtime
    # filesystem no longer name the device its approved UUID and mount agree
    # on (the kernel renumbered the disk at boot). Storage stays admitted;
    # the Owner is told once per boot and device numbers to update the
    # stale value (Owner decision 2026-10-22).
    # Value-free: no number, UUID or path.
    RECORDING_DEVICE_NUMBERS_CHANGED = "recording_device_numbers_changed"
    # Visible local warnings (NEW_DEVICE/UNVERIFIABLE hardware, unavailable
    # recording-health verdict). They are never an immediate Slack message.
    HARDWARE_INTEGRITY_WARNING = "hardware_integrity_warning"
    RECORDING_HEALTH_WARNING = "recording_health_warning"
    # Capture-node certificate approaching expiry without renewal, expired, or
    # a refused renewal (Issue #13). Local Owner-visible warning only.
    CAPTURE_CREDENTIAL_WARNING = "capture_credential_warning"
    # The deployment capture-node CA or the Main ingest listener certificate is
    # expiring, or the CA is too close to expiry to issue/renew node leaves at
    # the configured validity (Issues #125/#127). Local Owner-visible warning.
    CAPTURE_TRUST_WARNING = "capture_trust_warning"
    PERSON = "person"
    MOTION = "motion"
    ENTRY = "entry"
    CAMERA_OFFLINE = "camera_offline"
    DAILY_SUMMARY = "daily_summary"


# Always an immediate Slack message (when configured), independent of presence.
IMMEDIATE_KINDS = frozenset({
    NotificationKind.HARDWARE_INTEGRITY_FAILURE, NotificationKind.RECORDING_HEALTH_FAILURE,
    NotificationKind.HUMAN_ACCESS_FAULT, NotificationKind.HUMAN_ACCESS_RECOVERED,
    NotificationKind.CREDENTIAL_FINDING, NotificationKind.RECORDING_DEVICE_NUMBERS_CHANGED,
})
# Immediate only when confirmed: a confirmed server movement / camera tamper
# (Issue #26), and a camera source offline for the deployment's threshold
# (Issue #301 item 2, Owner decision 2026-10-22; `../monitoring/cameras.py`).
# An unconfirmed observation of these kinds stays local until the summary.
CONFIRMED_IMMEDIATE_KINDS = frozenset({
    NotificationKind.SERVER_MOVEMENT, NotificationKind.CAMERA_TAMPER,
    NotificationKind.CAMERA_OFFLINE,
})
# Immediate, but the end of a fault rather than an alert.
RECOVERY_KINDS = frozenset({NotificationKind.HUMAN_ACCESS_RECOVERED})
# Immediate, but a condition needing Owner attention rather than a failure:
# monitoring and recording continue (Issue #321).
ATTENTION_KINDS = frozenset({NotificationKind.RECORDING_DEVICE_NUMBERS_CHANGED})


def aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("notification time must include timezone")


@dataclass(frozen=True)
class NotificationEvent:
    kind: NotificationKind
    at: datetime
    confirmed: bool
    event_id: UUID = field(default_factory=uuid4)
    delivery: DeliveryResult = DeliveryResult.SUPPRESSED


@dataclass(frozen=True)
class DailySummary:
    monitored_seconds: int
    sources_online: int
    sources_degraded: int
    sources_offline: int
    agents_online: int
    agents_offline: int
    person_count: int
    motion_count: int
    entry_count: int
    critical_count: int
    recording_count: int
    error_count: int
    recording_bytes: int
    storage_state: StorageState
    # False when no capture/detection pipeline reports into this summary. The
    # source, agent and observation counts are then shown as unavailable, so a
    # summary never presents "0 person observations" as a verified absence.
    pipeline_available: bool = True

    def __post_init__(self):
        if (not isinstance(self.storage_state, StorageState)
                or type(self.pipeline_available) is not bool or any(
                    type(value) is not int or not 0 <= value < 2**63
                    for key, value in vars(self).items()
                    if key not in {"storage_state", "pipeline_available"})):
            raise ValueError("invalid summary aggregate")

    def text(self) -> str:
        if self.pipeline_available:
            pipeline = (f"Sources online/degraded/offline: {self.sources_online}/"
                        f"{self.sources_degraded}/{self.sources_offline}\n"
                        f"Agents online/offline: {self.agents_online}/{self.agents_offline}\n"
                        f"Person/motion/entry observations: {self.person_count}/"
                        f"{self.motion_count}/{self.entry_count}\n")
            monitored = f"Monitored seconds: {self.monitored_seconds}\n"
        else:
            # Service uptime is not monitored coverage: with no capture
            # pipeline nothing was watched, so no duration is claimed.
            monitored = ("Monitored seconds: unavailable (no capture pipeline reporting; "
                         f"service uptime seconds: {self.monitored_seconds})\n")
            pipeline = ("Sources: unavailable (no capture pipeline reporting)\n"
                        "Agents: unavailable\n"
                        "Person/motion/entry observations: unavailable\n")
        return ("ServerSentinel daily summary\n"
                + monitored + pipeline +
                f"Critical events: {self.critical_count}; recordings: {self.recording_count}\n"
                f"Recording bytes: {self.recording_bytes}; storage: {self.storage_state.value}\n"
                f"Errors: {self.error_count}")


class NotificationService:
    """Owner-thread local persistence with bounded asynchronous Slack delivery.

    The sink must durably upsert by event_id: the initial pending event and later
    delivery result share that ID. poll() invokes completion callbacks only on
    this owning thread, never on the network worker. No automatic resend occurs.
    """

    def __init__(self, local_sink: Callable[[NotificationEvent], None],
                 slack: SlackDelivery | None = None, *, queue_capacity: int = 16):
        if type(queue_capacity) is not int or not 1 <= queue_capacity <= 1024:
            raise ValueError("invalid notification capacity")
        self._local_sink = local_sink
        self._slack = slack or SlackDelivery()
        self._worker = DeliveryWorker(self._slack, queue_capacity)
        self._capacity = queue_capacity
        self._pending = {}
        # `record()` events whose delivery is final but whose local write was
        # refused (full disk, unverified filesystem): retried on every poll,
        # bounded by the same capacity, so a mandatory alert is not lost.
        self._unpersisted: dict[UUID, NotificationEvent] = {}
        self._owner = threading.get_ident()
        self.closed = False
        self.last_delivery = DeliveryResult.DISABLED
        self.local_delivery_failed = False
        self.delivery_failed = False

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def unpersisted_count(self) -> int:
        return len(self._unpersisted)

    @property
    def capacity(self) -> int:
        """The bound of the Slack queue (and of the local retry buffer)."""
        return self._capacity

    def in_flight(self, event_id: UUID) -> bool:
        """Whether ``event_id`` was submitted and its outcome is not yet persisted.

        That is a delivery still running, or one that finished while its
        local write is refused (`STORAGE_HARD_STOP`): it stays here, and so
        in `pending_count`, until the outcome row is written.
        """
        self._check()
        return event_id in self._pending

    def join(self, event_id: UUID, kind: NotificationKind, on_complete) -> bool:
        """Attach ``on_complete`` to the delivery of ``event_id`` already in flight.

        Returns False (nothing attached) when no such delivery is in flight or
        it is of another kind. Unlike a coalesced `record()`, the time of the
        joined delivery is not compared: an upstream outbox that learns about
        an alert submitted earlier under the same identity (Issue #318, an
        alert attempted while its durable record was refused) is told that
        delivery's outcome instead of sending a second message.
        """
        self._check()
        if not isinstance(event_id, UUID) or not callable(on_complete):
            raise ValueError("invalid notification event")
        entry = self._pending.get(event_id)
        if entry is None or entry[0].kind != kind or not entry[0].confirmed:
            return False
        entry[1].append(on_complete)
        return True

    def can_accept(self, event_id: UUID) -> bool:
        """Whether `record(..., event_id=event_id)` would not be refused for capacity.

        An upstream durable outbox asks before it submits, so a full or closed
        queue leaves its work queued for a later attempt instead of turning
        into a final `failed` delivery for an alert that was never sent. A
        resubmission of an event already pending or retained always fits.
        Without Slack nothing is queued, but a refused local write must still
        fit the bounded retry buffer (`_retain`), or the event would be
        dropped; while that buffer is full nothing new is accepted.
        """
        self._check()
        if not isinstance(event_id, UUID):
            raise ValueError("invalid notification event")
        if event_id in self._pending or event_id in self._unpersisted:
            return True
        if not self._slack.configured:
            return len(self._unpersisted) < self._capacity
        return not self.closed and len(self._pending) < self._capacity

    def retained(self, event_id: UUID) -> bool:
        """Whether ``event_id`` is final but its local write is still being retried.

        Such a `record()` returned `failed` although nothing was sent (Slack
        disabled, or a closed or full queue) and nothing is lost: resubmitting
        the same ID retries the local write and returns the stored result.
        """
        self._check()
        return event_id in self._unpersisted

    def _check(self):
        if threading.get_ident() != self._owner:
            raise RuntimeError("notification owner thread required")

    def _local(self, event: NotificationEvent) -> bool:
        try:
            self._local_sink(event)
            return True
        except Exception:
            self.local_delivery_failed = True
            return False

    def _retain(self, event: NotificationEvent) -> bool:
        """Keep a refused local write for retry; a full buffer stays visible.

        Returns whether the event is retained (and so retried on poll).
        """
        self.local_delivery_failed = True
        if event.event_id in self._unpersisted or len(self._unpersisted) < self._capacity:
            self._unpersisted[event.event_id] = event
            return True
        return False

    def _flush_unpersisted(self) -> None:
        for identifier, event in tuple(self._unpersisted.items()):
            if self._local(event):
                del self._unpersisted[identifier]

    def _enqueue(self, event: NotificationEvent, text: str, on_complete=None,
                 retain: bool = False) -> DeliveryResult:
        if event.event_id in self._pending:
            prior = self._pending[event.event_id][0]
            if (event.kind, event.at, event.confirmed) != (prior.kind, prior.at, prior.confirmed):
                self.delivery_failed = True
                return DeliveryResult.FAILED
            # A coalesced resubmission (for example an Owner requeue, which
            # starts a new presence claim generation) is told the outcome of
            # the delivery it joined, as is the original submitter.
            if on_complete is not None:
                self._pending[event.event_id][1].append(on_complete)
            return DeliveryResult.PENDING
        if not self._slack.configured:
            result = DeliveryResult.DISABLED
        elif self.closed or len(self._pending) >= self._capacity:
            result = DeliveryResult.FAILED
            self.delivery_failed = True
        else:
            result = DeliveryResult.PENDING
        event = replace(event, delivery=result)
        if not self._local(event) and result != DeliveryResult.PENDING:
            if retain:
                self._retain(event)
            self.last_delivery = DeliveryResult.FAILED
            return self.last_delivery
        self.last_delivery = result
        if result == DeliveryResult.PENDING:
            self._pending[event.event_id] = [event, [on_complete] if on_complete else [], None]
            try:
                self._worker.submit(event.event_id, text)
            except Exception:
                self._pending[event.event_id][2] = DeliveryResult.FAILED
                self.delivery_failed = True
                self.poll()
                return DeliveryResult.FAILED
        return result

    def poll(self) -> tuple[NotificationEvent, ...]:
        """Persist completed results without waiting; failed persistence retries locally."""
        self._check()
        self._flush_unpersisted()
        for identifier, result in self._worker.results():
            self._pending[identifier][2] = result
        completed = []
        for identifier, (event, callbacks, result) in tuple(self._pending.items()):
            if result is None:
                continue
            update = replace(event, delivery=result)
            if result == DeliveryResult.FAILED:
                self.delivery_failed = True
            if not self._local(update):
                continue
            # Every submitter of a coalesced delivery is told; a callback that
            # raised is retried on the next poll, the others are not repeated.
            failed = []
            for callback in callbacks:
                try:
                    callback(result)
                except Exception:
                    failed.append(callback)
            if failed:
                self.local_delivery_failed = True
                self._pending[identifier][1] = failed
                continue
            self.last_delivery = result
            completed.append(update)
            del self._pending[identifier]
        return tuple(completed)

    def record(self, kind: NotificationKind, *, at: datetime,
               confirmed: bool = False, event_id: UUID | None = None,
               on_complete=None) -> DeliveryResult:
        self._check()
        aware(at)
        if (not isinstance(kind, NotificationKind) or type(confirmed) is not bool
                or event_id is not None and not isinstance(event_id, UUID)):
            raise ValueError("invalid notification event")
        if kind == NotificationKind.DAILY_SUMMARY:
            raise ValueError("daily summary requires aggregate data")
        event = NotificationEvent(kind, at, confirmed, event_id=event_id or uuid4())
        prior = self._unpersisted.get(event.event_id)
        if prior is not None:
            # A resubmission of a retained event retries its local write
            # instead of delivering it a second time.
            if (kind, at, confirmed) != (prior.kind, prior.at, prior.confirmed):
                self.delivery_failed = True
                return DeliveryResult.FAILED
            if not self._local(prior):
                return DeliveryResult.FAILED
            del self._unpersisted[event.event_id]
            return prior.delivery
        immediate = (kind in IMMEDIATE_KINDS or confirmed and kind in CONFIRMED_IMMEDIATE_KINDS)
        if not immediate:
            # SUPPRESSED: written locally, or retained for the poll retry.
            # FAILED: the write was refused and the retry buffer is full, so
            # the event is dropped; the caller must not count it as recorded.
            if not self._local(event) and not self._retain(event):
                return DeliveryResult.FAILED
            return DeliveryResult.SUPPRESSED
        prefix = ("ServerSentinel recovery notice" if kind in RECOVERY_KINDS
                  else "ServerSentinel attention notice" if kind in ATTENTION_KINDS
                  else "ServerSentinel critical alert")
        return self._enqueue(event, f"{prefix}: {kind.value}", on_complete, retain=True)

    def daily(self, summary: DailySummary, *, at: datetime, on_complete=None) -> DeliveryResult:
        self._check()
        aware(at)
        if not isinstance(summary, DailySummary):
            raise ValueError("invalid daily summary")
        return self._enqueue(NotificationEvent(NotificationKind.DAILY_SUMMARY, at, False),
                             summary.text(), on_complete)

    def close(self) -> None:
        self._check()
        self.closed = True
        self._worker.close()
