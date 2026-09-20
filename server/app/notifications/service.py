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
    PERSON = "person"
    MOTION = "motion"
    ENTRY = "entry"
    CAMERA_OFFLINE = "camera_offline"
    DAILY_SUMMARY = "daily_summary"


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

    def __post_init__(self):
        if not isinstance(self.storage_state, StorageState) or any(
            type(value) is not int or not 0 <= value < 2**63
            for key, value in vars(self).items() if key != "storage_state"
        ):
            raise ValueError("invalid summary aggregate")

    def text(self) -> str:
        return ("ServerSentinel daily summary\n"
                f"Monitored seconds: {self.monitored_seconds}\n"
                f"Sources online/degraded/offline: {self.sources_online}/"
                f"{self.sources_degraded}/{self.sources_offline}\n"
                f"Agents online/offline: {self.agents_online}/{self.agents_offline}\n"
                f"Person/motion/entry observations: {self.person_count}/{self.motion_count}/{self.entry_count}\n"
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
        self._owner = threading.get_ident()
        self.closed = False
        self.last_delivery = DeliveryResult.DISABLED
        self.local_delivery_failed = False
        self.delivery_failed = False

    @property
    def pending_count(self) -> int:
        return len(self._pending)

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

    def _enqueue(self, event: NotificationEvent, text: str, on_complete=None) -> DeliveryResult:
        if event.event_id in self._pending:
            prior = self._pending[event.event_id][0]
            if (event.kind, event.at, event.confirmed) != (prior.kind, prior.at, prior.confirmed):
                self.delivery_failed = True
                return DeliveryResult.FAILED
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
            self.last_delivery = DeliveryResult.FAILED
            return self.last_delivery
        self.last_delivery = result
        if result == DeliveryResult.PENDING:
            self._pending[event.event_id] = [event, on_complete, None]
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
        for identifier, result in self._worker.results():
            self._pending[identifier][2] = result
        completed = []
        for identifier, (event, callback, result) in tuple(self._pending.items()):
            if result is None:
                continue
            update = replace(event, delivery=result)
            if result == DeliveryResult.FAILED:
                self.delivery_failed = True
            if not self._local(update):
                continue
            try:
                if callback:
                    callback(result)
            except Exception:
                self.local_delivery_failed = True
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
        immediate = (kind in {NotificationKind.HARDWARE_INTEGRITY_FAILURE,
                              NotificationKind.RECORDING_HEALTH_FAILURE}
                     or confirmed and kind in {NotificationKind.SERVER_MOVEMENT,
                                               NotificationKind.CAMERA_TAMPER})
        if not immediate:
            self._local(event)
            return DeliveryResult.SUPPRESSED
        return self._enqueue(event, f"ServerSentinel critical alert: {kind.value}", on_complete)

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
