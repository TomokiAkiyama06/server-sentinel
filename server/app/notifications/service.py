"""Sparse immediate alerts plus fixed, aggregate daily summary data."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Callable

from app.notifications.slack import DeliveryResult, SlackDelivery
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
    def __init__(self, local_sink: Callable[[NotificationEvent], None],
                 slack: SlackDelivery | None = None):
        self._local_sink = local_sink
        self._slack = slack or SlackDelivery()
        self.last_delivery = DeliveryResult.DISABLED
        self.local_delivery_failed = False

    def _local(self, event: NotificationEvent) -> None:
        try:
            self._local_sink(event)
        except Exception:
            self.local_delivery_failed = True

    def record(self, kind: NotificationKind, *, at: datetime,
               confirmed: bool = False) -> DeliveryResult:
        aware(at)
        if not isinstance(kind, NotificationKind) or type(confirmed) is not bool:
            raise ValueError("invalid notification event")
        if kind == NotificationKind.DAILY_SUMMARY:
            raise ValueError("daily summary requires aggregate data")
        self._local(NotificationEvent(kind, at, confirmed))
        immediate = (kind in {NotificationKind.HARDWARE_INTEGRITY_FAILURE,
                              NotificationKind.RECORDING_HEALTH_FAILURE}
                     or confirmed and kind in {NotificationKind.SERVER_MOVEMENT,
                                               NotificationKind.CAMERA_TAMPER})
        if not immediate:
            return DeliveryResult.SUPPRESSED
        # Category text only: no room/source names, identities, frames or paths.
        self.last_delivery = self._slack.send(f"ServerSentinel critical alert: {kind.value}")
        return self.last_delivery

    def daily(self, summary: DailySummary, *, at: datetime) -> DeliveryResult:
        aware(at)
        if not isinstance(summary, DailySummary):
            raise ValueError("invalid daily summary")
        self._local(NotificationEvent(NotificationKind.DAILY_SUMMARY, at, False))
        self.last_delivery = self._slack.send(summary.text())
        return self.last_delivery
