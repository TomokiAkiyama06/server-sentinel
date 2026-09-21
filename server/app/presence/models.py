"""Neutral observation inputs; no face matching or confidence thresholds here."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
import math
from uuid import UUID, uuid4


class PresenceState(StrEnum):
    PRESENT = "PRESENT"
    PROBABLY_PRESENT = "PROBABLY_PRESENT"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class Kind(StrEnum):
    PERSON = "person"
    MOTION = "motion"
    OWNER_ENTRY = "owner_entry"
    OWNER_EXIT = "owner_exit"
    ANONYMOUS_ENTRY = "anonymous_entry"
    ANONYMOUS_EXIT = "anonymous_exit"
    SERVER_MOVEMENT = "server_movement"
    CAMERA_TAMPER = "camera_tamper"
    CAMERA_HEALTH = "camera_health"
    NODE_HEALTH = "node_health"
    RECORDING = "recording"
    STORAGE = "storage"
    PRESENCE = "presence"
    CONFIGURATION = "configuration"


class Quality(StrEnum):
    SUFFICIENT = "sufficient"
    INSUFFICIENT = "insufficient"
    UNKNOWN = "unknown"


class Value(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    READY = "ready"
    FAILED = "failed"
    CREATED = "created"
    DELETED = "deleted"
    CHANGED = "changed"


CRITICAL = frozenset({Kind.SERVER_MOVEMENT, Kind.CAMERA_TAMPER})
LABELS = {
    Kind.PERSON: "Person observation", Kind.MOTION: "Motion observation",
    Kind.OWNER_ENTRY: "Owner entry observation", Kind.OWNER_EXIT: "Owner exit observation",
    Kind.ANONYMOUS_ENTRY: "Anonymous entry observation", Kind.ANONYMOUS_EXIT: "Anonymous exit observation",
    Kind.SERVER_MOVEMENT: "Server movement observation", Kind.CAMERA_TAMPER: "Camera tamper observation",
    Kind.CAMERA_HEALTH: "Camera health", Kind.NODE_HEALTH: "Capture node health",
    Kind.RECORDING: "Recording state", Kind.STORAGE: "Storage state",
    Kind.PRESENCE: "Presence state", Kind.CONFIGURATION: "Configuration change",
}


class InvalidObservation(ValueError):
    pass


def utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidObservation("aware timestamp required")
    return value.astimezone(timezone.utc)


def timestamp(value):
    return utc(value).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class Observation:
    kind: Kind
    occurred_at: datetime
    received_at: datetime
    value: Value = Value.OBSERVED
    source_id: UUID | None = None
    node_id: UUID | None = None
    confidence: float | None = None
    quality: Quality = Quality.UNKNOWN
    clock_trusted: bool = False
    uncertainty_us: int = 0
    confirmed: bool = False
    identifier: UUID = field(default_factory=uuid4)
    presence_state: PresenceState | None = None

    def __post_init__(self):
        if not isinstance(self.kind, Kind) or not isinstance(self.value, Value) or not isinstance(self.quality, Quality):
            raise InvalidObservation("invalid observation category")
        utc(self.occurred_at)
        utc(self.received_at)
        if any(value is not None and not isinstance(value, UUID) for value in (self.source_id, self.node_id)):
            raise InvalidObservation("invalid attribution")
        if not isinstance(self.identifier, UUID):
            raise InvalidObservation("invalid observation identity")
        if self.kind in {Kind.PERSON, Kind.MOTION, Kind.OWNER_ENTRY, Kind.OWNER_EXIT,
                         Kind.ANONYMOUS_ENTRY, Kind.ANONYMOUS_EXIT, *CRITICAL, Kind.CAMERA_HEALTH}:
            if self.source_id is None:
                raise InvalidObservation("source attribution required")
        if self.presence_state is not None and (self.kind != Kind.PRESENCE
                                                 or not isinstance(self.presence_state, PresenceState)):
            raise InvalidObservation("invalid presence projection")
        if self.kind == Kind.NODE_HEALTH and self.node_id is None:
            raise InvalidObservation("node attribution required")
        if self.confidence is not None and (type(self.confidence) not in (int, float)
                                           or not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1):
            raise InvalidObservation("invalid confidence")
        if type(self.clock_trusted) is not bool or type(self.confirmed) is not bool:
            raise InvalidObservation("explicit trust required")
        if type(self.uncertainty_us) is not int or not 0 <= self.uncertainty_us < 2 ** 63:
            raise InvalidObservation("invalid clock uncertainty")
        if self.kind == Kind.PERSON and self.quality != Quality.SUFFICIENT and self.value == Value.NOT_OBSERVED:
            raise InvalidObservation("unreliable person result must be unknown")
        if self.confirmed and (self.quality != Quality.SUFFICIENT or self.value != Value.OBSERVED
                               or self.confidence is None):
            raise InvalidObservation("confirmation prerequisites unavailable")

    def uncertain(self):
        return replace(self, clock_trusted=False)

    def payload(self):
        return {
            "id": str(self.identifier), "kind": self.kind.value, "value": self.value.value,
            "label": LABELS[self.kind], "occurred_at": timestamp(self.occurred_at),
            "received_at": timestamp(self.received_at),
            "source_id": str(self.source_id) if self.source_id else None,
            "node_id": str(self.node_id) if self.node_id else None,
            "confidence": self.confidence, "quality": self.quality.value,
            "clock_trusted": self.clock_trusted, "uncertainty_us": self.uncertainty_us,
            "confirmed": self.confirmed, "presence_state": self.presence_state.value if self.presence_state else None,
        }

    @classmethod
    def from_payload(cls, value):
        return cls(Kind(value["kind"]), datetime.fromisoformat(value["occurred_at"]),
                   datetime.fromisoformat(value["received_at"]), value=Value(value["value"]),
                   source_id=UUID(value["source_id"]) if value["source_id"] else None,
                   node_id=UUID(value["node_id"]) if value["node_id"] else None,
                   confidence=value["confidence"], quality=Quality(value["quality"]),
                   clock_trusted=value["clock_trusted"], uncertainty_us=value["uncertainty_us"],
                   confirmed=value["confirmed"], identifier=UUID(value["id"]),
                   presence_state=PresenceState(value["presence_state"]) if value["presence_state"] else None)
