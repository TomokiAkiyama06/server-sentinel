"""Typed local port for durable critical evidence/notification orchestration."""

from dataclasses import dataclass
from typing import Protocol

from .contracts import CriticalKind, CriticalObservation


# A single confirmed sample can produce one observation per critical kind, so
# staging smaller than that could never accept a whole batch: it would refuse
# the batch before any recorder ran and could not progress by retrying it.
MAXIMUM_BATCH = len(CriticalKind)


class CriticalRecorder(Protocol):
    def __call__(self, observation: CriticalObservation) -> None:
        """Durably accept this UUID idempotently before returning.

        The downstream presence service owns its evidence/notification outbox.
        Its critical path must run in every presence state. This callback never
        means that an external Slack delivery or physical evidence was verified.
        """
        ...


@dataclass(frozen=True)
class DeliveryState:
    accepted: tuple
    pending: tuple
    available: bool


class CriticalDelivery:
    """Finite local retry staging; capture and recording remain independent.

    A caller must drain/check capacity before running another detector tick.
    Capacity is at least `MAXIMUM_BATCH`, so a batch from one sample is always
    admissible when the staging is drained and backpressure only ever reflects
    undelivered evidence rather than a size a caller can never satisfy.
    Refusing a new batch is explicit backpressure, never silent evidence loss.
    Process durability starts only when the injected recorder accepts the UUID;
    pending data must be preserved by the Main runtime during shutdown.
    """

    def __init__(self, *, capacity: int, recorder: CriticalRecorder | None = None):
        if type(capacity) is not int or capacity < MAXIMUM_BATCH:
            raise ValueError("critical staging must hold a full detector batch")
        self.capacity, self.recorder = capacity, recorder
        self._pending = {}

    @property
    def remaining(self):
        return self.capacity - len(self._pending)

    def submit(self, observations: tuple[CriticalObservation, ...]):
        if any(not isinstance(item, CriticalObservation) or not item.confirmed for item in observations):
            raise ValueError("only confirmed critical observations may be submitted")
        new = {item.identifier: item for item in observations}
        if len(set(new) - set(self._pending)) > self.remaining:
            raise BufferError("critical delivery staging is full")
        self._pending.update(new)
        return self.retry()

    def retry(self):
        accepted = []
        if self.recorder is not None:
            for identifier, observation in tuple(self._pending.items()):
                try:
                    self.recorder(observation)
                except Exception:
                    continue
                accepted.append(identifier)
                del self._pending[identifier]
        return DeliveryState(tuple(accepted), tuple(self._pending), not self._pending)
