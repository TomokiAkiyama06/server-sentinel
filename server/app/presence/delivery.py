"""Explicit asynchronous action results; queued work is never called delivered."""

from enum import StrEnum

from .models import CRITICAL


class ActionResult(StrEnum):
    DELIVERED = "delivered"
    QUEUED = "queued"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    UNCERTAIN = "uncertain"
    DISABLED = "disabled"


class NotificationAdapter:
    """Adapter for #21 NotificationService, constructed by reviewed integration.

    Pass its NotificationKind enum as kind_factory. No import/network work occurs
    here; the owning notification worker must call service.poll() for completion.
    """
    def __init__(self, service, kind_factory):
        self.service, self.kind_factory = service, kind_factory

    @staticmethod
    def _result(result):
        return {"sent": ActionResult.DELIVERED, "pending": ActionResult.QUEUED,
                "failed": ActionResult.FAILED, "disabled": ActionResult.DISABLED}.get(
                    result.value, ActionResult.UNCERTAIN)

    def __call__(self, observation, complete):
        if observation.kind not in CRITICAL or not observation.confirmed:
            raise ValueError("confirmed critical observation required")
        result = self.service.record(
            self.kind_factory(observation.kind.value), at=observation.received_at,
            confirmed=True, event_id=observation.identifier,
            on_complete=lambda result: complete(self._result(result)),
        )
        return self._result(result)
