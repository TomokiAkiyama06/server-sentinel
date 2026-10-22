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


def notification_result(result) -> ActionResult:
    """Map a #21 `DeliveryResult` onto the presence delivery outcome.

    Only `sent` completes the critical action. `pending` is accepted work, not
    a delivery, and anything unrecognized is uncertain, never success.
    """
    return {"sent": ActionResult.DELIVERED, "pending": ActionResult.QUEUED,
            "failed": ActionResult.FAILED, "disabled": ActionResult.DISABLED}.get(
                getattr(result, "value", None), ActionResult.UNCERTAIN)


class NotificationAdapter:
    """Adapter for #21 NotificationService, constructed by reviewed integration.

    Pass its NotificationKind enum as kind_factory. No import/network work occurs
    here; the owning notification worker must call service.poll() for completion.

    `service` is the service itself or, with ``provided=True``, a
    zero-argument callable returning the current service or None, for a
    service a runtime creates later on its own worker (the Main monitoring
    runtime). The adapter must be called on that service's owning thread. It
    asks `service.can_accept()` before submitting: no service yet, a call
    from the wrong thread, or a full or closed queue returns `unavailable`
    with nothing submitted, so presence retries the action later instead of
    recording a final failure for an alert that was never sent. The message is
    the service's fixed category text only (`server_movement` or
    `camera_tamper`): no image, source, person or cause.
    """
    def __init__(self, service, kind_factory, *, provided=False):
        if provided and not callable(service):
            raise ValueError("notification service provider required")
        self.service, self.kind_factory, self.provided = service, kind_factory, provided

    _result = staticmethod(notification_result)

    def __call__(self, observation, complete):
        if observation.kind not in CRITICAL or not observation.confirmed:
            raise ValueError("confirmed critical observation required")
        service = self.service() if self.provided else self.service
        if service is None:
            return ActionResult.UNAVAILABLE
        try:
            accepted = service.can_accept(observation.identifier)
        except Exception:
            # Nothing was submitted: a wrong thread or a service that cannot
            # answer is retried later, never counted as an attempted delivery.
            return ActionResult.UNAVAILABLE
        if accepted is not True:
            return ActionResult.UNAVAILABLE
        result = service.record(
            self.kind_factory(observation.kind.value), at=observation.received_at,
            confirmed=True, event_id=observation.identifier,
            on_complete=lambda result: complete(self._result(result)),
        )
        outcome = self._result(result)
        if outcome is ActionResult.FAILED and service.retained(observation.identifier):
            # Nothing was sent and the event waits in the service's local
            # retry buffer: keep the action retryable rather than final; the
            # next submission of this ID retries the local write.
            return ActionResult.UNAVAILABLE
        return outcome
