"""Explicit asynchronous action results; queued work is never called delivered."""

from collections import OrderedDict
from datetime import datetime
from enum import StrEnum
import logging
import threading
from uuid import UUID

from app.logging import Event

from .models import CRITICAL, Kind


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

    An alert for the same observation may already have been attempted while
    its durable record was refused (`UnrecordedCriticalAlerts`, Issue #318).
    Before submitting, the adapter therefore joins a delivery of that event
    ID still in flight, and, with ``outcomes`` (the service's durable event
    rows by ID), takes a stored outcome as this action's outcome instead of
    sending a second message: `sent` is delivered, `failed` and `disabled`
    stay so, and a `pending` row (a delivery of an earlier process whose
    outcome is unknown) is uncertain. Only an audited Owner requeue
    (``requeued=True``) bypasses the stored outcome and sends again.
    """
    # `PresenceService.dispatch_pending` passes the claim's Owner requeue flag.
    requeue_aware = True

    def __init__(self, service, kind_factory, *, provided=False, configured=None,
                 outcomes=None):
        if provided and not callable(service):
            raise ValueError("notification service provider required")
        if configured is not None and not callable(configured):
            raise ValueError("invalid delivery capability probe")
        if outcomes is not None and not callable(outcomes):
            raise ValueError("invalid delivery outcome lookup")
        self.service, self.kind_factory, self.provided = service, kind_factory, provided
        self.configured = configured
        self.outcomes = outcomes

    def current(self):
        """The notification service now, or None before the runtime created it."""
        return self.service() if self.provided else self.service

    def stored(self, identifier: UUID):
        """The stored #21 delivery result of ``identifier``, or None without a row.

        Without an ``outcomes`` lookup it is always None. Raises when the rows
        cannot be read; call it on the service's owning thread.
        """
        if self.outcomes is None:
            return None
        return self.outcomes((identifier,)).get(identifier)

    def armed(self) -> bool:
        """Whether an external Owner notification can be delivered at all.

        ``configured`` reports the deployment's delivery capability (the Main
        composition: whether Slack is configured). Without Slack the service
        still records a local `disabled` event for every critical observation,
        but presence reports `critical_notifications` unavailable from the
        start, not only once a `disabled` outcome was recorded.
        """
        return True if self.configured is None else self.configured() is True

    _result = staticmethod(notification_result)

    def __call__(self, observation, complete, *, requeued=False):
        if observation.kind not in CRITICAL or not observation.confirmed:
            raise ValueError("confirmed critical observation required")
        service = self.current()
        if service is None:
            return ActionResult.UNAVAILABLE
        kind = self.kind_factory(observation.kind.value)
        try:
            # An alert of this observation attempted earlier (Issue #318) and
            # still in flight: this action is told its outcome, nothing is
            # sent again.
            if service.join(observation.identifier, kind,
                            lambda result: complete(self._result(result))):
                return ActionResult.QUEUED
            if requeued is not True:
                # Its outcome is already stored: take it, never resend.
                stored = self.stored(observation.identifier)
                if stored is not None:
                    outcome = self._result(stored)
                    return ActionResult.UNCERTAIN if outcome is ActionResult.QUEUED else outcome
            accepted = service.can_accept(observation.identifier)
        except Exception:
            # Nothing was submitted: a wrong thread or a service that cannot
            # answer is retried later, never counted as an attempted delivery.
            return ActionResult.UNAVAILABLE
        if accepted is not True:
            return ActionResult.UNAVAILABLE
        result = service.record(
            kind, at=observation.received_at,
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


# Alerts handed over while their observation could not be recorded and not
# yet submitted (any thread adds, the monitoring worker drains). Beyond it a
# hand-over is counted and logged, never queued. In practice the scene
# runtime's critical staging (32 observations by default) and the watched
# records below bound the hand-overs; the cap is a safety bound.
UNRECORDED_ALERT_CAPACITY = 64
# Confirmed observations recorded but whose notification row was not yet
# claimed (or was left `unavailable`): escalated when a dispatch step fails,
# for example storage refused right after the record. The oldest beyond it is
# no longer watched (counted as `untracked`).
RECORDED_WATCH_CAPACITY = 64
# Event IDs already attempted in this process, so the scene runtime's retries
# of the same refused observation do not attempt it again.
UNRECORDED_ALERT_REMEMBERED = 1024


class UnrecordedCriticalAlerts:
    """Slack attempt for a confirmed critical storage keeps from its claim (Issue #318).

    While storage is refused (`STORAGE_HARD_STOP`, a lost or replaced
    recording filesystem) a confirmed server movement or camera tamper either
    cannot be written to the timeline at all, or was written just before the
    refusal and its notification row cannot be claimed: either way the
    dispatcher cannot submit it. Owner decision 2026-10-22: like a
    recording-health failure it still attempts the immediate Slack alert,
    accepting the risk of a duplicate.

    Two hand-overs feed it, both callable from any thread and never blocking
    (a short lock, no I/O, no wait for the monitoring worker):

    - `refused()`: the timeline recorder could not record the observation;
    - `recorded()` / `escalate()`: the recorder wrote it, and it stays watched
      until a successful dispatch step finds its notification row neither
      `pending` nor `unavailable` (`prune()`); a dispatch step that fails
      escalates every watched one to `refused()`. A row left `unavailable`
      because the notification queue was full stays watched as well.

    A full queue counts the hand-over in `dropped` and logs
    `unrecorded_critical_alert_dropped` value-free (first and every
    doubling). Nothing else is kept: no image, source, time, person or cause.

    `drain()` runs on the monitoring worker that owns the notification
    service. It submits through the same `NotificationService.record()` as
    the dispatcher, under the same event ID (the observation identity), with
    the fixed category text only. The service keeps the delivery in memory
    while its local event row is refused and writes it once storage admits
    it, so its queue slot stays taken until then. These alerts may hold at
    most half of the service queue (at least one slot), so scene alerts
    cannot monopolise it: with the default queue of 16 at most 8 are attempted
    during one hard stop and the rest wait for recovery. Other immediate
    alerts may still fill the remaining slots.

    After recovery the scene runtime records the staged observation and the
    dispatcher reaches it through `NotificationAdapter`: a delivery still in
    flight is joined and a stored outcome is taken over, so the same process
    sends one message. If the process ends after the attempt but before its
    outcome row was written, the next process cannot know about it and a
    recovered observation is notified again: that one duplicate is the
    accepted risk. An alert never submitted before the process ended is
    covered only by the timeline (the scene runtime counts its loss).
    """

    def __init__(self, adapter: NotificationAdapter, *,
                 capacity: int = UNRECORDED_ALERT_CAPACITY,
                 watched: int = RECORDED_WATCH_CAPACITY,
                 remembered: int = UNRECORDED_ALERT_REMEMBERED):
        if not isinstance(adapter, NotificationAdapter):
            raise TypeError("notification adapter required")
        if (type(capacity) is not int or not 1 <= capacity <= 1024
                or type(watched) is not int or not 1 <= watched <= 1024
                or type(remembered) is not int or not capacity <= remembered <= 65536):
            raise ValueError("bounded unrecorded alert queue required")
        self._adapter = adapter
        self._capacity, self._watched, self._remembered = capacity, watched, remembered
        self._lock = threading.Lock()
        self._queued: OrderedDict[UUID, Kind] = OrderedDict()
        self._recorded: OrderedDict[UUID, Kind] = OrderedDict()
        self._attempted: OrderedDict[UUID, None] = OrderedDict()
        # Worker only: this process's attempts whose outcome is not persisted.
        self._in_flight: set[UUID] = set()
        self._dropped = self._submitted = self._untracked = 0

    @property
    def queued(self) -> int:
        with self._lock:
            return len(self._queued)

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def submitted(self) -> int:
        with self._lock:
            return self._submitted

    def counts(self) -> dict:
        """Value-free counts for Owner status (this process only)."""
        with self._lock:
            return {"attempted": self._submitted, "waiting": len(self._queued),
                    "dropped": self._dropped, "untracked": self._untracked}

    @staticmethod
    def _kind(kind) -> Kind:
        kind = Kind(getattr(kind, "value", kind))
        if kind not in CRITICAL:
            raise ValueError("critical kind required")
        return kind

    def refused(self, identifier: UUID, kind) -> None:
        """Hand over a confirmed critical that cannot be submitted now; never blocks."""
        if not isinstance(identifier, UUID):
            raise ValueError("invalid critical identity")
        kind = self._kind(kind)
        if not self._adapter.armed():
            # Without Slack there is nothing to attempt; the local event is
            # written by the dispatcher once the observation is recorded.
            return
        with self._lock:
            if identifier in self._queued or identifier in self._attempted:
                return
            if len(self._queued) < self._capacity:
                self._queued[identifier] = kind
                return
            self._dropped += 1
            dropped = self._dropped
        if dropped & (dropped - 1) == 0:
            logging.getLogger(__name__).warning(Event.UNRECORDED_CRITICAL_ALERT_DROPPED)

    def recorded(self, identifier: UUID, kind) -> None:
        """Watch a confirmed critical the recorder wrote until it is claimed; never blocks."""
        if not isinstance(identifier, UUID):
            raise ValueError("invalid critical identity")
        kind = self._kind(kind)
        if not self._adapter.armed():
            return
        with self._lock:
            self._recorded[identifier] = kind
            self._recorded.move_to_end(identifier)
            while len(self._recorded) > self._watched:
                self._recorded.popitem(last=False)
                self._untracked += 1

    def awaiting(self) -> tuple[UUID, ...]:
        """The watched identities, checked by a successful dispatch step."""
        with self._lock:
            return tuple(self._recorded)

    def prune(self, checked, keep) -> None:
        """Stop watching ``checked`` identities not in ``keep`` (claimed or resolved)."""
        keep = set(keep)
        with self._lock:
            for identifier in checked:
                if identifier not in keep:
                    self._recorded.pop(identifier, None)

    def escalate(self) -> None:
        """A dispatch step failed: attempt every watched, unclaimed one."""
        with self._lock:
            watched = tuple(self._recorded.items())
        for identifier, kind in watched:
            self.refused(identifier, kind)

    def _attempt(self, identifier: UUID) -> None:
        # Called with the lock held.
        self._queued.pop(identifier, None)
        self._attempted[identifier] = None
        while len(self._attempted) > self._remembered:
            self._attempted.popitem(last=False)

    def drain(self, *, at: datetime) -> int:
        """Submit queued alerts on the service's owning thread; returns how many wait.

        Stops at the first one the service cannot take now (queue full or
        closed, or these alerts already hold their share of it); it is
        retried by the next drain. Raises nothing for a single alert's failure.
        """
        service = self._adapter.current()
        if service is None:
            return self.queued
        if not self._adapter.armed():
            with self._lock:
                self._queued.clear()
            return 0
        self._in_flight = {item for item in self._in_flight if service.in_flight(item)}
        # Half of the queue, and at least one slot (a queue of one).
        limit = max(1, service.capacity // 2)
        with self._lock:
            waiting = tuple(self._queued.items())
        for identifier, kind in waiting:
            if service.in_flight(identifier):
                # The dispatcher already submitted it after a recovery.
                with self._lock:
                    self._attempt(identifier)
                continue
            try:
                stored = self._adapter.stored(identifier)
            except Exception:
                # Unreadable while storage is refused: attempt it anyway.
                stored = None
            if stored is not None:
                with self._lock:
                    self._attempt(identifier)
                continue
            if len(self._in_flight) >= limit or service.can_accept(identifier) is not True:
                break
            result = service.record(self._adapter.kind_factory(kind.value), at=at,
                                    confirmed=True, event_id=identifier)
            if notification_result(result) is ActionResult.FAILED and not service.retained(identifier):
                # Refused without anything sent: left queued for the next drain.
                break
            if service.in_flight(identifier):
                self._in_flight.add(identifier)
            with self._lock:
                self._attempt(identifier)
                self._submitted += 1
            logging.getLogger(__name__).warning(Event.UNRECORDED_CRITICAL_ALERT_ATTEMPTED)
        return self.queued
