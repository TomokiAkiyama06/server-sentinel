"""Sparse immediate alerts plus fixed, aggregate daily summary data."""

from collections import OrderedDict
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Callable
from uuid import UUID, uuid4
import threading
import time

from app.notifications.slack import DeliveryResult, SlackDelivery
from app.notifications.worker import DeliveryWorker
from app.storage.database import bounded_lock_waits
from app.stop_budget import SETTLE_POLL_OVERSHOOT_SECONDS
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
    # Issue #205 (Owner decision 2026-10-22, option A): after a Main restart
    # a scene reference was re-acquired from the camera without the Owner,
    # or a stored calibration could not be re-acquired. Immediate and
    # value-free: no source, image or reason.
    SCENE_REFERENCE_REACQUIRED = "scene_reference_reacquired"
    SCENE_CALIBRATION_REQUIRED = "scene_calibration_required"
    # Issue #14 (Owner decision 2026-11-12; `../monitoring/capture_nodes.py`):
    # a capture node's heartbeat reports that it cannot write its ring buffer
    # (immediate), a renumbered media disk or a clock problem (attention,
    # after 5 min), and a configured ingest listener that has not been running
    # for 5 min. Value-free: no node, address or reason text.
    CAPTURE_NODE_STORAGE_FAILURE = "capture_node_storage_failure"
    CAPTURE_NODE_DEVICE_NUMBERS_CHANGED = "capture_node_device_numbers_changed"
    CAPTURE_NODE_CLOCK_DEGRADED = "capture_node_clock_degraded"
    CAPTURE_INGEST_UNAVAILABLE = "capture_ingest_unavailable"
    # Issue #397 (Owner decision 2026-11-12): a node with an active pairing
    # credential sent no heartbeat for 5 min (its Agent stopped, failed to
    # start, or cannot reach the Main). Value-free.
    CAPTURE_NODE_HEARTBEAT_LOST = "capture_node_heartbeat_lost"
    DAILY_SUMMARY = "daily_summary"


# Always an immediate Slack message (when configured), independent of presence.
IMMEDIATE_KINDS = frozenset({
    NotificationKind.HARDWARE_INTEGRITY_FAILURE, NotificationKind.RECORDING_HEALTH_FAILURE,
    NotificationKind.HUMAN_ACCESS_FAULT, NotificationKind.HUMAN_ACCESS_RECOVERED,
    NotificationKind.CREDENTIAL_FINDING, NotificationKind.RECORDING_DEVICE_NUMBERS_CHANGED,
    NotificationKind.SCENE_REFERENCE_REACQUIRED, NotificationKind.SCENE_CALIBRATION_REQUIRED,
    NotificationKind.CAPTURE_NODE_STORAGE_FAILURE, NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED,
    NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED, NotificationKind.CAPTURE_INGEST_UNAVAILABLE,
    NotificationKind.CAPTURE_NODE_HEARTBEAT_LOST,
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
ATTENTION_KINDS = frozenset({
    NotificationKind.RECORDING_DEVICE_NUMBERS_CHANGED,
    NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED, NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED,
})
# Kinds whose alert may be sent after the condition already ended: the text
# then says so (Issue #349, a held camera outage that recovered first).
RECOVERED_SUFFIX = " (already recovered)"
RECOVERED_KINDS = frozenset({
    NotificationKind.CAMERA_OFFLINE,
    # Issue #14: a node notice held by its hourly cap past the episode's end.
    NotificationKind.CAPTURE_NODE_STORAGE_FAILURE, NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED,
    NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED, NotificationKind.CAPTURE_NODE_HEARTBEAT_LOST,
})
# Issue #394: how many final outcomes `final_outcome` remembers. Far above
# what one process keeps referring to (one latest alert per camera source,
# at most four sources) and bounded whatever the delivery rate.
OUTCOME_MEMORY = 256


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
                 slack: SlackDelivery | None = None, *, queue_capacity: int = 16,
                 local_batch_sink: Callable[[tuple[NotificationEvent, ...]], None] | None = None,
                 stopping: Callable[[], bool] | None = None,
                 settle_overshoot_seconds: float = SETTLE_POLL_OVERSHOOT_SECONDS):
        if type(queue_capacity) is not int or not 1 <= queue_capacity <= 1024:
            raise ValueError("invalid notification capacity")
        if local_batch_sink is not None and not callable(local_batch_sink):
            raise ValueError("invalid notification batch sink")
        if stopping is not None and not callable(stopping):
            raise ValueError("invalid notification stop check")
        if (type(settle_overshoot_seconds) not in (int, float)
                or not 0 <= settle_overshoot_seconds <= 60):
            raise ValueError("invalid notification settle overshoot")
        # Issue #396: once ``stopping()`` is true a poll without a deadline
        # writes nothing and calls no callback (the one gate for every
        # deadline-less poll; it only takes the worker's finished results),
        # and a refused submission goes to the retry buffer instead of a
        # poll (`_unsubmitted`); the shutdown settles poll with their
        # deadline. ``settle_overshoot_seconds`` is how long after a
        # poll's deadline the lock waits of the write or callback in progress
        # may still run (`stop_budget.SETTLE_POLL_OVERSHOOT_SECONDS`).
        self._stopping = stopping or (lambda: False)
        self._settle_overshoot = float(settle_overshoot_seconds)
        self._local_sink = local_sink
        # Issue #385 (Owner decision 2026-11-08): writes several final
        # outcomes as one write (`persist_completed`); without it they are
        # written one by one.
        self._local_batch_sink = local_batch_sink
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
        # Issue #394: the final Slack outcome of recent deliveries by event
        # ID (bounded, oldest dropped first), so the camera offline monitor
        # can tell whether a source's latest alert reached Slack even while
        # its row could not be written yet.
        self._outcomes: OrderedDict[UUID, DeliveryResult] = OrderedDict()

    def _note_outcome(self, event_id: UUID, result: DeliveryResult) -> None:
        self._outcomes[event_id] = result
        self._outcomes.move_to_end(event_id)
        while len(self._outcomes) > OUTCOME_MEMORY:
            self._outcomes.popitem(last=False)

    def final_outcome(self, event_id: UUID) -> DeliveryResult | None:
        """The final Slack outcome of ``event_id`` known to this process (#394).

        ``sent`` / ``failed`` (or ``disabled``) of a delivery this process
        submitted and that finished, whether or not its row is written yet;
        ``None`` for one still in flight, never submitted here, or forgotten
        (beyond ``OUTCOME_MEMORY``). Value-free.
        """
        return self._outcomes.get(event_id)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def _collect(self) -> None:
        """Take the delivery worker's finished results (no I/O).

        Each outcome is noted once here (Issue #394, `final_outcome`), also
        by the result-only poll once the stop began (Issue #396), whether or
        not its row is written later.
        """
        for identifier, result in self._worker.results():
            self._pending[identifier][2] = result
            self._note_outcome(identifier, result)

    def _occupied(self) -> int:
        """How many submissions count against the queue capacity.

        Every delivery not yet persisted, as before; once the stop began
        (Issue #396, PR #400 review) only those still being sent. A poll
        without a deadline then writes nothing, so the finished ones would
        otherwise keep their slots until the settle and refuse the last
        confirmed criticals the shutdown dispatch submits (`can_accept`).
        The finished ones stay in `_pending` and are written by the settle or
        the stop's `persist_completed`.
        """
        if not self._stopping():
            return len(self._pending)
        self._collect()
        return sum(1 for _event, _callbacks, result in self._pending.values() if result is None)

    def holds_capacity(self, event_id: UUID) -> bool:
        """Whether ``event_id`` counts against the queue capacity (`_occupied`).

        Before the stop that is `in_flight`: a finished delivery whose outcome
        is not yet persisted keeps its place until a poll writes it. Once the
        stop began (Issue #396) only a delivery still being sent does.
        """
        self._check()
        entry = self._pending.get(event_id)
        if entry is None or not self._stopping():
            return entry is not None
        self._collect()
        return entry[2] is None

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
        return not self.closed and self._occupied() < self._capacity

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

    def _unsubmitted(self, event_id: UUID) -> None:
        """Issue #396 (PR #400 review): a submission refused once the stop began.

        A poll without a deadline writes nothing then, so the refused
        delivery would stay in `_pending` and in flight, and a caller asking
        `in_flight` would take it as submitted. It leaves `_pending` for the
        bounded local retry buffer instead (no I/O here): the settles and the
        stop's `persist_completed` write its `failed` row. Its callbacks are
        not called; the caller already got `failed` from `record()`. When the
        buffer is full it stays in `_pending`, written the same way.
        """
        entry = self._pending[event_id]
        if event_id not in self._unpersisted and len(self._unpersisted) >= self._capacity:
            return
        del self._pending[event_id]
        self._unpersisted[event_id] = replace(entry[0], delivery=DeliveryResult.FAILED)

    def _flush_unpersisted(self, past=lambda: False) -> None:
        for identifier, event in tuple(self._unpersisted.items()):
            if past():
                return
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
        elif self.closed or self._occupied() >= self._capacity:
            result = DeliveryResult.FAILED
            self.delivery_failed = True
            self._note_outcome(event.event_id, result)
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
            # A new delivery of this ID: an earlier refused attempt's outcome
            # no longer describes it (Issue #394).
            self._outcomes.pop(event.event_id, None)
            try:
                self._worker.submit(event.event_id, text)
            except Exception:
                self._pending[event.event_id][2] = DeliveryResult.FAILED
                self.delivery_failed = True
                # Issue #394: a refused submission is this delivery's outcome,
                # also when it moves to the retry buffer once the stop began.
                self._note_outcome(event.event_id, DeliveryResult.FAILED)
                if self._stopping():
                    self._unsubmitted(event.event_id)
                else:
                    self.poll()
                return DeliveryResult.FAILED
        return result

    def poll(self, deadline: float | None = None) -> tuple[NotificationEvent, ...]:
        """Persist completed results without waiting; failed persistence retries locally.

        Issue #385: with a ``deadline`` (``time.monotonic``) no further local
        write or completion callback starts once it passed; the rest stay
        pending, unchanged, for the next poll. Issue #396: every SQLite lock
        wait of the writes it makes, its own outcome writes and those of the
        completion callbacks (`app.storage.database.bounded_lock_waits`),
        ends by ``settle_overshoot_seconds`` after the deadline, so the poll
        ends then plus the I/O of the write in progress, however many locks
        a callback's transaction waits for. A write that cannot get its lock
        in time is refused like an exhausted busy timeout: an outcome write
        stays pending for the next poll (or the stop's `persist_completed`),
        a callback is retried by the next poll.

        Without a deadline, once ``stopping()`` is true (Issue #396), it
        writes nothing and calls no callback; it only takes the worker's
        finished results, so they no longer hold queue capacity. The
        shutdown settles own the polling then.
        """
        self._check()
        if deadline is None:
            if self._stopping():
                # No write, but the finished results are taken, so they no
                # longer hold queue capacity (`_occupied`).
                self._collect()
                return ()
            return self._poll(lambda: False)
        with bounded_lock_waits(deadline + self._settle_overshoot):
            return self._poll(lambda: time.monotonic() >= deadline)

    def _poll(self, past) -> tuple[NotificationEvent, ...]:
        self._flush_unpersisted(past)
        self._collect()
        completed = []
        for identifier, (event, callbacks, result) in tuple(self._pending.items()):
            if result is None:
                continue
            if past():
                break
            update = replace(event, delivery=result)
            if result == DeliveryResult.FAILED:
                self.delivery_failed = True
            if not self._local(update):
                continue
            # Every submitter of a coalesced delivery is told; a callback that
            # raised is retried on the next poll, the others are not repeated.
            # Past the deadline the callbacks not yet called are left for the
            # next poll the same way, without counting as a failure.
            failed = []
            deferred = []
            for index, callback in enumerate(callbacks):
                if past():
                    deferred = list(callbacks[index:])
                    break
                try:
                    callback(result)
                except Exception:
                    failed.append(callback)
            if deferred:
                if failed:
                    self.local_delivery_failed = True
                self._pending[identifier][1] = failed + deferred
                continue
            if failed:
                self.local_delivery_failed = True
                self._pending[identifier][1] = failed
                continue
            self.last_delivery = result
            completed.append(update)
            del self._pending[identifier]
        return tuple(completed)

    def persist_completed(self) -> int:
        """Write every final outcome not yet written, as one local write.

        Issue #385 (Owner decision 2026-11-08): the Main stop calls it once,
        just before `close()`. A settle ends at its deadline, so a delivery
        that finished after it (or while it ended unsettled, when the final
        storage sample has no wait left) would otherwise stay `pending` in
        `notification_events`, and the next start could send a reconciled
        kind a second time. With ``local_batch_sink`` the rows (the finished
        deliveries and the retained refused writes) go in one transaction,
        all of its lock waits bounded by one SQLite busy timeout
        (`stop_budget.LATE_OUTCOME_WRITE_SECONDS`). No completion callback is
        called: a callback can take several writes, and the outbox reconciles
        its unconfirmed claims from these rows at the next start. The daily
        summary's schedule row, which only its callback updates, then keeps
        `pending` (uncertain, as for any delivery not confirmed): nothing reads
        it and the next date replaces it (second PR #389 review). Returns how
        many rows were written; a refused write writes none, is counted in
        `local_delivery_failed` and raises nothing.
        """
        self._check()
        self._collect()
        finished = [(identifier, replace(event, delivery=result))
                    for identifier, (event, _callbacks, result) in self._pending.items()
                    if result is not None]
        retained = list(self._unpersisted.items())
        events = tuple(event for _identifier, event in retained) + tuple(
            update for _identifier, update in finished)
        if not events:
            return 0
        if any(update.delivery == DeliveryResult.FAILED for _identifier, update in finished):
            self.delivery_failed = True
        if self._local_batch_sink is None:
            # Without a batch sink (an embedder or a test; the Main
            # composition always passes one) the rows are written one by one,
            # through the same writes as `poll()`, so not as one write.
            before = len(self._unpersisted)
            self._flush_unpersisted()
            written = before - len(self._unpersisted)
            for _identifier, update in finished:
                if self._local(update):
                    self.last_delivery = update.delivery
                    written += 1
            return written
        try:
            self._local_batch_sink(events)
        except Exception:
            self.local_delivery_failed = True
            return 0
        for identifier, _event in retained:
            del self._unpersisted[identifier]
        if finished:
            self.last_delivery = finished[-1][1].delivery
        return len(events)

    def record(self, kind: NotificationKind, *, at: datetime,
               confirmed: bool = False, event_id: UUID | None = None,
               on_complete=None, recovered: bool = False) -> DeliveryResult:
        self._check()
        aware(at)
        if (not isinstance(kind, NotificationKind) or type(confirmed) is not bool
                or event_id is not None and not isinstance(event_id, UUID)
                or type(recovered) is not bool or recovered and kind not in RECOVERED_KINDS):
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
        # ``recovered`` changes only the fixed text, never the stored row.
        suffix = RECOVERED_SUFFIX if recovered else ""
        return self._enqueue(event, f"{prefix}: {kind.value}{suffix}", on_complete, retain=True)

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
