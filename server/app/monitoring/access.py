"""Human-access faults as immediate, value-free Owner notifications (Issue #232 item 4).

Owner decision (2026-10-16): a failing ``HostnameReservationCheck`` (its
``ReservationFault`` events and the composition's ``state`` /
``check_failures``) and every ``CredentialFindingSink`` finding produce an
immediate Owner notification through the same ``NotificationService`` path as
hardware-integrity and recording-health failures, and mark the monitoring
health degraded. Human access already fails closed; this only makes the
fault visible.

``AccessFaultMonitor`` is the one object the composition root passes as the
check's ``sink=`` (``FaultSink``), as the ceremonies' ``findings=``
(``CredentialFindingSink``) and as ``MonitoringDependencies(access_faults=)``.
``create_app`` refuses a ``HumanAccess`` whose check or ceremonies report
elsewhere when a monitor is configured, and attaches the composition so its
recovery can be observed. ``emit`` and ``credential_finding`` run on the
check's worker thread or a request thread: they only latch fixed values under
a short lock and never block, raise or touch SQLite or the network.
``drain`` runs on the monitoring worker (the ``NotificationService`` owner
thread) on every monitoring tick.

Value-free: nothing is kept from a ``ReservationFault`` but its fixed
``Reason`` codes (to notice a new reason within an episode), and the
principal of a credential finding is discarded on arrival. A notification is
one of the fixed kinds ``human_access_fault``, ``human_access_recovered`` and
``credential_finding``: no hostname, address, route, identity, principal,
credential or reason leaves the process, and the local notification row holds
only kind/time/delivery state (PRIVACY.md "Slack"). The Owner reads details
from the audit log and the local fault status.

De-duplication: access notifies on the transition into a fault, on a
reason the current episode had not reported yet, and on recovery (a check
that passed while the composition serves), never on every failing check. A
fault that started and ended between two drains is still reported (the
emitted fault is latched). At most ``access_budget`` access notifications go
out per rolling hour; past that the latest state is sent once the budget
allows, and a fault episode that ended unreported is reported first. Both
rolling hours survive a restart (``restore_windows``, Issue #281 item 2).
Credential findings (Owner decision 2026-10-16, PR #271 提案4) notify
immediately, one notification each, up to ``finding_budget`` per rolling
hour; only the ones over that cap are batched into one notification sent
once the budget allows. The finding budget is separate from the access
budget, so neither can hold the other back. A finding has
no recovery to observe, so ``credential_finding_degraded`` stays set for
``finding_hold_seconds`` (default one day) after the latest one.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import math
import threading
from typing import TYPE_CHECKING
from uuid import UUID, uuid4, uuid5

from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult

if TYPE_CHECKING:
    from app.auth.human_surface import HumanAccess
    from app.auth.passkeys import CredentialFinding
    from app.auth.reservation import Reason, ReservationFault

# ``app.monitoring.runtime`` imports this module and must stay importable
# with the standard library alone (the installer and the lifecycle inventory
# run it without the application's dependencies), so the human-access types
# are imported where they are used, never at module import time.


# Fixed namespace for this monitor's event IDs; a per-process nonce keeps a
# restarted process from upserting over an earlier process's rows.
ACCESS_EVENT_NAMESPACE = UUID("8d3c2f1e-5b7a-5c49-9e10-4a6b2d8c7f35")
HOUR_SECONDS = 3600.0
DEFAULT_ACCESS_BUDGET = 4
DEFAULT_FINDING_BUDGET = 4
DEFAULT_FINDING_HOLD_SECONDS = 24 * HOUR_SECONDS
_MAX_COUNT = 2**31


class AccessHealth(str, Enum):
    HEALTHY = "healthy"
    FAULT = "fault"


@dataclass(frozen=True)
class AccessFaultStatus:
    """Bounded, value-free result of one ``drain``."""

    human_access_degraded: bool
    credential_finding_degraded: bool


def _positive(value, *, integer: bool = False) -> bool:
    if integer:
        return type(value) is int and 0 < value <= 1024
    return (type(value) in (int, float) and math.isfinite(value) and value > 0)


class AccessFaultMonitor:
    """``FaultSink`` + ``CredentialFindingSink`` feeding the monitoring runtime."""

    def __init__(self, *, access_budget: int = DEFAULT_ACCESS_BUDGET,
                 finding_budget: int = DEFAULT_FINDING_BUDGET,
                 finding_hold_seconds: float = DEFAULT_FINDING_HOLD_SECONDS):
        if (not _positive(access_budget, integer=True) or not _positive(finding_budget, integer=True)
                or not _positive(finding_hold_seconds)):
            raise ValueError("invalid access fault monitor setting")
        self.access_budget = access_budget
        self.finding_budget = finding_budget
        self.finding_hold = float(finding_hold_seconds)
        self._lock = threading.Lock()
        self._nonce = uuid4()
        self._sequence = 0
        self._access: "HumanAccess | None" = None
        # Latched by emit() (any thread) until the next drain.
        self._latched = False
        self._latched_reasons: "frozenset[Reason]" = frozenset()
        # Arrivals since the last drain; the principal is never kept.
        self._finding_arrivals = 0
        # Owner-thread state (drain only).
        self._current = AccessHealth.HEALTHY
        self._notified = AccessHealth.HEALTHY
        self._episode_reasons: "frozenset[Reason]" = frozenset()
        self._new_reasons = False
        # A restored episode's reasons are unknown: its first reasons become
        # the baseline rather than "new" (Codex PR #271).
        self._reasons_unknown = False
        self._unreported_fault = False
        self._sent: deque[float] = deque()
        # A notification the service refused (``FAILED``), by kind: retried
        # with the same time and event ID until accepted (Codex PR #271).
        self._attempts: dict[NotificationKind, tuple[datetime, UUID]] = {}
        self._findings_pending = 0
        # Monotonic times of finding notifications in the rolling hour.
        self._finding_sent: deque[float] = deque()
        # Set once a finding exceeded the cap: the pending ones then go out
        # as one batched notification when the budget allows.
        self._findings_batched = False
        # A finding the restart recovery found unnotified (counted at drain,
        # unless that drain already has a live arrival for it).
        self._recovered_finding = False
        # The cursor event ID of the last accepted finding notification: a
        # drain that runs after a finding's audit commit but before its sink
        # call names an earlier finding's notification after it, so the
        # later notification must not reuse that ID (PR #271 review).
        self._last_cursor: UUID | None = None
        self._finding_seen_at: float | None = None

    # -- composition -------------------------------------------------------

    def attach(self, access: "HumanAccess") -> None:
        """Observe ``access`` for recovery; one composition per monitor."""
        from app.auth.human_surface import HumanAccess

        if not isinstance(access, HumanAccess):
            raise ValueError("human access composition required")
        with self._lock:
            if self._access is not None and self._access is not access:
                raise ValueError("access fault monitor already attached")
            self._access = access

    @property
    def attached(self) -> "HumanAccess | None":
        return self._access

    # -- sinks (any thread; never block or raise on valid input) ------------

    def emit(self, fault: "ReservationFault") -> None:
        """``FaultSink``: latch one failing check; keeps only its reason codes."""
        from app.auth.reservation import Reason, ReservationFault

        if not isinstance(fault, ReservationFault):
            raise ValueError("reservation fault required")
        reasons = frozenset(reason for reason in fault.reasons if isinstance(reason, Reason))
        with self._lock:
            self._latched = True
            self._latched_reasons |= reasons

    def composition_failed(self) -> None:
        """Latch a human-access composition the launcher could not build.

        Codex PR #282: the launcher then serves with every human path closed
        and no composition attached, so nothing polls healthy again and the
        fault (``human_access_fault``, no reason) stays until a restart
        composes access. Keeps nothing but the latch.
        """
        with self._lock:
            self._latched = True

    def credential_finding(self, kind: "CredentialFinding", principal_id: UUID) -> None:
        """``CredentialFindingSink``: count one committed finding.

        ``principal_id`` is accepted for the protocol and discarded: the Owner
        notification names no person, and the audit record already exists.
        """
        from app.auth.passkeys import CredentialFinding

        if not isinstance(kind, CredentialFinding):
            raise ValueError("credential finding required")
        del principal_id
        with self._lock:
            self._finding_arrivals = min(self._finding_arrivals + 1, _MAX_COUNT)

    # -- owner thread --------------------------------------------------------

    def recover_finding(self, *, age_seconds: float, monotonic: float,
                        notify: bool = True) -> None:
        """Owner thread: restore the newest committed finding after a restart.

        Called once at startup by the monitoring runtime from the audit log
        (Codex PR #271). The degraded hold always runs from the finding's own
        time, also when it was already notified; ``notify`` (its notification
        was never delivered) makes the next ``drain`` notify it like a new
        arrival.
        """
        if (type(age_seconds) not in (int, float) or not math.isfinite(age_seconds)
                or type(monotonic) not in (int, float) or type(notify) is not bool):
            raise ValueError("invalid recovered finding")
        if notify:
            self._recovered_finding = True
        if math.isfinite(monotonic):
            seen = monotonic - max(0.0, float(age_seconds))
            if self._finding_seen_at is None or seen > self._finding_seen_at:
                self._finding_seen_at = seen

    def restore_fault_episode(self, *, delivered: bool = True, event_id: UUID | None = None,
                              at: datetime | None = None) -> None:
        """Owner thread: the last access notification before a restart was a fault.

        Called once at startup by the monitoring runtime from the durable
        notification rows (Codex PR #271), before any access notification of
        this process: the episode continues, so a fault that persists is not
        re-notified and a check that now passes sends the recovery notice.
        A fault whose delivery never finished (``delivered=False``, a
        ``pending`` row) is sent again first, reusing that row's ``event_id``
        and ``at`` so the retry updates it instead of adding a second fault.
        Ignored once this process has notified access state itself.
        """
        if (type(delivered) is not bool or (event_id is None) != (at is None)
                or event_id is not None and not isinstance(event_id, UUID)
                or at is not None and not isinstance(at, datetime)):
            raise ValueError("invalid restored episode")
        if self._sent or self._notified is not AccessHealth.HEALTHY:
            return
        self._current = AccessHealth.FAULT
        self._reasons_unknown = True
        if delivered:
            self._notified = AccessHealth.FAULT
            self._unreported_fault = False
        else:
            self._unreported_fault = True
            if event_id is not None:
                self._attempts[NotificationKind.HUMAN_ACCESS_FAULT] = (at, event_id)

    def restore_pending_recovery(self, *, event_id: UUID, at: datetime,
                                 fault_event_id: UUID | None = None,
                                 fault_at: datetime | None = None) -> None:
        """Owner thread: the last access notification was a recovery never delivered.

        Called once at startup by the monitoring runtime (Codex PR #271): the
        Owner's last delivered access message is the fault, so the episode is
        restored as notified and the recovery notice is sent again, under
        that ``pending`` row's own ``event_id`` and ``at``, once a check
        passes while serving. When the episode's fault row is still pending
        too (``fault_event_id`` / ``fault_at``), that fault is sent first,
        under its own row, so a recovery never arrives without its alert.
        Ignored once this process has notified access state itself.
        """
        if not isinstance(event_id, UUID) or not isinstance(at, datetime):
            raise ValueError("invalid restored recovery")
        if self._sent or self._notified is not AccessHealth.HEALTHY:
            return
        if fault_event_id is not None or fault_at is not None:
            self.restore_fault_episode(delivered=False, event_id=fault_event_id, at=fault_at)
        else:
            self.restore_fault_episode()
        self._attempts[NotificationKind.HUMAN_ACCESS_RECOVERED] = (at, event_id)

    def restore_windows(self, *, access_ages, finding_ages, monotonic: float) -> None:
        """Owner thread: re-seed both rolling hours after a restart (Issue #281 item 2).

        Called once at startup by the monitoring runtime with the ages, in
        seconds by the wall clock, of the previous processes' accepted
        (non-``pending``) notification rows, so a restart does not reset the
        hourly budgets. Converted to this process's monotonic clock as
        ``monotonic - age``, like ``recover_finding``. An age that is
        negative (a row stamped in the future, so the clock moved back) or a
        full hour or more is ignored, which at worst sends a notification
        early, as before this recovery; a clock moved back by less than a
        row's age keeps that row counted longer than its real age, but no
        restored row counts for more than an hour after the restart, so a
        held-back notification is delayed at most that hour, never lost. A
        window this process already used is left as it is (its own rows are
        in it).
        """
        if type(monotonic) not in (int, float):
            raise ValueError("invalid restored window")
        windows = ((self._sent, access_ages, self.access_budget),
                   (self._finding_sent, finding_ages, self.finding_budget))
        restored = []
        for _sent, ages, budget in windows:
            ages = tuple(ages)
            if (len(ages) > budget
                    or any(type(age) not in (int, float) or not math.isfinite(age) for age in ages)):
                raise ValueError("invalid restored window")
            restored.append(sorted(monotonic - age for age in ages if 0 <= age < HOUR_SECONDS))
        if not math.isfinite(monotonic):
            return
        for (sent, _ages, _budget), times in zip(windows, restored):
            if not sent:
                sent.extend(times)

    def _polled(self) -> AccessHealth | None:
        """Current composition health, or ``None`` while indeterminate.

        A failed or raising check is a fault; healthy only when this lifespan
        serves on an open verdict. Starting, stopped and an in-progress check
        of a previously open verdict decide nothing.
        """
        access = self._access
        if access is None:
            return None
        from app.auth.human_surface import HumanAccessState

        state = access.state
        verdict = access.reservation.verdict
        if (state in (HumanAccessState.CHECK_FAILING, HumanAccessState.FAILED)
                or access.check_failures > 0 or (not verdict.open and verdict.reasons)):
            return AccessHealth.FAULT
        if state is HumanAccessState.SERVING and verdict.open:
            return AccessHealth.HEALTHY
        return None

    def _event_id(self, kind: NotificationKind) -> UUID:
        self._sequence += 1
        return uuid5(ACCESS_EVENT_NAMESPACE, f"access:{self._nonce}:{self._sequence}:{kind.value}")

    def _budget_available(self, now: float) -> bool:
        return self._window_open(self._sent, self.access_budget, now)

    @staticmethod
    def _window_open(sent: deque, budget: int, now: float) -> bool:
        if not math.isfinite(now):
            return True
        while sent and not (sent[0] <= now < sent[0] + HOUR_SECONDS):
            # Expired, or a backwards clock: never postpone indefinitely.
            sent.popleft()
        return len(sent) < budget

    def _notify(self, notifications: NotificationService, kind: NotificationKind,
                at: datetime, event_id: UUID | None = None) -> bool:
        """Hand one notification to the service; ``True`` once it accepted it.

        ``FAILED`` means the service kept nothing (its queue was full or
        closed, or a refused local write found its retry buffer full): the
        transition stays pending and the next drain retries the same time
        and event ID, so a retry upserts one row instead of adding rows. Any
        other result is final: a refused local write is retained and retried
        by the service itself, and a failed network delivery stays visible
        (``delivery_failed``) without an automatic resend.
        """
        attempt = self._attempts.get(kind)
        if attempt is None or (event_id is not None and event_id != attempt[1]):
            attempt = (at, event_id or self._event_id(kind))
        result = notifications.record(kind, at=attempt[0], event_id=attempt[1])
        if result == DeliveryResult.FAILED:
            self._attempts[kind] = attempt
            return False
        self._attempts.pop(kind, None)
        return True

    def drain(self, notifications: NotificationService, *, at: datetime,
              monotonic: float, finding_event_id=None) -> AccessFaultStatus:
        """Apply latched events and the polled state; notify transitions.

        ``finding_event_id()``, when given, names a ``credential_finding``
        notification after the newest finding audit record it covers, the
        durable cursor the runtime's restart recovery compares (Codex PR
        #271); a failure or ``None`` falls back to a per-process ID.
        """
        with self._lock:
            latched, reasons = self._latched, self._latched_reasons
            self._latched, self._latched_reasons = False, frozenset()
            arrivals, self._finding_arrivals = self._finding_arrivals, 0
        # Before any notification: a raising ``record`` must not lose the
        # arrivals already taken out of the latch (PR #271 review).
        if arrivals:
            self._findings_pending = min(self._findings_pending + arrivals, _MAX_COUNT)
            if math.isfinite(monotonic):
                self._finding_seen_at = monotonic
        elif self._recovered_finding:
            # The newest audited finding, unnotified before a restart; a live
            # arrival in the same drain is most likely that same finding.
            self._findings_pending = min(self._findings_pending + 1, _MAX_COUNT)
        self._recovered_finding = False
        polled = self._polled()
        if latched or polled is AccessHealth.FAULT:
            if self._current is not AccessHealth.FAULT:
                self._episode_reasons = frozenset()
                self._new_reasons = False
            elif self._reasons_unknown:
                pass
            elif reasons - self._episode_reasons:
                self._new_reasons = True
            if reasons:
                self._reasons_unknown = False
            self._episode_reasons |= reasons
            self._current = AccessHealth.FAULT
            if self._notified is not AccessHealth.FAULT:
                self._unreported_fault = True
        elif polled is AccessHealth.HEALTHY:
            self._current = AccessHealth.HEALTHY
        self._access_notifications(notifications, at, monotonic)
        self._finding_notifications(notifications, at, monotonic, finding_event_id)
        return AccessFaultStatus(
            human_access_degraded=self._current is AccessHealth.FAULT,
            credential_finding_degraded=self._finding_degraded(monotonic),
        )

    def _access_notifications(self, notifications, at, now) -> None:
        if self._unreported_fault and self._notified is not AccessHealth.FAULT:
            # Into a fault, also one that already ended unreported.
            if (self._budget_available(now)
                    and self._notify(notifications, NotificationKind.HUMAN_ACCESS_FAULT, at)):
                self._record_sent(now)
                self._notified = AccessHealth.FAULT
                self._unreported_fault = False
                self._new_reasons = False
            return
        if self._current is AccessHealth.FAULT and self._new_reasons:
            if (self._budget_available(now)
                    and self._notify(notifications, NotificationKind.HUMAN_ACCESS_FAULT, at)):
                self._record_sent(now)
                self._new_reasons = False
            return
        if self._current is AccessHealth.HEALTHY and self._notified is AccessHealth.FAULT:
            if (self._budget_available(now)
                    and self._notify(notifications, NotificationKind.HUMAN_ACCESS_RECOVERED, at)):
                self._record_sent(now)
                self._notified = AccessHealth.HEALTHY

    def _record_sent(self, now: float) -> None:
        if math.isfinite(now):
            self._sent.append(now)

    def _finding_notifications(self, notifications, at, now, finding_event_id=None) -> None:
        """One immediate notification per finding up to the hourly cap.

        Past the cap the pending findings are batched into one notification,
        sent as soon as the rolling hour allows. The last notification of a
        drain, which covers the newest finding, is named by
        ``finding_event_id()`` (the restart recovery's durable cursor); the
        others get per-process IDs, so no two sends share one event.
        """
        while self._findings_pending:
            if not self._window_open(self._finding_sent, self.finding_budget, now):
                self._findings_batched = True
                return
            batch = self._findings_batched
            newest = batch or self._findings_pending == 1
            event_id = None
            if newest and finding_event_id is not None:
                try:
                    event_id = finding_event_id()
                except Exception:
                    event_id = None
            if not isinstance(event_id, UUID) or event_id == self._last_cursor:
                event_id = None
            if not self._notify(notifications, NotificationKind.CREDENTIAL_FINDING, at, event_id):
                return
            if event_id is not None:
                self._last_cursor = event_id
            if math.isfinite(now):
                self._finding_sent.append(now)
            if batch:
                self._findings_pending = 0
                self._findings_batched = False
            else:
                self._findings_pending -= 1

    def _finding_degraded(self, now: float) -> bool:
        seen = self._finding_seen_at
        if self._findings_pending:
            return True
        if seen is None:
            return False
        # A backwards or invalid clock keeps the flag rather than clearing it.
        return not math.isfinite(now) or now < seen or now - seen < self.finding_hold
