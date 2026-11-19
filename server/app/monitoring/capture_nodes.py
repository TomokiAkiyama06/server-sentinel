"""Owner notices for capture-node health and the ingest listener (Issue #14).

Owner decision 2026-11-12. The inputs are the capture ingest listener's state
word and the in-memory node health of its registry
(``app.cameras.remote_agent.node_health``), read through a provider the
composition root builds (``app.main``). ``drain`` runs on the monitoring
worker on every monitoring tick, like the camera offline monitor, and submits
through the same ``NotificationService`` (durable row, optional Slack).

Notices, by the reason words of a node's latest heartbeat (degraded only):

* ``storage_unavailable`` -> ``capture_node_storage_failure`` at the next
  tick (the Agent cannot write its ring buffer);
* ``storage_device_numbers_stale`` -> ``capture_node_device_numbers_changed``
  once it lasted ``NOTICE_AFTER_SECONDS`` (5 min; Issue #324, the Agent
  counterpart of Main's ``recording_device_numbers_changed``);
* any ``clock_*`` reason -> ``capture_node_clock_degraded`` after the same
  5 min;
* ``capture_unconfigured`` and ``other`` are never notified (the Agent
  reports ``capture_unconfigured`` until its capture adapter is wired).

Each episode (one node and one notice kind, from the first heartbeat that
showed the reason to the first heartbeat without it) notifies once; a
recovery is not notified. While a node is offline (no heartbeat within the
idle timeout) its episodes neither end nor become due, and only observed
time counts towards the 5 min: the episode's start moves forward by the time
it was not observed (heartbeat loss is below). A revoked node is forgotten by
the registry, and its episodes with it.

At most ``HOURLY_LIMIT`` (4) node notices per node per rolling hour. An
episode that reached its delay while observed is owed: the cap holds it
(also while the node is offline) and it is sent once the cap frees, saying
so if it already recovered. Per node and kind at most one owed episode that
already recovered is kept beside the current one; a further one replaces the
older (bounded, as the camera offline monitor's hold limit). After a Main
restart the hour is re-seeded from the node notices accepted in the last
hour (``restore_window``): a row names no node, but its event ID is matched
to a node by ``notice_id``, so a restart loop cannot exceed any node's cap
and one node's notices never delay another's.

Heartbeat loss (Issue #397, Owner decision 2026-11-12): every node whose
pairing credential is active (the provider's ``expected`` set, read from the
ledger) is watched, including one that has not connected since the Main
started. A node without a heartbeat (offline in the registry, or not in it
at all) for ``NOTICE_AFTER_SECONDS`` of observed time sends one
``capture_node_heartbeat_lost`` per episode, under the same per-node cap and
hold rules; the episode starts when the monitor first sees the node lost
(within one tick of the registry's idle timeout). A heartbeat ends it,
without a recovery notice. There is no exception for an intentional stop
yet: an Agent stopped for longer is notified once. While the listener is not
running, or the ledger could not be read (``expected`` is None), loss
episodes are paused: the listener notice covers the first, and the next
tick retries the second.

Credential contention (Issue #407, Owner decision 2026-11-16): the
registry marks a node ``contended`` once 3 of its sessions replaced a
still-live session of it (``superseded``) within 10 min, and keeps it so until
10 min after the latest such replacement (``node_health``). A contended node
sends one critical ``capture_node_credential_contention`` per episode at the
next tick, under the same per-node cap and hold rules (an owed one that
ended first says ``already recovered``); the episode ends, without a
recovery notice, once 10 min pass without a replacement that kept the count.
It counts whatever the node's heartbeat state, since replacements are
recorded as they happen. The notice says only that more than one connection
presents the node's credential (for example two Agents from a cloned SD
card or a restored backup), never which host or that either is malicious.

Credential expiry (Issue #426, Owner decision 2026-11-19): the provider's
optional fourth element maps every node whose pairing credential is active
to the expiry (``not_after``, UTC epoch seconds) of that current credential,
as the ledger records it (``pairing.active_credential_expiries_on``: set at
activation, moved on the first admission of a renewed certificate). A staged
renewal the Agent has not presented yet does not count: the certificate in
use still expires. With ``CREDENTIAL_WARNING_SECONDS`` (14 days) or less
left, the node sends one attention notice ``capture_credential_warning``;
with ``CREDENTIAL_CRITICAL_SECONDS`` (3 days) or less left, or once expired,
one critical ``capture_credential_critical`` (a node first seen inside 3 days
sends only the critical one, and an owed warning the cap still holds is
replaced by it). Once one of them was recorded and the expiry is again more
than 14 days ahead (a renewal promoted, or the node re-paired), one
``capture_credential_recovered`` follows; an owed notice that was never
recorded is dropped instead, without a recovery. These share the per-node
hourly cap above. A refused or unavailable renewal is never notified on its
own (the listener status and the log keep it). A node that is revoked, or
whose credential leaves the ledger's active set, drops its credential state
without a notice; an unreadable ledger (``None``) pauses the evaluation, and
an owed credential notice is not delivered on such a tick: the next readable
one rechecks it against the current credential first.

Each credential notice belongs to one credential: its event ID is derived
from the node and that credential's expiry (``credential_subject``) as well
as the kind and time, so the stored row binds it without naming either. A
warning or critical is for the current credential; a recovery is for the
credential the warning was for. A notice recorded for one credential never
suppresses a notice for another (a node revoked and paired again under the
same UUID starts afresh), and when the current credential changes while
still within 14 days the new one gets its own notices, without a recovery.

What was recorded survives a restart: ``restore_credential_notices`` is
given the newest stored credential notice rows (any age the notification
retention kept). A row applies to a node only if its event ID matches the
node and its *current* credential's expiry; the latest such row says what
was sent (a warning, a critical, or a recovery that closed it). Until it was
called the expiry is not evaluated, so a restart never repeats a notice
already sent for the current credential. A renewal is promoted by the
running Main (the ingest listener admits the renewed certificate), so its
recovery is owed in that process; one not yet recorded when the Main stops
(the tick after the promotion, or held by the cap) is not sent after the
restart, because the rows of the old credential no longer apply. The cap
re-seeding matches credential rows against the node's current and last
warned credential, so a row of an older credential within the hour is not
counted (at most the three notices of a credential replaced within it).

The listener: configured (state ``starting`` or ``unavailable``: material
unreadable, bind being retried) but not ``running`` for 5 min sends one
``capture_ingest_unavailable`` per episode. ``disabled`` (no deployment
section) and ``stopped`` (the stop) start none.

Only time up to the last drain that observed a condition counts towards its
delay (at most one tick, 60 s, of resolution).

Event IDs are deterministic (``notice_id``: the kind, the node and the UTC
time of the first attempt), and that time is kept for every retry. A
full or closed queue (``can_accept``) and an unrecorded result leave the
notice owed; a result kept for the local write retry (``retained``) counts as
recorded. Node health lives in memory, so a Main restart starts new episodes:
a node still degraded after a restart is notified again once (within the
restored cap). Notices are value-free: the kind word only, never a node UUID,
address or reason text.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
from typing import Callable
from uuid import UUID, uuid5

from app.notifications.service import DeliveryResult, NotificationKind, NotificationService


NOTICE_AFTER_SECONDS = 300.0
# Issue #426 (Owner decision 2026-11-19): time left on a node's current
# credential at which it is notified (inclusive).
CREDENTIAL_WARNING_SECONDS = 14 * 24 * 3600.0
CREDENTIAL_CRITICAL_SECONDS = 3 * 24 * 3600.0
_CREDENTIAL_WARNING = NotificationKind.CAPTURE_CREDENTIAL_WARNING
_CREDENTIAL_CRITICAL = NotificationKind.CAPTURE_CREDENTIAL_CRITICAL
_CREDENTIAL_RECOVERED = NotificationKind.CAPTURE_CREDENTIAL_RECOVERED
CREDENTIAL_NOTICE_KINDS = (_CREDENTIAL_WARNING, _CREDENTIAL_CRITICAL, _CREDENTIAL_RECOVERED)
# What a node's latest recorded credential notice leaves it at.
_CREDENTIAL_LEVEL = {_CREDENTIAL_WARNING: 1, _CREDENTIAL_CRITICAL: 2, _CREDENTIAL_RECOVERED: 0}
# The node notice kinds whose accepted rows re-seed the hourly cap.
NODE_NOTICE_KINDS = (
    NotificationKind.CAPTURE_NODE_STORAGE_FAILURE,
    NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED,
    NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED, NotificationKind.CAPTURE_NODE_HEARTBEAT_LOST,
    NotificationKind.CAPTURE_NODE_CREDENTIAL_CONTENTION,
) + CREDENTIAL_NOTICE_KINDS
# How many stored credential notice rows a restart reads back (newest first).
CREDENTIAL_HISTORY_ROWS = 256
_LOST = NotificationKind.CAPTURE_NODE_HEARTBEAT_LOST
_CONTENTION = NotificationKind.CAPTURE_NODE_CREDENTIAL_CONTENTION
HOURLY_LIMIT = 4
_HOUR = 3600.0
_NAMESPACE = UUID("7b0c55a4-4f3e-5d4b-9c55-2f1a8e5d0c14")
_LISTENER = "listener"
# (kind, delay, matches the reasons of a degraded heartbeat)
_NODE_NOTICES: tuple[tuple[NotificationKind, float, Callable[[tuple[str, ...]], bool]], ...] = (
    (NotificationKind.CAPTURE_NODE_STORAGE_FAILURE, 0.0,
     lambda reasons: "storage_unavailable" in reasons),
    (NotificationKind.CAPTURE_NODE_DEVICE_NUMBERS_CHANGED, NOTICE_AFTER_SECONDS,
     lambda reasons: "storage_device_numbers_stale" in reasons),
    (NotificationKind.CAPTURE_NODE_CLOCK_DEGRADED, NOTICE_AFTER_SECONDS,
     lambda reasons: any(reason.startswith("clock_") for reason in reasons)),
)
_LISTENER_PENDING = frozenset({"starting", "unavailable"})


@dataclass(frozen=True)
class CaptureNodeView:
    """One known node as the registry sees it (``CaptureNodeHealthRegistry.nodes``)."""

    node_id: UUID
    state: str
    reasons: tuple[str, ...]
    # Issue #407: replaced repeatedly within the window (`node_health`).
    contended: bool = False


@dataclass(frozen=True)
class CaptureHealthStatus:
    """Value-free counts for the runtime status and the daily summary."""

    online_nodes: int = 0
    degraded_nodes: int = 0
    offline_nodes: int = 0
    # Degraded for a reason that is notified (not `capture_unconfigured` or
    # `other` alone): what the daily summary counts as degraded.
    notable_degraded_nodes: int = 0
    # A configured listener that is not running yet or any more.
    listener_unavailable: bool = False
    # Owed node notices not recorded yet (cap, full queue, refused write).
    held_notices: int = 0
    # Issue #397 (PR #409 review): expected nodes without a heartbeat, and a
    # running listener whose ledger could not be read (the watch is paused).
    lost_nodes: int = 0
    loss_watch_unavailable: bool = False
    # Issue #410 item 1: the expected nodes were read, so the offline count
    # includes the expected nodes that never connected. Without it the
    # daily summary shows the agent counts as unavailable, not as a guess.
    nodes_counted: bool = False
    # Issue #407: known nodes whose sessions keep replacing each other.
    contended_nodes: int = 0
    # Issue #426: active nodes whose current credential has 14 days or less
    # left (expired ones included).
    expiring_credentials: int = 0


def notice_id(kind: NotificationKind, node: object, at: datetime) -> UUID:
    """The event ID of a node notice first attempted at ``at``.

    Derived from the row's own kind and UTC time (``NotificationEventStore``
    writes ``at`` as this text), so after a restart a row can be matched to a
    node the registry knows again without the row naming it.
    """
    return uuid5(_NAMESPACE, f"{kind.value}:{node}:{at.astimezone(timezone.utc).isoformat()}")


def credential_subject(node: UUID, not_after: float) -> str:
    """What a credential notice's ``notice_id`` is derived from (Issue #426).

    The node and the expiry of the credential the notice is for, so a stored
    row is bound to that credential without naming the node or the expiry.
    """
    return f"{node}@{round(not_after)}"


@dataclass
class _Episode:
    kind: NotificationKind
    delay: float
    started: float
    # The last drain that observed the condition; only time up to it counts.
    last_seen: float
    notified: bool = False
    recovered: bool = False
    # Observed with its reason on this drain (False while the node is
    # offline: its episode then neither ends nor becomes due).
    observed: bool = True
    # Reached its delay while observed: owed from then on.
    reached: bool = False
    # The first attempt's time and ID, kept for every retry of the same row.
    at: datetime | None = None
    event_id: UUID | None = None
    # Issue #426: what the event ID is derived from instead of the node (a
    # credential notice: `credential_subject`), and that credential's expiry.
    subject: str | None = None
    not_after: float | None = None

    def pause(self) -> None:
        self.observed = False

    def seen(self, now: float) -> None:
        """Observed with its condition on this drain."""
        if not self.observed:
            # Only observed time counts: the gap since the last observation
            # (offline, listener down, ledger unreadable) is left out.
            self.started += max(0.0, now - self.last_seen)
            self.observed = True
        self.last_seen = now
        if now - self.started >= self.delay:
            self.reached = True

    def due(self) -> bool:
        return not self.notified and (self.recovered or self.reached)


class CaptureNodeHealthMonitor:
    # ``provider()`` returns ``(state, nodes, expected)`` or, with the
    # credential expiry of Issue #426, ``(state, nodes, expected, expiries)``
    # (``Iterable[CaptureNodeView]``, ``Iterable[UUID] | None`` and
    # ``Mapping[UUID, float] | None``).
    def __init__(self, provider: Callable[[], tuple], *,
                 after_seconds: float = NOTICE_AFTER_SECONDS, hourly_limit: int = HOURLY_LIMIT):
        if (not callable(provider) or type(after_seconds) not in (int, float)
                or not math.isfinite(after_seconds) or after_seconds < 0
                or type(hourly_limit) is not int or hourly_limit <= 0):
            raise ValueError("invalid capture node health monitor")
        self._provider = provider
        self._after = float(after_seconds)
        self.hourly_limit = hourly_limit
        # Current episodes, and owed ones that already recovered.
        self._episodes: dict[tuple[object, NotificationKind], _Episode] = {}
        self._held: dict[tuple[object, NotificationKind], _Episode] = {}
        self._sent: dict[UUID, deque[float]] = {}
        # Restored node notice rows of an earlier process:
        # (accepted monotonic time, event ID, kind, UTC time).
        self._restored: list[tuple[float, UUID, NotificationKind, datetime]] = []
        # This process's own notices (bounded; only the restore reads it).
        self._own: deque[UUID] = deque(maxlen=256)
        # Issue #426: owed credential notices by (node, kind), and per node
        # the level of its latest recorded one (1 warning, 2 critical; a
        # recorded recovery removes it). The stored rows of an earlier
        # process, (event ID, kind, UTC at) newest first, seed a node the
        # first time it is evaluated; None until restored.
        self._credential: dict[tuple[UUID, NotificationKind], _Episode] = {}
        # node -> (level, expiry of the credential it was recorded for)
        self._credential_sent: dict[UUID, tuple[int, float]] = {}
        # node -> its current credential's expiry, as last read.
        self._credential_current: dict[UUID, float] = {}
        self._credential_history: tuple[tuple[UUID, NotificationKind, datetime], ...] | None = None
        self._credential_seeded: set[UUID] = set()
        self._expiring = 0
        # Whether this drain read the expiries and rechecked every owed
        # credential notice against the current credential (PR #427 review):
        # only then may one be delivered.
        self._credential_checked = False

    def restore_window(self, rows, *, monotonic: float) -> None:
        """Re-seed the hour from ``(event ID, kind, UTC at, age seconds)`` of accepted rows.

        A row counts for the node whose ``notice_id`` it matches (checked
        when that node is next capped), so one node's notices never delay
        another's. Rows of this process's own notices are not counted twice.
        """
        rows = tuple(rows)
        if (type(monotonic) not in (int, float) or any(
                type(row) is not tuple or len(row) != 4 or not isinstance(row[0], UUID)
                or not isinstance(row[1], NotificationKind) or not isinstance(row[2], datetime)
                or type(row[3]) not in (int, float) or not math.isfinite(row[3])
                for row in rows)):
            raise ValueError("invalid restored window")
        if not math.isfinite(monotonic):
            return
        self._restored = [(monotonic - age, event_id, kind, at)
                          for event_id, kind, at, age in rows
                          if 0 <= age < _HOUR and event_id not in self._own]

    def restore_credential_notices(self, rows) -> None:
        """Seed what was sent from stored ``(event ID, kind, UTC at)`` credential rows.

        Issue #426: given once (later calls change nothing), before the
        expiry is first evaluated. A row counts for the node whose
        ``notice_id`` it matches; for each node only its latest row matters.
        """
        rows = tuple(rows)
        if any(type(row) is not tuple or len(row) != 3 or not isinstance(row[0], UUID)
               or row[1] not in CREDENTIAL_NOTICE_KINDS or not isinstance(row[2], datetime)
               or row[2].tzinfo is None for row in rows):
            raise ValueError("invalid restored credential notices")
        if self._credential_history is not None:
            return
        self._credential_history = tuple(sorted(rows, key=lambda row: row[2], reverse=True))[
            :CREDENTIAL_HISTORY_ROWS]

    @property
    def credential_notices_restored(self) -> bool:
        return self._credential_history is not None

    def _credential_seed(self, node: UUID, not_after: float) -> int:
        """The level recorded for ``node``'s credential expiring at ``not_after``."""
        subject = credential_subject(node, not_after)
        for event_id, kind, at in self._credential_history or ():
            if notice_id(kind, subject, at) == event_id:
                return _CREDENTIAL_LEVEL[kind]
        return 0

    def _restored_for(self, node: UUID, now: float) -> int:
        # Credential notices are bound to a credential: matched against the
        # node's current one and the one it was last warned for.
        subjects = {credential_subject(node, value) for value in (
            self._credential_current.get(node),
            (self._credential_sent.get(node) or (None, None))[1]) if value is not None}
        count = 0
        for accepted, event_id, kind, at in self._restored:
            if now - accepted >= _HOUR:
                continue
            candidates = subjects if kind in CREDENTIAL_NOTICE_KINDS else (node,)
            count += any(notice_id(kind, subject, at) == event_id for subject in candidates)
        return count

    def drain(self, notifications: NotificationService, *, at: datetime,
              monotonic: float) -> CaptureHealthStatus:
        """Observe the provider once, then record every owed notice the cap allows."""
        provided = tuple(self._provider())
        if len(provided) not in (3, 4):
            raise ValueError("invalid capture node provider result")
        state, nodes, expected = provided[:3]
        expiries = provided[3] if len(provided) == 4 else None
        nodes = tuple(nodes)
        expected = None if expected is None else frozenset(expected)
        if expiries is not None:
            expiries = dict(expiries)
            if any(not isinstance(node, UUID) or type(value) not in (int, float)
                   or not math.isfinite(value) for node, value in expiries.items()):
                raise ValueError("invalid credential expiry")
        self._observe_listener(state, at, monotonic)
        # A node with a credential expiry keeps its hour (`_window`) as an
        # expected node does.
        self._observe_nodes(nodes, None if expected is None and expiries is None
                            else (expected or frozenset()) | frozenset(expiries or ()),
                            at, monotonic)
        self._observe_contention(nodes, at, monotonic)
        self._observe_loss(nodes, expected, state == "running", at, monotonic)
        self._observe_credentials(expiries, at, monotonic)
        self._restored = [row for row in self._restored if monotonic - row[0] < _HOUR]
        held = 0
        # Event IDs given on this drain: a held (recovered) and a current
        # episode of one node and kind first attempted together must not
        # share one (PR #408 review), so `at` moves by a microsecond.
        used: set[UUID] = set()
        owed = [(key, episode, self._held) for key, episode in self._held.items()]
        owed += [(key, episode, self._episodes) for key, episode in self._episodes.items()]
        if self._credential_checked:
            owed += [(key, episode, self._credential)
                     for key, episode in self._credential.items()]
        else:
            # Ledger unreadable (or not restored yet): still owed, but not
            # sent until a readable tick rechecked it (the credential may
            # have been renewed or revoked meanwhile).
            held += sum(episode.due() for episode in self._credential.values())
        for key, episode, table in sorted(owed, key=lambda item: item[1].started):
            if not episode.due():
                continue
            node = key[0]
            window = None if node == _LISTENER else self._window(node, monotonic)
            if window is not None and (len(window) + self._restored_for(node, monotonic)
                                       >= self.hourly_limit):
                held += 1
                continue
            if episode.at is None:
                subject = node if episode.subject is None else episode.subject
                attempt = at
                while notice_id(episode.kind, subject, attempt) in used:
                    attempt += timedelta(microseconds=1)
                episode.at = attempt
                episode.event_id = notice_id(episode.kind, subject, attempt)
            used.add(episode.event_id)
            if not notifications.can_accept(episode.event_id):
                # Queue full or closed: retried on the next drain.
                held += 1
                continue
            result = notifications.record(episode.kind, at=episode.at, confirmed=True,
                                          event_id=episode.event_id,
                                          recovered=episode.recovered)
            if (result is DeliveryResult.FAILED
                    and not notifications.retained(episode.event_id)):
                # Not recorded (local write refused, retry buffer full):
                # still owed, tried again on the next tick.
                held += 1
                continue
            episode.notified = True
            self._own.append(episode.event_id)
            if window is not None:
                window.append(monotonic)
            if table is self._held:
                del self._held[key]
            elif table is self._credential:
                # One-shot: what was recorded is kept per node instead.
                del self._credential[key]
                level = _CREDENTIAL_LEVEL[episode.kind]
                prior = self._credential_sent.get(node)
                if level:
                    if prior is not None and prior[1] == episode.not_after:
                        level = max(level, prior[0])
                    self._credential_sent[node] = (level, episode.not_after)
                elif prior is not None and prior[1] == episode.not_after:
                    self._credential_sent.pop(node, None)
        seen = {node.node_id for node in nodes}
        return CaptureHealthStatus(
            online_nodes=sum(node.state == "online" for node in nodes),
            degraded_nodes=sum(node.state == "degraded" for node in nodes),
            # An expected node not connected since the start is offline too.
            offline_nodes=sum(node.state == "offline" for node in nodes)
            + len((expected or frozenset()) - seen),
            notable_degraded_nodes=sum(
                node.state == "degraded"
                and any(matches(node.reasons) for _kind, _delay, matches in _NODE_NOTICES)
                for node in nodes),
            listener_unavailable=state in _LISTENER_PENDING,
            held_notices=held,
            lost_nodes=sum(1 for node in (expected or ())
                           if node not in seen or any(view.node_id == node
                                                      and view.state == "offline"
                                                      for view in nodes)),
            loss_watch_unavailable=expected is None and state == "running",
            nodes_counted=expected is not None,
            contended_nodes=sum(node.contended for node in nodes),
            expiring_credentials=self._expiring)

    # -- observation ---------------------------------------------------------

    def _window(self, node: UUID, now: float) -> deque[float]:
        window = self._sent.setdefault(node, deque())
        while window and now - window[0] >= _HOUR:
            window.popleft()
        return window

    def _begin(self, key, kind: NotificationKind, delay: float, at: datetime,
               now: float) -> None:
        current = self._episodes.get(key)
        if current is None:
            current = self._episodes[key] = _Episode(kind, delay, now, now)
        current.seen(now)

    def _recovered(self, key, now: float) -> None:
        """End the current episode of ``key``; keep it if it is owed."""
        episode = self._episodes.pop(key, None)
        if episode is None:
            return
        # Not observed on this drain: the condition ended since `last_seen`.
        if not episode.notified and episode.reached:
            # It reached its delay while observed (the cap held it, or it
            # was reached since the last drain): still sent once, saying it
            # already recovered. A newer owed one replaces an older.
            episode.recovered = True
            self._held[key] = episode

    def _observe_listener(self, state: str, at: datetime, now: float) -> None:
        key = (_LISTENER, NotificationKind.CAPTURE_INGEST_UNAVAILABLE)
        if state in _LISTENER_PENDING:
            self._begin(key, NotificationKind.CAPTURE_INGEST_UNAVAILABLE, self._after, at, now)
        else:
            # Running again, or no listener at all: no recovery notice, and a
            # notice not yet sent is not owed (the listener has no hourly cap).
            self._episodes.pop(key, None)

    def _observe_loss(self, nodes: tuple[CaptureNodeView, ...], expected, running: bool,
                      at: datetime, now: float) -> None:
        states = {node.node_id: node.state for node in nodes}
        if expected is None or not running:
            for key, episode in self._episodes.items():
                if key[1] is _LOST:
                    episode.pause()
            return
        for node in expected:
            key = (node, _LOST)
            if states.get(node, "offline") == "offline":
                self._begin(key, _LOST, self._after, at, now)
            else:
                self._recovered(key, now)
        for table in (self._episodes, self._held):
            for key in [key for key in table if key[1] is _LOST and key[0] not in expected]:
                # Revoked or superseded: no longer expected.
                del table[key]

    def _observe_contention(self, nodes: tuple[CaptureNodeView, ...], at: datetime,
                            now: float) -> None:
        # Not paused while offline: the registry keeps the replacement times
        # and ends the condition itself 10 min after the latest one.
        # Forgotten nodes lose their episodes in `_observe_nodes`.
        for node in nodes:
            key = (node.node_id, _CONTENTION)
            if node.contended:
                self._begin(key, _CONTENTION, 0.0, at, now)
            else:
                self._recovered(key, now)

    def _observe_nodes(self, nodes: tuple[CaptureNodeView, ...], expected, at: datetime,
                       now: float) -> None:
        known = set(expected or ())
        for node in nodes:
            known.add(node.node_id)
            if node.state == "offline":
                for kind, _delay, _matches in _NODE_NOTICES:
                    episode = self._episodes.get((node.node_id, kind))
                    if episode is not None:
                        episode.pause()
                continue
            reasons = node.reasons if node.state == "degraded" else ()
            for kind, delay, matches in _NODE_NOTICES:
                key = (node.node_id, kind)
                # Only the storage failure is immediate; the others wait
                # `after_seconds` (5 min by the Owner decision).
                delay = 0.0 if delay == 0 else self._after
                if matches(reasons):
                    self._begin(key, kind, delay, at, now)
                else:
                    self._recovered(key, now)
        for table in (self._episodes, self._held):
            for key in [key for key in table if key[0] != _LISTENER and key[0] not in known
                        and key[1] is not _LOST]:
                # Forgotten by the registry (revoked, or dropped for room).
                # Loss episodes follow the ledger (`_observe_loss`).
                del table[key]
        active = (known | {key[0] for key in self._episodes} | {key[0] for key in self._held}
                  | {key[0] for key in self._credential} | set(self._credential_sent))
        for node in [node for node in self._sent if node not in active]:
            del self._sent[node]

    def _observe_credentials(self, expiries: dict[UUID, float] | None, at: datetime,
                             now: float) -> None:
        """Issue #426: owe the notices a node's current credential expiry calls for."""
        self._credential_checked = False
        if expiries is None or self._credential_history is None:
            # Ledger unreadable, or what was sent not restored yet: paused,
            # owed notices kept and not delivered (`drain`).
            return
        self._credential_checked = True
        wall = at.timestamp()
        expiring = 0
        for node, not_after in expiries.items():
            self._credential_current[node] = not_after
            if node not in self._credential_seeded:
                # Only rows of this credential apply (a revoked one's do not).
                self._credential_seeded.add(node)
                level = self._credential_seed(node, not_after)
                if level:
                    self._credential_sent[node] = (level, not_after)
            remaining = not_after - wall
            level = (2 if remaining <= CREDENTIAL_CRITICAL_SECONDS
                     else 1 if remaining <= CREDENTIAL_WARNING_SECONDS else 0)
            for kind in (_CREDENTIAL_WARNING, _CREDENTIAL_CRITICAL):
                owed = self._credential.get((node, kind))
                if owed is not None and owed.not_after != not_after:
                    # Owed for a credential that is no longer current.
                    del self._credential[(node, kind)]
            sent_level, sent_for = self._credential_sent.get(node, (0, None))
            if level:
                expiring += 1
                # Inside the window again: a recovery not recorded yet is
                # no longer true.
                self._credential.pop((node, _CREDENTIAL_RECOVERED), None)
                if sent_level and sent_for != not_after:
                    # Replaced by another credential still within 14 days:
                    # the new one has its own notices, and no recovery.
                    del self._credential_sent[node]
                    sent_level = 0
                if level == 2 and sent_level < 2:
                    # The critical notice supersedes a warning still owed.
                    self._credential.pop((node, _CREDENTIAL_WARNING), None)
                    self._owe_credential(node, _CREDENTIAL_CRITICAL, not_after, now)
                elif level == 1 and sent_level < 1:
                    self._owe_credential(node, _CREDENTIAL_WARNING, not_after, now)
            else:
                # Renewed (or re-paired): a notice never recorded is not
                # sent late; one that was recorded is closed by one recovery,
                # bound to the credential it was for.
                self._credential.pop((node, _CREDENTIAL_WARNING), None)
                self._credential.pop((node, _CREDENTIAL_CRITICAL), None)
                if sent_level:
                    self._owe_credential(node, _CREDENTIAL_RECOVERED, sent_for, now)
        self._expiring = expiring
        watched = ({key[0] for key in self._credential} | set(self._credential_sent)
                   | self._credential_seeded | set(self._credential_current))
        for node in watched - set(expiries):
            # Revoked, superseded or no recorded expiry: not watched, and
            # nothing about it is notified (no recovery either). A credential
            # it is given later has another expiry, so its rows never apply.
            for kind in CREDENTIAL_NOTICE_KINDS:
                self._credential.pop((node, kind), None)
            self._credential_sent.pop(node, None)
            self._credential_current.pop(node, None)
            self._credential_seeded.discard(node)

    def _owe_credential(self, node: UUID, kind: NotificationKind, not_after: float,
                        now: float) -> None:
        key = (node, kind)
        if key not in self._credential:
            self._credential[key] = _Episode(
                kind, 0.0, now, now, reached=True,
                subject=credential_subject(node, not_after), not_after=not_after)
