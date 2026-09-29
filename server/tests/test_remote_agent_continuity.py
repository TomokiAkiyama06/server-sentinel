"""Synthetic coverage for transport-neutral Agent session/continuity tracking.

These tests use in-process mocks only.  They do not claim any real LAN, TLS,
camera, or transport-candidate behavior; see MANUAL_TEST.md section G.
"""

import threading
import unittest
from uuid import UUID

from app.cameras.remote_agent.continuity import (
    AgentSession, ContinuityLimits, ContinuityTracker, DeliveryOutcome, GapReason,
    MediaUnitHeader, SourceFlow,
)
from app.cameras.remote_agent.ingest import (
    AgentAction, AgentIngestQueue, AgentMessage, DenyIngestAuthorizer, IngestLimits,
    IngestOutcome,
)

NODES = tuple(UUID(int=n) for n in range(1, 6))
SOURCES = tuple(UUID(int=n) for n in range(11, 16))
NODE, OTHER_NODE = NODES[0], NODES[1]
SOURCE, OTHER_SOURCE = SOURCES[0], SOURCES[1]


class Authorizer:
    def __init__(self, pairs=((NODE, SOURCE),)):
        self.pairs = set(pairs)
        self.revoked = set()

    def require_node(self, node_id):
        if node_id in self.revoked or not any(node_id == n for n, _ in self.pairs):
            raise PermissionError

    def require_source(self, node_id, source_id):
        if (node_id, source_id) not in self.pairs:
            raise PermissionError


class RevokeDuringCheckAuthorizer(Authorizer):
    """Revokes between the tracker's own check and the queue's recheck."""

    def __init__(self, *, revoke_node):
        super().__init__()
        self.revoke_node = revoke_node
        self.armed = False

    def require_source(self, node_id, source_id):
        super().require_source(node_id, source_id)
        if self.armed:
            self.armed = False
            if self.revoke_node:
                self.revoked.add(node_id)
            else:
                self.pairs.discard((node_id, source_id))


class SignallingAuthorizer(Authorizer):
    """Signals every authorization call so a test can revoke right after it."""

    def __init__(self, pairs=((NODE, SOURCE),)):
        super().__init__(pairs)
        self.checked = threading.Event()

    def require_node(self, node_id):
        self.checked.set()
        super().require_node(node_id)


def revoke_while_waiting(lock, authorizer, call, revoke):
    """Run ``call`` while ``lock`` is held and revoke before releasing it.

    A check made before waiting for the lock signals ``checked`` and is then
    applied after the revocation; a check made under the lock cannot signal
    until the lock is released and therefore observes the revocation.
    """
    result = {}

    def run():
        try:
            result["value"] = call()
        except PermissionError as error:
            result["value"] = error

    authorizer.checked.clear()
    with lock:
        thread = threading.Thread(target=run)
        thread.start()
        authorizer.checked.wait(0.2)
        revoke()
    thread.join(5)
    if thread.is_alive():
        raise AssertionError("call did not finish")
    return result["value"]


class GatedAuthorizer(Authorizer):
    """Pauses once, after a passing node check, until the test releases it."""

    def __init__(self, pairs=((NODE, SOURCE),)):
        super().__init__(pairs)
        self.armed = False
        self.passed = threading.Event()
        self.release = threading.Event()

    def require_node(self, node_id):
        super().require_node(node_id)
        if self.armed:
            self.armed = False
            self.passed.set()
            if not self.release.wait(5):
                raise AssertionError("gate was never released")


def start(target):
    result = {}

    def run():
        try:
            result["value"] = target()
        except PermissionError as error:
            result["value"] = error

    thread = threading.Thread(target=run)
    thread.start()
    return thread, result


def revoke_in_fence(fence, authorizer, *, committed, hold=None, node=NODE):
    def commit():
        with fence(revoked_node=node) as change:
            authorizer.revoked.add(node)
            committed.set()
            if hold is not None and not hold.wait(5):
                raise AssertionError("fence was never released")
        return change
    return commit


class TransientRefusalQueue(AgentIngestQueue):
    refusing = False

    def submit(self, message):
        if self.refusing:
            return self._admission(IngestOutcome.REJECTED, "transient_refusal")
        return super().submit(message)


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


def build(*, authorizer=None, queued=4, message_bytes=8, sources=4, pending=4,
          stale=100, rate=1000, nodes=64):
    authorizer = authorizer or Authorizer()
    clock = Clock()
    ingest = AgentIngestQueue(IngestLimits(message_bytes, queued, queued * message_bytes,
                                           rate, 10 ** 12), authorizer, clock_ns=clock)
    tracker = ContinuityTracker(ContinuityLimits(sources, pending, stale, nodes), authorizer,
                                ingest, clock_ns=clock)
    return tracker, ingest, clock, authorizer


def unit(sequence, *, source=SOURCE, epoch=1, at=None):
    return MediaUnitHeader(source, epoch, sequence, sequence * 10 if at is None else at)


def flow(tracker, source=SOURCE):
    return next(item for item in tracker.snapshot() if item.source_id == source)


class ContinuityTrackerTests(unittest.TestCase):
    def test_deny_by_default_and_unauthenticated_node_gets_no_session(self):
        denied, _, _, _ = build(authorizer=DenyIngestAuthorizer())
        with self.assertRaises(PermissionError):
            denied.open_session(NODE)
        tracker, ingest, _, _ = build()
        with self.assertRaises(PermissionError):
            tracker.open_session(OTHER_NODE)
        forged = AgentSession(NODE, 1)
        self.assertEqual((DeliveryOutcome.REJECTED, "stale_session"),
                         (tracker.receive(forged, unit(0), b"v").outcome,
                          tracker.receive(forged, unit(0), b"v").reason))
        self.assertEqual(0, ingest.snapshot().queued_messages)

    def test_node_cannot_deliver_another_nodes_source(self):
        authorizer = Authorizer({(NODE, SOURCE), (OTHER_NODE, OTHER_SOURCE)})
        tracker, ingest, _, _ = build(authorizer=authorizer)
        session = tracker.open_session(NODE)
        result = tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v")
        self.assertEqual((DeliveryOutcome.REJECTED, "unauthorized"),
                         (result.outcome, result.reason))
        self.assertEqual(0, ingest.snapshot().queued_messages)
        # Even if an authorizer were misconfigured, a source stays bound to the
        # node that first delivered it.
        authorizer.pairs.add((OTHER_NODE, SOURCE))
        tracker.receive(session, unit(0), b"v")
        other = tracker.open_session(OTHER_NODE)
        self.assertEqual("source_identity_mismatch",
                         tracker.receive(other, unit(1), b"v").reason)

    def test_in_order_units_are_healthy_without_gaps(self):
        tracker, ingest, _, _ = build()
        session = tracker.open_session(NODE)
        for sequence in range(3):
            self.assertEqual(DeliveryOutcome.ACCEPTED,
                             tracker.receive(session, unit(sequence), b"v").outcome)
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        self.assertEqual((), tracker.drain_gaps(10))
        self.assertEqual([0, 1, 2], [m.sequence for m in ingest.drain(10)])

    def test_retry_of_committed_unit_is_idempotent_duplicate(self):
        tracker, ingest, _, _ = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        tracker.receive(session, unit(1), b"v")
        for retry in (0, 1):
            result = tracker.receive(session, unit(retry), b"v")
            self.assertEqual((DeliveryOutcome.DUPLICATE, "already_committed"),
                             (result.outcome, result.reason))
        self.assertEqual(2, ingest.snapshot().queued_messages)

    def test_sequence_skip_reports_exact_missing_units_and_degrades(self):
        tracker, _, _, _ = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        result = tracker.receive(session, unit(4), b"v")
        self.assertEqual(DeliveryOutcome.ACCEPTED, result.outcome)
        (gap,) = result.gaps
        self.assertEqual((GapReason.SEQUENCE_SKIP, 0, 4, 3),
                         (gap.reason, gap.after_sequence, gap.before_sequence,
                          gap.missing_units))
        self.assertEqual(SourceFlow.DEGRADED, flow(tracker).flow)
        self.assertEqual((gap,), tracker.drain_gaps(10))
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)

    def test_first_unit_after_zero_is_reported_as_leading_loss(self):
        tracker, _, _, _ = build()
        session = tracker.open_session(NODE)
        (gap,) = tracker.receive(session, unit(5), b"v").gaps
        self.assertEqual((None, 5, 5), (gap.after_sequence, gap.before_sequence,
                                        gap.missing_units))

    def test_lossless_reconnect_reports_no_gap_and_lossy_reconnect_is_exact(self):
        tracker, _, clock, _ = build()
        first = tracker.open_session(NODE)
        tracker.receive(first, unit(0), b"v")
        tracker.close_session(first)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        clock.now = 5
        second = tracker.open_session(NODE)
        self.assertGreater(second.generation, first.generation)
        self.assertEqual((), tracker.receive(second, unit(1), b"v").gaps)
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        tracker.close_session(second)
        third = tracker.open_session(NODE)
        (gap,) = tracker.receive(third, unit(7), b"v").gaps
        self.assertEqual((GapReason.SEQUENCE_SKIP, 1, 7, 5),
                         (gap.reason, gap.after_sequence, gap.before_sequence,
                          gap.missing_units))

    def test_reconnected_node_keeps_each_source_interrupted_until_it_delivers(self):
        tracker, _, clock, _ = build(
            stale=100, authorizer=Authorizer(((NODE, SOURCE), (NODE, OTHER_SOURCE))))
        first = tracker.open_session(NODE)
        tracker.receive(first, unit(0), b"v")
        tracker.receive(first, unit(0, source=OTHER_SOURCE), b"v")
        tracker.close_session(first)
        # Reconnect well within ``stale_after_ns``: node connectivity alone
        # must not clear either camera's known interruption.
        clock.now = 5
        second = tracker.open_session(NODE)
        self.assertTrue(tracker.heartbeat(second))
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker, OTHER_SOURCE).flow)
        # Only the camera that delivers on the new session recovers.
        tracker.receive(second, unit(1), b"v")
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker, OTHER_SOURCE).flow)

    def test_superseding_session_does_not_mark_undelivered_source_receiving(self):
        tracker, ingest, clock, _ = build(stale=100, queued=1)
        old = tracker.open_session(NODE)
        tracker.receive(old, unit(0), b"v")
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        # A superseding session (no close) before staleness keeps the flow
        # interrupted until media arrives on it; pressure on the new session
        # counts as delivery activity and reports ``degraded``.
        clock.now = 5
        new = tracker.open_session(NODE)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        self.assertEqual(DeliveryOutcome.BACKPRESSURED,
                         tracker.receive(new, unit(1), b"v").outcome)
        self.assertEqual(SourceFlow.DEGRADED, flow(tracker).flow)
        ingest.drain(1)
        tracker.receive(new, unit(1), b"v")
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)

    def test_superseded_session_cannot_deliver_or_close_newer_session(self):
        tracker, _, _, _ = build()
        old = tracker.open_session(NODE)
        new = tracker.open_session(NODE)
        self.assertEqual("stale_session", tracker.receive(old, unit(0), b"v").reason)
        self.assertFalse(tracker.heartbeat(old))
        tracker.close_session(old)
        self.assertTrue(tracker.heartbeat(new))
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(new, unit(0), b"v").outcome)

    def test_capture_restart_is_unknown_loss_and_stale_epoch_is_rejected(self):
        tracker, _, _, _ = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(9, epoch=2), b"v")
        (gap,) = tracker.receive(session, unit(0, epoch=3, at=0), b"v").gaps
        self.assertEqual((GapReason.CAPTURE_RESTART, None), (gap.reason, gap.missing_units))
        result = tracker.receive(session, unit(10, epoch=2), b"v")
        self.assertEqual((DeliveryOutcome.REJECTED, "stale_capture_epoch"),
                         (result.outcome, result.reason))

    def test_capture_clock_regression_is_reported_not_hidden(self):
        tracker, _, _, _ = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0, at=100), b"v")
        result = tracker.receive(session, unit(1, at=50), b"v")
        self.assertEqual(DeliveryOutcome.ACCEPTED, result.outcome)
        self.assertEqual([GapReason.CAPTURE_CLOCK_REGRESSION], [g.reason for g in result.gaps])
        self.assertEqual(SourceFlow.DEGRADED, flow(tracker).flow)

    def test_slow_consumer_backpressure_is_bounded_and_retry_does_not_advance(self):
        tracker, ingest, _, _ = build(queued=2)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        tracker.receive(session, unit(1), b"v")
        for _ in range(50):
            result = tracker.receive(session, unit(2), b"v")
            self.assertEqual((DeliveryOutcome.BACKPRESSURED, "queue_limit"),
                             (result.outcome, result.reason))
        self.assertEqual(2, ingest.snapshot().queued_messages)
        self.assertEqual((SourceFlow.DEGRADED, True, 1),
                         (flow(tracker).flow, flow(tracker).backpressured,
                          flow(tracker).last_sequence))
        ingest.drain(1)
        result = tracker.receive(session, unit(2), b"v")
        self.assertEqual((DeliveryOutcome.ACCEPTED, ()), (result.outcome, result.gaps))
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)

    def test_queued_unit_preserves_full_continuity_envelope(self):
        tracker, ingest, _, _ = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0, epoch=1, at=70), b"a")
        tracker.receive(session, unit(0, epoch=2, at=5), b"b")
        queued = ingest.drain(10)
        self.assertEqual([(1, 0, 70, b"a"), (2, 0, 5, b"b")],
                         [(m.capture_epoch, m.sequence, m.capture_time_ns, m.payload)
                          for m in queued])

    def test_first_unit_pressure_is_visible_before_any_commit(self):
        authorizer = Authorizer({(NODE, SOURCE), (NODE, OTHER_SOURCE)})
        tracker, ingest, _, _ = build(authorizer=authorizer, queued=1)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        result = tracker.receive(session, unit(3, source=OTHER_SOURCE), b"v")
        self.assertEqual(DeliveryOutcome.BACKPRESSURED, result.outcome)
        pressured = flow(tracker, OTHER_SOURCE)
        self.assertEqual((SourceFlow.DEGRADED, True, None, 0),
                         (pressured.flow, pressured.backpressured,
                          pressured.last_sequence, pressured.pending_gaps))
        ingest.drain(1)
        result = tracker.receive(session, unit(3, source=OTHER_SOURCE), b"v")
        # Once admitted, the first unit is treated as the start of the flow:
        # leading loss is reported, not a capture restart.
        self.assertEqual(DeliveryOutcome.ACCEPTED, result.outcome)
        self.assertEqual([(GapReason.SEQUENCE_SKIP, 3)],
                         [(g.reason, g.missing_units) for g in result.gaps])
        self.assertEqual((3, False), (flow(tracker, OTHER_SOURCE).last_sequence,
                                      flow(tracker, OTHER_SOURCE).backpressured))

    def test_first_unit_rate_limit_and_transient_refusal_are_visible(self):
        authorizer = Authorizer({(NODE, SOURCE), (NODE, OTHER_SOURCE)})
        tracker, _, clock, _ = build(authorizer=authorizer, rate=1)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        self.assertEqual(DeliveryOutcome.RATE_LIMITED,
                         tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v").outcome)
        self.assertEqual((SourceFlow.DEGRADED, None),
                         (flow(tracker, OTHER_SOURCE).flow,
                          flow(tracker, OTHER_SOURCE).last_sequence))
        tracker, _, clock, _ = build(authorizer=authorizer)
        session = tracker.open_session(NODE)
        clock.now = 50
        tracker.receive(session, unit(0), b"v")
        clock.now = 40
        result = tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v")
        self.assertEqual((DeliveryOutcome.REJECTED, "clock_regression"),
                         (result.outcome, result.reason))
        clock.now = 55
        self.assertEqual((SourceFlow.DEGRADED, None),
                         (flow(tracker, OTHER_SOURCE).flow,
                          flow(tracker, OTHER_SOURCE).last_sequence))
        clock.now = 60
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v").outcome)
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker, OTHER_SOURCE).flow)

    def _uncommitted_first_unit(self, kind):
        """Leave OTHER_SOURCE seen (epoch 2, sequence 0) but never committed."""
        authorizer = Authorizer({(NODE, SOURCE), (NODE, OTHER_SOURCE)})
        clock = Clock()
        ingest = TransientRefusalQueue(IngestLimits(8, 1, 8, 1000, 10 ** 12),
                                       authorizer, clock_ns=clock)
        tracker = ContinuityTracker(ContinuityLimits(4, 4, 100), authorizer, ingest,
                                    clock_ns=clock)
        session = tracker.open_session(NODE)
        if kind == "backpressure":
            tracker.receive(session, unit(0), b"v")
            expected = DeliveryOutcome.BACKPRESSURED
        else:
            ingest.refusing = True
            expected = DeliveryOutcome.REJECTED
        self.assertEqual(expected, tracker.receive(
            session, unit(0, source=OTHER_SOURCE, epoch=2), b"v").outcome)
        self.assertEqual((SourceFlow.DEGRADED, None, 2),
                         (flow(tracker, OTHER_SOURCE).flow,
                          flow(tracker, OTHER_SOURCE).last_sequence,
                          flow(tracker, OTHER_SOURCE).capture_epoch))
        ingest.drain(10)
        ingest.refusing = False
        return tracker, ingest, session

    def test_restart_before_first_commit_reports_capture_restart(self):
        for kind in ("backpressure", "transient_refusal"):
            with self.subTest(kind=kind):
                tracker, ingest, session = self._uncommitted_first_unit(kind)
                # The capture process restarted before the unit was retried:
                # the uncommitted epoch-2 unit is known loss, not a new flow.
                result = tracker.receive(
                    session, unit(0, source=OTHER_SOURCE, epoch=3), b"n")
                self.assertEqual(DeliveryOutcome.ACCEPTED, result.outcome)
                self.assertEqual([(GapReason.CAPTURE_RESTART, 3, None, 0, None)],
                                 [(g.reason, g.capture_epoch, g.after_sequence,
                                   g.before_sequence, g.missing_units)
                                  for g in result.gaps])
                state = flow(tracker, OTHER_SOURCE)
                self.assertEqual((SourceFlow.DEGRADED, 3, 0, 1, False),
                                 (state.flow, state.capture_epoch, state.last_sequence,
                                  state.pending_gaps, state.backpressured))

    def test_older_epoch_after_uncommitted_first_unit_is_stale(self):
        tracker, ingest, session = self._uncommitted_first_unit("backpressure")
        result = tracker.receive(session, unit(0, source=OTHER_SOURCE, epoch=1), b"o")
        self.assertEqual((DeliveryOutcome.REJECTED, "stale_capture_epoch"),
                         (result.outcome, result.reason))
        self.assertEqual(0, ingest.snapshot().queued_messages)
        self.assertEqual((SourceFlow.DEGRADED, None, 2),
                         (flow(tracker, OTHER_SOURCE).flow,
                          flow(tracker, OTHER_SOURCE).last_sequence,
                          flow(tracker, OTHER_SOURCE).capture_epoch))

    def test_same_epoch_after_uncommitted_first_unit_is_not_a_restart(self):
        tracker, _, session = self._uncommitted_first_unit("backpressure")
        result = tracker.receive(session, unit(2, source=OTHER_SOURCE, epoch=2), b"s")
        self.assertEqual(DeliveryOutcome.ACCEPTED, result.outcome)
        self.assertEqual([(GapReason.SEQUENCE_SKIP, None, 2, 2)],
                         [(g.reason, g.after_sequence, g.before_sequence,
                           g.missing_units) for g in result.gaps])
        tracker, _, session = self._uncommitted_first_unit("backpressure")
        result = tracker.receive(session, unit(0, source=OTHER_SOURCE, epoch=2), b"r")
        self.assertEqual((DeliveryOutcome.ACCEPTED, ()), (result.outcome, result.gaps))
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker, OTHER_SOURCE).flow)

    def test_uncommitted_sources_stay_within_source_capacity(self):
        authorizer = Authorizer({(NODE, s) for s in SOURCES})
        tracker, _, _, _ = build(authorizer=authorizer, queued=1)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0, source=SOURCES[0]), b"v")
        for source in SOURCES[1:4]:
            self.assertEqual(DeliveryOutcome.BACKPRESSURED,
                             tracker.receive(session, unit(0, source=source), b"v").outcome)
        self.assertEqual(4, len(tracker.snapshot()))
        self.assertEqual("source_capacity",
                         tracker.receive(session, unit(0, source=SOURCES[4]), b"v").reason)
        self.assertEqual((), tracker.forget_node(NODE))
        self.assertEqual((), tracker.snapshot())

    def test_rate_limited_unit_is_not_committed(self):
        tracker, _, _, _ = build(rate=1)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        self.assertEqual(DeliveryOutcome.RATE_LIMITED,
                         tracker.receive(session, unit(1), b"v").outcome)
        self.assertEqual(0, flow(tracker).last_sequence)

    def test_duplicate_retries_consume_rate_budget_without_enqueueing(self):
        tracker, ingest, clock, _ = build(rate=3)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        tracker.receive(session, unit(1), b"v")
        self.assertEqual(DeliveryOutcome.DUPLICATE,
                         tracker.receive(session, unit(0), b"v").outcome)
        # The budget is spent: further duplicates and new units are throttled.
        for header in (unit(0), unit(1), unit(2)):
            result = tracker.receive(session, header, b"v")
            self.assertEqual((DeliveryOutcome.RATE_LIMITED, "rate_limit"),
                             (result.outcome, result.reason))
        self.assertEqual(3, ingest.snapshot().rate_limited)
        self.assertEqual([0, 1], [m.sequence for m in ingest.drain(10)])
        self.assertEqual(1, flow(tracker).last_sequence)
        # A new window restores the idempotent acknowledgement.
        clock.now = 10 ** 12
        self.assertEqual(DeliveryOutcome.DUPLICATE,
                         tracker.receive(session, unit(1), b"v").outcome)
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(2), b"v").outcome)

    def test_over_budget_duplicate_does_not_change_continuity(self):
        tracker, _, _, _ = build(rate=1)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        self.assertEqual(DeliveryOutcome.RATE_LIMITED,
                         tracker.receive(session, unit(0), b"v").outcome)
        state = flow(tracker)
        self.assertEqual((SourceFlow.RECEIVING, False, 0, 0),
                         (state.flow, state.backpressured, state.last_sequence,
                          state.pending_gaps))

    def test_early_refusals_of_authorized_node_consume_rate_budget(self):
        def exhausted(tracker, session, header=None):
            result = tracker.receive(session, header or unit(0), b"v")
            return (result.outcome, result.reason)

        limited = (DeliveryOutcome.RATE_LIMITED, "rate_limit")
        with self.subTest("stale_session"):
            tracker, ingest, _, _ = build(rate=1)
            old = tracker.open_session(NODE)
            new = tracker.open_session(NODE)
            self.assertEqual("stale_session", tracker.receive(old, unit(0), b"v").reason)
            self.assertEqual(limited, exhausted(tracker, new))
            self.assertEqual(limited, exhausted(tracker, old))
            self.assertEqual(0, ingest.snapshot().queued_messages)
        with self.subTest("stale_capture_epoch"):
            tracker, _, _, _ = build(rate=3)
            session = tracker.open_session(NODE)
            tracker.receive(session, unit(9, epoch=2), b"v")
            tracker.receive(session, unit(0, epoch=3, at=0), b"v")
            self.assertEqual("stale_capture_epoch",
                             tracker.receive(session, unit(10, epoch=2), b"v").reason)
            self.assertEqual(limited, exhausted(tracker, session, unit(1, epoch=3)))
        with self.subTest("source_identity_mismatch"):
            authorizer = Authorizer({(NODE, SOURCE), (OTHER_NODE, SOURCE),
                                     (OTHER_NODE, OTHER_SOURCE)})
            tracker, _, _, _ = build(authorizer=authorizer, rate=2)
            session = tracker.open_session(NODE)
            other = tracker.open_session(OTHER_NODE)
            tracker.receive(session, unit(0), b"v")
            for sequence in (1, 2):
                self.assertEqual("source_identity_mismatch",
                                 tracker.receive(other, unit(sequence), b"v").reason)
            self.assertEqual(limited, exhausted(tracker, other, unit(0, source=OTHER_SOURCE)))
            # The budget is per node: the source owner is not throttled.
            self.assertEqual(DeliveryOutcome.ACCEPTED,
                             tracker.receive(session, unit(1), b"v").outcome)
        with self.subTest("source_capacity"):
            authorizer = Authorizer({(NODE, SOURCE), (NODE, OTHER_SOURCE)})
            tracker, _, _, _ = build(authorizer=authorizer, sources=1, rate=2)
            session = tracker.open_session(NODE)
            tracker.receive(session, unit(0), b"v")
            self.assertEqual("source_capacity",
                             tracker.receive(session, unit(0, source=OTHER_SOURCE),
                                             b"v").reason)
            self.assertEqual(limited, exhausted(tracker, session, unit(1)))
        with self.subTest("unauthorized_source"):
            tracker, _, _, _ = build(rate=1)
            session = tracker.open_session(NODE)
            self.assertEqual("unauthorized",
                             tracker.receive(session, unit(0, source=OTHER_SOURCE),
                                             b"v").reason)
            self.assertEqual(limited, exhausted(tracker, session))
            self.assertTrue(tracker.heartbeat(session))
        with self.subTest("source_revoked_between_checks"):
            authorizer = RevokeDuringCheckAuthorizer(revoke_node=False)
            authorizer.pairs.add((NODE, OTHER_SOURCE))
            tracker, _, _, _ = build(authorizer=authorizer, rate=2)
            session = tracker.open_session(NODE)
            tracker.receive(session, unit(0), b"v")
            authorizer.armed = True
            self.assertEqual("unauthorized",
                             tracker.receive(session, unit(0, source=OTHER_SOURCE),
                                             b"v").reason)
            self.assertEqual(limited, exhausted(tracker, session, unit(1)))

    def test_node_revoked_during_source_check_invalidates_and_is_not_charged(self):
        class RevokeInSourceCheck(Authorizer):
            armed = False

            def require_source(self, node_id, source_id):
                if self.armed:
                    self.armed = False
                    self.revoked.add(node_id)
                    raise PermissionError
                super().require_source(node_id, source_id)

        authorizer = RevokeInSourceCheck()
        tracker, _, _, _ = build(authorizer=authorizer, rate=2)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        authorizer.armed = True
        result = tracker.receive(session, unit(1), b"v")
        self.assertEqual((DeliveryOutcome.REJECTED, "unauthorized"),
                         (result.outcome, result.reason))
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        # The refusal of the revoked node spent no rate budget: after the
        # revocation is lifted, one of the two window slots remains.
        authorizer.revoked.discard(NODE)
        self.assertFalse(tracker.heartbeat(session))
        renewed = tracker.open_session(NODE)
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(renewed, unit(1), b"v").outcome)
        self.assertEqual(DeliveryOutcome.RATE_LIMITED,
                         tracker.receive(renewed, unit(2), b"v").outcome)

    def test_node_revoked_before_charged_duplicate_invalidates_and_is_not_charged(self):
        authorizer = RevokeDuringCheckAuthorizer(revoke_node=True)
        tracker, ingest, _, _ = build(authorizer=authorizer, rate=2)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        authorizer.armed = True
        result = tracker.receive(session, unit(0), b"v")
        self.assertEqual((DeliveryOutcome.REJECTED, "unauthorized"),
                         (result.outcome, result.reason))
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        self.assertEqual(0, ingest.snapshot().rate_limited)
        authorizer.revoked.discard(NODE)
        renewed = tracker.open_session(NODE)
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(renewed, unit(1), b"v").outcome)
        self.assertEqual(DeliveryOutcome.RATE_LIMITED,
                         tracker.receive(renewed, unit(2), b"v").outcome)

    def test_revoked_node_attempts_are_not_charged(self):
        tracker, ingest, _, authorizer = build(rate=1)
        session = tracker.open_session(NODE)
        authorizer.revoked.add(NODE)
        self.assertEqual("unauthorized", tracker.receive(session, unit(0), b"v").reason)
        self.assertEqual(0, ingest.snapshot().tracked_rate_windows)

    def test_permanently_refused_unit_is_reported_loss(self):
        tracker, ingest, _, _ = build(message_bytes=4)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        result = tracker.receive(session, unit(1), b"too large")
        self.assertEqual((DeliveryOutcome.REJECTED, "message_too_large"),
                         (result.outcome, result.reason))
        (gap,) = result.gaps
        self.assertEqual((GapReason.INGEST_REFUSED, 0, 2, 1),
                         (gap.reason, gap.after_sequence, gap.before_sequence,
                          gap.missing_units))
        self.assertEqual(DeliveryOutcome.DUPLICATE,
                         tracker.receive(session, unit(1), b"too large").outcome)
        self.assertEqual(1, ingest.snapshot().queued_messages)

    def test_transient_ingest_refusal_is_not_committed_as_loss(self):
        tracker, ingest, clock, _ = build()
        session = tracker.open_session(NODE)
        clock.now = 50
        tracker.receive(session, unit(0), b"v")
        # The ingest boundary fails closed on a Main clock regression; that is
        # not a property of the unit, so the unit must stay retryable.
        clock.now = 40
        result = tracker.receive(session, unit(1), b"v")
        self.assertEqual((DeliveryOutcome.REJECTED, "clock_regression", ()),
                         (result.outcome, result.reason, result.gaps))
        clock.now = 55
        self.assertEqual(0, flow(tracker).last_sequence)
        self.assertEqual(SourceFlow.DEGRADED, flow(tracker).flow)
        self.assertEqual((), tracker.drain_gaps(10))
        clock.now = 60
        result = tracker.receive(session, unit(1), b"v")
        self.assertEqual((DeliveryOutcome.ACCEPTED, ()), (result.outcome, result.gaps))
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        self.assertEqual([0, 1], [m.sequence for m in ingest.drain(10)])

    def test_pending_gap_events_are_bounded_by_coalescing(self):
        tracker, _, _, _ = build(pending=2, queued=16)
        session = tracker.open_session(NODE)
        for sequence in range(0, 20, 2):
            tracker.receive(session, unit(sequence), b"v")
        gaps = tracker.drain_gaps(100)
        self.assertEqual(2, len(gaps))
        self.assertEqual((GapReason.COALESCED, None, 18),
                         (gaps[-1].reason, gaps[-1].missing_units, gaps[-1].before_sequence))

    def test_one_to_four_sources_and_fifth_source_is_refused(self):
        for count in range(1, 5):
            pairs = {(NODES[i], SOURCES[i]) for i in range(5)}
            tracker, ingest, _, _ = build(authorizer=Authorizer(pairs), queued=8)
            sessions = [tracker.open_session(NODES[i]) for i in range(count)]
            for i, session in enumerate(sessions):
                self.assertEqual(DeliveryOutcome.ACCEPTED,
                                 tracker.receive(session, unit(0, source=SOURCES[i]),
                                                 b"v").outcome)
            self.assertEqual(count, len(tracker.snapshot()))
            self.assertEqual(count, ingest.snapshot().queued_messages)
        # A fifth node may hold a session, but not a fifth active source.
        fifth = tracker.open_session(NODES[4])
        self.assertEqual("source_capacity",
                         tracker.receive(fifth, unit(0, source=SOURCES[4]), b"v").reason)
        self.assertEqual(4, len(tracker.snapshot()))
        authorizer = Authorizer({(NODE, s) for s in SOURCES})
        tracker, _, _, _ = build(authorizer=authorizer, queued=8)
        session = tracker.open_session(NODE)
        for source in SOURCES[:4]:
            tracker.receive(session, unit(0, source=source), b"v")
        self.assertEqual("source_capacity",
                         tracker.receive(session, unit(0, source=SOURCES[4]), b"v").reason)

    def test_deactivated_source_releases_slot_and_keeps_other_flows(self):
        authorizer = Authorizer({(NODE, s) for s in SOURCES})
        tracker, _, _, _ = build(authorizer=authorizer, queued=16)
        session = tracker.open_session(NODE)
        for source in SOURCES[:4]:
            tracker.receive(session, unit(0, source=source), b"v")
        tracker.receive(session, unit(3, source=SOURCES[0]), b"v")
        authorizer.pairs.discard((NODE, SOURCES[0]))
        pending = tracker.forget_source(SOURCES[0])
        # Undrained loss is handed back, never silently dropped.
        self.assertEqual([(GapReason.SEQUENCE_SKIP, 2)],
                         [(g.reason, g.missing_units) for g in pending])
        self.assertEqual((), tracker.forget_source(SOURCES[0]))
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(0, source=SOURCES[4]), b"v").outcome)
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(1, source=SOURCES[1]), b"v").outcome)
        self.assertEqual(4, len(tracker.snapshot()))
        self.assertEqual("unauthorized",
                         tracker.receive(session, unit(4, source=SOURCES[0]), b"v").reason)
        self.assertTrue(tracker.heartbeat(session))
        with self.assertRaises(ValueError):
            tracker.forget_source("x")

    def test_nodes_without_sources_do_not_exhaust_active_source_capacity(self):
        pairs = {(NODES[i], SOURCES[i]) for i in range(5)}
        tracker, _, clock, _ = build(authorizer=Authorizer(pairs), queued=8, stale=10,
                                     nodes=4)
        sessions = [tracker.open_session(NODES[i]) for i in range(4)]
        for i, session in enumerate(sessions[:2]):
            tracker.receive(session, unit(0, source=SOURCES[i]), b"v")
        # Replaced source on a closed host: that host no longer holds a slot.
        tracker.forget_source(SOURCES[0])
        tracker.close_session(sessions[0])
        fifth = tracker.open_session(NODES[4])
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(fifth, unit(0, source=SOURCES[4]), b"v").outcome)
        self.assertEqual("stale_session",
                         tracker.receive(sessions[0], unit(1, source=SOURCES[0]), b"v").reason)
        # Live source-less sessions keep their slots; a source owner is never retired.
        with self.assertRaises(PermissionError):
            tracker.open_session(NODES[0])
        # A source-less session that went stale releases its slot.
        clock.now = 11
        self.assertTrue(tracker.heartbeat(sessions[1]))
        self.assertTrue(tracker.heartbeat(sessions[3]))
        renewed = tracker.open_session(NODES[0])
        self.assertFalse(tracker.heartbeat(sessions[2]))
        self.assertTrue(tracker.heartbeat(renewed))
        self.assertEqual({SOURCES[1], SOURCES[4]},
                         {item.source_id for item in tracker.snapshot()})

    def test_live_source_less_sessions_do_not_consume_active_source_capacity(self):
        pairs = {(NODES[i], SOURCES[i]) for i in range(5)}
        tracker, _, _, _ = build(authorizer=Authorizer(pairs), queued=8)
        sessions = [tracker.open_session(NODES[i]) for i in range(4)]
        self.assertTrue(all(tracker.heartbeat(session) for session in sessions))
        fifth = tracker.open_session(NODES[4])
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(fifth, unit(0, source=SOURCES[4]), b"v").outcome)
        self.assertTrue(all(tracker.heartbeat(session) for session in sessions))
        # The node-session table is still hard-bounded on its own.
        capped, _, _, _ = build(authorizer=Authorizer(pairs), nodes=2)
        capped.open_session(NODES[0])
        capped.open_session(NODES[1])
        with self.assertRaises(PermissionError):
            capped.open_session(NODES[2])

    def test_forgotten_node_old_grant_never_becomes_current_again(self):
        tracker, ingest, _, authorizer = build()
        old = tracker.open_session(NODE)
        tracker.receive(old, unit(0), b"v")
        authorizer.revoked.add(NODE)
        tracker.forget_node(NODE)
        # Re-enrollment of the same UUID with a new credential.
        authorizer.revoked.discard(NODE)
        fresh = tracker.open_session(NODE)
        self.assertNotEqual(old.generation, fresh.generation)
        self.assertEqual("stale_session", tracker.receive(old, unit(0), b"v").reason)
        self.assertFalse(tracker.heartbeat(old))
        tracker.close_session(old)
        self.assertTrue(tracker.heartbeat(fresh))
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(fresh, unit(0), b"v").outcome)
        self.assertEqual(2, ingest.snapshot().queued_messages)

    def test_forget_node_discards_rate_window_for_re_enrolled_node(self):
        tracker, ingest, _, authorizer = build(rate=1)
        old = tracker.open_session(NODE)
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(old, unit(0), b"v").outcome)
        # The old credential exhausts its rate budget for this window.
        limited = tracker.receive(old, unit(1), b"v")
        self.assertEqual((DeliveryOutcome.RATE_LIMITED, "rate_limit"),
                         (limited.outcome, limited.reason))
        self.assertEqual(1, ingest.snapshot().tracked_rate_windows)
        authorizer.revoked.add(NODE)
        tracker.forget_node(NODE)
        self.assertEqual(0, ingest.snapshot().tracked_rate_windows)
        # Re-enrollment of the same UUID with a new credential starts with a
        # fresh budget instead of inheriting the old window.
        authorizer.revoked.discard(NODE)
        fresh = tracker.open_session(NODE)
        delivery = tracker.receive(fresh, unit(0), b"v")
        self.assertEqual((DeliveryOutcome.ACCEPTED, None),
                         (delivery.outcome, delivery.reason))

    def test_forget_node_discards_future_rate_window_start(self):
        tracker, ingest, clock, authorizer = build()
        clock.now = 1000
        old = tracker.open_session(NODE)
        tracker.receive(old, unit(0), b"v")
        authorizer.revoked.add(NODE)
        tracker.forget_node(NODE)
        # The re-enrolled node's first unit is sampled before the old
        # window's start; a retained window would refuse it as a regression.
        clock.now = 500
        authorizer.revoked.discard(NODE)
        fresh = tracker.open_session(NODE)
        delivery = tracker.receive(fresh, unit(0), b"v")
        self.assertEqual((DeliveryOutcome.ACCEPTED, None),
                         (delivery.outcome, delivery.reason))
        self.assertEqual(1, ingest.snapshot().tracked_rate_windows)

    def test_forget_source_keeps_other_node_state_and_resets_source_watermarks(self):
        tracker, ingest, _, authorizer = build(
            authorizer=Authorizer(((NODE, SOURCE), (NODE, OTHER_SOURCE))))
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(5, at=10 ** 6), b"v")
        tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v")
        authorizer.pairs.discard((NODE, SOURCE))
        tracker.forget_source(SOURCE)
        authorizer.pairs.add((NODE, SOURCE))
        # A reactivated source identity starts without the old sequence,
        # epoch or capture-clock watermark, so an earlier capture time or
        # lower sequence is neither a duplicate nor a clock regression.
        delivery = tracker.receive(session, unit(0, at=1), b"v")
        self.assertEqual((DeliveryOutcome.ACCEPTED, ()),
                         (delivery.outcome, delivery.gaps))
        self.assertEqual(0, flow(tracker).last_sequence)
        self.assertEqual(0, flow(tracker, OTHER_SOURCE).last_sequence)
        self.assertEqual(1, ingest.snapshot().tracked_rate_windows)

    def test_grant_from_another_tracker_lifetime_is_stale(self):
        before_restart, _, _, _ = build()
        old = before_restart.open_session(NODE)
        after_restart, ingest, _, _ = build()
        fresh = after_restart.open_session(NODE)
        self.assertEqual(old.generation, fresh.generation)
        self.assertEqual("stale_session", after_restart.receive(old, unit(0), b"v").reason)
        self.assertFalse(after_restart.heartbeat(old))
        after_restart.close_session(old)
        self.assertTrue(after_restart.heartbeat(fresh))
        self.assertEqual(0, ingest.snapshot().queued_messages)

    def test_stale_flow_and_clock_regression_fail_closed(self):
        tracker, _, clock, _ = build(stale=10)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        clock.now = 11
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        clock.now = 12
        tracker.receive(session, unit(1), b"v")
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        clock.now = 5
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)

    def test_revocation_rejects_units_and_forget_returns_undrained_gaps(self):
        tracker, _, _, authorizer = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        tracker.receive(session, unit(3), b"v")
        authorizer.revoked.add(NODE)
        self.assertEqual("unauthorized", tracker.receive(session, unit(4), b"v").reason)
        with self.assertRaises(PermissionError):
            tracker.open_session(NODE)
        pending = tracker.forget_node(NODE)
        self.assertEqual([GapReason.SEQUENCE_SKIP], [g.reason for g in pending])
        self.assertEqual((), tracker.snapshot())

    def test_revoked_node_heartbeat_is_refused_and_session_invalidated(self):
        tracker, _, clock, authorizer = build(stale=100)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        self.assertTrue(tracker.heartbeat(session))
        authorizer.revoked.add(NODE)
        clock.now = 50
        self.assertFalse(tracker.heartbeat(session))
        # The grant is invalidated even if authorization were restored later;
        # the node must reauthenticate and open a new session.
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        authorizer.revoked.discard(NODE)
        self.assertFalse(tracker.heartbeat(session))
        self.assertEqual("stale_session", tracker.receive(session, unit(1), b"v").reason)
        renewed = tracker.open_session(NODE)
        self.assertTrue(tracker.heartbeat(renewed))

    def test_revoked_node_media_invalidates_session(self):
        tracker, _, _, authorizer = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        authorizer.revoked.add(NODE)
        self.assertEqual("unauthorized", tracker.receive(session, unit(1), b"v").reason)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)

    def test_unauthorized_source_does_not_invalidate_node_session(self):
        tracker, _, _, _ = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        self.assertEqual("unauthorized",
                         tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v").reason)
        self.assertTrue(tracker.heartbeat(session))
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)

    def test_node_revoked_between_checks_invalidates_session(self):
        authorizer = RevokeDuringCheckAuthorizer(revoke_node=True)
        tracker, ingest, _, _ = build(authorizer=authorizer)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        authorizer.armed = True
        self.assertEqual("unauthorized", tracker.receive(session, unit(1), b"v").reason)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        authorizer.revoked.discard(NODE)
        self.assertFalse(tracker.heartbeat(session))
        self.assertEqual("stale_session", tracker.receive(session, unit(1), b"v").reason)
        self.assertEqual(1, ingest.snapshot().queued_messages)

    def test_source_revoked_between_checks_keeps_node_session(self):
        authorizer = RevokeDuringCheckAuthorizer(revoke_node=False)
        authorizer.pairs.add((NODE, OTHER_SOURCE))
        tracker, _, _, _ = build(authorizer=authorizer)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        authorizer.armed = True
        self.assertEqual("unauthorized",
                         tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v").reason)
        self.assertTrue(tracker.heartbeat(session))
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(1), b"v").outcome)

    def test_sustained_backpressure_stays_degraded_not_interrupted(self):
        tracker, _, clock, _ = build(queued=1, stale=10)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        for now in range(5, 45, 5):
            clock.now = now
            self.assertEqual(DeliveryOutcome.BACKPRESSURED,
                             tracker.receive(session, unit(1), b"v").outcome)
            self.assertTrue(tracker.heartbeat(session))
        clock.now = 45
        state = flow(tracker)
        self.assertEqual((SourceFlow.DEGRADED, True, 0),
                         (state.flow, state.backpressured, state.last_sequence))
        # Once attempts stop, staleness still makes the flow interrupted.
        clock.now = 51
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)

    def test_sustained_transient_refusal_stays_degraded_not_interrupted(self):
        authorizer = Authorizer()
        clock = Clock()
        ingest = TransientRefusalQueue(IngestLimits(8, 4, 32, 1000, 10 ** 12),
                                       authorizer, clock_ns=clock)
        tracker = ContinuityTracker(ContinuityLimits(4, 4, 10), authorizer, ingest,
                                    clock_ns=clock)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        ingest.refusing = True
        for now in range(5, 45, 5):
            clock.now = now
            self.assertEqual("transient_refusal",
                             tracker.receive(session, unit(1), b"v").reason)
        clock.now = 45
        self.assertEqual((SourceFlow.DEGRADED, 0),
                         (flow(tracker).flow, flow(tracker).last_sequence))
        ingest.refusing = False
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(1), b"v").outcome)
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)

    def test_deterministic_impairment_matrix(self):
        """Link loss, slow consumer and duplicate retries over one synthetic run."""
        tracker, ingest, clock, _ = build(queued=3)
        session = tracker.open_session(NODE)
        committed, reported_missing, sequence = [], 0, 0
        plan = ["ok"] * 3 + ["link_loss"] + ["ok"] * 2 + ["slow"] * 4 + ["ok"] * 3
        for step in plan:
            clock.now += 1
            if step == "link_loss":
                tracker.close_session(session)
                sequence += 4  # Agent could not send these; they are lost.
                session = tracker.open_session(NODE)
                continue
            result = tracker.receive(session, unit(sequence), b"v")
            reported_missing += sum(g.missing_units or 0 for g in result.gaps)
            if result.outcome is DeliveryOutcome.ACCEPTED:
                committed.append(sequence)
                # A lost acknowledgement makes the Agent retry once.
                self.assertEqual(DeliveryOutcome.DUPLICATE,
                                 tracker.receive(session, unit(sequence), b"v").outcome)
                sequence += 1
            if step != "slow":
                committed.extend(m.sequence for m in ingest.drain(10)
                                 if m.sequence not in committed)
            self.assertLessEqual(ingest.snapshot().queued_messages, 3)
        self.assertEqual(4, reported_missing)
        self.assertEqual(len(set(committed)), len(committed))
        self.assertEqual(sorted(committed), committed)

    def test_concurrent_retries_commit_each_unit_once(self):
        tracker, ingest, _, _ = build(queued=64)
        session = tracker.open_session(NODE)
        outcomes = []

        def send():
            for sequence in range(32):
                outcomes.append(tracker.receive(session, unit(sequence), b"v").outcome)

        threads = [threading.Thread(target=send) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(32, ingest.snapshot().queued_messages)
        self.assertEqual(32, outcomes.count(DeliveryOutcome.ACCEPTED))

    def test_liveness_time_is_sampled_while_holding_the_locks(self):
        """A delayed caller must not apply a sample taken before a newer update."""
        authorizer = Authorizer()
        samples = []
        holders = {}

        def clock_for(name):
            def read():
                samples.append((name, holders[name].locked()))
                return 5
            return read

        ingest = AgentIngestQueue(IngestLimits(8, 4, 32, 1000, 10 ** 12), authorizer,
                                  clock_ns=clock_for("ingest"))
        tracker = ContinuityTracker(ContinuityLimits(4, 4, 100, 64), authorizer, ingest,
                                    clock_ns=clock_for("tracker"))
        holders.update(tracker=tracker._lock, ingest=ingest._lock)
        session = tracker.open_session(NODE)
        self.assertTrue(tracker.heartbeat(session))
        tracker.receive(session, unit(0), b"v")
        self.assertEqual("already_committed", tracker.receive(session, unit(0), b"v").reason)
        tracker.snapshot()
        self.assertEqual({"tracker", "ingest"}, {name for name, _ in samples})
        self.assertEqual([], [name for name, held in samples if not held])

    def test_older_clock_sample_never_rewinds_liveness_or_retires_live_session(self):
        pairs = {(NODES[i], SOURCES[i]) for i in range(3)}
        tracker, _, clock, _ = build(authorizer=Authorizer(pairs), stale=10, nodes=2)
        clock.now = 50
        live = tracker.open_session(NODES[0])
        tracker.open_session(NODES[1])
        # An older sample (delayed caller or regressed clock) is not staleness:
        # the live source-less session keeps its slot and the newcomer is refused.
        clock.now = 45
        with self.assertRaises(PermissionError):
            tracker.open_session(NODES[2])
        self.assertTrue(tracker.heartbeat(live))
        # The older heartbeat did not rewind liveness from 50 to 45, so at 58
        # the session is still fresh (58 - 50 <= 10) and is not retired.
        clock.now = 58
        with self.assertRaises(PermissionError):
            tracker.open_session(NODES[2])
        self.assertTrue(tracker.heartbeat(live))
        # Genuine staleness still frees the slot of an unrefreshed session.
        clock.now = 69
        self.assertTrue(tracker.heartbeat(live))
        tracker.open_session(NODES[2])
        self.assertTrue(tracker.heartbeat(live))

    def test_new_source_under_regressed_clock_keeps_node_liveness_watermark(self):
        authorizer = Authorizer({(NODE, SOURCE), (NODE, OTHER_SOURCE)})
        # Committed first unit.
        tracker, _, clock, _ = build(authorizer=authorizer, stale=10)
        clock.now = 100
        session = tracker.open_session(NODE)
        clock.now = 50
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(0), b"v").outcome)
        # During the regression the flow fails closed ...
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        # ... and after recovery it is not reported older than its session.
        clock.now = 105
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        # Uncommitted (backpressured) first unit.
        tracker, _, clock, _ = build(authorizer=authorizer, stale=10, queued=1)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        clock.now = 100
        self.assertTrue(tracker.heartbeat(session))
        clock.now = 50
        self.assertEqual(DeliveryOutcome.BACKPRESSURED,
                         tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v").outcome)
        clock.now = 105
        self.assertEqual(SourceFlow.DEGRADED, flow(tracker, OTHER_SOURCE).flow)

    def test_node_revoked_while_open_session_waits_gets_no_grant(self):
        authorizer = SignallingAuthorizer()
        tracker, _, _, _ = build(authorizer=authorizer)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        result = revoke_while_waiting(tracker._lock, authorizer,
                                      lambda: tracker.open_session(NODE),
                                      lambda: authorizer.revoked.add(NODE))
        self.assertIsInstance(result, PermissionError)
        # No fresh grant reopened the node: once the old grant fails its
        # heartbeat, the retained source is interrupted, not receiving.
        self.assertFalse(tracker.heartbeat(session))
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)

    def test_node_revoked_while_heartbeat_waits_refreshes_nothing(self):
        authorizer = SignallingAuthorizer()
        tracker, _, clock, _ = build(authorizer=authorizer, stale=10)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        clock.now = 8
        result = revoke_while_waiting(tracker._lock, authorizer,
                                      lambda: tracker.heartbeat(session),
                                      lambda: authorizer.revoked.add(NODE))
        self.assertIs(False, result)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)
        authorizer.revoked.discard(NODE)
        self.assertEqual("stale_session", tracker.receive(session, unit(1), b"v").reason)

    def test_source_revoked_while_receive_waits_is_not_acknowledged(self):
        authorizer = SignallingAuthorizer({(NODE, SOURCE), (NODE, OTHER_SOURCE)})
        tracker, ingest, _, _ = build(authorizer=authorizer)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        # A duplicate retry of a unit of a source revoked meanwhile is refused
        # rather than acknowledged as already committed.
        result = revoke_while_waiting(tracker._lock, authorizer,
                                      lambda: tracker.receive(session, unit(0), b"v"),
                                      lambda: authorizer.pairs.discard((NODE, SOURCE)))
        self.assertEqual((DeliveryOutcome.REJECTED, "unauthorized"),
                         (result.outcome, result.reason))
        # A source-only revocation keeps the node session and its other source.
        self.assertTrue(tracker.heartbeat(session))
        self.assertEqual(DeliveryOutcome.ACCEPTED,
                         tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v").outcome)
        self.assertEqual(2, ingest.snapshot().queued_messages)

    def test_node_revoked_while_charged_attempt_waits_is_not_charged(self):
        authorizer = SignallingAuthorizer()
        tracker, ingest, _, _ = build(authorizer=authorizer)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        ingest.forget_revoked_node(NODE)
        # The tracker's own check passes; the revocation lands while the
        # charge waits for the queue lock and must be seen by the queue.
        result = revoke_while_waiting(ingest._lock, authorizer,
                                      lambda: tracker.receive(session, unit(0), b"v"),
                                      lambda: authorizer.revoked.add(NODE))
        self.assertEqual((DeliveryOutcome.REJECTED, "unauthorized"),
                         (result.outcome, result.reason))
        self.assertEqual(0, ingest.snapshot().tracked_rate_windows)
        self.assertEqual(SourceFlow.INTERRUPTED, flow(tracker).flow)


    def test_revocation_commit_waits_for_an_authorized_session_grant(self):
        authorizer = GatedAuthorizer()
        tracker, ingest, _, _ = build(authorizer=authorizer)
        first = tracker.open_session(NODE)
        tracker.receive(first, unit(2), b"v")
        authorizer.armed = True
        opener, opened = start(lambda: tracker.open_session(NODE))
        self.assertTrue(authorizer.passed.wait(5))
        committed = threading.Event()
        revoker, revoked = start(revoke_in_fence(tracker.authorization_change, authorizer,
                                                 committed=committed))
        # The durable revocation cannot commit between the grant's passing
        # authorization check and the grant itself.
        self.assertFalse(committed.wait(0.2))
        authorizer.release.set()
        opener.join(5)
        revoker.join(5)
        self.assertFalse(opener.is_alive() or revoker.is_alive())
        self.assertTrue(committed.is_set())
        granted = opened["value"]
        self.assertIsInstance(granted, AgentSession)
        # The grant issued just before the commit was released by the fence
        # itself, before any later heartbeat or media recheck, and the
        # revoked node's undrained gap is handed back rather than dropped.
        self.assertIsNone(tracker._current(granted))
        self.assertEqual((), tracker.snapshot())
        self.assertEqual([GapReason.SEQUENCE_SKIP],
                         [gap.reason for gap in revoked["value"].released_gaps])
        self.assertEqual(0, ingest.snapshot().tracked_rate_windows)
        with self.assertRaises(PermissionError):
            tracker.open_session(NODE)
        self.assertEqual("unauthorized", tracker.receive(granted, unit(1), b"v").reason)

    def test_session_open_waits_for_an_in_progress_revocation_commit(self):
        authorizer = SignallingAuthorizer()
        tracker, _, _, _ = build(authorizer=authorizer)
        tracker.open_session(NODE)
        committed, hold = threading.Event(), threading.Event()
        revoker, _ = start(revoke_in_fence(tracker.authorization_change, authorizer,
                                           committed=committed, hold=hold))
        self.assertTrue(committed.wait(5))
        authorizer.checked.clear()
        opener, opened = start(lambda: tracker.open_session(NODE))
        # No authorization is read while the revocation is committing.
        self.assertFalse(authorizer.checked.wait(0.2))
        hold.set()
        revoker.join(5)
        opener.join(5)
        self.assertFalse(opener.is_alive() or revoker.is_alive())
        self.assertIsInstance(opened["value"], PermissionError)

    def test_source_deactivation_releases_its_slot_inside_the_fence(self):
        authorizer = Authorizer({(NODE, SOURCE)})
        tracker, _, _, _ = build(authorizer=authorizer, sources=1)
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(3), b"v")
        committed, hold = threading.Event(), threading.Event()

        def deactivate():
            with tracker.authorization_change(deactivated_source=SOURCE) as change:
                authorizer.pairs.discard((NODE, SOURCE))
                authorizer.pairs.add((NODE, OTHER_SOURCE))
                committed.set()
                if not hold.wait(5):
                    raise AssertionError("fence was never released")
            return change

        deactivator, deactivated = start(deactivate)
        self.assertTrue(committed.wait(5))
        # A replacement that waits for the commit must find the slot free.
        replacer, replaced = start(
            lambda: tracker.receive(session, unit(0, source=OTHER_SOURCE), b"v"))
        hold.set()
        deactivator.join(5)
        replacer.join(5)
        self.assertFalse(deactivator.is_alive() or replacer.is_alive())
        self.assertEqual(DeliveryOutcome.ACCEPTED, replaced["value"].outcome)
        self.assertEqual([OTHER_SOURCE], [item.source_id for item in tracker.snapshot()])
        self.assertEqual([(GapReason.SEQUENCE_SKIP, 3)],
                         [(gap.reason, gap.missing_units)
                          for gap in deactivated["value"].released_gaps])
        self.assertTrue(tracker.heartbeat(session))

    def test_failed_revocation_commit_changes_no_session_state(self):
        tracker, ingest, _, _ = build()
        session = tracker.open_session(NODE)
        tracker.receive(session, unit(0), b"v")
        with self.assertRaises(RuntimeError):
            with tracker.authorization_change(revoked_node=NODE,
                                              deactivated_source=SOURCE) as change:
                raise RuntimeError("durable commit failed")
        self.assertEqual((), change.released_gaps)
        self.assertTrue(tracker.heartbeat(session))
        self.assertEqual(SourceFlow.RECEIVING, flow(tracker).flow)
        self.assertEqual(1, ingest.snapshot().tracked_rate_windows)
        with self.assertRaises(ValueError):
            with tracker.authorization_change(revoked_node="node"):
                pass
        with self.assertRaises(ValueError):
            with tracker.authorization_change(deactivated_source="source"):
                pass

    def test_direct_queue_submit_is_serialized_with_revocation_commit(self):
        authorizer = GatedAuthorizer()
        _, ingest, _, _ = build(authorizer=authorizer)
        authorizer.armed = True
        message = AgentMessage(NODE, SOURCE, AgentAction.HEARTBEAT, 0, b"")
        submitter, submitted = start(lambda: ingest.submit(message))
        self.assertTrue(authorizer.passed.wait(5))
        committed = threading.Event()
        revoker, _ = start(revoke_in_fence(ingest.authorization_change, authorizer,
                                           committed=committed))
        self.assertFalse(committed.wait(0.2))
        authorizer.release.set()
        submitter.join(5)
        revoker.join(5)
        self.assertFalse(submitter.is_alive() or revoker.is_alive())
        # Admitted entirely before the commit; the fence then discarded the
        # rate window and every later attempt observes the revocation.
        self.assertEqual(IngestOutcome.ACCEPTED, submitted["value"].outcome)
        self.assertEqual(0, ingest.snapshot().tracked_rate_windows)
        self.assertEqual("unauthorized", ingest.submit(message).reason)
        self.assertEqual("unauthorized", ingest.charge_attempt(NODE).reason)
        with self.assertRaises(ValueError):
            with ingest.authorization_change(revoked_node="node"):
                pass

    def test_invalid_inputs_and_limits_are_rejected(self):
        for bad in ((0, 1, 1), (1, 0, 1), (1, 1, 0), (True, 1, 1), (1, 1, 1, 0),
                    (1, 1, 1, True)):
            with self.assertRaises(ValueError):
                ContinuityLimits(*bad)
        for bad in ((SOURCE, -1, 0, 0), (SOURCE, 0, 2 ** 63, 0), ("x", 0, 0, 0),
                    (SOURCE, 0, 0, 1.5)):
            with self.assertRaises(ValueError):
                MediaUnitHeader(*bad)
        tracker, _, _, _ = build()
        session = tracker.open_session(NODE)
        with self.assertRaises(ValueError):
            tracker.receive(session, unit(0), "text")
        with self.assertRaises(ValueError):
            tracker.drain_gaps(0)
        with self.assertRaises(ValueError):
            ContinuityTracker(ContinuityLimits(1, 1, 1), Authorizer(), object(),
                              clock_ns=Clock())


if __name__ == "__main__":
    unittest.main()
