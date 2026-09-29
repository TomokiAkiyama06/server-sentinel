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
    AgentIngestQueue, DenyIngestAuthorizer, IngestLimits,
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


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


def build(*, authorizer=None, queued=4, message_bytes=8, sources=4, pending=4,
          stale=100, rate=1000):
    authorizer = authorizer or Authorizer()
    clock = Clock()
    ingest = AgentIngestQueue(IngestLimits(message_bytes, queued, queued * message_bytes,
                                           rate, 10 ** 12), authorizer, clock_ns=clock)
    tracker = ContinuityTracker(ContinuityLimits(sources, pending, stale), authorizer,
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
        with self.assertRaises(PermissionError):
            tracker.open_session(NODES[4])
        authorizer = Authorizer({(NODE, s) for s in SOURCES})
        tracker, _, _, _ = build(authorizer=authorizer, queued=8)
        session = tracker.open_session(NODE)
        for source in SOURCES[:4]:
            tracker.receive(session, unit(0, source=source), b"v")
        self.assertEqual("source_capacity",
                         tracker.receive(session, unit(0, source=SOURCES[4]), b"v").reason)

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

    def test_invalid_inputs_and_limits_are_rejected(self):
        for bad in ((0, 1, 1), (1, 0, 1), (1, 1, 0), (True, 1, 1)):
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
