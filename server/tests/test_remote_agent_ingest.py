"""Synthetic coverage for the transport-neutral remote-agent ingest boundary."""

import unittest
from uuid import UUID

from app.cameras.remote_agent.ingest import (
    AgentAction, AgentIngestQueue, AgentMessage, DenyIngestAuthorizer,
    IngestLimits, IngestOutcome,
)

NODE, OTHER_NODE = UUID(int=1), UUID(int=2)
SOURCE, OTHER_SOURCE = UUID(int=11), UUID(int=12)


class Authorizer:
    def __init__(self, *, nodes=(NODE,), sources=((NODE, SOURCE),)):
        self.nodes, self.sources = set(nodes), set(sources)
        self.calls = []

    def require_node(self, node_id):
        self.calls.append(("node", node_id))
        if node_id not in self.nodes:
            raise PermissionError

    def require_source(self, node_id, source_id):
        self.calls.append(("source", node_id, source_id))
        if (node_id, source_id) not in self.sources:
            raise PermissionError


def message(*, node=NODE, source=SOURCE, sequence=0, payload=b"video", action=AgentAction.MEDIA):
    return AgentMessage(node, source, action, sequence, payload)


def queue(*, limits=None, authorizer=None, now=None):
    return AgentIngestQueue(
        limits or IngestLimits(8, 2, 10, 2, 100),
        authorizer or Authorizer(),
        clock_ns=(now if now is not None else lambda: 0),
    )


class RemoteAgentIngestTests(unittest.TestCase):
    def test_deny_by_default_and_unknown_node_or_source_never_queue_media(self):
        denied = queue(authorizer=DenyIngestAuthorizer())
        self.assertEqual(IngestOutcome.REJECTED, denied.submit(message()).outcome)
        self.assertEqual(0, denied.snapshot().queued_messages)
        boundary = queue(authorizer=Authorizer(nodes=(NODE,), sources=()))
        result = boundary.submit(message())
        self.assertEqual((IngestOutcome.REJECTED, "unauthorized"), (result.outcome, result.reason))
        self.assertEqual(1, boundary.snapshot().rejected)

    def test_only_narrow_typed_messages_with_uuid_identity_and_bytes_are_accepted(self):
        with self.assertRaises(ValueError):
            AgentMessage(NODE, SOURCE, "media", 0, b"")
        with self.assertRaises(ValueError):
            AgentMessage(NODE, SOURCE, AgentAction.MEDIA, -1, b"")
        with self.assertRaises(ValueError):
            AgentMessage(NODE, SOURCE, AgentAction.MEDIA, 0, bytearray(b"x"))
        boundary = queue()
        accepted = boundary.submit(message(payload=b"opaque"))
        self.assertEqual(IngestOutcome.ACCEPTED, accepted.outcome)
        self.assertEqual((message(payload=b"opaque"),), boundary.drain(1))

    def test_size_and_queue_limits_refuse_without_eviction_and_drain_releases_capacity(self):
        boundary = queue(limits=IngestLimits(6, 2, 7, 10, 100))
        self.assertEqual("message_too_large", boundary.submit(message(payload=b"1234567")).reason)
        self.assertEqual(IngestOutcome.ACCEPTED, boundary.submit(message(sequence=1, payload=b"1234")).outcome)
        full = boundary.submit(message(sequence=2, payload=b"1234"))
        self.assertEqual((IngestOutcome.BACKPRESSURED, "queue_limit"), (full.outcome, full.reason))
        self.assertEqual((message(sequence=1, payload=b"1234"),), boundary.drain(1))
        self.assertEqual(IngestOutcome.ACCEPTED, boundary.submit(message(sequence=3, payload=b"1234")).outcome)
        self.assertEqual((1, 4, 1, 1), (boundary.snapshot().queued_messages, boundary.snapshot().queued_bytes,
                                         boundary.snapshot().rejected, boundary.snapshot().backpressured))

    def test_authenticated_refusals_consume_rate_budget_but_keep_their_specific_reason(self):
        oversized = queue(limits=IngestLimits(4, 4, 16, 2, 100))
        self.assertEqual("message_too_large", oversized.submit(message(payload=b"12345")).reason)
        self.assertEqual("message_too_large", oversized.submit(message(sequence=1, payload=b"12345")).reason)
        rate_limited = oversized.submit(message(sequence=2, payload=b"12345"))
        self.assertEqual((IngestOutcome.RATE_LIMITED, "rate_limit"),
                         (rate_limited.outcome, rate_limited.reason))

        pressured = queue(limits=IngestLimits(4, 1, 4, 2, 100))
        self.assertEqual(IngestOutcome.ACCEPTED, pressured.submit(message(payload=b"1234")).outcome)
        pressured_result = pressured.submit(message(sequence=1, payload=b"1"))
        self.assertEqual((IngestOutcome.BACKPRESSURED, "queue_limit"),
                         (pressured_result.outcome, pressured_result.reason))
        rate_limited = pressured.submit(message(sequence=2, payload=b"1"))
        self.assertEqual((IngestOutcome.RATE_LIMITED, "rate_limit"),
                         (rate_limited.outcome, rate_limited.reason))

    def test_rate_is_per_authenticated_node_and_windowed_by_injected_monotonic_clock(self):
        now = [0]
        boundary = queue(authorizer=Authorizer(nodes=(NODE, OTHER_NODE),
                                                sources=((NODE, SOURCE), (OTHER_NODE, OTHER_SOURCE))),
                         now=lambda: now[0], limits=IngestLimits(8, 8, 64, 2, 100))
        self.assertEqual(IngestOutcome.ACCEPTED, boundary.submit(message(sequence=1)).outcome)
        self.assertEqual(IngestOutcome.ACCEPTED, boundary.submit(message(sequence=2)).outcome)
        self.assertEqual(IngestOutcome.RATE_LIMITED, boundary.submit(message(sequence=3)).outcome)
        self.assertEqual(IngestOutcome.ACCEPTED, boundary.submit(message(node=OTHER_NODE, source=OTHER_SOURCE)).outcome)
        now[0] = 100
        self.assertEqual(IngestOutcome.ACCEPTED, boundary.submit(message(sequence=4)).outcome)
        now[0] = 99
        self.assertEqual("clock_regression", boundary.submit(message(sequence=5)).reason)
        self.assertEqual(1, boundary.snapshot().rate_limited)

    def test_invalid_limits_dependencies_and_drain_are_rejected_without_network_or_health_claims(self):
        for limits in (IngestLimits(1, 1, 1, 1, 1),):
            self.assertIsInstance(limits, IngestLimits)
        with self.assertRaises(ValueError):
            IngestLimits(2, 1, 1, 1, 1)
        with self.assertRaises(ValueError):
            AgentIngestQueue(IngestLimits(1, 1, 1, 1, 1), object(), clock_ns=lambda: 0)
        boundary = queue()
        with self.assertRaises(ValueError):
            boundary.drain(0)
        self.assertEqual((0, 0, 0, 0, 0), tuple(boundary.snapshot().__dict__.values()))


if __name__ == "__main__":
    unittest.main()
