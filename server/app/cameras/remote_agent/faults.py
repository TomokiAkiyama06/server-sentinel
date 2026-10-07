"""Named crash points for fault-injection tests (Issue #109).

``reached(point)`` is called at every step of the multi-file CA, listener
and ledger writes where a crash leaves a distinct on-disk state. In
production it does nothing; tests replace it to stop a command exactly
there and then check that the next run of every command converges. No
option, setting or environment variable enables anything here.
"""
from __future__ import annotations


def reached(point: str) -> None:
    """A crash point; deliberately a no-op outside tests."""
    return None
