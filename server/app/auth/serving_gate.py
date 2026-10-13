"""The session gate every human commit uses (Issue #228 item 1, Issue #232 item 1).

Its own module so that ``app.audit.integration`` can require it without
importing the human surface (which composes ``AccessAdministration`` and would
otherwise form an import cycle). ``app.auth.human_surface`` re-exports it.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator

from .reservation import HumanAccessClosed


class ServingGate:
    """The reservation session gate, also closed while the composition is stopped.

    Issue #228 item 1: ``HumanAccess.stopped`` used to be read only at the
    request entry, so a request already past it when ``stop()`` ran, or when
    a periodic check failed, could still be authorized. ``admit()`` re-reads
    ``stopped()`` after taking the reservation gate lock, and ``epoch()`` is
    ``None`` while stopped. This is the gate every human commit uses: the
    routes' ``_authorize`` and later writes, the ceremonies (installed through
    ``PasskeyCeremonies.guard_session_gate``) and the Owner's access
    administration (``AccessAdministration`` accepts nothing else, Issue #232
    item 1). A commit admitted before ``stop()`` may still complete; none is
    admitted after it.

    ``reservation`` is the wrapped gate (in production the
    ``HostnameReservationCheck``; ``HumanAccess`` validates it), and
    ``stopped`` a callable read under its lock. A ``stopped`` that raises
    refuses the commit (fail closed).
    """

    def __init__(self, reservation, *, stopped: Callable[[], bool]):
        if (not callable(getattr(reservation, "admit", None))
                or not callable(getattr(reservation, "epoch", None)) or not callable(stopped)):
            raise ValueError("session gate is invalid")
        self.reservation = reservation
        self._stopped = stopped

    def _is_stopped(self) -> bool:
        return self._stopped() is not False

    def epoch(self) -> int | None:
        if self._is_stopped():
            return None
        return self.reservation.epoch()

    @contextmanager
    def admit(self, epoch: int | None) -> Iterator[None]:
        with self.reservation.admit(epoch):
            if self._is_stopped():
                raise HumanAccessClosed()
            yield
