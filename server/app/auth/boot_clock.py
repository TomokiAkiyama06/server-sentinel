"""Boot-scoped monotonic time for invitation validity (Owner decision 2026-10-11).

An invitation code is a bearer authorization whose lifetime is promised in
wall-clock terms, but the wall clock can be stepped backwards (an operator, a
bad NTP source, an RTC fault), which would silently extend the code. So every
invitation also records, at issuance, the kernel boot id
(``/proc/sys/kernel/random/boot_id``) and ``CLOCK_BOOTTIME`` (monotonic,
counts suspend, never stepped). At redemption (``invitation_clock_valid``):

- the wall-clock window ``issued <= now < expires`` must hold, as before;
- on the same boot, the monotonic elapsed time must be ``>= 0`` and below the
  invitation's lifetime, and the wall-clock elapsed time must not lag it by
  more than ``CLOCK_ROLLBACK_TOLERANCE`` (a detected rollback refuses). A
  wall clock stepped forwards only makes the code expire earlier, never
  later, so it is not refused separately: the earlier of the two clocks ends
  the code;
- after a reboot the monotonic reading is not comparable, so the wall-clock
  window alone decides (a rollback across a reboot is not detectable here);
- a row without the recorded pair (issued before this release) or a host
  where the pair cannot be read now is unverifiable and refuses (fail closed).

Owner step-up freshness (Issue #10 phase 2 S3, ``step_up_fresh``) uses the
same pair: a session records the boot id and ``CLOCK_BOOTTIME`` read together
with its in-transaction user-verification time, and an ``OWNER_OP`` request is
fresh only on the same boot, with both clocks inside the window and no
detected wall-clock step back. Unlike an invitation, a step-up is cheap to
repeat, so another boot, a missing pair or an unreadable clock is stale (fail
closed) rather than left to the wall clock (Owner decision 2026-10-12, PR
#236: a reboot, or a session established before migration 23, is stale).

Every refusal is the caller's generic denial; nothing here carries a value.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import re
import time


BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Allowance for the instant between the two reads of one wall/boot pair (the
# store samples them together, never across a lock or admission wait), not
# for clock steps: NTP slews both clocks together, so only a step separates
# them.
CLOCK_ROLLBACK_TOLERANCE = timedelta(seconds=30)
_TOLERANCE_US = CLOCK_ROLLBACK_TOLERANCE // timedelta(microseconds=1)
# Step-up freshness: both readings come from one in-transaction pair at each
# end, and one second is the allowance for the instant between the two reads
# of a pair; any larger lag of the wall clock behind the monotonic one makes
# the session stale. The slew rate is not bounded here: chrony's default
# ``maxslewrate`` is 83333 ppm (25 s over five minutes), not ntpd's 500 ppm.
# clock_gettime(2) documents CLOCK_MONOTONIC (and so CLOCK_BOOTTIME) as
# following adjtime/NTP adjustments, so a slew should move both clocks
# together and only a step (chrony ``makestep``, a manual set, a kernel leap
# second) separate them; if a slew back ever did separate them by more than a
# second, a just-verified session turns stale. Every such case fails closed:
# availability only (the Owner steps up again), never a longer window.
# MANUAL_TEST "Issue #10 phase 2 S3" records the observation on the host.
STEP_UP_ROLLBACK_TOLERANCE = timedelta(seconds=1)
_STEP_UP_TOLERANCE_US = STEP_UP_ROLLBACK_TOLERANCE // timedelta(microseconds=1)


@dataclass(frozen=True)
class BootInstant:
    """A kernel boot id and the ``CLOCK_BOOTTIME`` reading in microseconds."""

    boot_id: str
    boottime_us: int

    def __post_init__(self) -> None:
        if not valid_boot_id(self.boot_id) or type(self.boottime_us) is not int or self.boottime_us < 0:
            raise ValueError("boot instant is invalid")


def valid_boot_id(value: object) -> bool:
    return isinstance(value, str) and _BOOT_ID.fullmatch(value) is not None


def read_boot_instant() -> BootInstant | None:
    """The current ``BootInstant``, or ``None`` when it cannot be read."""
    try:
        with open(BOOT_ID_PATH, "r", encoding="ascii") as handle:
            boot_id = handle.read(64).strip()
        return BootInstant(boot_id, time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1000)
    except (OSError, ValueError, AttributeError, UnicodeDecodeError):
        return None


def invitation_clock_valid(*, issued_us: int, expires_us: int, issued_boot_id: object,
                           issued_boottime_us: object, now_us: int, now: object,
                           max_lifetime_us: int) -> bool:
    """Whether an invitation is inside its lifetime on both clocks (see module doc)."""
    if not isinstance(now, BootInstant) or not valid_boot_id(issued_boot_id):
        return False
    if type(issued_boottime_us) is not int or issued_boottime_us < 0:
        return False
    lifetime = expires_us - issued_us
    if not 0 < lifetime <= max_lifetime_us or not issued_us <= now_us < expires_us:
        return False
    if now.boot_id != issued_boot_id:
        # Another boot: the monotonic readings are unrelated; the wall-clock
        # window above decides.
        return True
    elapsed = now.boottime_us - issued_boottime_us
    if elapsed < 0 or elapsed >= lifetime:
        return False
    # A wall clock behind the monotonic one was stepped back: refuse.
    return now_us - issued_us >= elapsed - _TOLERANCE_US


def step_up_fresh(*, verified_us: object, verified_boot_id: object, verified_boottime_us: object,
                  now_us: int, now: object, freshness_us: int) -> bool:
    """Whether a user verification is inside the step-up window on both clocks.

    Fresh only when all hold: a verification pair was recorded and one is
    read now, on the same boot; ``0 <= now - verified < freshness`` on the
    wall clock and on ``CLOCK_BOOTTIME``; and the wall clock does not lag the
    monotonic one by more than ``STEP_UP_ROLLBACK_TOLERANCE`` (a wall clock
    stepped back after the verification makes the session stale instead of
    stretching the window). A wall clock stepped forwards ends the window
    early. Everything else is stale (fail closed).
    """
    if type(freshness_us) is not int or freshness_us <= 0 or type(now_us) is not int:
        return False
    if type(verified_us) is not int or type(verified_boottime_us) is not int or verified_boottime_us < 0:
        return False
    if not isinstance(now, BootInstant) or not valid_boot_id(verified_boot_id) or now.boot_id != verified_boot_id:
        return False
    wall = now_us - verified_us
    monotonic = now.boottime_us - verified_boottime_us
    if not 0 <= wall < freshness_us or not 0 <= monotonic < freshness_us:
        return False
    return wall >= monotonic - _STEP_UP_TOLERANCE_US
