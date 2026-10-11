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
