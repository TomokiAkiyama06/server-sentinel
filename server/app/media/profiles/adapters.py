"""Visible adapter selection when hardware acceleration is optional.

Hardware acceleration is an optimization (SPECIFICATION 6.2), never a
correctness requirement. When an accelerated adapter is missing, fails its
probe, or fails to start, selection either uses an explicitly listed software
adapter and records that fallback, or reports ``adapter_unavailable``. It
never returns an adapter silently and never probes real devices by itself:
probes and factories are supplied by an audited codec integration.

Reason codes are fixed strings. Backend exception text, device paths and
media content are never retained or exposed.
"""

from dataclasses import dataclass
from enum import StrEnum
import re
from threading import Lock
from typing import Callable

from .pipeline import AdapterFactory, AdapterUnavailable, PacketAdapter
from .planner import EncodePlan

_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_MAX_CANDIDATES = 8


class AdapterKind(StrEnum):
    HARDWARE = "hardware"
    SOFTWARE = "software"


class AccelerationPolicy(StrEnum):
    """Owner/integration choice; there is no implicit default policy."""

    PREFER_HARDWARE = "prefer_hardware"
    REQUIRE_HARDWARE = "require_hardware"
    SOFTWARE_ONLY = "software_only"


class AdapterStartFailed(Exception):
    """Every eligible adapter failed to start; carries no backend details."""


@dataclass(frozen=True)
class AdapterCandidate:
    """One audited adapter implementation.

    ``probe`` must be bounded and side-effect free; it reports whether this
    adapter supports the exact plan on this host. ``factory`` must validate
    the plan again and may raise ``AdapterUnavailable``.
    """

    name: str
    kind: AdapterKind
    probe: Callable[[EncodePlan], bool]
    factory: AdapterFactory

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME.fullmatch(self.name):
            raise ValueError("adapter name must be a short lowercase identifier")
        if not isinstance(self.kind, AdapterKind):
            raise ValueError("invalid adapter kind")
        if not callable(self.probe) or not callable(self.factory):
            raise ValueError("adapter probe and factory must be callable")


@dataclass(frozen=True)
class AdapterSelection:
    """Sanitized record of one selection attempt."""

    policy: AccelerationPolicy
    selected: str | None
    kind: AdapterKind | None
    fallback: bool
    reasons: tuple[str, ...]

    @property
    def available(self) -> bool:
        return self.selected is not None

    @property
    def state(self) -> str:
        if not self.available:
            return "unavailable"
        # A software fallback is correct output, not a recording-health
        # failure, but it must remain distinguishable from the accelerated path.
        return "software_fallback" if self.fallback else "ready"


class AdapterSelector:
    """An ``AdapterFactory`` that selects among explicit candidates.

    Pass an instance as a ``SourcePipeline`` recording or viewer factory. The
    most recent selection stays readable through ``last_selection`` so a
    health surface can show ``hardware_unavailable`` with ``software_fallback``
    instead of reporting the accelerated path as active.
    """

    def __init__(self, policy: AccelerationPolicy,
                 candidates: tuple[AdapterCandidate, ...]):
        if not isinstance(policy, AccelerationPolicy):
            raise ValueError("an explicit acceleration policy is required")
        if (not isinstance(candidates, tuple)
                or any(not isinstance(value, AdapterCandidate) for value in candidates)
                or len(candidates) > _MAX_CANDIDATES):
            raise ValueError("candidates must be a bounded tuple of adapter candidates")
        if len({value.name for value in candidates}) != len(candidates):
            raise ValueError("adapter candidate names must be unique")
        self.policy = policy
        self._candidates = candidates
        self._lock = Lock()
        self._last: AdapterSelection | None = None

    @property
    def last_selection(self) -> AdapterSelection | None:
        with self._lock:
            return self._last

    def _record(self, selection: AdapterSelection) -> None:
        with self._lock:
            self._last = selection

    def _eligible(self, kind: AdapterKind) -> tuple[AdapterCandidate, ...]:
        return tuple(value for value in self._candidates if value.kind is kind)

    def __call__(self, plan: EncodePlan) -> PacketAdapter:
        if not isinstance(plan, EncodePlan):
            raise ValueError("invalid encode plan")
        reasons: list[str] = []
        policy = self.policy
        start_failed = False
        tiers: list[AdapterKind] = []
        if policy is not AccelerationPolicy.SOFTWARE_ONLY:
            tiers.append(AdapterKind.HARDWARE)
        if policy is not AccelerationPolicy.REQUIRE_HARDWARE:
            tiers.append(AdapterKind.SOFTWARE)
        for kind in tiers:
            candidates = self._eligible(kind)
            if not candidates:
                reasons.append(f"{kind.value}_not_installed")
                if kind is AdapterKind.HARDWARE:
                    reasons.append("hardware_unavailable")
                continue
            tier_started = False
            for candidate in candidates:
                try:
                    supported = candidate.probe(plan) is True
                except Exception:
                    reasons.append(f"{kind.value}_probe_failed")
                    continue
                if not supported:
                    reasons.append(f"{kind.value}_unsupported_plan")
                    continue
                try:
                    adapter = candidate.factory(plan)
                except AdapterUnavailable:
                    reasons.append(f"{kind.value}_unsupported_plan")
                    continue
                except Exception:
                    # Never retain backend exception text, paths or media.
                    reasons.append(f"{kind.value}_start_failed")
                    start_failed = True
                    continue
                if adapter is None:
                    reasons.append(f"{kind.value}_start_failed")
                    start_failed = True
                    continue
                tier_started = True
                fallback = (kind is AdapterKind.SOFTWARE
                            and policy is AccelerationPolicy.PREFER_HARDWARE)
                if fallback:
                    reasons.append("software_fallback")
                self._record(AdapterSelection(policy, candidate.name, kind, fallback,
                                              tuple(dict.fromkeys(reasons))))
                return adapter
            if not tier_started and kind is AdapterKind.HARDWARE:
                reasons.append("hardware_unavailable")
        self._record(AdapterSelection(policy, None, None, False,
                                      tuple(dict.fromkeys(reasons))))
        if start_failed:
            # SourcePipeline maps a generic failure to adapter_start_failed.
            raise AdapterStartFailed()
        raise AdapterUnavailable()
