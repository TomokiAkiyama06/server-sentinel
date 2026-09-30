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
from weakref import WeakSet

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


class SelectedAdapter:
    """A started adapter bound to the selection that produced it.

    One selector may serve several paths or sources, each started at a
    different time. The selection therefore travels with the adapter it chose
    (``SourcePipeline`` exposes it as ``PathStatus.adapter_state``) instead of
    living only in one mutable selector-wide record. It stays active until the
    wrapped adapter closes successfully; a failed close keeps it visible
    because the adapter's resources remain allocated.
    """

    __slots__ = ("_adapter", "_selection", "_owner", "__weakref__")

    def __init__(self, adapter: PacketAdapter, selection: AdapterSelection,
                 owner: "AdapterSelector"):
        self._adapter = adapter
        self._selection = selection
        self._owner = owner

    @property
    def selection(self) -> AdapterSelection:
        return self._selection

    @property
    def selection_state(self) -> str:
        return self._selection.state

    def write(self, packet) -> None:
        self._adapter.write(packet)

    def reset(self) -> None:
        self._adapter.reset()

    def close(self) -> None:
        self._adapter.close()
        self._owner._released(self)


class AdapterSelector:
    """An ``AdapterFactory`` that selects among explicit candidates.

    Pass an instance as a ``SourcePipeline`` recording or viewer factory. Each
    returned adapter is a ``SelectedAdapter`` carrying its own selection, and
    ``active_selections`` lists the selections of every adapter that has not
    yet closed, so a later start on recovered hardware cannot hide an earlier
    path that is still on ``software_fallback``. ``last_selection`` is only the
    most recent attempt (including failed ones), never the state of active
    paths.
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
        # Weak references: an adapter dropped without close cannot pin memory
        # here, so tracking is bounded by the adapters callers still hold.
        self._active: WeakSet[SelectedAdapter] = WeakSet()

    @property
    def last_selection(self) -> AdapterSelection | None:
        with self._lock:
            return self._last

    @property
    def active_selections(self) -> tuple[AdapterSelection, ...]:
        with self._lock:
            return tuple(adapter.selection for adapter in self._active)

    @property
    def fallback_active(self) -> bool:
        return any(selection.fallback for selection in self.active_selections)

    def _released(self, adapter: SelectedAdapter) -> None:
        with self._lock:
            self._active.discard(adapter)

    def _record(self, selection: AdapterSelection) -> None:
        with self._lock:
            self._last = selection

    def _eligible(self, kind: AdapterKind) -> tuple[AdapterCandidate, ...]:
        return tuple(value for value in self._candidates if value.kind is kind)

    def __call__(self, plan: EncodePlan) -> SelectedAdapter:
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
                selection = AdapterSelection(policy, candidate.name, kind, fallback,
                                             tuple(dict.fromkeys(reasons)))
                selected = SelectedAdapter(adapter, selection, self)
                with self._lock:
                    self._last = selection
                    self._active.add(selected)
                return selected
            if not tier_started and kind is AdapterKind.HARDWARE:
                reasons.append("hardware_unavailable")
        self._record(AdapterSelection(policy, None, None, False,
                                      tuple(dict.fromkeys(reasons))))
        if start_failed:
            # SourcePipeline maps a generic failure to adapter_start_failed.
            raise AdapterStartFailed()
        raise AdapterUnavailable()
