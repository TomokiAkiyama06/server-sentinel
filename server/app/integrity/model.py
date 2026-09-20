"""Private observations and deliberately identifier-free comparison results."""

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum


class Kind(StrEnum):
    CPU = "CPU"
    MEMORY = "MEMORY"
    STORAGE = "STORAGE"
    GPU = "GPU"


class State(StrEnum):
    OK = "OK"
    CHANGED = "CHANGED"
    MISSING = "MISSING"
    NEW_DEVICE = "NEW_DEVICE"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class Component:
    kind: Kind
    location: str = field(repr=False)
    properties: tuple[tuple[str, str], ...] = field(repr=False)
    identity: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    complete: bool = True

    def __post_init__(self):
        if not self.location or len(self.location) > 256 or type(self.complete) is not bool:
            raise ValueError("INVALID_COMPONENT")
        for pairs in (self.properties, self.identity):
            if len(pairs) > 32 or len({key for key, _ in pairs}) != len(pairs):
                raise ValueError("INVALID_COMPONENT")
            if any(not key or len(key) > 64 or len(value) > 1024 for key, value in pairs):
                raise ValueError("INVALID_COMPONENT")


@dataclass(frozen=True)
class Inventory:
    components: tuple[Component, ...] = field(repr=False)
    unavailable: frozenset[Kind] = frozenset()

    def __post_init__(self):
        if len(self.components) > 1024:
            raise ValueError("INVENTORY_LIMIT")
        keys = [(item.kind, item.location) for item in self.components]
        if len(keys) != len(set(keys)):
            raise ValueError("AMBIGUOUS_INVENTORY")


@dataclass(frozen=True)
class Finding:
    kind: Kind
    state: State
    reason: str

    def __post_init__(self):
        if (not isinstance(self.kind, Kind) or not isinstance(self.state, State)
                or not isinstance(self.reason, str) or not 1 <= len(self.reason) <= 128):
            raise ValueError("INVALID_INTEGRITY_FINDING")

    @property
    def immediate(self) -> bool:
        return self.state in (State.CHANGED, State.MISSING) or (
            self.kind == Kind.STORAGE and self.state == State.UNVERIFIABLE
        )


def compare(approved: Inventory | None, current: Inventory) -> tuple[Finding, ...]:
    """Stable identity wins over enumeration order; no fingerprint invention.

    Failed category enumeration is unknown, never proof all devices vanished.
    A same-model device without a unique identifier can never produce OK.
    """
    if approved is None:
        return tuple(Finding(kind, State.UNVERIFIABLE, "BASELINE_REQUIRED") for kind in Kind)
    findings = []
    used = set()
    identity_counts = Counter((item.kind, item.identity) for item in current.components if item.identity)
    baseline_counts = Counter((item.kind, item.identity) for item in approved.components if item.identity)
    fields = Counter((item.kind, key, value) for item in current.components for key, value in item.identity)
    approved_fields = Counter((item.kind, key, value) for item in approved.components for key, value in item.identity)
    for old in approved.components:
        if old.kind in current.unavailable:
            findings.append(Finding(old.kind, State.UNVERIFIABLE, "PROBE_UNAVAILABLE"))
            continue
        candidates = [(index, item) for index, item in enumerate(current.components)
                      if index not in used and item.kind == old.kind]
        match = next(((index, item) for index, item in candidates
                      if old.identity and item.identity == old.identity), None)
        if match is None:
            # A retained unique serial/WWID still identifies a device when an
            # optional field disappears and the kernel renumbers its location.
            partial = [(index, item) for index, item in candidates
                       if any(fields[(old.kind, key, value)] == 1
                              and approved_fields[(old.kind, key, value)] == 1
                              for key, value in set(old.identity) & set(item.identity))]
            if len(partial) == 1:
                match = partial[0]
        if match is None:
            match = next(((index, item) for index, item in candidates
                          if (not old.identity or not item.identity) and item.properties == old.properties), None)
        if match is None:
            match = next(((index, item) for index, item in candidates
                          if item.location == old.location), None)
        if match is None:
            findings.append(Finding(old.kind, State.MISSING, "APPROVED_COMPONENT_ABSENT"))
            continue
        index, item = match
        used.add(index)
        old_properties, new_properties = dict(old.properties), dict(item.properties)
        old_identity, new_identity = dict(old.identity), dict(item.identity)
        changed = any(old_properties[key] != new_properties[key] for key in old_properties.keys() & new_properties.keys())
        changed = changed or any(old_identity[key] != new_identity[key] for key in old_identity.keys() & new_identity.keys())
        if changed:
            findings.append(Finding(old.kind, State.CHANGED, "APPROVED_COMPONENT_CHANGED"))
        elif not old.complete or not item.complete or old.properties != item.properties or old.identity != item.identity:
            findings.append(Finding(old.kind, State.UNVERIFIABLE, "IDENTIFIERS_OR_PROPERTIES_INCOMPLETE"))
        elif not old.identity or not item.identity:
            findings.append(Finding(old.kind, State.UNVERIFIABLE, "UNIQUE_ID_UNAVAILABLE"))
        elif identity_counts[(item.kind, item.identity)] != 1 or baseline_counts[(old.kind, old.identity)] != 1:
            findings.append(Finding(old.kind, State.UNVERIFIABLE, "AMBIGUOUS_IDENTITY"))
        else:
            findings.append(Finding(old.kind, State.OK, "IDENTITY_AND_PROPERTIES_MATCH"))
    covered = {item.kind for item in approved.components}
    for kind in (current.unavailable | approved.unavailable) - covered:
        findings.append(Finding(kind, State.UNVERIFIABLE, "PROBE_UNAVAILABLE"))
    for index, item in enumerate(current.components):
        if index not in used and item.kind not in current.unavailable:
            findings.append(Finding(item.kind, State.NEW_DEVICE, "UNAPPROVED_COMPONENT"))
    return tuple(findings)
