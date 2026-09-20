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
        # These are named fields, not ordered identities. Canonical immutable
        # pairs also prevent differently ordered duplicate IDs looking unique.
        object.__setattr__(self, "properties", tuple(sorted(self.properties)))
        object.__setattr__(self, "identity", tuple(sorted(self.identity)))


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


def _conflicts(before, after):
    before, after = dict(before), dict(after)
    return any(before[key] != after[key] for key in before.keys() & after.keys())


def _explained(claims: dict[int, set[int]]) -> set[int]:
    """Largest set of shared observations the approved components can cover.

    Hopcroft-Karp over the compatibility graph itself. Counting approved
    components per category instead would let one that no observation fits
    absorb another component's surplus observation and hide added hardware.
    """
    left, right = {}, {}

    def augment(index, depth):
        for candidate in claims[index]:
            owner = right.get(candidate)
            if owner is None or (depth.get(owner) == depth[index] + 1 and augment(owner, depth)):
                left[index], right[candidate] = candidate, index
                return True
        # Exhausted inside this layered phase; never retried at this length.
        depth[index] = -1
        return False

    while True:
        # Layer from the still unexplained components and stop at the shortest
        # augmenting length, which bounds both the phases and the recursion.
        depth = {index: 0 for index in claims if index not in left}
        frontier, reached = list(depth), False
        while frontier and not reached:
            following = []
            for index in frontier:
                for candidate in claims[index]:
                    owner = right.get(candidate)
                    if owner is None:
                        reached = True
                    elif owner not in depth:
                        depth[owner] = depth[index] + 1
                        following.append(owner)
            frontier = following
        if not reached:
            return set(right)
        for index in list(depth):
            if index not in left:
                augment(index, depth)


def compare(approved: Inventory | None, current: Inventory) -> tuple[Finding, ...]:
    """Match complete identities, unique partial identities, then weak graphs.

    Every phase considers all remaining baselines before consuming observations.
    Weak/shared observations never prove which approved device vanished, but
    observations the approved inventory cannot account for are still reported
    as NEW_DEVICE alongside the UNVERIFIABLE findings.
    """
    if approved is None:
        return tuple(Finding(kind, State.UNVERIFIABLE, "BASELINE_REQUIRED") for kind in Kind)
    old_items, new_items = approved.components, current.components
    results = [None] * len(old_items)
    used = set()
    uncertain = set()
    # Approved components exclusively bound to one observation, and the extra
    # identity links a still unbound component keeps for the surplus graph.
    bound = set()
    identified = {}
    identity_counts = Counter((item.kind, item.identity) for item in new_items if item.identity)
    baseline_counts = Counter((item.kind, item.identity) for item in old_items if item.identity)
    fields = Counter((item.kind, key, value) for item in new_items for key, value in item.identity)
    approved_fields = Counter((item.kind, key, value) for item in old_items for key, value in item.identity)

    def ambiguous(index):
        results[index] = Finding(old_items[index].kind, State.UNVERIFIABLE, "AMBIGUOUS_IDENTITY")

    def matched(index, candidate):
        old, item = old_items[index], new_items[candidate]
        if ((item.identity and identity_counts[(item.kind, item.identity)] != 1)
                or (old.identity and baseline_counts[(old.kind, old.identity)] != 1)):
            ambiguous(index)
        elif _conflicts(old.properties, item.properties) or _conflicts(old.identity, item.identity):
            results[index] = Finding(old.kind, State.CHANGED, "APPROVED_COMPONENT_CHANGED")
        elif not old.complete or not item.complete or old.properties != item.properties or old.identity != item.identity:
            results[index] = Finding(old.kind, State.UNVERIFIABLE, "IDENTIFIERS_OR_PROPERTIES_INCOMPLETE")
        elif not old.identity or not item.identity:
            results[index] = Finding(old.kind, State.UNVERIFIABLE, "UNIQUE_ID_UNAVAILABLE")
        else:
            results[index] = Finding(old.kind, State.OK, "IDENTITY_AND_PROPERTIES_MATCH")

    # First reserve all full identities, including ambiguity, independent of
    # baseline/sysfs order. Do not diff properties of an arbitrary duplicate.
    # Duplicated approved identities are only ambiguous while an observation
    # exists to choose among; with none, the later phases still prove absence.
    for index, old in enumerate(old_items):
        if old.kind in current.unavailable:
            results[index] = Finding(old.kind, State.UNVERIFIABLE, "PROBE_UNAVAILABLE")
            continue
        exact = {candidate for candidate, item in enumerate(new_items)
                 if item.kind == old.kind and old.identity and item.identity == old.identity}
        if len(exact) > 1 or (exact and baseline_counts[(old.kind, old.identity)] > 1):
            ambiguous(index)
            uncertain.update(exact)
            identified[index] = set(exact)
        elif exact:
            matched(index, next(iter(exact)))
            used.update(exact)
            bound.add(index)

    # A unique serial/WWID can survive loss of another field. The entire
    # bipartite graph must be one-to-one before drawing a property conclusion.
    partial = {}
    for index, old in enumerate(old_items):
        if results[index] is not None:
            continue
        partial[index] = {candidate for candidate, item in enumerate(new_items)
                          if candidate not in used and item.kind == old.kind
                          and any(fields[(old.kind, key, value)] == 1
                                  and approved_fields[(old.kind, key, value)] == 1
                                  for key, value in set(old.identity) & set(item.identity))}
    partial_reverse = Counter(candidate for candidates in partial.values() for candidate in candidates)
    for index, candidates in partial.items():
        if not candidates:
            continue
        if len(candidates) == 1 and partial_reverse[next(iter(candidates))] == 1:
            matched(index, next(iter(candidates)))
            used.update(candidates)
            bound.add(index)
        else:
            ambiguous(index)
            # Ambiguity claims no exclusive ownership. These observations may
            # also cover identity-less baselines in the following weak graph.
            uncertain.update(candidates)
            identified[index] = set(candidates)

    # Resolve every compatible weak link together. Missing values are not
    # contradictions, including partial non-unique serial/WWID observations.
    # Shared candidates remain ambiguous for ALL linked baselines; consuming
    # one while iterating would falsely turn a later unknown into MISSING.
    weak = {}
    for index, old in enumerate(old_items):
        if results[index] is not None:
            continue
        weak[index] = {candidate for candidate, item in enumerate(new_items)
                       if candidate not in used and item.kind == old.kind
                       and not _conflicts(old.properties, item.properties)
                       and not _conflicts(old.identity, item.identity)}
    weak_reverse = Counter(candidate for candidates in weak.values() for candidate in candidates)
    weak_used = set(weak_reverse)
    for index, candidates in weak.items():
        if not candidates:
            continue
        if len(candidates) == 1 and weak_reverse[next(iter(candidates))] == 1:
            matched(index, next(iter(candidates)))
        else:
            ambiguous(index)

    # Location is only a final drift hint after compatible identity/weak links
    # have been handled. It cannot steal a candidate reserved for another old
    # component or convert a shared weak candidate into a proven replacement.
    for index, old in enumerate(old_items):
        if results[index] is not None:
            continue
        location = next((candidate for candidate, item in enumerate(new_items)
                         if candidate not in used and item.kind == old.kind and item.location == old.location), None)
        if location is None:
            results[index] = Finding(old.kind, State.MISSING, "APPROVED_COMPONENT_ABSENT")
        elif location in weak_used or location in uncertain:
            ambiguous(index)
        else:
            matched(index, location)
            used.add(location)
            bound.add(index)
    # An ambiguous observation never proves WHICH approved component it is, but
    # one approved component still explains at most one current component, and
    # only one it could actually be. Rebuild every link an unbound component
    # keeps, whatever phase left it unbound: the same identity, a unique shared
    # identifier, a compatible observation, or its own slot as a CHANGED
    # successor. Report only what no assignment covers (SPECIFICATION 10.1-10.2).
    def links(index):
        old = old_items[index]
        return {candidate for candidate, item in enumerate(new_items)
                if candidate not in used and item.kind == old.kind
                and (candidate in identified.get(index, ()) or item.location == old.location
                     or not (_conflicts(old.properties, item.properties)
                             or _conflicts(old.identity, item.identity)))}

    linked = {index: candidates for index, candidates in
              ((index, links(index)) for index, old in enumerate(old_items)
               if index not in bound and old.kind not in current.unavailable) if candidates}
    shared = set().union(*linked.values()) if linked else set()
    explained = _explained(linked)
    surplus = (Counter(new_items[item].kind for item in shared)
               - Counter(new_items[item].kind for item in explained))
    covered = {item.kind for item in old_items}
    for kind in (current.unavailable | approved.unavailable) - covered:
        results.append(Finding(kind, State.UNVERIFIABLE, "PROBE_UNAVAILABLE"))
    for candidate, item in enumerate(new_items):
        if candidate not in used and candidate not in shared and item.kind not in current.unavailable:
            results.append(Finding(item.kind, State.NEW_DEVICE, "UNAPPROVED_COMPONENT"))
    for kind in Kind:
        results.extend([Finding(kind, State.NEW_DEVICE, "SURPLUS_AMBIGUOUS_COMPONENT")] * surplus[kind])
    return tuple(results)
