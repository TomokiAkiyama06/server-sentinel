"""Per-source profile allowlists and atomic active-source admission.

The allowlists are populated by an audited capture/codec integration after it
has inspected that particular source.  This module deliberately supplies no
camera modes or resource thresholds: real deployment defaults still require
the hardware benchmark.
"""

from dataclasses import dataclass, field
from threading import Lock
from uuid import UUID

from app.cameras.registry.models import SourceType

from .model import (
    SourceProfiles,
)


@dataclass(frozen=True)
class SourceProfileCapabilities:
    """Exact profile choices established for one physical/logical source."""

    source_id: UUID
    source_type: SourceType
    profile_sets: tuple[SourceProfiles, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, UUID) or not isinstance(self.source_type, SourceType):
            raise ValueError("invalid source capability identity")
        if (not isinstance(self.profile_sets, tuple) or not self.profile_sets
                or any(not isinstance(value, SourceProfiles) for value in self.profile_sets)
                or len(set(self.profile_sets)) != len(self.profile_sets)):
            raise ValueError("profile capabilities must be a nonempty unique tuple")
        formats = (
            *(profiles.capture.format for profiles in self.profile_sets),
            *(profiles.recording.format for profiles in self.profile_sets),
            *(profiles.viewer.format for profiles in self.profile_sets),
        )
        if any(not format_.verified or not format_.video_only for format_ in formats):
            raise ValueError("profile capabilities must be verified as video-only")


@dataclass(frozen=True)
class AdmissionDecision:
    admitted: bool
    reasons: tuple[str, ...]
    lease: "AdmissionLease | None" = None


@dataclass(frozen=True)
class AdmissionLease:
    """Generation-bound ownership used by one admitted pipeline lifecycle."""

    source_id: UUID
    generation: int
    profile_sets: tuple[SourceProfiles, ...]
    _owner: "SourceProfileAdmissions" = field(repr=False, compare=False)

    def permits(self, profiles: SourceProfiles) -> bool:
        return self._owner.permits(self, profiles)

    def _claim(self, profiles: SourceProfiles) -> "_PipelineClaim | None":
        return self._owner._claim_pipeline(self, profiles)


@dataclass(frozen=True)
class _PipelineClaim:
    """Opaque ownership capability retained only by its SourcePipeline."""

    source_id: UUID
    lease: AdmissionLease = field(repr=False)
    _owner: "SourceProfileAdmissions" = field(repr=False, compare=False)

    @property
    def active(self) -> bool:
        return self._owner._owns_pipeline(self)

    def transition(self, profiles: SourceProfiles) -> bool:
        return self._owner._transition_pipeline(self, profiles)

    def release(self) -> bool:
        return self._owner._release_pipeline(self)


class SourceProfileAdmissions:
    """Atomically admit explicit profiles without inventing source defaults.

    The camera registry remains authoritative for source records and its own
    enabled-source limit.  This scheduler-local guard independently prevents a
    caller from constructing more active media pipelines than its explicitly
    configured limit and prevents one source's allowlist being reused for
    another source or source type.
    """

    def __init__(self, maximum_active_sources: int):
        if type(maximum_active_sources) is not int or maximum_active_sources <= 0:
            raise ValueError("maximum_active_sources must be a positive integer")
        self.maximum_active_sources = maximum_active_sources
        self._profiles: dict[UUID, SourceProfiles] = {}
        self._source_types: dict[UUID, SourceType] = {}
        self._leases: dict[UUID, AdmissionLease] = {}
        self._pipeline_owners: dict[UUID, _PipelineClaim] = {}
        self._next_generation = 1
        self._lock = Lock()

    def admit(self, capabilities: SourceProfileCapabilities,
              profiles: SourceProfiles) -> AdmissionDecision:
        if not isinstance(capabilities, SourceProfileCapabilities):
            raise ValueError("invalid source capabilities")
        if not isinstance(profiles, SourceProfiles):
            raise ValueError("invalid source profiles")
        reasons = [] if profiles in capabilities.profile_sets else ["profile_set_unsupported"]
        with self._lock:
            known_type = self._source_types.get(capabilities.source_id)
            if known_type is not None and known_type is not capabilities.source_type:
                reasons.append("source_type_changed")
            if (capabilities.source_id not in self._profiles
                    and len(self._profiles) >= self.maximum_active_sources):
                reasons.append("active_source_limit")
            if self._pipeline_owners.get(capabilities.source_id) is not None:
                reasons.append("pipeline_active")
            if reasons:
                return AdmissionDecision(False, tuple(reasons))
            lease = AdmissionLease(capabilities.source_id, self._next_generation,
                                   capabilities.profile_sets, self)
            self._next_generation += 1
            self._profiles[capabilities.source_id] = profiles
            self._source_types[capabilities.source_id] = capabilities.source_type
            self._leases[capabilities.source_id] = lease
            return AdmissionDecision(True, (), lease)

    def release(self, lease: AdmissionLease) -> bool:
        if not isinstance(lease, AdmissionLease):
            raise ValueError("invalid admission lease")
        with self._lock:
            if self._leases.get(lease.source_id) is not lease:
                return False
            if self._pipeline_owners.get(lease.source_id) is not None:
                return False
            self._profiles.pop(lease.source_id, None)
            self._leases.pop(lease.source_id, None)
            return True

    def permits(self, lease: AdmissionLease,
                profiles: SourceProfiles | None = None) -> bool:
        if not isinstance(lease, AdmissionLease) or lease._owner is not self:
            return False
        with self._lock:
            return (self._leases.get(lease.source_id) is lease
                    and (profiles is None or self._profiles.get(lease.source_id) == profiles))

    def _claim_pipeline(self, lease: AdmissionLease,
                        profiles: SourceProfiles) -> _PipelineClaim | None:
        """Atomically bind the current selected set to one pipeline instance."""
        if (not isinstance(lease, AdmissionLease) or lease._owner is not self
                or not isinstance(profiles, SourceProfiles)):
            return None
        with self._lock:
            if (self._leases.get(lease.source_id) is not lease
                    or self._profiles.get(lease.source_id) != profiles
                    or self._pipeline_owners.get(lease.source_id) is not None):
                return None
            claim = _PipelineClaim(lease.source_id, lease, self)
            self._pipeline_owners[lease.source_id] = claim
            return claim

    def _owns_pipeline(self, claim: _PipelineClaim) -> bool:
        if not isinstance(claim, _PipelineClaim) or claim._owner is not self:
            return False
        with self._lock:
            return (self._leases.get(claim.source_id) is claim.lease
                    and self._pipeline_owners.get(claim.source_id) is claim)

    def _release_pipeline(self, claim: _PipelineClaim) -> bool:
        if not isinstance(claim, _PipelineClaim) or claim._owner is not self:
            return False
        with self._lock:
            if self._pipeline_owners.get(claim.source_id) is not claim:
                return False
            self._pipeline_owners.pop(claim.source_id, None)
            return True

    def _transition_pipeline(self, claim: _PipelineClaim,
                             profiles: SourceProfiles) -> bool:
        """Validate and publish a live generation's complete profile set."""
        if (not isinstance(claim, _PipelineClaim) or claim._owner is not self
                or not isinstance(profiles, SourceProfiles)):
            return False
        with self._lock:
            if (self._leases.get(claim.source_id) is not claim.lease
                    or self._pipeline_owners.get(claim.source_id) is not claim
                    or profiles not in claim.lease.profile_sets):
                return False
            self._profiles[claim.source_id] = profiles
            return True

    def admitted(self, source_id: UUID) -> SourceProfiles | None:
        if not isinstance(source_id, UUID):
            raise ValueError("source_id must be a UUID")
        with self._lock:
            return self._profiles.get(source_id)

    @property
    def active_sources(self) -> int:
        with self._lock:
            return len(self._profiles)
