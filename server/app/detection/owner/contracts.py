"""Owner-only local verification contracts; biometric bytes never enter repr."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4
import math
import re

from app.detection.foundation import GrayFrame
from app.detection.quality import FrameIdentity, QualityDecision


class OwnerError(RuntimeError):
    """Fixed non-sensitive failure category."""


class Operation(StrEnum):
    ENROLL = "ENROLL"
    REPLACE = "REPLACE"
    DELETE = "DELETE"


class Verdict(StrEnum):
    MATCH = "match"
    NO_MATCH = "no_match"
    UNKNOWN = "unknown"


class VerificationReason(StrEnum):
    EVALUATED = "evaluated"
    QUALITY = "quality_unavailable"
    UNENROLLED = "unenrolled"
    VERIFIER_UNAVAILABLE = "verifier_unavailable"
    MODEL_MISMATCH = "model_mismatch"
    TEMPLATE_CHANGED = "template_changed"
    FAILURE = "verification_failed"


@dataclass(frozen=True)
class ModelProvenance:
    """An explicitly reviewed adapter identity, not automatic license approval.

    review_id identifies the deployment's explicit model/license/threshold
    decision. This module supplies no production model or threshold defaults.
    """
    model: str
    version: str
    code_license: str
    weights_license: str
    upstream: str
    artifact_sha256: str
    comparison_policy_sha256: str
    review_id: UUID

    def __post_init__(self):
        for value in (self.model, self.version, self.code_license, self.weights_license, self.upstream):
            if type(value) is not str or not value or len(value) > 256 or any(ord(char) < 32 for char in value):
                raise ValueError("INVALID_MODEL_PROVENANCE")
        if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in (self.artifact_sha256, self.comparison_policy_sha256)):
            raise ValueError("INVALID_MODEL_PIN")
        if not isinstance(self.review_id, UUID):
            raise ValueError("MODEL_REVIEW_REQUIRED")


@dataclass(frozen=True)
class FaceCandidate:
    identifier: UUID
    crop: GrayFrame = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.identifier, UUID) or not isinstance(self.crop, GrayFrame):
            raise ValueError("INVALID_FACE_CANDIDATE")


@dataclass(frozen=True)
class OwnerAssessment:
    """Service-issued quality ticket; only that exact candidate may consume it."""
    decision: QualityDecision
    identifier: UUID = field(default_factory=uuid4, repr=False)


@dataclass(frozen=True)
class Comparison:
    verdict: Verdict
    confidence: float | None

    def __post_init__(self):
        if not isinstance(self.verdict, Verdict):
            raise ValueError("INVALID_VERDICT")
        if self.confidence is not None and (type(self.confidence) not in (int, float)
                                           or not math.isfinite(self.confidence) or not 0 <= self.confidence <= 1):
            raise ValueError("INVALID_CONFIDENCE")
        if self.verdict != Verdict.UNKNOWN and self.confidence is None:
            raise ValueError("CONCLUSION_REQUIRES_CONFIDENCE")


@dataclass(frozen=True)
class Verification:
    candidate_id: UUID
    frame: FrameIdentity
    generation: int
    verdict: Verdict
    confidence: float | None
    reason: VerificationReason
    receipt_id: UUID = field(default_factory=uuid4, repr=False)

    def __post_init__(self):
        if (not isinstance(self.candidate_id, UUID) or not isinstance(self.frame, FrameIdentity)
                or type(self.generation) is not int or self.generation < 0
                or not isinstance(self.reason, VerificationReason) or not isinstance(self.receipt_id, UUID)):
            raise ValueError("INVALID_VERIFICATION_RESULT")
        Comparison(self.verdict, self.confidence)
        if (self.verdict == Verdict.UNKNOWN) == (self.reason == VerificationReason.EVALUATED):
            raise ValueError("INVALID_VERIFICATION_REASON")


class OwnerAuthorizer(Protocol):
    def require_owner(self, operation: Operation) -> UUID:
        """Validate the current application principal; no caller-owned bool."""


class DenyOwner:
    def require_owner(self, operation: Operation) -> UUID:
        raise OwnerError("OWNER_AUTHORIZATION_REQUIRED")


class LocalVerifier(Protocol):
    """Audited, deployment-local code only; not a sandbox for arbitrary plugins.

    It must never send crops/templates externally, retain non-Owner candidates,
    automatically download weights, or treat the final threshold as preselected.
    """
    provenance: ModelProvenance

    def enroll(self, crop: GrayFrame) -> bytes:
        ...

    def compare(self, crop: GrayFrame, owner_template: bytes) -> Comparison:
        ...

    def forget_candidate(self) -> None:
        """Release candidate/intermediate face data after success or failure."""
