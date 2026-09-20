"""Quality-bound optional 1:1 verification and explicit Owner enrollment."""

from datetime import datetime
import weakref

from app.detection.foundation import Detection, Observation, Reason
from app.detection.quality import Execution, FrameIdentity, QualityContext, QualityGate
from .contracts import (Comparison, FaceCandidate, Operation, OwnerAssessment, OwnerError, Verdict,
                        Verification, VerificationReason)
from .store import OwnerTemplateStore


class OwnerVerificationService:
    def __init__(self, store: OwnerTemplateStore, verifier=None, *, max_receipts: int = 64):
        if type(max_receipts) is not int or not 1 <= max_receipts <= 4096:
            raise ValueError("INVALID_VERIFICATION_RECEIPT_LIMIT")
        self.store = store
        self._verifier = verifier
        self._max_receipts = max_receipts
        self._issued = {}
        self._assessments = {}

    def close_session(self):
        self._issued.clear()
        self._assessments.clear()
        self._forget()

    def assess(self, candidate: FaceCandidate, gate: QualityGate, *, context: QualityContext,
               execution: Execution = Execution.READY) -> OwnerAssessment:
        if (not isinstance(candidate, FaceCandidate) or not isinstance(gate, QualityGate)
                or gate.policy.detector != "owner_verification"):
            raise ValueError("INVALID_OWNER_QUALITY_INPUT")
        decision = gate.assess(candidate.crop, execution=execution, context=context)
        ticket = OwnerAssessment(decision)
        # A weak reference binds the exact immutable crop without retaining a
        # candidate image, derived face fingerprint, or reusable biometric ID.
        self._assessments[ticket.identifier] = (ticket, weakref.ref(candidate), gate)
        while len(self._assessments) > self._max_receipts:
            self._assessments.pop(next(iter(self._assessments)))
        return ticket

    def _quality(self, candidate: FaceCandidate, gate: QualityGate, assessment: OwnerAssessment):
        if (not isinstance(candidate, FaceCandidate) or not isinstance(gate, QualityGate)
                or gate.policy.detector != "owner_verification"
                or not isinstance(assessment, OwnerAssessment)):
            return False
        issued = self._assessments.get(assessment.identifier)
        if issued is None or issued[0] is not assessment or issued[1]() is not candidate or issued[2] is not gate:
            return False
        guarded = gate.guard_result(assessment.decision, Detection(Observation.PRESENT, Reason.EVALUATED),
                                    execution=Execution.SUCCEEDED, frame=FrameIdentity.from_frame(candidate.crop))
        return guarded.observation is Observation.PRESENT

    def enroll(self, candidate: FaceCandidate, gate: QualityGate, decision: OwnerAssessment, *,
               expected_generation: int, at: datetime):
        current = self.store.status()
        # The audited label cannot go stale: generation is monotonic, and the
        # transaction re-checks it, so a concurrent enroll/delete aborts the
        # mutation instead of committing under the other operation's name.
        # Authorization stays first so an unauthorized caller learns nothing
        # about the current enrollment state.
        operation = Operation.REPLACE if current.enrolled else Operation.ENROLL
        actor = self.store._authorize(operation)
        if current.generation != expected_generation:
            raise OwnerError("TEMPLATE_GENERATION_CHANGED")
        if self._verifier is None:
            raise OwnerError("LOCAL_VERIFIER_UNAVAILABLE")
        if not self._quality(candidate, gate, decision):
            raise OwnerError("OWNER_ENROLLMENT_QUALITY_UNAVAILABLE")
        try:
            template = self._verifier.enroll(candidate.crop)
            provenance = self._verifier.provenance
        except Exception:
            raise OwnerError("OWNER_ENROLLMENT_FAILED") from None
        finally:
            self._forget()
        if not self._quality(candidate, gate, decision):
            raise OwnerError("OWNER_ENROLLMENT_QUALITY_UNAVAILABLE")
        if self.store._authorize(operation) != actor:
            raise OwnerError("OWNER_AUTHORIZATION_CHANGED")
        return self.store._replace(template, provenance, operation=operation, actor=actor,
                                   expected_generation=expected_generation, at=at)

    def _forget(self):
        if self._verifier is not None:
            try:
                self._verifier.forget_candidate()
            except Exception:
                raise OwnerError("LOCAL_VERIFIER_CLEANUP_FAILED") from None

    def verify(self, candidate: FaceCandidate, gate: QualityGate, decision: OwnerAssessment) -> Verification:
        identity = FrameIdentity.from_frame(candidate.crop)
        generation = self.store.status().generation
        def unknown(reason):
            return Verification(candidate.identifier, identity, generation, Verdict.UNKNOWN, None, reason)
        if not self._quality(candidate, gate, decision):
            return unknown(VerificationReason.QUALITY)
        if self._verifier is None:
            return unknown(VerificationReason.VERIFIER_UNAVAILABLE)
        template = self.store._load_for_verification()
        if template is None:
            return unknown(VerificationReason.UNENROLLED)
        generation = template.generation
        try:
            provenance = self._verifier.provenance
        except Exception:
            gate.invalidate(execution=Execution.FAILED)
            self._issued.clear()
            return unknown(VerificationReason.FAILURE)
        if template.provenance != provenance:
            return unknown(VerificationReason.MODEL_MISMATCH)
        result = None
        try:
            result = self._verifier.compare(candidate.crop, template.data)
        except Exception:
            pass
        finally:
            try:
                self._forget()
            except OwnerError:
                result = None
        if not isinstance(result, Comparison):
            gate.invalidate(execution=Execution.FAILED)
            self._issued.clear()
            return unknown(VerificationReason.FAILURE)
        if self.store.status().generation != generation:
            return unknown(VerificationReason.TEMPLATE_CHANGED)
        if not self._quality(candidate, gate, decision):
            return unknown(VerificationReason.QUALITY)
        verification = Verification(candidate.identifier, identity, generation, result.verdict, result.confidence,
                                    VerificationReason.EVALUATED if result.verdict != Verdict.UNKNOWN else VerificationReason.FAILURE)
        if result.verdict is Verdict.MATCH:
            self._issued[verification.receipt_id] = (verification, gate, decision.decision)
            while len(self._issued) > self._max_receipts:
                self._issued.pop(next(iter(self._issued)))
        return verification

    def is_current(self, result: Verification) -> bool:
        receipt = self._issued.get(result.receipt_id)
        if receipt is None or receipt[0] is not result:
            return False
        status = self.store.status()
        if not status.enrolled or status.generation != result.generation:
            return False
        _, gate, decision = receipt
        guarded = gate.guard_result(decision, Detection(Observation.PRESENT, Reason.EVALUATED),
                                    execution=Execution.SUCCEEDED, frame=result.frame)
        return guarded.observation is Observation.PRESENT
