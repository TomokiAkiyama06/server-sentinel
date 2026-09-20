"""Exercise real private persistence with a generated, deliberately fake verifier."""

from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from app.detection.owner.contracts import FaceCandidate, Verdict
from app.detection.owner.service import OwnerVerificationService
from app.detection.owner.store import OwnerTemplateStore
from app.detection.quality import QualityGate
from tests.test_detector_quality import SOURCE, assess, calibrated_policy, context, synthetic_person
from tests.test_owner_verification import SyntheticAuthorizer, SyntheticVerifier


def run_owner_smoke(scenario):
    with TemporaryDirectory(prefix="synthetic-owner-") as temporary:
        store = OwnerTemplateStore(Path(temporary), max_template_bytes=1024,
                                   reservation=nullcontext, authorizer=SyntheticAuthorizer())
        verifier = SyntheticVerifier()
        service = OwnerVerificationService(store, verifier)
        gate = QualityGate(SOURCE, calibrated_policy("owner_verification"))
        assess(gate, synthetic_person(0))
        candidate = FaceCandidate(uuid4(), synthetic_person(1))
        quality = service.assess(candidate, gate, context=context(candidate.crop))
        try:
            service.enroll(candidate, gate, quality, expected_generation=0, at=datetime.now(timezone.utc))
            if scenario == "error":
                def fail():
                    raise RuntimeError("SYNTHETIC_PRIVATE_BIOMETRIC_VALUE")
                verifier.callback = fail
            result = service.verify(candidate, gate, quality)
            assert result.verdict == (Verdict.UNKNOWN if scenario == "error" else Verdict.MATCH)
            assert set(store.diagnostic_snapshot()) == {"enrolled", "generation"}
            store.delete(expected_generation=1, at=datetime.now(timezone.utc))
            assert not service.is_current(result)
            assert not store.status().enrolled
            assert not verifier.candidates
        finally:
            service.close_session()
            store.close()
