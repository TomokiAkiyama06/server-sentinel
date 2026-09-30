"""Owner-only, audited first-run wizard transitions.

This module registers no route. Human routes stay blocked on the accepted
per-person credential boundary (ADR-0004); a future route must reach wizard
progress only through this service on the human dashboard listener, never
through the capture ingest listener.
"""

from uuid import UUID, uuid5

from app.audit.model import ActorCategory, AuditAction, TargetKind
from app.audit.service import OwnerAuditService, OwnerAuthorizationError

from .model import STEP_CATALOG, WizardSnapshot, WizardStatus, WizardStep, WizardValidationError
from .store import WizardStateStore


# Fixed namespace for the per-step logical audit targets. The derived IDs name
# a wizard step only; they carry no setting, secret or hardware value.
WIZARD_STEP_NAMESPACE = UUID("3b8f2f64-6c1e-4d8e-9a57-0f2d6c5b7e10")
WIZARD_STEP_TARGETS = {
    definition.step: uuid5(WIZARD_STEP_NAMESPACE, definition.step.value)
    for definition in STEP_CATALOG
}


class SetupWizardService:
    """Run wizard progress changes through ``OwnerAuditService``.

    A transition is authorized as the deployment Owner first. A refused actor
    (an invited ``live:view`` / ``recordings:view`` principal, a capture-node
    credential or an unauthenticated caller) receives the bounded denial, a
    ``denied`` record is appended and the wizard state is not read or changed.
    A permitted transition commits in the same SQLite transaction as its
    ``succeeded`` record, so an audit write failure rolls the transition back.
    A rejected transition (stale revision, skipping a required step, a later
    step before an earlier one, or downgrading a completed step) rolls back and
    is recorded as ``failed``. Records carry only the fixed action, the step's
    logical UUID and the outcome, never the requested status or any value.
    """

    def __init__(self, audit_service: OwnerAuditService, store: WizardStateStore):
        if not isinstance(audit_service, OwnerAuditService):
            raise TypeError("audited Owner service is required")
        if not isinstance(store, WizardStateStore):
            raise TypeError("wizard state store is required")
        if getattr(audit_service.store, "database", None) != store.database:
            # The audit row must share the transition's SQLite transaction.
            raise ValueError("wizard audit must share the wizard database")
        self.audit = audit_service
        self.store = store

    def _require_owner(self, actor_context: object) -> None:
        try:
            self.audit.authorizer.require_owner(actor_context)
        except OwnerAuthorizationError:
            raise
        except PermissionError:
            # Never read or forward a foreign authorizer's detail: it may
            # contain identity. The bounded denial is all the caller learns.
            raise OwnerAuthorizationError(ActorCategory.UNAUTHENTICATED) from None

    def snapshot(self, actor_context: object) -> WizardSnapshot:
        """Read wizard progress for the deployment Owner only.

        A refused read writes nothing, like audit reading, so an unauthorized
        caller cannot grow the audit table.
        """
        self._require_owner(actor_context)
        return self.store.snapshot()

    def transition(self, actor_context: object, step: WizardStep, status: WizardStatus,
                   *, expected_revision: int) -> WizardSnapshot:
        """Apply one audited compare-and-swap transition and return the result."""
        if not isinstance(step, WizardStep):
            # The audit target is derived from the step, so an invalid step is
            # refused before authorization. It carries no deployment state.
            raise WizardValidationError("invalid wizard step")
        return self.audit.execute_transactional(
            actor_context, action=AuditAction.TRANSITION_SETUP_WIZARD_STEP,
            target_kind=TargetKind.SETUP_WIZARD_STEP,
            target_logical_id=WIZARD_STEP_TARGETS[step],
            operation=lambda connection: self.store.transition_on(
                connection, step, status, expected_revision=expected_revision,
            ),
        )
