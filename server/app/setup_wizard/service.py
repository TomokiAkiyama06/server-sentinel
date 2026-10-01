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

# The only step the generic Owner transition may mark ``COMPLETED``. Every
# other step records verified work (Owner bootstrap, storage mount/reserve
# checks, hardware baseline approval, source and profile setup, ...), so it may
# be completed only by that feature's own integration path once the integration
# has verified its result. No such integration exists yet, so those steps
# cannot be completed at runtime and ``deployment_ready`` cannot become true
# through this service. The Owner may still defer (``UNAVAILABLE``), skip an
# optional step, or retry (``PENDING``) through the generic path.
GENERIC_COMPLETABLE_STEPS = frozenset({WizardStep.WELCOME})


class SetupWizardService:
    """Run wizard progress changes through ``OwnerAuditService``.

    A transition is authorized as the deployment Owner first. A refused actor
    (an invited ``live:view`` / ``recordings:view`` principal, a capture-node
    credential or an unauthenticated caller) receives the bounded denial, a
    ``denied`` record is appended and the wizard state is not read or changed.
    A permitted transition commits in the same SQLite transaction as its
    ``succeeded`` record, so an audit write failure rolls the transition back.
    A rejected transition (stale revision, skipping a required step, a later
    step before an earlier one, downgrading a completed step, or completing a
    step outside ``GENERIC_COMPLETABLE_STEPS``) rolls back and is recorded as
    ``failed``. A request for the current status at the current revision
    changes nothing but is still recorded as one ``succeeded`` attempt. Records carry only the fixed action, the step's
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
            operation=lambda connection: self._generic_transition_on(
                connection, step, status, expected_revision,
            ),
        )

    def _generic_transition_on(self, connection, step: WizardStep, status: WizardStatus,
                               expected_revision: int) -> WizardSnapshot:
        # Enforced here on the server, not only by the web shell, so a
        # modified client or direct call cannot record unverified completion.
        # Raised inside the audited operation so the refusal is ``failed``.
        if status is WizardStatus.COMPLETED and step not in GENERIC_COMPLETABLE_STEPS:
            raise WizardValidationError("wizard step completion requires its integration")
        return self.store.transition_on(
            connection, step, status, expected_revision=expected_revision,
        )
