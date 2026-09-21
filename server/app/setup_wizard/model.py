"""Bounded first-run wizard vocabulary with no configuration payload fields."""

from dataclasses import dataclass
from enum import StrEnum


class WizardValidationError(ValueError):
    """Wizard state or a requested transition was invalid."""


class WizardStep(StrEnum):
    WELCOME = "welcome"
    DEPLOYMENT_OWNER = "deployment_owner"
    STORAGE = "storage"
    HARDWARE_AND_RECORDER = "hardware_and_recorder"
    LOCALE_AND_TIME = "locale_and_time"
    CAMERA_SOURCES = "camera_sources"
    DETECTION_PROFILES = "detection_profiles"
    OWNER_VERIFICATION = "owner_verification"
    SLACK = "slack"
    HUMAN_REMOTE_ACCESS = "human_remote_access"


class WizardStatus(StrEnum):
    PENDING = "pending"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"
    COMPLETED = "completed"


@dataclass(frozen=True)
class StepDefinition:
    step: WizardStep
    skippable: bool


# The order is the setup contract in docs/SETUP.md. Camera/profile and remote
# access integrations can be deferred while the shell is developed, and the
# two explicitly optional integrations can always be skipped. Core deployment
# ownership and safety steps cannot be presented as voluntarily skipped.
STEP_CATALOG = (
    StepDefinition(WizardStep.WELCOME, False),
    StepDefinition(WizardStep.DEPLOYMENT_OWNER, False),
    StepDefinition(WizardStep.STORAGE, False),
    StepDefinition(WizardStep.HARDWARE_AND_RECORDER, False),
    StepDefinition(WizardStep.LOCALE_AND_TIME, False),
    StepDefinition(WizardStep.CAMERA_SOURCES, True),
    StepDefinition(WizardStep.DETECTION_PROFILES, True),
    StepDefinition(WizardStep.OWNER_VERIFICATION, True),
    StepDefinition(WizardStep.SLACK, True),
    StepDefinition(WizardStep.HUMAN_REMOTE_ACCESS, True),
)

_DEFINITION_BY_STEP = {definition.step: definition for definition in STEP_CATALOG}


@dataclass(frozen=True)
class WizardState:
    """One bounded progress record; it deliberately cannot carry settings."""

    step: WizardStep
    status: WizardStatus
    revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.step, WizardStep) or not isinstance(self.status, WizardStatus):
            raise WizardValidationError("invalid wizard state")
        if type(self.revision) is not int or self.revision < 0:
            raise WizardValidationError("invalid wizard revision")
        if self.status is WizardStatus.SKIPPED and not _DEFINITION_BY_STEP[self.step].skippable:
            raise WizardValidationError("required wizard step cannot be skipped")


@dataclass(frozen=True)
class WizardSnapshot:
    states: tuple[WizardState, ...]

    def __post_init__(self) -> None:
        if tuple(state.step for state in self.states) != tuple(
                definition.step for definition in STEP_CATALOG):
            raise WizardValidationError("wizard state catalog does not match")

    @property
    def current_step(self) -> WizardStep | None:
        """First unresolved step, or None after every step is acknowledged."""
        return next((state.step for state in self.states
                     if state.status is WizardStatus.PENDING), None)

    @property
    def deployment_ready(self) -> bool:
        """True only when every non-skippable safety step is complete."""
        required = {item.step for item in STEP_CATALOG if not item.skippable}
        return all(state.status is WizardStatus.COMPLETED
                   for state in self.states if state.step in required)

    def state_for(self, step: WizardStep) -> WizardState:
        if not isinstance(step, WizardStep):
            raise WizardValidationError("invalid wizard step")
        return self.states[tuple(item.step for item in STEP_CATALOG).index(step)]
