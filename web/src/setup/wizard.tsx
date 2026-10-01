import {
  currentWizardStep, optionalWizardSteps, shellCompletableWizardSteps, wizardDeploymentReady,
  type WizardSnapshot, type WizardStatus, type WizardStep, type WizardStepState,
} from '../domain';
import { type Catalog } from '../i18n';

export type WizardTransition = (state: WizardStepState, status: WizardStatus) => void;

/** Owner-only first-run wizard shell.
 *
 * It renders progress only: step, status and the fixed explanation of each
 * step. No setting, secret, raw hardware identifier or biometric value reaches
 * it, because the snapshot carries none. Controls render only when an
 * authorized Owner transition provider is wired (`onTransition`); the server
 * authorizes, audits and may refuse every transition. The shell completes only
 * the explanatory Welcome step. Any other unfinished area can be deferred as
 * unavailable (or skipped when optional), which is never shown as completed.
 */
export function WizardView({ t, snapshot, onTransition, busy = false, failed = false }: {
  t: Catalog; snapshot: WizardSnapshot; onTransition?: WizardTransition | undefined;
  busy?: boolean | undefined; failed?: boolean | undefined;
}) {
  const current = currentWizardStep(snapshot);
  const ready = wizardDeploymentReady(snapshot);
  return <section className="wizard">
    <p className="muted">{t.wizardIntro}</p>
    <p role="status" data-wizard-ready={ready ? 'true' : 'false'}>
      <strong>{ready ? t.wizardReady : t.wizardNotReady}</strong>
    </p>
    {failed && <p role="alert" data-wizard-failed="true">{t.wizardActionFailed}</p>}
    {!onTransition && <p className="muted" data-wizard-readonly="true">{t.wizardOwnerOnly}</p>}
    <ol className="wizard-steps" aria-label={t.wizardProgressLabel}>
      {snapshot.states.map(state => <WizardStepItem key={state.step} t={t} state={state}
        current={state.step === current} onTransition={onTransition} busy={busy} />)}
    </ol>
    <p className="muted">{t.wizardAuditNote}</p>
  </section>;
}

function WizardStepItem({ t, state, current, onTransition, busy }: {
  t: Catalog; state: WizardStepState; current: boolean;
  onTransition?: WizardTransition | undefined; busy: boolean;
}) {
  const optional = optionalWizardSteps.includes(state.step);
  const completable = shellCompletableWizardSteps.includes(state.step);
  const action = (status: WizardStatus, label: string) =>
    <button type="button" disabled={busy} data-wizard-action={status}
      onClick={() => onTransition?.(state, status)}>{label}</button>;
  return <li className={`wizard-step wizard-${state.status}${current ? ' wizard-current' : ''}`}
    data-wizard-step={state.step} data-wizard-status={state.status}
    aria-current={current ? 'step' : undefined}>
    <div className="wizard-step-heading">
      <h2>{t[`wizardStep_${state.step}`]}</h2>
      <span className="badge">{optional ? t.wizardOptional : t.wizardRequired}</span>
      <span className={`badge wizard-status-${state.status}`}>{t[`wizardStatus_${state.status}`]}</span>
    </div>
    <p className="muted">{t[`wizardStepHint_${state.step}`]}</p>
    <StepDetail step={state.step} t={t} />
    {state.status === 'unavailable' && <p className="muted">{t.wizardUnavailableNote}</p>}
    {current && !completable && <p className="muted">{t.wizardIntegrationPending}</p>}
    {onTransition && current && <div className="wizard-actions">
      {completable && action('completed', t.wizardContinue)}
      {!completable && action('unavailable', t.wizardDefer)}
      {optional && action('skipped', t.wizardSkip)}
    </div>}
    {onTransition && (state.status === 'unavailable' || state.status === 'skipped') &&
      <div className="wizard-actions">{action('pending', t.wizardRetry)}</div>}
  </li>;
}

/** Fixed explanatory content. The access step keeps the two gates separate. */
function StepDetail({ step, t }: { step: WizardStep; t: Catalog }) {
  if (step === 'welcome') {
    return <ul className="wizard-points">
      <li>{t.welcomeSelfHosted}</li>
      <li>{t.welcomeVideoOnly}</li>
      <li>{t.welcomeSources}</li>
      <li>{t.welcomeViewers}</li>
      <li>{t.welcomeNoNativeApp}</li>
    </ul>;
  }
  if (step === 'human_remote_access') {
    return <div className="wizard-gates">
      <ol>
        <li data-access-gate="network"><strong>{t.accessGateNetworkTitle}</strong> {t.accessGateNetwork}</li>
        <li data-access-gate="application"><strong>{t.accessGateApplicationTitle}</strong> {t.accessGateApplication}</li>
      </ol>
      <p>{t.accessGateIndependent}</p>
      <p className="muted">{t.accessGateNoTailscaleAdmin}</p>
    </div>;
  }
  return null;
}
