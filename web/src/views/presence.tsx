import { useEffect, useState } from 'react';
import type { CriticalPath, DashboardServices, PresenceReport, PresenceSnapshot } from '../domain';
import type { Messages } from '../i18n';

function stamp(value: string): string {
  return value.slice(0, 19).replace('T', ' ');
}

/** Reports the three path states separately: unknown is not a known failure. */
function Path({ label, state, t }: { label: string; state: CriticalPath; t: Messages }) {
  return <div className={`presence-armed presence-path-${state}`}>
    <dt>{label}</dt><dd>{t[`path_${state}`]}</dd>
  </div>;
}

export function PresenceBody({ report, t, onCancel, failed }: {
  report: PresenceReport; t: Messages; onCancel?: (() => void) | undefined; failed?: boolean | undefined;
}) {
  const snapshot: PresenceSnapshot = report.snapshot;
  const override = snapshot.basis === 'manual_override';
  const paths: readonly CriticalPath[] = [snapshot.critical_detection, snapshot.critical_persistence,
    snapshot.critical_evidence, snapshot.critical_notifications];
  // Claim continuity only when every reported path is armed and none degraded.
  const allArmed = paths.every(state => state === 'armed');
  const armed = allArmed && !snapshot.critical_paths_degraded;
  // The backend suppresses ordinary automation only for a trusted PRESENT.
  const expectedSuppression = snapshot.state === 'PRESENT' && !snapshot.clock_degraded;
  return <section className="presence-screen">
    <section className={`presence-state presence-${snapshot.state}`} aria-label={t.presenceCurrent}>
      <p className="eyebrow">{t.presenceCurrent}</p>
      <p className="presence-value">{t[`state_${snapshot.state}`]}</p>
      <p className="muted">{t.presenceBasis}: {t[`basis_${snapshot.basis}`]}</p>
      {snapshot.clock_degraded && <p className="timeline-degraded" role="status">{t.clockDegradedNotice}</p>}
    </section>
    <section className="presence-override" aria-label={t.overrideCancel}>
      <h2>{t.basis_manual_override}</h2>
      <p>{override ? t.overrideActive : t.overrideNone}</p>
      <p className="muted">{t.overridePrecedence}</p>
      {override && <p>{t.overrideExpires}: {snapshot.override_expires_at
        ? stamp(snapshot.override_expires_at) : t.overrideNoExpiry}</p>}
      {override && <button type="button" className="primary" disabled={!onCancel}
        onClick={() => onCancel?.()}>{t.overrideCancel}</button>}
      {override && !onCancel && <p className="muted">{t.foundation}</p>}
      {snapshot.override_expiry_pending && <p className="timeline-degraded" role="alert">{t.overrideExpiryPending}</p>}
      {failed && <p role="alert">{t.overrideFailed}</p>}
    </section>
    <section className="presence-automation" aria-label={t.armedNotification}>
      {snapshot.suppress_ordinary !== expectedSuppression ? <>
        <p className="timeline-degraded" role="alert">{t.suppressMismatch}</p>
        <p className="muted">{t.suppressReported}: {snapshot.suppress_ordinary ? t.suppressActive : t.suppressInactive}</p>
      </> : snapshot.suppress_ordinary ? <p>{t.suppressOn}</p>
        : <p>{snapshot.state === 'PRESENT' ? t.suppressClockDegraded : t.suppressOff}</p>}
      {armed ? <p>{t.criticalArmed}</p>
        : <p className="timeline-degraded" role="alert">
          {allArmed ? t.criticalAggregateDegraded : t.criticalNotArmed}</p>}
      <h2>{t.criticalPaths}</h2>
      <dl className="presence-armed-list">
        <Path label={t.armedDetection} state={snapshot.critical_detection} t={t} />
        <Path label={t.armedPersistence} state={snapshot.critical_persistence} t={t} />
        <Path label={t.armedEvidence} state={snapshot.critical_evidence} t={t} />
        <Path label={t.armedNotification} state={snapshot.critical_notifications} t={t} />
      </dl>
      {snapshot.pending_critical_actions > 0
        && <p role="status">{t.pendingCritical}: {snapshot.pending_critical_actions}</p>}
    </section>
    <section className="presence-transitions" aria-label={t.controlHistory}>
      <h2>{t.controlHistory}</h2>
      <p className="muted">{t.utcNote}</p>
      {report.audit.length === 0 ? <p>{t.controlHistoryEmpty}</p>
        : <ol className="timeline-list">{report.audit.map(entry =>
          <li className="timeline-row" key={entry.sequence} data-control-action={entry.action}>
            <time className="timeline-time" dateTime={entry.at}>{stamp(entry.at)}</time>
            <span className="timeline-dot timeline-dot-configuration" aria-hidden="true" />
            <div className="timeline-detail">
              <p className="timeline-body">{t[`action_${entry.action}`]}</p>
              {entry.state && <p className="timeline-meta"><span>{t[`state_${entry.state}`]}</span></p>}
              {entry.action === 'critical_action_requeued'
                && <p className="timeline-meta"><span>{t.note_critical_action_requeued}</span></p>}
              {entry.action === 'critical_degradation_cleared'
                && <p className="timeline-meta"><span>{t.note_critical_degradation_cleared}</span></p>}
            </div>
          </li>)}</ol>}
    </section>
  </section>;
}

type State = { state: 'pending' } | { state: 'loading' } | { state: 'failed' } | { state: 'ready'; report: PresenceReport };

export function PresenceScreen({ services, t }: { services: DashboardServices; t: Messages }) {
  const [data, setData] = useState<State>({ state: 'pending' });
  const [failed, setFailed] = useState(false);
  // Bound to the service so class-based providers keep their receiver.
  const cancel = services.cancelPresenceOverride?.bind(services);

  useEffect(() => {
    const load = services.loadPresence?.bind(services);
    if (!load) return;
    const controller = new AbortController();
    setData({ state: 'loading' });
    void (async () => {
      try {
        const report = await load(controller.signal);
        if (!controller.signal.aborted) setData({ state: 'ready', report });
      } catch {
        if (!controller.signal.aborted) setData({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [services]);

  if (data.state === 'failed') return <p role="alert">{t.presenceUnavailable}</p>;
  if (data.state === 'loading') return <p role="status">{t.checking}</p>;
  if (data.state === 'pending') {
    return <section className="placeholder"><span className="placeholder-mark" aria-hidden="true">◇</span>
      <h2>{t.presence}</h2><p>{t.foundation}</p></section>;
  }
  const request = cancel ? () => {
    const controller = new AbortController();
    setFailed(false);
    void (async () => {
      try { setData({ state: 'ready', report: await cancel(controller.signal) }); }
      catch { setFailed(true); }
    })();
  } : undefined;
  return <PresenceBody report={data.report} t={t} onCancel={request} failed={failed} />;
}
