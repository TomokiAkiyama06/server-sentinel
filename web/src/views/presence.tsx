import { useEffect, useState } from 'react';
import type { DashboardServices, PresenceReport, PresenceSnapshot } from '../domain';
import type { Messages } from '../i18n';

function stamp(value: string): string {
  return value.slice(0, 19).replace('T', ' ');
}

function Armed({ label, armed, t }: { label: string; armed: boolean; t: Messages }) {
  return <div className="presence-armed">
    <dt>{label}</dt><dd>{armed ? t.armedYes : t.armedNo}</dd>
  </div>;
}

export function PresenceBody({ report, t, onCancel, failed }: {
  report: PresenceReport; t: Messages; onCancel?: (() => void) | undefined; failed?: boolean | undefined;
}) {
  const snapshot: PresenceSnapshot = report.snapshot;
  const override = snapshot.basis === 'manual_override';
  // Report the invariant only while every critical protection is actually armed.
  const armed = snapshot.critical_detection_armed && snapshot.critical_evidence_armed
    && snapshot.critical_notifications_armed;
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
      {failed && <p role="alert">{t.overrideFailed}</p>}
    </section>
    <section className="presence-automation" aria-label={t.armedNotification}>
      <p>{snapshot.suppress_ordinary ? t.suppressOn : t.suppressOff}</p>
      {armed ? <p>{t.criticalArmed}</p>
        : <p className="timeline-degraded" role="alert">{t.criticalNotArmed}</p>}
      <dl className="presence-armed-list">
        <Armed label={t.armedDetection} armed={snapshot.critical_detection_armed} t={t} />
        <Armed label={t.armedEvidence} armed={snapshot.critical_evidence_armed} t={t} />
        <Armed label={t.armedNotification} armed={snapshot.critical_notifications_armed} t={t} />
      </dl>
      {snapshot.pending_critical_actions > 0
        && <p role="status">{t.pendingCritical}: {snapshot.pending_critical_actions}</p>}
    </section>
    <section className="presence-transitions" aria-label={t.transitions}>
      <h2>{t.transitions}</h2>
      <p className="muted">{t.utcNote}</p>
      {report.transitions.length === 0 ? <p>{t.transitionsEmpty}</p>
        : <ol className="timeline-list">{report.transitions.map(entry =>
          <li className="timeline-row" key={`${entry.at}-${entry.state}`}>
            <time className="timeline-time" dateTime={entry.at}>{stamp(entry.at)}</time>
            <span className="timeline-dot timeline-dot-configuration" aria-hidden="true" />
            <div className="timeline-detail">
              <p className="timeline-body">{t[`state_${entry.state}`]}</p>
              <p className="timeline-meta"><span>{t.presenceBasis}: {t[`basis_${entry.basis}`]}</span></p>
            </div>
          </li>)}</ol>}
    </section>
  </section>;
}

type State = { state: 'pending' } | { state: 'loading' } | { state: 'failed' } | { state: 'ready'; report: PresenceReport };

export function PresenceScreen({ services, t }: { services: DashboardServices; t: Messages }) {
  const [data, setData] = useState<State>({ state: 'pending' });
  const [failed, setFailed] = useState(false);
  const load = services.loadPresence;
  const cancel = services.cancelPresenceOverride;

  useEffect(() => {
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
  }, [load]);

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
