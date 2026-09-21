import { useEffect, useRef, useState } from 'react';
import type { CriticalPath, DashboardServices, PresenceAuditAction, PresenceReport, PresenceSnapshot } from '../domain';
import type { Messages } from '../i18n';

function stamp(value: string): string {
  return value.slice(0, 19).replace('T', ' ');
}

/** Names what an Owner recovery action applied to, without inventing detail.
 *
 * The observation identifier is shown in full: no prefix length is guaranteed
 * to be unique, and two approvals must stay distinguishable in the audit.
 */
function describeTarget(value: string | null, action: PresenceAuditAction, t: Messages): string | null {
  if (!value) return null;
  if (action === 'critical_event_cleared') {
    return `${t.targetLabel}: ${t.targetObservation} ${value}`;
  }
  const separator = value.indexOf(':');
  const targetKind = separator === -1 ? value : value.slice(0, separator);
  const identifier = separator === -1 ? '' : value.slice(separator + 1);
  const path = targetKind === 'evidence' ? t.armedEvidence
    : targetKind === 'notification' ? t.armedNotification : targetKind;
  return identifier
    ? `${t.targetLabel}: ${path} / ${t.targetObservation} ${identifier}`
    : `${t.targetLabel}: ${path}`;
}

/** Reports the three path states separately: unknown is not a known failure. */
function Path({ label, state, t }: { label: string; state: CriticalPath; t: Messages }) {
  return <div className={`presence-armed presence-path-${state}`}>
    <dt>{label}</dt><dd>{t[`path_${state}`]}</dd>
  </div>;
}

export function PresenceBody({ report, t, onCancel, failed, cancelling, onRefresh, fetchedAt,
  refreshFailed, now = Date.now() }: {
  report: PresenceReport; t: Messages; onCancel?: (() => void) | undefined; failed?: boolean | undefined;
  cancelling?: boolean | undefined; onRefresh?: (() => void) | undefined; fetchedAt?: string | undefined;
  refreshFailed?: boolean | undefined; now?: number | undefined;
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
  // Untrusted control timing keeps an override applied past its stated expiry.
  const expiredButApplied = override && snapshot.clock_degraded && !snapshot.override_expiry_pending
    && snapshot.override_expires_at !== null && Date.parse(snapshot.override_expires_at) <= now;
  return <section className="presence-screen">
    <section className={`presence-state presence-${snapshot.state}`} aria-label={t.presenceCurrent}>
      <p className="eyebrow">{t.presenceCurrent}</p>
      <p className="presence-value">{t[`state_${snapshot.state}`]}</p>
      <p className="muted">{t.presenceBasis}: {t[`basis_${snapshot.basis}`]}</p>
      {fetchedAt && <p className="muted">{t.presenceFetchedAt}: {stamp(fetchedAt)}</p>}
      {refreshFailed && <p role="alert">{t.presenceRefreshFailed}</p>}
      {onRefresh && <button type="button" disabled={cancelling}
        onClick={onRefresh}>{t.presenceRefresh}</button>}
      {snapshot.clock_degraded && <p className="timeline-degraded" role="status">{t.clockDegradedNotice}</p>}
      {snapshot.observation_clock_degraded
        && <p className="timeline-degraded" role="status">{t.observationClockDegraded}</p>}
    </section>
    <section className="presence-override" aria-label={t.overrideCancel}>
      <h2>{t.basis_manual_override}</h2>
      <p>{override ? t.overrideActive : t.overrideNone}</p>
      <p className="muted">{t.overridePrecedence}</p>
      {override && <p>{t.overrideExpires}: {snapshot.override_expires_at
        ? stamp(snapshot.override_expires_at) : t.overrideNoExpiry}</p>}
      {override && <button type="button" className="primary" disabled={!onCancel || cancelling}
        onClick={() => onCancel?.()}>{cancelling ? t.overrideCancelling : t.overrideCancel}</button>}
      {override && !onCancel && <p className="muted">{t.foundation}</p>}
      {snapshot.override_expiry_pending && <p className="timeline-degraded" role="alert">{t.overrideExpiryPending}</p>}
      {expiredButApplied && <p className="timeline-degraded" role="alert">{t.overrideExpiredApplied}</p>}
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
              {describeTarget(entry.target, entry.action, t)
                && <p className="timeline-meta"><span>{describeTarget(entry.target, entry.action, t)}</span></p>}
              {entry.action === 'critical_action_requeued'
                && <p className="timeline-meta"><span>{t.note_critical_action_requeued}</span></p>}
              {entry.action === 'critical_degradation_cleared'
                && <p className="timeline-meta"><span>{t.note_critical_degradation_cleared}</span></p>}
              {entry.action === 'critical_event_cleared'
                && <p className="timeline-meta"><span>{t.note_critical_event_cleared}</span></p>}
            </div>
          </li>)}</ol>}
    </section>
  </section>;
}

type State = { state: 'pending' } | { state: 'loading' } | { state: 'failed' }
  | { state: 'ready'; report: PresenceReport; refreshFailed: boolean; cancelFailed: boolean };

/** An authoritative report replaces every earlier read or control failure. */
export function withReport(report: PresenceReport): State {
  return { state: 'ready', report, refreshFailed: false, cancelFailed: false };
}

/** A failure keeps the last known status; only the first read can fail closed. */
export function withFailure(previous: State, kind: 'refresh' | 'cancel'): State {
  if (previous.state !== 'ready') return kind === 'refresh' ? { state: 'failed' } : previous;
  return kind === 'refresh' ? { ...previous, refreshFailed: true } : { ...previous, cancelFailed: true };
}

const HOUR = 3600000;

/** Only a future expiry schedules a refresh, so a stale one cannot loop. */
export function refreshDelay(expiry: string | null, now: number): number | null {
  if (!expiry) return null;
  const remaining = Date.parse(expiry) - now;
  if (Number.isNaN(remaining) || remaining <= 0) return null;
  return Math.min(remaining + 1000, HOUR);
}

/** Re-arms bounded checks until a distant expiry is actually reached.
 *
 * A clamped hourly check refreshes the snapshot and schedules the next one, so
 * an override that outlives the clamp cannot keep reporting itself as active
 * after it expired. An audited control operation in flight defers the check.
 */
export function scheduleExpiryRefresh(expiry: string | null, refresh: () => void,
  busy: () => boolean, now: () => number = Date.now): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  function arm() {
    const delay = refreshDelay(expiry, now());
    timer = delay === null ? undefined : setTimeout(fire, delay);
  }
  function fire() {
    // An audited control result always wins over an automatic re-read.
    if (busy()) { timer = setTimeout(fire, 1000); return; }
    refresh();
    arm();
  }
  arm();
  return () => { if (timer !== undefined) clearTimeout(timer); };
}

export function PresenceScreen({ services, t }: { services: DashboardServices; t: Messages }) {
  const [data, setData] = useState<State>({ state: 'pending' });
  const [cancelling, setCancelling] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);
  // One audited control operation at a time, independent of render timing.
  const inFlight = useRef(false);
  // A superseded read must never overwrite a newer control result.
  const ticket = useRef(0);
  // Bound to the service so class-based providers keep their receiver.
  const cancel = services.cancelPresenceOverride?.bind(services);

  useEffect(() => {
    const load = services.loadPresence?.bind(services);
    if (!load) return;
    const controller = new AbortController();
    const current = ticket.current += 1;
    // A refresh keeps the last known status on screen while it runs.
    setData(previous => previous.state === 'ready'
      ? { ...previous, refreshFailed: false } : { state: 'loading' });
    void (async () => {
      try {
        const report = await load(controller.signal);
        if (!controller.signal.aborted && current === ticket.current) {
          setData(withReport(report));
          setFetchedAt(new Date().toISOString());
        }
      } catch {
        if (!controller.signal.aborted && current === ticket.current) {
          setData(previous => withFailure(previous, 'refresh'));
        }
      }
    })();
    return () => controller.abort();
  }, [services, attempt]);

  const expiry = data.state === 'ready' ? data.report.snapshot.override_expires_at : null;
  // A known expiry must not leave an expired override on screen as active.
  useEffect(() => scheduleExpiryRefresh(expiry, () => setAttempt(value => value + 1),
    () => inFlight.current), [expiry]);

  if (data.state === 'failed') return <section className="notice">
    <p role="alert">{t.presenceUnavailable}</p>
    <button type="button" className="primary" onClick={() => setAttempt(value => value + 1)}>{t.retry}</button>
  </section>;
  if (data.state === 'loading') return <p role="status">{t.checking}</p>;
  if (data.state === 'pending') {
    return <section className="placeholder"><span className="placeholder-mark" aria-hidden="true">◇</span>
      <h2>{t.presence}</h2><p>{t.foundation}</p></section>;
  }
  const request = cancel ? () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setCancelling(true);
    setData(previous => previous.state === 'ready' ? { ...previous, cancelFailed: false } : previous);
    const controller = new AbortController();
    const current = ticket.current += 1;
    void (async () => {
      try {
        const report = await cancel(controller.signal);
        if (current === ticket.current) {
          setData(withReport(report));
          setFetchedAt(new Date().toISOString());
        }
      } catch {
        setData(previous => withFailure(previous, 'cancel'));
      } finally {
        inFlight.current = false;
        setCancelling(false);
      }
    })();
  } : undefined;
  return <PresenceBody report={data.report} t={t} onCancel={request} failed={data.cancelFailed}
    cancelling={cancelling} onRefresh={() => setAttempt(value => value + 1)}
    fetchedAt={fetchedAt ?? undefined} refreshFailed={data.refreshFailed} />;
}
