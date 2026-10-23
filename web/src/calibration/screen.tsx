/**
 * The Owner's scene calibration (Issue #205), shown on the Sources view.
 *
 * Shown to the Owner only; the server authorizes every request again and this
 * screen widens nothing. Per configured source it shows where the calibration
 * in use came from (`owner`, or `restart_reacquired`: taken again from the
 * camera after a Main restart without the Owner, Owner decision 2026-10-22,
 * option A), its version and time, an attempt in progress and the last fixed
 * refusal. It never shows the reference image, its digest, the ROI polygon
 * or the policy: the server sends none of them.
 *
 * A calibration takes the camera's next good frames as the new reference, so
 * the Owner first states, with an explicit checkbox, that the camera and the
 * server are in their normal position (the server requires that statement in
 * the request). A calibration refused with `step_up_required` asks the Owner
 * to confirm with their passkey and is retried once (`shared/step_up.ts`).
 * Nothing is written to browser storage.
 */
import { useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import type { CalibrationReason, CalibrationResult, DashboardServices, SceneCalibrationSource } from '../domain';
import type { Catalog } from '../i18n';
import { StepUpPrompt, utcStamp } from '../access/screen';
import { runOwnerChange, type OwnerOutcome } from '../shared/step_up';

type Status = { state: 'loading' | 'failed' } | { state: 'ready'; items: readonly SceneCalibrationSource[] };
/** The last calibration's answer for one source. */
export type Outcome =
  | { source: string; state: 'calibrated'; version: number }
  | { source: string; state: 'refused'; reason: CalibrationReason }
  | { source: string; state: Exclude<OwnerOutcome<unknown>['state'], 'aborted' | 'done'> };

export function refusalText(t: Catalog, reason: CalibrationReason): string {
  return t[`calibrationRefused_${reason}`];
}

export function CalibrationScreen({ services, t }: { services: DashboardServices; t: Catalog }) {
  const [status, setStatus] = useState<Status>({ state: 'loading' });
  const [names, setNames] = useState<ReadonlyMap<string, string>>(new Map());
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);
  const [ceremony, setCeremony] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [prompt, setPrompt] = useState<((confirmed: boolean) => void) | null>(null);
  const [confirmed, setConfirmed] = useState<string | null>(null);
  const operation = useRef<AbortController | null>(null);
  /** The source of the calibration in flight. */
  const target = useRef<string | null>(null);
  const answer = useRef<((confirmed: boolean) => void) | null>(null);
  /** `stale` from a `step_up_required` refusal until the one retry is sent. */
  const phase = useRef<'idle' | 'sent' | 'stale'>('idle');
  const load = services.loadSceneCalibration;
  const loadNames = services.loadLiveSources;

  useEffect(() => {
    if (!load) return;
    const controller = new AbortController();
    setStatus({ state: 'loading' });
    void (async () => {
      try {
        const items = await load(controller.signal);
        if (!controller.signal.aborted) setStatus({ state: 'ready', items });
      } catch {
        if (!controller.signal.aborted) setStatus({ state: 'failed' });
      }
    })();
    return () => controller.abort();
  }, [load, reload]);

  // Camera names come from the live source list (the Owner may read it); a
  // source without one is shown by a shortened id.
  useEffect(() => {
    if (!loadNames) return;
    const controller = new AbortController();
    void (async () => {
      try {
        const items = await loadNames(controller.signal);
        if (!controller.signal.aborted) setNames(new Map(items.map(item => [item.id, item.name])));
      } catch { /* names are optional */ }
    })();
    return () => controller.abort();
  }, [loadNames]);

  // Leaving the screen abandons a calibration in flight; an unanswered
  // step-up question declines (nothing was performed).
  useEffect(() => {
    const hide = () => {
      const pending = operation.current;
      const source = target.current;
      const unanswered = phase.current === 'stale';
      phase.current = 'idle';
      operation.current = null;
      target.current = null;
      pending?.abort();
      answer.current?.(false);
      if (pending) {
        flushSync(() => {
          setPrompt(null);
          setCeremony(false);
          setBusy(null);
          if (source !== null) setOutcome({ source, state: unanswered ? 'not_performed' : 'unknown' });
          if (!unanswered) setReload(value => value + 1);
        });
      }
    };
    addEventListener('pagehide', hide);
    return () => {
      removeEventListener('pagehide', hide);
      operation.current?.abort();
      answer.current?.(false);
    };
  }, []);

  if (!load) return null;
  const calibrate = services.calibrateSource;

  function run(source: string) {
    if (busy !== null || !calibrate || confirmed !== source) return;
    const controller = new AbortController();
    operation.current = controller;
    target.current = source;
    phase.current = 'sent';
    setBusy(source);
    setOutcome(null);
    void (async () => {
      const result = await runOwnerChange<CalibrationResult>(signal => calibrate(source, signal), {
        confirm: () => new Promise<boolean>(resolve => {
          const settle = (value: boolean) => {
            answer.current = null;
            setPrompt(null);
            resolve(value);
          };
          answer.current = settle;
          if (operation.current === controller) phase.current = 'stale';
          setPrompt(() => settle);
        }),
        stepUp: services.stepUp,
        onCeremony: () => setCeremony(true),
        onRetry: () => { if (operation.current === controller) phase.current = 'sent'; },
      }, controller.signal);
      if (result.state === 'aborted' || controller.signal.aborted || operation.current !== controller) return;
      operation.current = null;
      target.current = null;
      phase.current = 'idle';
      setCeremony(false);
      setBusy(null);
      setConfirmed(null);
      if (result.state === 'done') {
        const value = result.value;
        setOutcome(value.outcome === 'calibrated'
          ? { source, state: 'calibrated', version: value.version }
          : { source, state: 'refused', reason: value.reason });
      } else {
        setOutcome({ source, state: result.state });
      }
      // Anything but a refusal before the commit may have changed the status.
      if (result.state !== 'not_performed') setReload(value => value + 1);
    })();
  }

  const message = outcome === null ? null
    : outcome.state === 'calibrated' ? `${t.calibrationDone} (${t.calibrationVersion} ${outcome.version})`
      : outcome.state === 'refused' ? refusalText(t, outcome.reason)
        : outcome.state === 'not_performed' ? t.accessNotPerformed : t.calibrationUnknown;

  return <section className="calibration-screen" aria-labelledby="calibration-title">
    <h2 id="calibration-title">{t.calibrationTitle}</h2>
    <p className="muted">{t.calibrationNote}</p>
    <p className="muted">{t.calibrationMemoryNote}</p>
    <p className="muted">{t.calibrationStepUpNote}</p>
    {prompt && <StepUpPrompt t={t} onAnswer={value => prompt(value)} />}
    {ceremony && <p role="status">{t.stepUpRunning}</p>}
    {busy !== null && !prompt && !ceremony && <p role="status">{t.calibrationRunning}</p>}
    {message && <p role={outcome?.state === 'calibrated' ? 'status' : 'alert'} data-calibration-result={outcome?.state}
      className={outcome?.state === 'calibrated' ? 'access-result' : 'notice-inline'}>{message}</p>}
    {status.state === 'loading' && <p role="status">{t.checking}</p>}
    {status.state === 'failed' && <section className="notice" role="alert"><p>{t.calibrationUnavailable}</p>
      <button className="primary" type="button" onClick={() => setReload(value => value + 1)}>{t.retry}</button></section>}
    {status.state === 'ready' && status.items.length === 0 && <p>{t.calibrationEmpty}</p>}
    {status.state === 'ready' && status.items.map(item => <CalibrationCard key={item.source_id} t={t} item={item}
      name={names.get(item.source_id) ?? null} disabled={busy !== null} busy={busy === item.source_id}
      confirmed={confirmed === item.source_id}
      onConfirm={value => setConfirmed(value ? item.source_id : null)}
      onCalibrate={calibrate && item.owner_calibration_available ? () => run(item.source_id) : undefined} />)}
  </section>;
}

/** One source's calibration state and, when a template exists, its control. */
export function CalibrationCard({ t, item, name, disabled, busy = false, confirmed, onConfirm, onCalibrate }: {
  t: Catalog; item: SceneCalibrationSource; name: string | null; disabled: boolean; busy?: boolean; confirmed: boolean;
  onConfirm: (confirmed: boolean) => void; onCalibrate?: (() => void) | undefined;
}) {
  const id = `calibration-confirm-${item.source_id}`;
  return <article className="calibration-source" data-calibration-source={item.source_id}
    data-calibration-origin={item.origin} aria-busy={busy || undefined}>
    <h3>{name ?? `${t.calibrationSourceId} ${item.source_id.slice(0, 8)}`}</h3>
    <p>
      <span className={`badge calibration-origin-${item.origin}`}>{t[`calibrationOrigin_${item.origin}`]}</span>{' '}
      <span className={`badge calibration-detection-${item.detection}`}>
        {t.calibrationDetection}: {t[`calibrationDetection_${item.detection}`]}</span>
    </p>
    <dl>
      {item.version !== null && <><dt>{t.calibrationVersion}</dt><dd className="numeric">{item.version}</dd></>}
      {item.calibrated_at !== null && <><dt>{t.calibrationAt}</dt>
        <dd className="numeric">{utcStamp(item.calibrated_at)}</dd></>}
      <dt>{t.calibrationReasonCode}</dt><dd><code>{item.detection_reason}</code></dd>
    </dl>
    {item.origin === 'restart_reacquired' && <p role="note" className="calibration-warning">
      {t.calibrationRestartWarning}</p>}
    {item.phase === 'acquiring' && <p role="status">{t.calibrationPhase_acquiring}</p>}
    {item.phase === 'reacquire_pending' && <p role="status">{t.calibrationPhase_reacquire_pending}</p>}
    {item.failure !== null && <p className="notice-inline" data-calibration-failure={item.failure}>
      {t.calibrationLastFailure}: {refusalText(t, item.failure)}</p>}
    {!item.owner_calibration_available && <p className="muted">{t.calibrationNoTemplate}</p>}
    {onCalibrate && <div className="calibration-action">
      <label htmlFor={id} className="calibration-confirm">
        <input id={id} type="checkbox" checked={confirmed} disabled={disabled}
          onChange={event => onConfirm(event.target.checked)} />
        {t.calibrationConfirm}
      </label>
      <button type="button" className="primary" disabled={disabled || !confirmed} onClick={onCalibrate}>
        {t.calibrationRun}</button>
    </div>}
  </article>;
}
