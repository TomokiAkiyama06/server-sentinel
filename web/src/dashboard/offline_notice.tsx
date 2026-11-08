/**
 * The Owner's camera offline notice (Issue #301 item 2).
 *
 * The server answers `GET /api/monitoring/camera-offline` (`OWNER_READ`) with
 * one boolean and one fixed word: a camera offline condition the Owner would
 * be notified of is current and no notification leaves the Main Server,
 * because no notification destination (Slack) is configured
 * (`not_configured`) or because Slack is configured but the latest camera
 * offline delivery did not reach it (`delivery_failed`, Issue #394). The App loads it only for an Owner
 * session; the server repeats that check and refuses everyone else.
 *
 * The notice states facts only: which camera is offline is on the Live
 * screen, and nothing here claims a cause, an intrusion or a culprit.
 */
import type { Catalog } from '../i18n';

/** How often the App samples the notice while an Owner session is open. The
 *  monitoring runtime updates the underlying status once per tick (60 s). */
export const CAMERA_OFFLINE_NOTICE_REFRESH_MS = 60000;

export type OfflineNoticeState =
  | { state: 'pending' | 'loading' | 'failed' }
  | { state: 'ready'; cause: 'not_configured' | 'delivery_failed' | null };

type Timers = {
  set(run: () => void, ms: number): unknown;
  clear(handle: unknown): void;
};
const realTimers: Timers = {
  set: (run, ms) => setTimeout(run, ms),
  clear: handle => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** Sample the notice now and every `refreshMs` after each answer, reporting
 *  every answer (or failure) until the returned `stop()`. Nothing is
 *  reported after `stop()`, and one sample is in flight at a time. */
export function startOfflineNoticeSampling(
  load: (signal: AbortSignal) => Promise<'not_configured' | 'delivery_failed' | null>,
  report: (next: OfflineNoticeState) => void,
  { refreshMs = CAMERA_OFFLINE_NOTICE_REFRESH_MS, timers = realTimers }: { refreshMs?: number; timers?: Timers } = {}) {
  const controller = new AbortController();
  let timer: unknown;
  const sample = async () => {
    let next: OfflineNoticeState;
    try {
      next = { state: 'ready', cause: await load(controller.signal) };
    } catch {
      next = { state: 'failed' };
    }
    if (controller.signal.aborted) return;
    report(next);
    timer = timers.set(() => { void sample(); }, refreshMs);
  };
  void sample();
  return () => {
    controller.abort();
    if (timer !== undefined) timers.clear(timer);
  };
}

export function CameraOfflineNotice({ t, notice }: { t: Catalog; notice: OfflineNoticeState }) {
  if (notice.state === 'ready' && notice.cause !== null) {
    const failed = notice.cause === 'delivery_failed';
    return <section className="notice-inline notice-offline" role="alert" data-camera-offline-unnotified="true"
      data-camera-offline-cause={notice.cause}>
      <strong>{t.cameraOfflineUnnotifiedTitle}</strong>
      <p>{failed ? t.cameraOfflineDeliveryFailed : t.cameraOfflineUnnotified}</p>
      <p>{failed ? t.cameraOfflineDeliveryFailedHint : t.cameraOfflineUnnotifiedHint}</p>
    </section>;
  }
  // A check that could not be made is said so, never shown as "nothing to report".
  if (notice.state === 'failed') return <p role="status" className="muted">{t.cameraOfflineNoticeUnavailable}</p>;
  return null;
}
