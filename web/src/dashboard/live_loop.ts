/**
 * One viewer's frame-pull loop for one Camera Source (#205 CP-5).
 *
 * Interim transport (Owner decision D5): open a viewer session, then pull the
 * newest frame with `after=<last sequence>`, waiting the server's
 * `frame_interval_ms` (default `FRAME_INTERVAL_MS`, about 5 fps) plus
 * `FRAME_SLACK_MS` after each answer, so a pull never arrives early. A `204`
 * means no newer frame yet. A refusal (the server's generic `404`: no
 * permission any more, revoked, lease expired, source not live, over a limit)
 * ends the loop for good, with one exception: an open refused shortly after
 * this page closed a session is retried once after `OPEN_RETRY_MS`, since the
 * server may still be releasing that slot. Any other failure is retried with
 * exponential backoff.
 *
 * Opens are coalesced: a new player waits `startDelayMs` before its first
 * open, and a page that becomes visible again waits `REOPEN_DELAY_MS`, so
 * quickly switching sources or hiding and showing the page does not spend an
 * open per change.
 *
 * Viewer-only work stops while nobody looks (SPECIFICATION 6.5): when the
 * document is hidden the session is closed and the frame is dropped, and a
 * fresh session is opened when it is visible again. `stop()` closes the
 * session too. A session that `open` grants after the loop stopped is closed
 * at once, so no viewer slot is left behind.
 */
import { ApiError } from '../api';
import type { LiveFrame, LiveGrant } from '../domain';

// Re-exported so a separately bundled test raises the class this loop checks.
export { ApiError };

export const FRAME_INTERVAL_MS = 200;
export const FRAME_SLACK_MS = 20;
/** Delay before reopening when the page is visible again. */
export const REOPEN_DELAY_MS = 1000;
/** Delay before the single retry of an open refused right after a close. */
export const OPEN_RETRY_MS = 2000;
/** Without a newer frame for this long the shown frame is marked not current. */
export const STALE_AFTER_MS = 5000;
/** An open, or a frame request with its decode, unfinished after this long
 *  is abandoned as a transient failure, so a stalled connection or decode
 *  never keeps an old frame labelled current (shorter than STALE_AFTER_MS). */
export const REQUEST_TIMEOUT_MS = 4000;
export const BACKOFF_BASE_MS = 500;
export const BACKOFF_MAX_MS = 8000;

export type LiveStatus = 'connecting' | 'live' | 'stale' | 'retrying' | 'paused' | 'ended';

export interface LiveTransport {
  open(sourceId: string, signal: AbortSignal): Promise<LiveGrant>;
  /** True shortly after a close this page sent (see OPEN_RETRY_MS). */
  closedRecently?(): boolean;
  read(sessionId: string, after: number, signal: AbortSignal): Promise<LiveFrame | null>;
  close(sessionId: string): void;
}

export interface Visibility {
  hidden(): boolean;
  /** Calls back on every change; returns the unsubscribe function. */
  subscribe(changed: () => void): () => void;
}

export interface Clock {
  now(): number;
  set(run: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

export interface LiveLoopOptions {
  transport: LiveTransport;
  sourceId: string;
  /** Draw one frame; a rejection counts as a transient failure. `current()`
   *  turns false once the frame belongs to a paused, ended or stopped
   *  session: check it after any await and draw nothing then. */
  onFrame(frame: LiveFrame, current: () => boolean): Promise<void> | void;
  /** `paused` and `ended` also mean: drop whatever frame is shown. */
  onStatus(status: LiveStatus): void;
  visibility: Visibility;
  clock?: Clock;
  /** Wait this long before the first open (coalesces quick source changes). */
  startDelayMs?: number;
}

const systemClock: Clock = {
  now: () => performance.now(),
  set: (run, ms) => setTimeout(run, ms),
  clear: handle => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function backoff(failures: number): number {
  return Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, failures - 1));
}

const refused = (error: unknown) => error instanceof ApiError && error.code === 'unauthorized';

/** Start the loop; the returned function stops it and closes its session. */
export function startLiveLoop({ transport, sourceId, onFrame, onStatus, visibility, clock = systemClock, startDelayMs = 0 }: LiveLoopOptions): () => void {
  let generation = 0;
  let stopped = false;
  let ended = false;
  let session: string | null = null;
  let controller: AbortController | null = null;
  let timer: unknown = null;
  let deadline: unknown = null;
  let watchdog: unknown = null;
  let after = 0;
  let interval = FRAME_INTERVAL_MS;
  let openRetried = false;
  let failures = 0;
  let lastFrame = 0;
  let status: LiveStatus | null = null;

  const report = (next: LiveStatus) => {
    if (status === next) return;
    status = next;
    onStatus(next);
  };

  /** Abandon the current session: cancel what is in flight and close it. */
  function release() {
    generation += 1;
    controller?.abort();
    controller = null;
    if (timer !== null) { clock.clear(timer); timer = null; }
    disarm();
    if (watchdog !== null) { clock.clear(watchdog); watchdog = null; }
    if (session !== null) { transport.close(session); session = null; }
  }

  function disarm() {
    if (deadline !== null) { clock.clear(deadline); deadline = null; }
  }

  /** `request` bounded by REQUEST_TIMEOUT_MS whether or not it honours the signal. */
  function bounded<T>(request: Promise<T>, attempt: AbortController): Promise<T> {
    disarm();
    const expired = new Promise<never>((_, reject) => {
      deadline = clock.set(() => {
        deadline = null;
        attempt.abort();
        reject(new ApiError('unavailable'));
      }, REQUEST_TIMEOUT_MS);
    });
    return Promise.race([request, expired]).finally(() => { if (controller === attempt) disarm(); });
  }

  /** Independent of any request in flight: STALE_AFTER_MS after the last
   *  shown frame (or the open), the picture is marked not current. */
  function watch(current: number) {
    if (watchdog !== null) clock.clear(watchdog);
    watchdog = clock.set(() => {
      watchdog = null;
      if (current === generation && (status === 'live' || status === 'connecting')) report('stale');
    }, STALE_AFTER_MS);
  }

  function schedule(run: (current: number) => void, ms: number, current: number) {
    timer = clock.set(() => { timer = null; if (current === generation) run(current); }, ms);
  }

  function fail(current: number, retry: (current: number) => void) {
    failures += 1;
    report('retrying');
    schedule(retry, backoff(failures), current);
  }

  function end() {
    ended = true;
    release();
    report('ended');
  }

  function connect(current: number) {
    report(failures ? 'retrying' : 'connecting');
    const attempt = new AbortController();
    controller = attempt;
    void (async () => {
      let granted: LiveGrant;
      const request = transport.open(sourceId, attempt.signal);
      try {
        granted = await bounded(request, attempt);
      } catch (error) {
        // A grant that still arrives after the timeout is given back at once.
        request.then(late => transport.close(late.sessionId), () => undefined);
        if (current !== generation) return;
        if (refused(error)) {
          if (!openRetried && transport.closedRecently?.()) {
            openRetried = true;
            report('retrying');
            schedule(connect, OPEN_RETRY_MS, current);
            return;
          }
          end();
          return;
        }
        fail(current, connect);
        return;
      }
      // Granted after a stop, pause or newer attempt: give the slot back now.
      if (current !== generation) { transport.close(granted.sessionId); return; }
      session = granted.sessionId;
      interval = granted.frameIntervalMs ?? FRAME_INTERVAL_MS;
      openRetried = false;
      after = 0;
      lastFrame = clock.now();
      watch(current);
      pull(current);
    })();
  }

  function pull(current: number) {
    const attempt = new AbortController();
    controller = attempt;
    const id = session;
    if (id === null) return;
    void (async () => {
      try {
        // Read and decode share one deadline; a decode that ends after it
        // (or after a pause, refusal or stop) is no longer current.
        const isCurrent = () => !stopped && current === generation && !attempt.signal.aborted;
        const frame = await bounded((async () => {
          const value = await transport.read(id, after, attempt.signal);
          if (value && isCurrent()) await onFrame(value, isCurrent);
          return value;
        })(), attempt);
        if (current !== generation) return;
        if (frame) {
          after = frame.sequence;
          lastFrame = clock.now();
          watch(current);
          report('live');
        } else if (clock.now() - lastFrame >= STALE_AFTER_MS) {
          report('stale');
        } else if (status !== 'live' && status !== 'stale') {
          report('connecting');
        }
        failures = 0;
        // Counted from the answer, which the server sent after it served the
        // previous frame: the next pull never reaches it inside its interval.
        schedule(pull, interval + FRAME_SLACK_MS, current);
      } catch (error) {
        if (current !== generation) return;
        if (refused(error)) { end(); return; }
        fail(current, pull);
      }
    })();
  }

  function resume() {
    if (stopped || ended) return;
    if (visibility.hidden()) {
      if (status !== 'paused') { release(); report('paused'); }
      return;
    }
    if (status === 'paused' || status === null) {
      const delay = status === null ? startDelayMs : REOPEN_DELAY_MS;
      release();
      failures = 0;
      report('connecting');
      if (delay > 0) schedule(connect, delay, generation);
      else connect(generation);
    }
  }

  const unsubscribe = visibility.subscribe(resume);
  resume();
  return () => {
    if (stopped) return;
    stopped = true;
    unsubscribe();
    release();
  };
}

/** The browser's page visibility: hidden while the tab is in the background
 *  or the page is being unloaded / kept in the back-forward cache. */
export function documentVisibility(target: Document = document, events: Window = window): Visibility {
  let unloading = false;
  return {
    hidden: () => unloading || target.visibilityState !== 'visible',
    subscribe(changed) {
      const hide = () => { unloading = true; changed(); };
      const show = () => { unloading = false; changed(); };
      target.addEventListener('visibilitychange', changed);
      events.addEventListener('pagehide', hide);
      events.addEventListener('pageshow', show);
      return () => {
        target.removeEventListener('visibilitychange', changed);
        events.removeEventListener('pagehide', hide);
        events.removeEventListener('pageshow', show);
      };
    },
  };
}
