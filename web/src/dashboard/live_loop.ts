/**
 * One viewer's frame-pull loop for one Camera Source (#205 CP-5).
 *
 * Interim transport (Owner decision D5): open a viewer session, then pull the
 * newest frame with `after=<last sequence>` at most every `FRAME_INTERVAL_MS`
 * (about 5 fps). A `204` means no newer frame yet. A refusal (the server's
 * generic `404`: no permission any more, revoked, lease expired, source not
 * live, over the viewer limit) ends the loop for good: it is never retried
 * automatically. Any other failure is retried with exponential backoff.
 *
 * Viewer-only work stops while nobody looks (SPECIFICATION 6.5): when the
 * document is hidden the session is closed and the frame is dropped, and a
 * fresh session is opened when it is visible again. `stop()` closes the
 * session too. A session that `open` grants after the loop stopped is closed
 * at once, so no viewer slot is left behind.
 */
import { ApiError } from '../api';
import type { LiveFrame } from '../domain';

// Re-exported so a separately bundled test raises the class this loop checks.
export { ApiError };

export const FRAME_INTERVAL_MS = 200;
/** Without a newer frame for this long the shown frame is marked not current. */
export const STALE_AFTER_MS = 5000;
export const BACKOFF_BASE_MS = 500;
export const BACKOFF_MAX_MS = 8000;

export type LiveStatus = 'connecting' | 'live' | 'stale' | 'retrying' | 'paused' | 'ended';

export interface LiveTransport {
  open(sourceId: string, signal: AbortSignal): Promise<string>;
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
  /** Draw one frame; a rejection counts as a transient failure. */
  onFrame(frame: LiveFrame): Promise<void> | void;
  /** `paused` and `ended` also mean: drop whatever frame is shown. */
  onStatus(status: LiveStatus): void;
  visibility: Visibility;
  clock?: Clock;
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
export function startLiveLoop({ transport, sourceId, onFrame, onStatus, visibility, clock = systemClock }: LiveLoopOptions): () => void {
  let generation = 0;
  let stopped = false;
  let ended = false;
  let session: string | null = null;
  let controller: AbortController | null = null;
  let timer: unknown = null;
  let after = 0;
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
    if (session !== null) { transport.close(session); session = null; }
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
      let granted: string;
      try {
        granted = await transport.open(sourceId, attempt.signal);
      } catch (error) {
        if (current !== generation) return;
        if (refused(error)) { end(); return; }
        fail(current, connect);
        return;
      }
      // Granted after a stop, pause or newer attempt: give the slot back now.
      if (current !== generation) { transport.close(granted); return; }
      session = granted;
      after = 0;
      lastFrame = clock.now();
      pull(current);
    })();
  }

  function pull(current: number) {
    const attempt = new AbortController();
    controller = attempt;
    const started = clock.now();
    const id = session;
    if (id === null) return;
    void (async () => {
      try {
        const frame = await transport.read(id, after, attempt.signal);
        if (current !== generation) return;
        if (frame) {
          await onFrame(frame);
          if (current !== generation) return;
          after = frame.sequence;
          lastFrame = clock.now();
          report('live');
        } else if (clock.now() - lastFrame >= STALE_AFTER_MS) {
          report('stale');
        } else if (status !== 'live' && status !== 'stale') {
          report('connecting');
        }
        failures = 0;
        schedule(pull, Math.max(0, FRAME_INTERVAL_MS - (clock.now() - started)), current);
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
      release();
      failures = 0;
      connect(generation);
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
