/**
 * The production `DashboardServices` (Issue #10, #205 CP-5).
 *
 * Every request goes to the dashboard's own origin with the session cookie
 * (`credentials: 'same-origin'`, `mode: 'same-origin'`), is never cached and
 * never follows a redirect. A mutating request carries the session's
 * `X-CSRF-Token` (Owner decision D2) and uses the `same-origin` referrer
 * policy with an empty referrer: Fetch then sends the exact `Origin` the
 * server requires (under `no-referrer` it would be `null`) and still no
 * `Referer`. The CSRF token is held only in this closure, never in storage.
 *
 * The server answers every refusal with the same generic `404` (ADR-0003);
 * this module maps it, and `401`/`403`, to `ApiError('unauthorized')` and
 * never reads a refusal's body. Authorization is the server's: nothing here
 * decides who may see what.
 */
import { ApiError } from '../api';
import { type CameraHealth, type DashboardServices, type LiveFrame, type LiveGrant, type LiveSource, type Permission, type Session } from '../domain';

/** Agreed with the server routes (#205 CP-4). */
export const SESSION_PATH = '/api/session';
export const SIGN_OUT_PATH = '/api/auth/sign-out';
export const LIVE_SOURCES_PATH = '/api/live/sources';
export const LIVE_SESSIONS_PATH = '/api/live/sessions';
export const FRAME_SEQUENCE_HEADER = 'X-Frame-Sequence';
/** A frame larger than this is refused unread into a canvas. */
export const MAX_FRAME_BYTES = 8 * 1024 * 1024;
/** Sign-out waits at most this long for viewer opens and closes, then proceeds. */
export const SIGN_OUT_CLEANUP_MS = 2000;
/** A session check, source list or sign-out request unfinished after this is
 *  abandoned and reported as failed, so the screen offers its retry. */
export const REQUEST_TIMEOUT_MS = 10000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CSRF = /^[A-Za-z0-9_-]{43}$/;
const SEQUENCE = /^(0|[1-9][0-9]{0,15})$/;
const HEALTH: readonly CameraHealth[] = ['online', 'degraded', 'offline', 'manual_intervention_required'];
const PERMISSIONS: readonly Permission[] = ['live:view', 'recordings:view'];
/** The server's `text_value` bound, in Unicode code points (not UTF-16 units). */
const MAX_NAME = 256;
/** A `frame_interval_ms` outside this range is ignored (the default applies). */
const MIN_INTERVAL_MS = 50;
const MAX_INTERVAL_MS = 5000;
/** A close within this long (about one server lease) makes one open refusal
 *  worth one delayed retry: the server may not have released the slot yet. */
export const RECENT_CLOSE_MS = 15000;

const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** `GET /api/session` body ⇒ the UI session and its CSRF token, or throws. */
export function parseSession(value: unknown): { session: Session; csrf: string } {
  if (!record(value)) throw new ApiError('invalid_response');
  const { csrf, role, permissions } = value;
  if (typeof csrf !== 'string' || !CSRF.test(csrf) || !Array.isArray(permissions)) throw new ApiError('invalid_response');
  // An unknown role or permission fails closed instead of being guessed.
  const mapped = role === 'owner' ? 'owner' : role === 'invited_user' ? 'viewer' : null;
  if (mapped === null || !permissions.every(item => PERMISSIONS.includes(item as Permission))
      || new Set(permissions).size !== permissions.length) throw new ApiError('invalid_response');
  return { session: { state: 'allowed', role: mapped, permissions: [...permissions] as Permission[] }, csrf };
}

/** `GET /api/live/sources` body `{"sources":[{id,name,health}]}`.
 *
 * A body without a `sources` array fails closed. Within it, a malformed entry
 * (bad or repeated id, a name that is not 1..256 code points, an unknown
 * health value) is dropped on its own, so one entry never hides the rest.
 * Every other field is dropped too. */
export function parseLiveSources(value: unknown): LiveSource[] {
  if (!record(value) || !Array.isArray(value.sources)) throw new ApiError('invalid_response');
  const seen = new Set<string>();
  const sources: LiveSource[] = [];
  for (const item of value.sources as unknown[]) {
    if (!record(item)) continue;
    const { id, name, health } = item;
    if (typeof id !== 'string' || !UUID.test(id) || seen.has(id) || typeof name !== 'string') continue;
    const points = [...name].length;
    if (points === 0 || points > MAX_NAME) continue;
    if (health !== undefined && health !== null && !HEALTH.includes(health as CameraHealth)) continue;
    seen.add(id);
    sources.push({ id, name, health: (health ?? null) as CameraHealth | null });
  }
  return sources;
}

/** Read at most `limit` bytes of `response`'s body, whatever its headers say. */
async function cappedBody(response: Response, limit: number, signal: AbortSignal): Promise<Uint8Array[]> {
  if (!response.body) throw new ApiError('invalid_response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        void reader.cancel().catch(() => undefined);
        throw new ApiError('invalid_response');
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(signal.aborted ? 'cancelled' : 'unavailable');
  }
  if (total === 0) throw new ApiError('invalid_response');
  return chunks;
}

interface Send {
  method: 'GET' | 'POST';
  path: string;
  accept: string;
  signal?: AbortSignal;
  csrf?: string;
  body?: unknown;
  keepalive?: boolean;
}

export function createDashboardServices(origin: string, request: typeof fetch = (...args) => fetch(...args),
  { cleanupMs = SIGN_OUT_CLEANUP_MS, requestMs = REQUEST_TIMEOUT_MS }: { cleanupMs?: number; requestMs?: number } = {}): DashboardServices {
  const deployment = new URL(origin);
  if (!['http:', 'https:'].includes(deployment.protocol)) throw new ApiError('invalid_request');
  let csrf: string | null = null;
  // Viewer sessions this page opened and has not closed yet. Sign-out closes
  // them first: once the token is gone a later close could not be sent, and
  // the viewer slot would stay taken until the server's lease ends it.
  const viewers = new Set<string>();
  // Opens in flight: sign-out waits for them so a session granted meanwhile
  // is closed too, and no new open starts while it runs.
  const opening = new Set<Promise<LiveGrant>>();
  let signingOut = false;
  let lastClose = -Infinity;

  async function closeWith(id: string, header: string): Promise<void> {
    viewers.delete(id);
    lastClose = Date.now();
    try {
      const response = await send({ method: 'POST', path: sessionPath(id, 'close'), accept: 'application/json', csrf: header, keepalive: true });
      void response.body?.cancel().catch(() => undefined);
    } catch { /* best effort: the server's lease ends it */ }
  }

  async function send({ method, path, accept, signal, csrf: token, body, keepalive }: Send): Promise<Response> {
    const url = new URL(path, deployment.origin);
    if (url.origin !== deployment.origin || !url.pathname.startsWith('/api/')) throw new ApiError('invalid_request');
    const headers: Record<string, string> = { Accept: accept };
    if (token !== undefined) headers['X-CSRF-Token'] = token;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const init: RequestInit = {
      method, credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error',
      ...(method === 'POST' ? { referrer: '', referrerPolicy: 'same-origin' as const } : { referrerPolicy: 'no-referrer' as const }),
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      ...(keepalive ? { keepalive: true } : {}),
      ...(signal ? { signal } : {}),
    };
    let response: Response;
    try {
      response = await request(url.href, init);
    } catch { throw new ApiError(signal?.aborted ? 'cancelled' : 'unavailable'); }
    if ([401, 403, 404].includes(response.status)) {
      void response.body?.cancel().catch(() => undefined);
      throw new ApiError('unauthorized');
    }
    return response;
  }

  async function json(response: Response, signal?: AbortSignal): Promise<unknown> {
    if (response.headers.get('Content-Type')?.split(';')[0]?.trim() !== 'application/json') {
      throw new ApiError('invalid_response');
    }
    try { return await response.json(); }
    catch { throw new ApiError(signal?.aborted ? 'cancelled' : 'invalid_response'); }
  }

  function token(): string {
    if (csrf === null) throw new ApiError('unauthorized');
    return csrf;
  }

  function sessionPath(sessionId: string, action: 'frame' | 'close'): string {
    if (!UUID.test(sessionId)) throw new ApiError('invalid_request');
    return `${LIVE_SESSIONS_PATH}/${sessionId}/${action}`;
  }

  /** Run `work` with a signal that also aborts after `requestMs`; the result
   *  is bounded whether or not fetch honours the abort. */
  async function bounded<T>(signal: AbortSignal, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const deadline = new AbortController();
    const forward = () => deadline.abort();
    if (signal.aborted) deadline.abort();
    signal.addEventListener('abort', forward);
    let expiry: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      expiry = setTimeout(() => { deadline.abort(); reject(new ApiError('unavailable')); }, requestMs);
    });
    try {
      return await Promise.race([work(deadline.signal), expired]);
    } finally {
      clearTimeout(expiry);
      signal.removeEventListener('abort', forward);
    }
  }

  async function open(sourceId: string, header: string, signal: AbortSignal): Promise<LiveGrant> {
    const response = await send({
      method: 'POST', path: LIVE_SESSIONS_PATH, accept: 'application/json', signal, csrf: header,
      body: { source_id: sourceId },
    });
    if (response.status !== 200) throw new ApiError('unavailable');
    const value = await json(response, signal);
    if (!record(value) || typeof value.session_id !== 'string' || !UUID.test(value.session_id)) {
      throw new ApiError('invalid_response');
    }
    viewers.add(value.session_id);
    const interval = value.frame_interval_ms;
    const frameIntervalMs = typeof interval === 'number' && Number.isSafeInteger(interval)
      && interval >= MIN_INTERVAL_MS && interval <= MAX_INTERVAL_MS ? interval : null;
    return { sessionId: value.session_id, frameIntervalMs };
  }

  return {
    async loadSession(signal) {
      csrf = null;
      const parsed = await bounded(signal, async bound => {
        let response: Response;
        try {
          response = await send({ method: 'GET', path: SESSION_PATH, accept: 'application/json', signal: bound });
        } catch (error) {
          // The generic refusal: no current session for this browser.
          if (error instanceof ApiError && error.code === 'unauthorized') return null;
          throw error;
        }
        if (response.status !== 200) throw new ApiError('unavailable');
        return parseSession(await json(response, bound));
      });
      if (parsed === null) return { state: 'denied' };
      if (signal.aborted) throw new ApiError('cancelled');
      csrf = parsed.csrf;
      return parsed.session;
    },

    async signOut(signal) {
      const header = token();
      signingOut = true;
      try {
        // Bounded best effort: a hung open or close never holds the sign-out.
        let timer: ReturnType<typeof setTimeout> | undefined;
        const limit = new Promise<void>(resolve => { timer = setTimeout(resolve, cleanupMs); });
        // Known viewers close now; each open still in flight closes its
        // grant when it lands. Neither waits for the other.
        const cleanup = Promise.allSettled([
          ...[...viewers].map(id => closeWith(id, header)),
          ...[...opening].map(pending => pending.then(grant => closeWith(grant.sessionId, header))),
        ]);
        await Promise.race([cleanup, limit]);
        clearTimeout(timer);
        // Bounded too: a stalled request is reported as failed so the person
        // can retry.
        const response = await bounded(signal, bound =>
          send({ method: 'POST', path: SIGN_OUT_PATH, accept: 'application/json', signal: bound, csrf: header }));
        if (response.status !== 204) throw new ApiError('unavailable');
        csrf = null;
      } finally { signingOut = false; }
    },

    async loadLiveSources(signal) {
      return bounded(signal, async bound => {
        const response = await send({ method: 'GET', path: LIVE_SOURCES_PATH, accept: 'application/json', signal: bound });
        if (response.status !== 200) throw new ApiError('unavailable');
        return parseLiveSources(await json(response, bound));
      });
    },

    async openLiveSession(sourceId, signal) {
      if (!UUID.test(sourceId)) throw new ApiError('invalid_request');
      if (signingOut) throw new ApiError('unauthorized');
      const header = token();
      const pending = open(sourceId, header, signal);
      opening.add(pending);
      try { return await pending; } finally { opening.delete(pending); }
    },

    async readLiveFrame(sessionId, after, signal): Promise<LiveFrame | null> {
      if (!Number.isSafeInteger(after) || after < 0) throw new ApiError('invalid_request');
      const response = await send({
        method: 'GET', path: `${sessionPath(sessionId, 'frame')}?after=${after}`, accept: 'image/jpeg', signal,
      });
      if (response.status === 204) return null;
      if (response.status !== 200) throw new ApiError('unavailable');
      const type = response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase();
      const raw = response.headers.get(FRAME_SEQUENCE_HEADER) ?? '';
      const declared = response.headers.get('Content-Length');
      const sequence = Number(raw);
      // The declared length is checked first, and the body is read with the
      // same cap, so a missing or wrong header (a proxy re-chunking it) never
      // lets more than MAX_FRAME_BYTES in.
      if (type !== 'image/jpeg' || !SEQUENCE.test(raw) || !Number.isSafeInteger(sequence) || sequence <= after
          || (declared !== null && !(/^[0-9]{1,10}$/.test(declared) && Number(declared) <= MAX_FRAME_BYTES))) {
        void response.body?.cancel().catch(() => undefined);
        throw new ApiError('invalid_response');
      }
      const data = new Blob(await cappedBody(response, MAX_FRAME_BYTES, signal) as BlobPart[], { type: 'image/jpeg' });
      return { sequence, data };
    },

    liveClosedRecently() {
      return Date.now() - lastClose < RECENT_CLOSE_MS;
    },

    closeLiveSession(sessionId) {
      // `keepalive` lets the close outlive an unloading page; the server's
      // lease ends a session whose close never arrives.
      let path: string;
      let header: string;
      try { path = sessionPath(sessionId, 'close'); header = token(); } catch { return; }
      viewers.delete(sessionId);
      lastClose = Date.now();
      void send({ method: 'POST', path, accept: 'application/json', csrf: header, keepalive: true })
        .then(response => { void response.body?.cancel().catch(() => undefined); }, () => undefined);
    },
  };
}
