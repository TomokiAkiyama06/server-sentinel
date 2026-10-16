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
import { type CameraHealth, type DashboardServices, type LiveFrame, type LiveSource, type Permission, type Session } from '../domain';

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
/** The sign-out request itself is abandoned (reported as failed) after this. */
export const SIGN_OUT_TIMEOUT_MS = 10000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CSRF = /^[A-Za-z0-9_-]{43}$/;
const SEQUENCE = /^(0|[1-9][0-9]{0,15})$/;
const HEALTH: readonly CameraHealth[] = ['online', 'degraded', 'offline', 'manual_intervention_required'];
const PERMISSIONS: readonly Permission[] = ['live:view', 'recordings:view'];
const MAX_NAME = 200;

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

/** `GET /api/live/sources` body `{"sources":[{id,name,health?}]}`; extra fields are dropped. */
export function parseLiveSources(value: unknown): LiveSource[] {
  if (!record(value) || !Array.isArray(value.sources)) throw new ApiError('invalid_response');
  const seen = new Set<string>();
  return value.sources.map((item: unknown): LiveSource => {
    if (!record(item)) throw new ApiError('invalid_response');
    const { id, name, health } = item;
    if (typeof id !== 'string' || !UUID.test(id) || seen.has(id) || typeof name !== 'string'
        || name.length === 0 || name.length > MAX_NAME
        || (health !== undefined && health !== null && !HEALTH.includes(health as CameraHealth))) {
      throw new ApiError('invalid_response');
    }
    seen.add(id);
    return { id, name, health: (health ?? null) as CameraHealth | null };
  });
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
  { cleanupMs = SIGN_OUT_CLEANUP_MS, signOutMs = SIGN_OUT_TIMEOUT_MS }: { cleanupMs?: number; signOutMs?: number } = {}): DashboardServices {
  const deployment = new URL(origin);
  if (!['http:', 'https:'].includes(deployment.protocol)) throw new ApiError('invalid_request');
  let csrf: string | null = null;
  // Viewer sessions this page opened and has not closed yet. Sign-out closes
  // them first: once the token is gone a later close could not be sent, and
  // the viewer slot would stay taken until the server's lease ends it.
  const viewers = new Set<string>();
  // Opens in flight: sign-out waits for them so a session granted meanwhile
  // is closed too, and no new open starts while it runs.
  const opening = new Set<Promise<string>>();
  let signingOut = false;

  async function closeWith(id: string, header: string): Promise<void> {
    viewers.delete(id);
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

  async function open(sourceId: string, header: string, signal: AbortSignal): Promise<string> {
    const response = await send({
      method: 'POST', path: LIVE_SESSIONS_PATH, accept: 'application/json', signal, csrf: header,
      body: { source_id: sourceId },
    });
    if (response.status !== 200 && response.status !== 201) throw new ApiError('unavailable');
    const value = await json(response, signal);
    if (!record(value) || typeof value.session_id !== 'string' || !UUID.test(value.session_id)) {
      throw new ApiError('invalid_response');
    }
    viewers.add(value.session_id);
    return value.session_id;
  }

  return {
    async loadSession(signal) {
      csrf = null;
      let response: Response;
      try {
        response = await send({ method: 'GET', path: SESSION_PATH, accept: 'application/json', signal });
      } catch (error) {
        // The generic refusal: no current session for this browser.
        if (error instanceof ApiError && error.code === 'unauthorized') return { state: 'denied' };
        throw error;
      }
      if (response.status !== 200) throw new ApiError('unavailable');
      const parsed = parseSession(await json(response, signal));
      if (!signal.aborted) csrf = parsed.csrf;
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
          ...[...opening].map(pending => pending.then(id => closeWith(id, header))),
        ]);
        await Promise.race([cleanup, limit]);
        clearTimeout(timer);
        // Bounded too, whether or not fetch honours the abort: a stalled
        // request is reported as failed so the person can retry.
        const deadline = new AbortController();
        const forward = () => deadline.abort();
        signal.addEventListener('abort', forward);
        let expiry: ReturnType<typeof setTimeout> | undefined;
        const expired = new Promise<never>((_, reject) => {
          expiry = setTimeout(() => { deadline.abort(); reject(new ApiError('unavailable')); }, signOutMs);
        });
        try {
          const response = await Promise.race([
            send({ method: 'POST', path: SIGN_OUT_PATH, accept: 'application/json', signal: deadline.signal, csrf: header }),
            expired,
          ]);
          if (response.status !== 204) throw new ApiError('unavailable');
          csrf = null;
        } finally {
          clearTimeout(expiry);
          signal.removeEventListener('abort', forward);
        }
      } finally { signingOut = false; }
    },

    async loadLiveSources(signal) {
      const response = await send({ method: 'GET', path: LIVE_SOURCES_PATH, accept: 'application/json', signal });
      if (response.status !== 200) throw new ApiError('unavailable');
      return parseLiveSources(await json(response, signal));
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
      const length = Number(response.headers.get('Content-Length') ?? '0');
      if (type !== 'image/jpeg' || !SEQUENCE.test(raw) || !(length <= MAX_FRAME_BYTES)) {
        void response.body?.cancel().catch(() => undefined);
        throw new ApiError('invalid_response');
      }
      const sequence = Number(raw);
      if (!Number.isSafeInteger(sequence) || sequence <= after) throw new ApiError('invalid_response');
      let data: Blob;
      try { data = await response.blob(); }
      catch { throw new ApiError(signal.aborted ? 'cancelled' : 'unavailable'); }
      if (data.size === 0 || data.size > MAX_FRAME_BYTES) throw new ApiError('invalid_response');
      return { sequence, data };
    },

    closeLiveSession(sessionId) {
      // `keepalive` lets the close outlive an unloading page; the server's
      // lease ends a session whose close never arrives.
      let path: string;
      let header: string;
      try { path = sessionPath(sessionId, 'close'); header = token(); } catch { return; }
      viewers.delete(sessionId);
      void send({ method: 'POST', path, accept: 'application/json', csrf: header, keepalive: true })
        .then(response => { void response.body?.cancel().catch(() => undefined); }, () => undefined);
    },
  };
}
