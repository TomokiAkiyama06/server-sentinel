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
 * never reads a refusal's body. The one exception is an Owner change (Issue
 * #10 phase 2 S6, routes A2-A6): there a `403` whose small JSON body is
 * exactly `{"detail":"step_up_required"}` (Owner decision D3) becomes
 * `ApiError('step_up_required')`, so the screen can run the step-up ceremony
 * (`stepUp`) and retry once (`step_up.ts`). Authorization is the server's:
 * nothing here decides who may see what, or whether a session is fresh.
 */
import { ApiError } from '../api';
import {
  type AccessCredential, type AccessPrincipal, type CameraHealth, type DashboardServices, type IssuedInvitation,
  type LiveFrame, type LiveGrant, type LiveSource, type Permission, type Session,
} from '../domain';
import { decodeRequestOptions, serializeAssertion, type AssertionJSON } from './webauthn';

/** Agreed with the server routes (#205 CP-4). */
export const SESSION_PATH = '/api/session';
export const SIGN_OUT_PATH = '/api/auth/sign-out';
export const LIVE_SOURCES_PATH = '/api/live/sources';
export const LIVE_SESSIONS_PATH = '/api/live/sessions';
export const FRAME_SEQUENCE_HEADER = 'X-Frame-Sequence';
/** Owner access administration (S4b, A1-A6) and the step-up ceremony (S3). */
export const ADMIN_PRINCIPALS_PATH = '/api/admin/principals';
export const STEP_UP_OPTIONS_PATH = '/api/auth/step-up/options';
export const STEP_UP_PATH = '/api/auth/step-up';
/** The server's fixed step-up body `{"detail":"step_up_required"}` (Owner
 *  decision D3). A body larger than this is not that answer and is not read. */
const STEP_UP_DETAIL = 'step_up_required';
const MAX_STEP_UP_BODY = 256;
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
/** A stored display name: 1 to 128 code points (a new one is at most 64, but
 *  a row written under the earlier, looser rule stays readable). */
const MAX_STORED_DISPLAY_NAME = 128;
/** The credential label bound (`human_surface._label`), in code points. */
const MAX_LABEL = 64;
/** A new invitee's display name (`store.display_name_acceptable`). */
export const MAX_DISPLAY_NAME = 64;
const REFUSED_NAME_CHARACTERS = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;
/** ISO 8601 UTC as Python's `isoformat()` writes an aware UTC time. */
const UTC_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:\+00:00|Z)$/;
/** The canonical invitation code (`server/app/auth/invitation_code.py`): 32
 *  Crockford base32 characters (no I, L, O, U) in eight groups of four. */
export const INVITATION_CODE = /^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){7}$/;
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

/** Whether `value` is a display name the server accepts for a new invitee.
 *  Advisory only: the server repeats the check and its refusal is generic. */
export function displayNameAcceptable(value: string): boolean {
  const points = [...value].length;
  return points >= 1 && points <= MAX_DISPLAY_NAME && !REFUSED_NAME_CHARACTERS.test(value);
}

function utc(value: unknown): string {
  if (typeof value !== 'string' || !UTC_TIME.test(value)) throw new ApiError('invalid_response');
  return value;
}

function optionalUtc(value: unknown): string | null {
  return value === null ? null : utc(value);
}

function bool(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ApiError('invalid_response');
  return value;
}

function permissionList(value: unknown): Permission[] {
  if (!Array.isArray(value) || !value.every(item => PERMISSIONS.includes(item as Permission))
      || new Set(value).size !== value.length) throw new ApiError('invalid_response');
  return [...value] as Permission[];
}

function parseCredential(value: unknown): AccessCredential {
  if (!record(value)) throw new ApiError('invalid_response');
  const { handle, label, status, inconsistency_reason: reason } = value;
  if (typeof handle !== 'string' || !UUID.test(handle)) throw new ApiError('invalid_response');
  if (label !== null && (typeof label !== 'string' || label.length === 0 || [...label].length > MAX_LABEL)) {
    throw new ApiError('invalid_response');
  }
  if (status !== 'active' && status !== 'revoked' && status !== 'inconsistent') throw new ApiError('invalid_response');
  if (reason !== null && reason !== 'backup_eligibility_changed') throw new ApiError('invalid_response');
  // The server derives `revoked` from the revocation time alone.
  const revokedAt = optionalUtc(value.revoked_at);
  if ((status === 'revoked') !== (revokedAt !== null)) throw new ApiError('invalid_response');
  return {
    handle, label: label as string | null, status,
    inconsistency_reason: reason as AccessCredential['inconsistency_reason'],
    backup_eligible: bool(value.backup_eligible), backup_state: bool(value.backup_state),
    created_at: utc(value.created_at), last_used_at: optionalUtc(value.last_used_at), revoked_at: revokedAt,
  };
}

/** `GET /api/admin/principals` body `{"principals":[...]}` (A1).
 *
 * The whole inventory fails closed on any malformed entry: an access list
 * that silently left one person out would misstate who can reach the
 * deployment. Only the documented fields are copied, so anything else a
 * server might add (never a proxy identity, Owner decision D14) is dropped
 * before it could be rendered. */
export function parsePrincipals(value: unknown): AccessPrincipal[] {
  if (!record(value) || !Array.isArray(value.principals)) throw new ApiError('invalid_response');
  const seen = new Set<string>();
  return (value.principals as unknown[]).map(item => {
    if (!record(item)) throw new ApiError('invalid_response');
    const { id, display_name: name, role, status, invitation } = item;
    if (typeof id !== 'string' || !UUID.test(id) || seen.has(id)) throw new ApiError('invalid_response');
    seen.add(id);
    if (typeof name !== 'string' || name.length === 0 || [...name].length > MAX_STORED_DISPLAY_NAME) {
      throw new ApiError('invalid_response');
    }
    if (role !== 'owner' && role !== 'invited_user') throw new ApiError('invalid_response');
    if (status !== 'invited' && status !== 'active' && status !== 'revoked') throw new ApiError('invalid_response');
    if (!record(invitation)) throw new ApiError('invalid_response');
    // The server sends an expiry exactly for a pending code.
    const pending = bool(invitation.pending);
    const expires = optionalUtc(invitation.expires_at);
    if (pending !== (expires !== null)) throw new ApiError('invalid_response');
    if (!Array.isArray(item.credentials)) throw new ApiError('invalid_response');
    const handles = new Set<string>();
    const credentials = (item.credentials as unknown[]).map(entry => {
      const credential = parseCredential(entry);
      if (handles.has(credential.handle)) throw new ApiError('invalid_response');
      handles.add(credential.handle);
      return credential;
    });
    return {
      id, display_name: name, role, status, created_at: utc(item.created_at), revoked_at: optionalUtc(item.revoked_at),
      permissions: permissionList(item.permissions), invitation: { pending, expires_at: expires }, credentials,
    };
  });
}

/** An issued code (A2 / A3 bodies): the canonical form and its expiry, or throws. */
export function parseIssuedInvitation(value: unknown): IssuedInvitation {
  if (!record(value) || typeof value.code !== 'string' || !INVITATION_CODE.test(value.code)) {
    throw new ApiError('invalid_response');
  }
  return { code: value.code, expires_at: utc(value.expires_at) };
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
  /** An Owner operation: its fixed `403 step_up_required` is reported as such. */
  stepUp?: boolean;
}

/** Whether `response` (a `403`) is exactly the server's step-up answer. The
 *  body is read only as JSON and at most MAX_STEP_UP_BODY bytes (a declared
 *  larger length is not read at all, a missing one is capped while reading);
 *  any other `403` is a refusal like every other. */
async function stepUpAnswer(response: Response, signal: AbortSignal | undefined): Promise<boolean> {
  if (response.headers.get('Content-Type')?.split(';')[0]?.trim() !== 'application/json') return false;
  const declared = response.headers.get('Content-Length');
  if (declared !== null && !(/^[0-9]{1,10}$/.test(declared) && Number(declared) <= MAX_STEP_UP_BODY)) return false;
  try {
    const chunks = await cappedBody(response, MAX_STEP_UP_BODY, signal ?? new AbortController().signal);
    const bytes = new Uint8Array(await new Blob(chunks as BlobPart[]).arrayBuffer());
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return record(value) && Object.keys(value).length === 1 && value.detail === STEP_UP_DETAIL;
  } catch { return false; }
}

/** One user-verified assertion for `publicKey`, serialized for the server. */
export type AssertWith = (publicKey: PublicKeyCredentialRequestOptions, signal: AbortSignal) => Promise<AssertionJSON>;

const browserAssertion: AssertWith = async (publicKey, signal) => {
  if (typeof navigator === 'undefined' || !navigator.credentials || typeof PublicKeyCredential === 'undefined') {
    throw new ApiError('unavailable');
  }
  return serializeAssertion(await navigator.credentials.get({ publicKey, signal }));
};

export function createDashboardServices(origin: string, request: typeof fetch = (...args) => fetch(...args),
  { cleanupMs = SIGN_OUT_CLEANUP_MS, requestMs = REQUEST_TIMEOUT_MS, assertWith = browserAssertion }:
    { cleanupMs?: number; requestMs?: number; assertWith?: AssertWith } = {}): DashboardServices {
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

  async function send({ method, path, accept, signal, csrf: token, body, keepalive, stepUp }: Send): Promise<Response> {
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
    if (stepUp && response.status === 403 && await stepUpAnswer(response, signal)) {
      throw new ApiError('step_up_required');
    }
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

  function principalPath(principalId: string, suffix: string): string {
    if (!UUID.test(principalId)) throw new ApiError('invalid_request');
    return `${ADMIN_PRINCIPALS_PATH}/${principalId}${suffix}`;
  }

  /** One Owner change (A2-A6): CSRF, a JSON body, bounded in time, and the
   *  step-up answer reported as `step_up_required`. Any status other than
   *  `expected` is a failure whose outcome the caller must not guess. */
  async function change(path: string, body: unknown, expected: 200 | 204, signal: AbortSignal): Promise<unknown> {
    const header = token();
    return bounded(signal, async bound => {
      const response = await send({ method: 'POST', path, accept: 'application/json', signal: bound, csrf: header,
        body, stepUp: true });
      if (response.status !== expected || expected === 204) {
        void response.body?.cancel().catch(() => undefined);
        if (response.status !== expected) throw new ApiError('unavailable');
        return undefined;
      }
      return json(response, bound);
    });
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

    async loadPrincipals(signal) {
      return bounded(signal, async bound => {
        const response = await send({ method: 'GET', path: ADMIN_PRINCIPALS_PATH, accept: 'application/json', signal: bound });
        if (response.status !== 200) throw new ApiError('unavailable');
        return parsePrincipals(await json(response, bound));
      });
    },

    async invitePrincipal(displayName, permissions, signal) {
      if (!displayNameAcceptable(displayName) || !permissions.every(item => PERMISSIONS.includes(item))
          || new Set(permissions).size !== permissions.length) throw new ApiError('invalid_request');
      const value = await change(ADMIN_PRINCIPALS_PATH, { display_name: displayName, permissions: [...permissions] },
        200, signal);
      const issued = parseIssuedInvitation(value);
      if (!record(value) || typeof value.principal_id !== 'string' || !UUID.test(value.principal_id)) {
        throw new ApiError('invalid_response');
      }
      return { ...issued, principal_id: value.principal_id };
    },

    async reissueInvitation(principalId, signal) {
      return parseIssuedInvitation(await change(principalPath(principalId, '/invitation'), {}, 200, signal));
    },

    async changePermission(principalId, permission, granted, signal) {
      if (!PERMISSIONS.includes(permission) || typeof granted !== 'boolean') throw new ApiError('invalid_request');
      await change(principalPath(principalId, '/permissions'), { permission, granted }, 204, signal);
    },

    async revokePrincipal(principalId, signal) {
      await change(principalPath(principalId, '/revoke'), {}, 204, signal);
    },

    async revokeCredential(principalId, handle, signal) {
      if (!UUID.test(handle)) throw new ApiError('invalid_request');
      await change(principalPath(principalId, `/credentials/${handle}/revoke`), {}, 204, signal);
    },

    async stepUp(signal) {
      const header = token();
      // Each request is bounded; the ceremony in between waits for the person
      // (the authenticator prompt carries the server's own timeout).
      const options = await bounded(signal, async bound => {
        const response = await send({ method: 'POST', path: STEP_UP_OPTIONS_PATH, accept: 'application/json',
          signal: bound, csrf: header, body: {} });
        if (response.status !== 200) throw new ApiError('unavailable');
        return json(response, bound);
      });
      let publicKey: PublicKeyCredentialRequestOptions;
      try { publicKey = decodeRequestOptions(options); } catch { throw new ApiError('invalid_response'); }
      // The server names this session's own credential as the only one
      // allowed; it is passed through unchanged (no picker, no fallback).
      let assertion: AssertionJSON;
      try { assertion = await assertWith(publicKey, signal); } catch {
        throw new ApiError(signal.aborted ? 'cancelled' : 'unavailable');
      }
      await bounded(signal, async bound => {
        const response = await send({ method: 'POST', path: STEP_UP_PATH, accept: 'application/json', signal: bound,
          csrf: header, body: assertion });
        void response.body?.cancel().catch(() => undefined);
        if (response.status !== 204) throw new ApiError('unavailable');
      });
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
