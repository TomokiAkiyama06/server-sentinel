/**
 * Pre-credential sign-in shell (Issue #10 phase 2 S5a, Owner decisions S5-1,
 * S5-4, S5-5).
 *
 * Served at `/` with `/s.js` and `/s.css` to anyone who reaches the reserved
 * origin, before any credential exists (ADR-0003 "minimal neutral markup and
 * script"). It is therefore Japanese only, unbranded, and shows only the
 * fixed local messages below: no server response body, status text or
 * error detail is ever rendered. It never imports the dashboard, React or
 * the i18n catalog (`scripts/build.mjs` refuses any other input).
 *
 * The invitation code travels only in the JSON body of the two redemption
 * requests: never in a URL, history entry, storage or form submission (there
 * is no form element and the inputs have no `name`), and the field is cleared
 * after every attempt.
 */
import {
  decodeCreationOptions, decodeRequestOptions, serializeAssertion, serializeRegistration,
} from '../shared/webauthn';
import { credentialLabel, normalizeInvitationCode } from './code';

const MESSAGES = {
  unsupported: 'このブラウザーまたは接続ではパスキーを使えません。',
  failed: '完了できませんでした。もう一度お試しください。',
  registered: '登録しました。サインインしてください',
  deviceBound: 'この登録では、同期されないパスキーが必要です。セキュリティキーか、この端末だけに保存されるパスキーで登録してください。',
} as const;

const APP = '/app/';

class Denied extends Error {}
class DeviceBound extends Error {}

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Denied();
  return found as T;
}

const message = element<HTMLParagraphElement>('m');
const panel = element<HTMLDivElement>('f');
const signIn = element<HTMLButtonElement>('a');
const register = element<HTMLButtonElement>('r');
const code = element<HTMLInputElement>('c');
const label = element<HTMLInputElement>('n');

function show(text: string): void { message.textContent = text; }

let current: AbortController | null = null;

function request(method: 'GET' | 'POST', path: string, signal: AbortSignal, body?: unknown): Promise<Response> {
  const init: RequestInit = {
    method, credentials: 'same-origin', mode: 'same-origin', cache: 'no-store',
    redirect: 'error', referrerPolicy: 'no-referrer', signal,
    headers: body === undefined ? { Accept: 'application/json' }
      : { Accept: 'application/json', 'Content-Type': 'application/json' },
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  return fetch(path, init);
}

async function options(path: string, signal: AbortSignal, body: unknown): Promise<unknown> {
  const response = await request('POST', path, signal, body);
  if (response.status !== 200) throw new Denied();
  return response.json();
}

function busy(state: boolean): void {
  signIn.disabled = state;
  register.disabled = state;
  panel.setAttribute('aria-busy', String(state));
}

/**
 * Run one ceremony at a time; any failure is the one generic message. `run`
 * may return a step for after the controls are enabled again (a disabled
 * button cannot take focus).
 */
async function ceremony(run: (signal: AbortSignal) => Promise<(() => void) | void>): Promise<void> {
  if (current) return;
  const controller = new AbortController();
  current = controller;
  busy(true);
  show('');
  let after: (() => void) | void = undefined;
  try {
    after = await run(controller.signal);
  } catch (error) {
    if (!controller.signal.aborted) show(error instanceof DeviceBound ? MESSAGES.deviceBound : MESSAGES.failed);
  } finally {
    current = null;
    busy(false);
  }
  after?.();
}

function startSignIn(): void {
  void ceremony(async signal => {
    const publicKey = decodeRequestOptions(await options('/api/auth/authentication/options', signal, {}));
    const asserted = await navigator.credentials.get({ publicKey, signal });
    const response = await request('POST', '/api/auth/authentication', signal, serializeAssertion(asserted));
    if (response.status !== 204) throw new Denied();
    location.replace(APP);
  });
}

function startRegistration(): void {
  if (current) return;
  // Read and clear first: the field is empty again whatever happens next.
  const typed = code.value;
  code.value = '';
  const name = credentialLabel(label.value);
  void ceremony(async signal => {
    const canonical = normalizeInvitationCode(typed);
    if (canonical === null || name === undefined) throw new Denied();
    const publicKey = decodeCreationOptions(await options('/api/auth/registration/options', signal, { code: canonical }));
    const created = await navigator.credentials.create({ publicKey, signal });
    const body: Record<string, unknown> = { code: canonical, credential: serializeRegistration(created) };
    if (name !== null) body.label = name;
    const response = await request('POST', '/api/auth/registration', signal, body);
    if (response.status === 409) {
      // The only distinct outcome: the server's fixed device-bound refusal.
      let detail: unknown;
      try { detail = ((await response.json()) as { detail?: unknown } | null)?.detail; } catch { detail = undefined; }
      if (detail === 'device_bound_credential_required') throw new DeviceBound();
      throw new Denied();
    }
    if (response.status !== 204) throw new Denied();
    label.value = '';
    show(MESSAGES.registered);
    return () => signIn.focus();
  });
}

async function start(): Promise<void> {
  if (!window.isSecureContext || typeof PublicKeyCredential === 'undefined'
      || !navigator.credentials) {
    show(MESSAGES.unsupported);
    return;
  }
  const controller = new AbortController();
  current = controller;
  try {
    const response = await request('GET', '/api/session', controller.signal);
    if (response.status === 200) { location.replace(APP); return; }
  } catch {
    // No session, or no answer: the sign-in form is the only next step.
  } finally {
    current = null;
  }
  signIn.addEventListener('click', startSignIn);
  register.addEventListener('click', startRegistration);
  for (const field of [code, label]) {
    field.addEventListener('keydown', event => { if (event.key === 'Enter' && !event.isComposing) startRegistration(); });
  }
  panel.hidden = false;
}

// Leaving the page abandons the ceremony in progress.
addEventListener('pagehide', () => current?.abort());
void start();
