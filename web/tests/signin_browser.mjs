/**
 * Chrome CDP checks of the built sign-in shell (Issue #10 phase 2 S5a).
 *
 * Every request is intercepted and answered locally by a synthetic stand-in
 * for the Main Server; a Chrome virtual authenticator (CDP `WebAuthn`, CTAP2,
 * resident keys, user verification) performs the real browser ceremonies. The
 * page is loaded at `http://localhost`, a secure context, so WebAuthn is
 * available. This is not real Safari / Android / passkey-provider
 * acceptance; that stays in MANUAL_TEST.md.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { launchChrome, pageFor, routeTracker, unexpectedAbandoned } from './chrome.mjs';
import { APP_CSP, SHELL_CSP } from '../scripts/policy.mjs';

const secure = 'http://localhost';
const insecure = 'http://server-sentinel.test';
const files = new Map([
  ['/', [await readFile('dist/shell/index.html'), 'text/html; charset=utf-8', SHELL_CSP]],
  ['/s.js', [await readFile('dist/shell/s.js'), 'text/javascript; charset=utf-8', null]],
  ['/s.css', [await readFile('dist/shell/s.css'), 'text/css; charset=utf-8', null]],
  ['/app/', [Buffer.from('<!doctype html><html lang="ja"><title>app</title><p id="app">app</p></html>'), 'text/html; charset=utf-8', APP_CSP]],
]);
const PRIVATE = 'synthetic private error';
const b64 = bytes => Buffer.from(bytes).toString('base64url');
// A synthetic code in canonical form and a hand-typed spelling of it:
// lower case, spaces instead of hyphens, and the O / I / L aliases.
const CODE = '0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ';
const TYPED = 'O123 4567 89ab cdef ghjk mnpq rstv wxyz';
// Aliases (o, l), a full-width space and the katakana prolonged sound mark an IME may type.
const TYPED_ALIASES = 'ol2e-4567 89AB\u3000cdef\u30fcghjk mnpq rstv wxyz';
const ALIAS_CANONICAL = '012E-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ';
const MESSAGE = {
  failed: '完了できませんでした。もう一度お試しください。',
  registered: '登録しました。サインインしてください。',
  deviceBound: 'この登録では、同期されないパスキーが必要です。セキュリティキーか、この端末だけに保存されるパスキーで登録してください。',
  unsupported: 'このブラウザーまたは接続ではパスキーを使えません。',
};

const browser = await launchChrome();
let cases = 0;
let origins = 0;

function serverStandIn(overrides) {
  const state = { userId: b64(randomBytes(16)), challenges: [] };
  const challenge = () => { const value = b64(randomBytes(32)); state.challenges.push(value); return value; };
  const json = (status, value) => [status, JSON.stringify(value), 'application/json'];
  const denied = () => json(404, { detail: PRIVATE });
  const handlers = {
    'GET /api/session': denied,
    'POST /api/auth/registration/options': () => json(200, {
      rp: { id: 'localhost', name: 'localhost' },
      user: { id: state.userId, name: 'person-a.invalid', displayName: 'person-a.invalid' },
      challenge: challenge(), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
      timeout: 60000, excludeCredentials: [],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      attestation: 'none',
    }),
    'POST /api/auth/registration': () => [204, '', null],
    'POST /api/auth/authentication/options': () => json(200, {
      challenge: challenge(), rpId: 'localhost', timeout: 60000, userVerification: 'required', allowCredentials: [],
    }),
    'POST /api/auth/authentication': () => [204, '', null],
    ...overrides,
  };
  return { state, handlers, denied, json };
}

async function scenario(name, { origin = secure, overrides = {}, viewport = { width: 390, height: 844 }, violations = [], expectAbandoned = [] }, assertions) {
  const page = await pageFor(browser, viewport);
  const stand = serverStandIn(typeof overrides === 'function' ? overrides : () => ({}));
  if (typeof overrides !== 'function') Object.assign(stand.handlers, overrides);
  else Object.assign(stand.handlers, overrides(stand));
  const requests = [];
  const unexpected = [];
  const exceptions = [];
  // Interception handlers and the requests the page abandoned (#334).
  const routes = routeTracker();
  const abandoned = [];
  const cleanup = [
    browser.on('Runtime.exceptionThrown', (_, sessionId) => { if (sessionId === page.sessionId) exceptions.push('unhandled error'); }),
    browser.on('Network.webSocketCreated', (_, sessionId) => { if (sessionId === page.sessionId) unexpected.push('websocket'); }),
  ];
  await page.command('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await page.command('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  await page.command('Page.addScriptToEvaluateOnNewDocument', { source: `
    window.__policyViolations = [];
    window.__writes = [];
    document.addEventListener('securitypolicyviolation', event => window.__policyViolations.push(event.violatedDirective));
    for (const name of ['setItem', 'removeItem', 'clear']) {
      const original = Storage.prototype[name];
      Storage.prototype[name] = function (...args) { window.__writes.push('storage ' + name); return original.apply(this, args); };
    }
    for (const name of ['pushState', 'replaceState']) {
      const original = History.prototype[name];
      History.prototype[name] = function (...args) { window.__writes.push('history ' + name); return original.apply(this, args); };
    }
  ` });
  async function route({ requestId, networkId, request }) {
    const url = new URL(request.url);
    // A request the page cancelled while paused here is recorded as
    // abandoned (failing the scenario unless it expects it); any other
    // refusal is a harness error.
    async function send(method, params) {
      if (!await page.answer(networkId, method, { requestId, ...params })) abandoned.push({ method: request.method, path: url.pathname });
    }
    let body = request.postData ?? '';
    if (!body && request.postDataEntries) body = request.postDataEntries.map(entry => Buffer.from(entry.bytes ?? '', 'base64').toString()).join('');
    requests.push({ method: request.method, url: request.url, path: url.pathname, body, headers: request.headers });
    async function fulfill(responseCode, content, contentType, csp) {
      const responseHeaders = [{ name: 'Cache-Control', value: 'no-store' }];
      if (contentType) responseHeaders.push({ name: 'Content-Type', value: contentType });
      if (csp) responseHeaders.push({ name: 'Content-Security-Policy', value: csp });
      await send('Fetch.fulfillRequest', { responseCode, responseHeaders,
        body: Buffer.from(content).toString('base64') });
    }
    if (url.origin !== origin) {
      unexpected.push(`origin ${url.origin}`);
      await send('Fetch.failRequest', { errorReason: 'BlockedByClient' }); return;
    }
    if (request.method === 'GET' && files.has(url.pathname) && url.search === '') {
      const [content, type, csp] = files.get(url.pathname);
      await fulfill(200, content, type, csp); return;
    }
    if (request.method === 'GET' && url.pathname === '/favicon.ico') { await fulfill(404, '', null, null); return; }
    const handler = stand.handlers[`${request.method} ${url.pathname}`];
    if (handler && url.search === '') {
      const answer = handler(body);
      // `null` leaves the request unanswered (a Main Server that never replies).
      if (answer !== null) await fulfill(...answer, null);
      return;
    }
    unexpected.push(`${request.method} ${url.pathname}`);
    await send('Fetch.failRequest', { errorReason: 'BlockedByClient' });
  }
  cleanup.push(browser.on('Fetch.requestPaused', (params, sessionId) => {
    if (sessionId === page.sessionId) routes.track(route(params));
  }));
  await page.command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  const posted = path => requests.filter(item => item.method === 'POST' && item.path === path).map(item => JSON.parse(item.body));
  const text = () => page.evaluate("document.getElementById('m').textContent");
  const ui = {
    async ready() { await page.wait("Boolean(document.getElementById('f')) && !document.getElementById('f').hidden"); },
    async type(id, value) {
      await page.evaluate(`(() => { const field = document.getElementById(${JSON.stringify(id)});
        field.focus(); field.value = ${JSON.stringify(value)}; field.dispatchEvent(new Event('input', { bubbles: true })); })()`);
    },
    async click(id) {
      await page.wait(`!document.getElementById(${JSON.stringify(id)}).disabled`);
      await page.evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);
    },
    async message(expected) { await page.wait(`document.getElementById('m').textContent === ${JSON.stringify(expected)}`); },
    async idle() { await page.wait("!document.getElementById('a').disabled && !document.getElementById('r').disabled"); },
  };
  let checked = false;
  try {
    await page.navigate(`${origin}/`);
    await assertions({ page, ui, requests, posted, stand, text, authenticatorId });
    await delay(100);
    assert.deepEqual(exceptions, [], 'no unhandled browser errors');
    assert.deepEqual(await routes.settle(), [], 'request interception must succeed');
    assert.deepEqual(unexpectedAbandoned(abandoned, expectAbandoned), [], 'no request is abandoned unless the scenario expects it');
    assert.deepEqual(unexpected, [], 'every request is expected');
    assert.deepEqual(await page.evaluate('window.__policyViolations'), violations, 'CSP violations');
    assert.deepEqual(await page.evaluate('window.__writes'), [], 'no storage or history writes');
    assert.equal(await page.evaluate('localStorage.length + sessionStorage.length'), 0);
    assert.equal(await page.evaluate('document.cookie'), '');
    assert.doesNotMatch(await page.evaluate('document.body.innerText'), new RegExp(PRIVATE));
    assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'no horizontal overflow');
    // The code travels only in JSON bodies: never in any URL or the location.
    const spellings = [CODE, CODE.replaceAll('-', ''), ALIAS_CANONICAL, ALIAS_CANONICAL.replaceAll('-', '')].map(value => value.toLowerCase());
    for (const item of [...requests.map(request => request.url), await page.evaluate('location.href')]) {
      const lowered = decodeURIComponent(item).toLowerCase().replace(/[\s+]/g, '');
      for (const spelling of spellings) assert.equal(lowered.includes(spelling), false, 'no URL carries the code');
    }
    for (const request of requests) {
      if (request.method !== 'POST') continue;
      // Pre-credential POSTs are same-origin JSON with no referrer, and carry
      // the exact Origin the ceremony routes require (never `null`).
      assert.match(request.headers['Content-Type'] ?? request.headers['content-type'] ?? '', /^application\/json/);
      assert.equal(request.headers.Referer ?? request.headers.referer, undefined);
      assert.equal(request.headers.Origin ?? request.headers.origin, origin, `Origin on POST ${request.path}`);
      origins++;
    }
    checked = true;
  } finally {
    // A handler the page started after the last check is still checked
    // before the page closes (#334); the teardown's own refusals are not errors.
    let late = [];
    try { late = await routes.finish(page.command); } finally { cleanup.forEach(remove => remove()); await page.close(); }
    if (checked) {
      assert.deepEqual(late, [], 'request interception must succeed until the page closes');
      // A request the page abandoned after the last check counts as well.
      assert.deepEqual(unexpectedAbandoned(abandoned, expectAbandoned), [], 'no request is abandoned unless the scenario expects it');
      // So does a request nobody expected (Codex PR #352).
      assert.deepEqual(unexpected, [], 'every request is expected until the page closes');
    }
  }
  cases++;
  process.stdout.write(`sign-in shell: ${name}\n`);
}

try {
  process.stdout.write(`Browser execution: ${browser.version.product}\n`);

  await scenario('an existing session goes straight to /app/', { overrides: { 'GET /api/session': () => [200, '{"csrf":"x","role":"viewer","permissions":[]}', 'application/json'] } }, async ({ page, requests }) => {
    await page.wait("location.pathname === '/app/'");
    assert.equal(requests.some(item => item.method === 'POST'), false);
  });

  await scenario('an insecure context shows one fixed message and makes no request', { origin: insecure }, async ({ ui, requests, page }) => {
    await ui.message(MESSAGE.unsupported);
    assert.equal(await page.evaluate("document.getElementById('f').hidden"), true);
    assert.deepEqual(requests.map(item => item.path).filter(path => path.startsWith('/api/')), []);
  });

  // Positive control: the shell policy is in force in this harness (Trusted
  // Types refuses a string HTML sink and reports it), so "no violation"
  // elsewhere is meaningful.
  await scenario('the shell policy is enforced (positive control)', { violations: ['require-trusted-types-for'] }, async ({ ui, page }) => {
    await ui.ready();
    assert.equal(await page.evaluate("(() => { try { document.body.insertAdjacentHTML('beforeend', '<b>x</b>'); return 'inserted'; } catch { return 'refused'; } })()"), 'refused');
    await page.wait('window.__policyViolations.length === 1');
  });

  for (const viewport of [{ width: 390, height: 844 }, { width: 1440, height: 900 }]) {
    await scenario(`register then sign in (${viewport.width}px)`, { viewport }, async ({ page, ui, posted, stand }) => {
      await ui.ready();
      assert.equal(await page.evaluate('document.title'), 'サインイン');
      await ui.type('c', TYPED);
      await ui.type('n', '  研究室の鍵  ');
      await ui.click('r');
      await ui.message(MESSAGE.registered);
      assert.equal(await page.evaluate('document.activeElement.id'), 'a');
      assert.equal(await page.evaluate("document.getElementById('c').value"), '');
      assert.deepEqual(posted('/api/auth/registration/options'), [{ code: CODE }]);
      const [registration] = posted('/api/auth/registration');
      assert.deepEqual(Object.keys(registration).sort(), ['code', 'credential', 'label']);
      assert.equal(registration.code, CODE);
      assert.equal(registration.label, '研究室の鍵');
      const created = registration.credential;
      assert.deepEqual(Object.keys(created).sort(), ['id', 'rawId', 'response', 'type']);
      assert.deepEqual(Object.keys(created.response).sort(), ['attestationObject', 'clientDataJSON']);
      assert.equal(created.type, 'public-key');
      assert.equal(created.id, created.rawId);
      const createData = JSON.parse(Buffer.from(created.response.clientDataJSON, 'base64url'));
      assert.equal(createData.type, 'webauthn.create');
      assert.equal(createData.origin, secure);
      assert.equal(createData.challenge, stand.state.challenges[0]);
      for (const value of [created.rawId, created.response.clientDataJSON, created.response.attestationObject]) {
        assert.match(value, /^[A-Za-z0-9_-]+$/, 'unpadded base64url');
      }

      await ui.click('a');
      await page.wait("location.pathname === '/app/'");
      assert.deepEqual(posted('/api/auth/authentication/options'), [{}]);
      const [assertion] = posted('/api/auth/authentication');
      assert.deepEqual(Object.keys(assertion).sort(), ['id', 'rawId', 'response', 'type']);
      assert.deepEqual(Object.keys(assertion.response).sort(), ['authenticatorData', 'clientDataJSON', 'signature', 'userHandle']);
      assert.equal(assertion.rawId, created.rawId);
      assert.equal(assertion.response.userHandle, stand.state.userId);
      const getData = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64url'));
      assert.equal(getData.type, 'webauthn.get');
      assert.equal(getData.challenge, stand.state.challenges[1]);
    });
  }

  await scenario('aliases and spacing normalize; an empty label is omitted', {}, async ({ ui, posted }) => {
    await ui.ready();
    await ui.type('c', TYPED_ALIASES);
    await ui.click('r');
    await ui.message(MESSAGE.registered);
    assert.deepEqual(posted('/api/auth/registration/options'), [{ code: ALIAS_CANONICAL }]);
    assert.deepEqual(Object.keys(posted('/api/auth/registration')[0]).sort(), ['code', 'credential']);
  });

  await scenario('a refused invitation (404) shows the generic message', { overrides: ({ denied }) => ({ 'POST /api/auth/registration/options': denied }) }, async ({ ui, posted, page }) => {
    await ui.ready();
    await ui.type('c', CODE);
    await ui.click('r');
    await ui.message(MESSAGE.failed);
    await ui.idle();
    assert.equal(await page.evaluate("document.getElementById('c').value"), '');
    assert.deepEqual(posted('/api/auth/registration'), []);
  });

  await scenario('a malformed code is refused locally and sends nothing', {}, async ({ ui, requests }) => {
    await ui.ready();
    await ui.type('c', CODE.slice(0, -1) + 'U');
    await ui.click('r');
    await ui.message(MESSAGE.failed);
    assert.equal(requests.some(item => item.method === 'POST'), false);
  });

  await scenario('a device-bound refusal (409) shows the device-bound guidance', { overrides: ({ json }) => ({ 'POST /api/auth/registration': () => json(409, { detail: 'device_bound_credential_required' }) }) }, async ({ ui, page }) => {
    await ui.ready();
    await ui.type('c', CODE);
    await ui.click('r');
    await ui.message(MESSAGE.deviceBound);
    assert.equal(await page.evaluate("document.getElementById('c').value"), '');
  });

  await scenario('any other registration refusal shows the generic message', { overrides: ({ json }) => ({ 'POST /api/auth/registration': () => json(409, { detail: PRIVATE }) }) }, async ({ ui }) => {
    await ui.ready();
    await ui.type('c', CODE);
    await ui.click('r');
    await ui.message(MESSAGE.failed);
  });

  await scenario('a refused sign-in (404) shows the generic message and stays', { overrides: ({ denied }) => ({ 'POST /api/auth/authentication': denied }) }, async ({ ui, page, posted }) => {
    await ui.ready();
    await ui.type('c', CODE);
    await ui.click('r');
    await ui.message(MESSAGE.registered);
    await ui.click('a');
    await ui.message(MESSAGE.failed);
    assert.equal(await page.evaluate('location.pathname'), '/');
    assert.equal(posted('/api/auth/authentication').length, 1);
  });

  await scenario('a cancelled ceremony shows the generic message', {}, async ({ ui, page, authenticatorId, posted }) => {
    await ui.ready();
    // Without a stored credential, or with user verification refused, the
    // browser ceremony fails: the page reports it generically and posts nothing.
    await page.command('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
    await ui.click('a');
    await ui.message(MESSAGE.failed);
    assert.deepEqual(posted('/api/auth/authentication'), []);
  });

  await scenario('leaving the page empties the code and label fields', {}, async ({ ui, page, requests }) => {
    await ui.ready();
    await ui.type('c', CODE);
    await ui.type('n', '研究室の鍵');
    // A document entering the back-forward cache fires pagehide (persisted).
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))");
    assert.deepEqual(await page.evaluate("[document.getElementById('c').value, document.getElementById('n').value]"), ['', '']);
    // And a restore from that cache clears again, whatever the browser kept.
    await ui.type('c', CODE);
    await ui.type('n', '研究室の鍵');
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))");
    assert.deepEqual(await page.evaluate("[document.getElementById('c').value, document.getElementById('n').value]"), ['', '']);
    // A first load (persisted: false) leaves what the user is typing alone.
    await ui.type('c', CODE);
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: false }))");
    assert.equal(await page.evaluate("document.getElementById('c').value"), CODE);
    assert.equal(requests.some(item => item.method === 'POST'), false);
  });

  await scenario('a label of 64 emoji is sent whole; 65 are refused locally', {}, async ({ ui, page, posted, requests }) => {
    await ui.ready();
    assert.equal(await page.evaluate("document.getElementById('n').maxLength"), -1, 'no UTF-16 maxlength');
    await ui.type('c', CODE);
    await ui.type('n', '😀'.repeat(64));
    await ui.click('r');
    await ui.message(MESSAGE.registered);
    assert.equal(posted('/api/auth/registration')[0].label, '😀'.repeat(64));
    const before = requests.length;
    await ui.type('c', CODE);
    await ui.type('n', '😀'.repeat(65));
    await ui.click('r');
    await ui.message(MESSAGE.failed);
    assert.equal(requests.length, before, 'nothing sent for a 65-character label');
    assert.equal(await page.evaluate("document.getElementById('c').value"), '');
  });

  await scenario('an unanswered session check shows the form after its timeout', { overrides: { 'GET /api/session': () => null } }, async ({ ui, page }) => {
    const started = Date.now();
    while (!(await page.evaluate("Boolean(document.getElementById('f')) && !document.getElementById('f').hidden"))) {
      assert.ok(Date.now() - started < 9000, 'the form appears after the session check timeout');
      await delay(100);
    }
    const waited = Date.now() - started;
    assert.ok(waited >= 4000, `form shown after ${waited} ms, not before the timeout`);
    await ui.idle();
  });

  assert.ok(origins >= 10, 'the Origin assertion ran on the ceremony POSTs');
  process.stdout.write(`${cases} sign-in shell scenarios passed (${origins} POSTs carried the exact Origin); a virtual authenticator is not real-device acceptance.\n`);
} finally { await browser.close(); }
